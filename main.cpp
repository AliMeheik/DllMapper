#include <windows.h>
#include <string>
#include <iostream>
#include <fstream>
#include "util.h"

using std::wcin;
using std::wstring;

//define function pointers to be used in TargetProcess
using GetProcAddress_t  = FARPROC ( __stdcall* )( HMODULE moduleHandle, LPCSTR procName               );
using LoadLibrary_t     = HMODULE ( __stdcall* )( LPCSTR moduleName                                   );
using DllMain_t         = BOOL    ( __stdcall* )( HMODULE dllHandle, DWORD reason, void* pReserverd   );

struct ShellArgs_t {
    
    //functions
    GetProcAddress_t _GetProcAddress;
    LoadLibrary_t    _LoadLibrary;
    DllMain_t        _DllMain;

    //addresses
    BYTE*            pBase;

};

#define RELOC_FLAG32( relocEntry ) ( ( relocEntry & 0xF000 ) == IMAGE_REL_BASED_HIGHLOW )
#define RELOC_FLAG64( relocEntry ) ( ( relocEntry & 0xF000 ) == IMAGE_REL_BASED_DIR64 )
#ifdef _WIN64 
#define RELOC_FLAG RELOC_FLAG64
#else 
#define RELOC_FLAG RELOC_FLAG32
#endif

DWORD ShellCode( ShellArgs_t* args ) {
    
    //validate args
    if( !args ) {
        return 0;
    }
    
    //setup header pointers
    BYTE* pBase = args->pBase;
    auto pRemoteDosHeader      = reinterpret_cast<PIMAGE_DOS_HEADER     >( pBase );
    auto pRemoteNtHeader       = reinterpret_cast<PIMAGE_NT_HEADERS     >( pBase + pRemoteDosHeader->e_lfanew );
    auto pRemoteOptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>( &pRemoteNtHeader->OptionalHeader );
    

    
    //check for relocation
    DWORD relocationDelta = reinterpret_cast<DWORD>( pBase - pRemoteOptionalHeader->ImageBase );
    if( relocationDelta ) {

        if( !pRemoteOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size ) {
            return 0;
        }
        
        //get the pointer to first entry in RelocArray of PIMAGE_BASE_RELOCATION structures
        auto pRelocArray = reinterpret_cast<PIMAGE_BASE_RELOCATION>( pBase + pRemoteOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress );
        while( pRelocArray->VirtualAddress ) {
            WORD* pRelocEntry = reinterpret_cast<WORD*>( pRelocArray + 1 ); //get to the first entry of RelocAddresses array which are of type WORD
            DWORD numOfRelocEntry = ( pRelocArray->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD ); 
            
            for( int i = 0; i != numOfRelocEntry; i++ ) {
                if( RELOC_FLAG( pRelocEntry[i] ) ) { //check if its the reloc type we care about 
                    DWORD* patchAddress = reinterpret_cast<DWORD*>( pBase + pRelocArray->VirtualAddress + ( pRelocEntry[i] & 0xFFF ) ); 
                    *patchAddress += relocationDelta;  
                }
            }
            pRelocArray = reinterpret_cast<PIMAGE_BASE_RELOCATION>( reinterpret_cast<BYTE*>( pRelocArray ) + pRelocArray->SizeOfBlock );
        }
    }
    
    //fix imports
    if( pRemoteOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size ) {

        auto pImportArray = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>( pBase + pRemoteOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress ); 
            
        for( ; pImportArray->Name ; pImportArray++ ) {
            
            //get the current import module handle
            HMODULE    hImportModule      = args->_LoadLibrary( reinterpret_cast<char*>( pBase + pImportArray->Name ) ); 

            if( !hImportModule ) {
                continue;
            }

            ULONG_PTR* pNameImportTable   = reinterpret_cast<ULONG_PTR*>( pBase + pImportArray->OriginalFirstThunk  );
            ULONG_PTR* pAddresImportTable = reinterpret_cast<ULONG_PTR*>( pBase + pImportArray->FirstThunk          );
            
            //in the end they both point to the same thing IMAGE_THUNK_DATA array, after the fix IAT will point to actual addresses 
            if( !( *pNameImportTable ) ) {
                pNameImportTable = pAddresImportTable;
            }
            
            for( ; *pNameImportTable; pNameImportTable++, pAddresImportTable++ ) {
                if( IMAGE_SNAP_BY_ORDINAL( *pNameImportTable ) ) {
                   //if import by function ordinal
                   *pAddresImportTable = reinterpret_cast<ULONG_PTR>( args->_GetProcAddress( hImportModule, reinterpret_cast<char*>( *pNameImportTable & 0xFFFF ) ) );

                } else {
                    //if import by function name
                    auto pImportFunctionData = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>( pBase + *pNameImportTable );
                    *pAddresImportTable      = reinterpret_cast<ULONG_PTR>( args->_GetProcAddress( hImportModule, reinterpret_cast<char*>( pImportFunctionData->Name ) ) );
                }
            }
        }   
    }
    
    //assign and call DllMain function
    args->_DllMain = reinterpret_cast<DllMain_t>( pBase + pRemoteOptionalHeader->AddressOfEntryPoint );
    args->_DllMain( reinterpret_cast<HINSTANCE>( pBase ), DLL_PROCESS_ATTACH, NULL );
    return 1;
}


DWORD ShellStub() { return 0; }

void Run( LPCSTR path, const HANDLE hTargetProcess ) {

    std::ifstream streamBuffer( path, std::ios::binary | std::ios::ate );

    //file size
    DWORD fileSize = static_cast<DWORD>( streamBuffer.tellg() );
    BYTE* pLocalFileBuffer = new BYTE[ fileSize ];

    //load file into memory
    streamBuffer.seekg( 0, std::ios::beg );
    streamBuffer.read( reinterpret_cast<char*>( pLocalFileBuffer ), fileSize );
    streamBuffer.close();

    //Set header pointers 
    auto pLocalDosHeader      = reinterpret_cast<PIMAGE_DOS_HEADER     >( pLocalFileBuffer );
    auto pLocalNtHeader       = reinterpret_cast<PIMAGE_NT_HEADERS     >( pLocalFileBuffer + pLocalDosHeader->e_lfanew );
    auto pLocalSectionHeader  = reinterpret_cast<PIMAGE_SECTION_HEADER >( pLocalNtHeader + 1 );
    auto pLocalFileHeader     = reinterpret_cast<PIMAGE_FILE_HEADER    >( &pLocalNtHeader->FileHeader ); 
    auto pLocalOptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>( &pLocalNtHeader->OptionalHeader );

    //Calculate the allocation size
    DWORD shellCodeSize       = ( reinterpret_cast<DWORD>( ShellStub ) - reinterpret_cast<DWORD>( ShellCode ) );
    DWORD remoteBufferSize    = pLocalOptionalHeader->SizeOfImage + shellCodeSize + sizeof( ShellArgs_t );
    //alloc external memory in process 
    BYTE* pRemoteFileBuffer   = reinterpret_cast<BYTE*>( VirtualAllocEx( hTargetProcess, reinterpret_cast<LPVOID>( pLocalOptionalHeader->ImageBase ), remoteBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) );

    //check can we allocate at desired image base, if not allocate where ever. 
    if( !pRemoteFileBuffer ) {
        pRemoteFileBuffer =  reinterpret_cast<BYTE*>( VirtualAllocEx( hTargetProcess, NULL, remoteBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) );
        if( !pRemoteFileBuffer ) {
            printf( "Failed to allocate memory in target process, ERROR[ %x ]\n", GetLastError() );
            delete[] pLocalFileBuffer;
            system( "pause" );
            return;
        }
    }

    //write all( including section headers ) image headers
    if( !WriteProcessMemory( hTargetProcess, reinterpret_cast<LPVOID>( pRemoteFileBuffer ), pLocalFileBuffer, pLocalOptionalHeader->SizeOfHeaders, nullptr ) ) {
        printf( "Failed to write image headers, ERROR[%x]\n", GetLastError() );
        delete[] pLocalFileBuffer;
        system( "pause" );
        return;
    } 

    //write sections 
    DWORD sectionCount = pLocalFileHeader->NumberOfSections;

    for( int i = 0; i != sectionCount; i++ ) {
        if( !WriteProcessMemory( hTargetProcess, reinterpret_cast<LPVOID>( pRemoteFileBuffer + pLocalSectionHeader[i].VirtualAddress ), reinterpret_cast<LPCVOID>( pLocalFileBuffer + pLocalSectionHeader[i].PointerToRawData ), pLocalSectionHeader[i].SizeOfRawData,  nullptr )) {
            printf( "Failed to write section %s, ERROR[%x]\n", pLocalSectionHeader[i].Name, GetLastError() );
            delete [] pLocalFileBuffer;
            system( "pause" );
            return;
        }
    }

    //setup addreses 
    LPVOID argsAddress      =  reinterpret_cast<LPVOID>( pRemoteFileBuffer + pLocalOptionalHeader->SizeOfImage );
    LPVOID shellCodeAddress =  reinterpret_cast<LPVOID>( reinterpret_cast<BYTE*>( argsAddress ) + sizeof( ShellArgs_t ) );

    delete [] pLocalFileBuffer;

    //setup args and write them
    ShellArgs_t args;
    args._GetProcAddress = GetProcAddress;
    args._LoadLibrary    = LoadLibraryA;
    args.pBase           = pRemoteFileBuffer;
    
    
    if( !WriteProcessMemory( hTargetProcess, argsAddress, &args, sizeof( ShellArgs_t ), nullptr ) ) {
        printf( "Failed to write shell code arguments, ERROR[%x]\n", GetLastError() );
        system( "pause" );
        return;
    }

    
    if( !WriteProcessMemory( hTargetProcess, shellCodeAddress, ShellCode, shellCodeSize, nullptr) ) {
        printf( "Failed to write shellcode, ERROR[%x]\n", GetLastError() );
        system( "pause" );
        return;
    }

    HANDLE hRemoteThread = CreateRemoteThread( hTargetProcess, nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>( shellCodeAddress ), argsAddress, NULL, nullptr ); 
    if( !hRemoteThread ) {
        printf( "Failed to create remote thread, ERROR[%x]\n", GetLastError() );
        system( "pause" );
        return;
    }
    
    WaitForSingleObject( hRemoteThread, INFINITE );
    VirtualFreeEx( hRemoteThread, pRemoteFileBuffer, 0, MEM_RELEASE ); 
    
    printf( "injection success\n" );
    return;
}

int main() {

    //get the dll path & name
    LPCSTR dllPath = "DllForInjecting.dll";

    printf( "Enter process name: ");

    wstring processName;
    getline ( wcin, processName );

    const DWORD processId = FindProcessId( processName.c_str() );
    if( !processId ) {
        printf( "Failed to get process id. ERROR[%x]\n", GetLastError() );
        system("pause");
        return 0;
    }


    //get handle to process
    const HANDLE hTargetProcess = OpenProcess( PROCESS_ALL_ACCESS, false, processId );
    if( !hTargetProcess ) {
        printf( "Couldent open target process [%S]\n", processName.c_str() );
        system("pause");
        return 0;
    }

    Run( dllPath, hTargetProcess ); 
    system( "pause" );
    return 0;
}

