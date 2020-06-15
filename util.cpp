#include "util.h"
#include <TlHelp32.h>

DWORD FindProcessId( LPCWSTR name ) {
    HANDLE modules_handle = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, NULL );

    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof( process_entry ); 

    if( Process32First( modules_handle, &process_entry ) ) {

        do {
            if(  !_wcsicmp( name, process_entry.szExeFile )) {
                CloseHandle( modules_handle );
                return process_entry.th32ProcessID;
            }

        } while ( Process32Next( modules_handle, &process_entry ));
    }
    return NULL;
}
