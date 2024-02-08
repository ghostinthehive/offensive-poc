; Dynamic SysCall invocation
; HellsGate implementation

.data 
    wSystemCall DWORD 000h

.code 
    ; loads extracted syscall
    LoadSystemcall PROC
        mov wSystemCall, 000h
        mov wSystemCall, ecx
        ret
    LoadSystemcall ENDP

    ; construct the syscall stub with extracted SysCall
    ExecuteSystemcall PROC
        mov r10, rcx
        mov eax, wSystemCall

        syscall
        ret
    ExecuteSystemcall ENDP
end