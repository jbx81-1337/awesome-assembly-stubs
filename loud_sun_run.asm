;=============================================================================;
; Author: jbx81-1337
; Compatible: Windows 7 / Server 2003 and newer
; Architecture: x64
; Size: TBD
; Loud Sun Run implementation in Assembler
; Original work: https://github.com/susMdT/LoudSunRun
; =============================================================================;

[BITS 64]


; Original PoC
; Out of Scope, get the function address.
; PVOID pPrintf = GetProcAddress(LoadLibraryA("msvcrt.dll"), "printf");

; STEP 1: Find the Gadget \xff\x23 on kernel32.dll .text (?)
;   - navigate PEB
;   - find kernel32 (save base address)
;   - find ntdll (save base address)
;   - find .text of kernel32
;   - find the gadget
;   - save the gadget
;
; p.trampoline = FindGadget((LPBYTE)GetModuleHandle(L"kernel32.dll"), 0x200000);
; printf("[+] Gadget is at 0x%llx\n", p.trampoline);

; Step 2: Get BaseThreadInitThunk and RtlUserThreadStart function

; ReturnAddress = (PBYTE)(GetProcAddress(LoadLibraryA("kernel32.dll"), "BaseThreadInitThunk")) + 0x14; // Would walk export table but am lazy
; p.BTIT_ss = CalculateFunctionStackSizeWrapper(ReturnAddress);
; p.BTIT_retaddr = ReturnAddress;

; ReturnAddress = (PBYTE)(GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlUserThreadStart")) + 0x21;
; p.RUTS_ss = CalculateFunctionStackSizeWrapper(ReturnAddress);
; p.RUTS_retaddr = ReturnAddress;

; p.Gadget_ss = CalculateFunctionStackSizeWrapper(p.trampoline);

%define hKernel32               [r9]
%define hNtDll                  [r9 + 8]
%define pGadgetAddr             [r9 + 16]
%define pGadgetStack            [r9 + 24]
%define pBTITRet                [r9 + 32]
%define pBTITStack              [r9 + 40]
%define pRUTSRet                [r9 + 48]
%define pRUTSStack              [r9 + 56]

TEXT_HASH               EQU 0xEBC2F9B4
KERNEL32_DLL_HASH       EQU 0xDEADBEEF      ; ror13('kernel32.dll')
NTDLL_DLL_HASH          EQU 0xDEADBEEF      ; ror13('ntdll.dll')
ROR13_UPPERCASE         EQU 1
ROR13_NULLTERM          EQU 2

;
; UINT_PTR SpoofCall(DWORD dwFunctionHash, UINT_PTR * lpArgs, DWORD dwNumOfArgs, LPVOID **lpSpoofStruct)
;   rcx = Function Hash (ror13)
;   rdx = lpArgs
;   r8  = dwNumberOfArgs
;   r
SpoofCall:
    cmp     hKernel32, 0
    jne     .get_ntdll   
.get_kernel32:
    mov     r10, KERNEL32_DLL_HASH        ; kernel32 hash
    call    GetModuleHandleH
    mov     hKernel32, rax
.get_ntdll:
    cmp     hNtDll, 0
    jne     .get_gadget_addr
    mov     r10, NTDLL_DLL_HASH        ; ntdll hash
    call    GetModuleHandleH
    mov     hNtDll, rax
.get_gadget_addr:
    cmp     pGadgetAddr, 0
    jne     .get_gadget_stack
    call    FindGadget
    mov     pGadgetAddr, rax
.get_gadget_stack:
.get_btit_ret:
.get_btit_stack:
.get_ruts_ret:
.get_ruts_stack:

.ret:
    ret

;
;   input RCX
;

CalculateFunctionStackSizeWrapper:
    push    rbp
    mov     rbp, rsp
    
CalculateFunctionStackSizeWrapper_end:
    ret
;
;   Find the opcode \xFF\x23 inside kernel32 
;   rax = address of the gadget
;
FindGadget:
    xor     rax, rax
    mov     r10, KERNEL32_DLL_HASH
    call    GetModuleHandleH
    mov     rcx, rax
    mov     r10, TEXT_HASH
    call    GetSectionH
    mov     rcx, r10
.find_gadget_loop:
    cmp     word [rax], 0x23FF      ; \xFF\x23 stored little-endian
    je      .find_gadget_found
    inc     rax
    dec     rcx
    test    rcx, rcx
    jnz     .find_gadget_loop
    xor     rax, rax
.find_gadget_found:
    ret

; HELPER
; HMODULE GetModuleHandleH(DWORD dwModuleHash)
; Walk the PEB InMemoryOrderModuleList and return the base address
; of the module whose BaseDllName matches the given ror13 hash.
;
; Arguments:
;   r10  = dwModuleHash — ror13 hash of the module name (uppercase UTF-16LE bytes)
; Returns:
;   rax  = module base address, or 0 if not found
; Clobbers: rax, rcx, rdx, r11, r12
; Preserves: rbx, r10
GetModuleHandleH:
    push    r12                     ; save r12
    push    rbx                     ; save rbx
    xor     rdx, rdx                ; clear rdx
    mov     rdx, [gs:rdx+0x60]      ; Get a pointer to the PEB
    mov     rdx, [rdx+0x18]         ; Get PEB->Ldr
    mov     rdx, [rdx+0x20]         ; Get the first module from the InMemoryOrder module list
.walk_modules:
    test    rdx, rdx
    jz      .not_found
    push    rdx
    ; Offsets relative to the InMemoryOrder Flink pointer (entry start):
    ;   DllBase             = +0x20
    ;   BaseDllName.Length  = +0x48
    ;   BaseDllName.Buffer  = +0x50  (PWSTR, points to UTF-16LE name)
    movzx   rcx, word [rdx + 0x48]     ; BaseDllName.Length (bytes)
    test    rcx, rcx
    jz      .next_module
    mov     rdx, [rdx + 0x50]          ; BaseDllName.Buffer (PWSTR)
    mov     r11, ROR13_UPPERCASE
    call    Ror13Hash
    cmp     r12d, r10d
    jne     .next_module
    pop     rax
    mov     rax, [rax + 0x20]
    jmp     GetModuleHandleH_end
.next_module:
    xor     rax, rax                   ; return
    pop     rdx
    mov     rdx, [rdx]                 ; Flink -> next LIST_ENTRY
    jmp     .walk_modules
.not_found:
    xor     rax, rax
GetModuleHandleH_end:
    pop     rbx
    pop     r12
    ret

; HELPER
; PVOID GetSectionH(HMODULE hModule, DWORD dwSectionHash)
; Locate a PE section by ror13 hash of its name (null-terminated, max 8 bytes).
;
; Arguments:
;   rcx  = hModule        — base address of the loaded module
;   r10  = dwSectionHash  — ror13 hash of the section name (e.g. ".text")
; Returns:
;   rax  = section virtual address (base + VirtualAddress), or 0 if not found
;   r10  = section VirtualSize, or 0 if not found
; Clobbers: rax, rcx, rdx, r11, r12
; Preserves: rbx, rdi
GetSectionH:
    push    r12                         ; save callee-saved
    push    rbx
    push    rdi
    mov     rdi, rcx                    ; rdi = DLL base address
    mov     eax, [rdi + 0x3C]           ; e_lfanew
    lea     rbx, [rdi + rax]            ; rbx = IMAGE_NT_HEADERS
    movzx   ecx, word [rbx + 0x06]      ; NumberOfSections
    movzx   eax, word [rbx + 0x14]      ; SizeOfOptionalHeader
    lea     rbx, [rbx + 0x18 + rax]     ; rbx = first IMAGE_SECTION_HEADER
.walk_sections:
    test    ecx, ecx
    jz      .section_not_found
    push    rcx                         ; save section counter
    mov     rdx, rbx                    ; section name pointer
    mov     ecx, 8                      ; max 8 bytes
    mov     r11, ROR13_NULLTERM
    call    Ror13Hash
    pop     rcx                         ; restore section counter
    cmp     r12d, r10d
    je      .section_found
    add     rbx, 40                     ; sizeof(IMAGE_SECTION_HEADER)
    dec     ecx
    jmp     .walk_sections
.section_found:
    mov     r10d, [rbx + 0x08]          ; Misc.VirtualSize
    mov     eax, [rbx + 0x0C]           ; VirtualAddress
    add     rax, rdi                    ; rax = base + VirtualAddress
    jmp     GetSectionH_end
.section_not_found:
    xor     rax, rax
    xor     r10, r10
GetSectionH_end:
    pop     rdi
    pop     rbx
    pop     r12
    ret

; HELPER
; PVOID GetProcAddressH(HMODULE hLibrary, DWORD dwFunctionHash)
; Walk the export table of a loaded module and resolve a function
; by ror13 hash of its exported name (null-terminated ASCII).
; NOTE: Does not handle forwarded exports.
;
; Arguments:
;   rcx  = hLibrary       — base address of the loaded module
;   r10  = dwFunctionHash — ror13 hash of the function name
; Returns:
;   rax  = function virtual address, or 0 if not found
; Clobbers: rax, rcx, rdx, r11, r12
; Preserves: rbx, rdi, r10
GetProcAddressH:
    push    r12
    push    rbx
    push    rdi
    xor     rax, rax
    mov     rdi, rcx
    mov     eax, [rdi + 0x3C]
    lea     rax, [rdi + eax]
    mov     eax, dword [rax + 0x88]
    test    rax, rax
    jz      .no_export
    add     rax, rdi
    mov     ecx, [rax + 0x18]          ; NumberOfNames
    mov     ebx, [rax + 0x20]          ; AddressOfNames RVA
    add     rbx, rdi                   ; AddressOfNames VA
    push    rax                        ; save export directory ptr
_loop_export_functions:
    test    ecx, ecx
    jz      .no_match
    dec     ecx
    push    rcx                        ; save counter
    push    r10                        ; save target hash
    mov     edx, [rbx + rcx*4]        ; name RVA
    add     rdx, rdi                   ; name VA
    mov     ecx, 0xFF
    mov     r11, ROR13_NULLTERM
    call    Ror13Hash                  ; r12d = hash
    pop     r10                        ; restore target hash
    pop     rcx                        ; restore counter
    cmp     r12d, r10d
    jne     _loop_export_functions
    ; Match found at index ecx
    pop     rax                        ; restore export directory ptr
    mov     edx, [rax + 0x24]         ; AddressOfNameOrdinals RVA
    add     rdx, rdi
    movzx   edx, word [rdx + rcx*2]   ; ordinal index
    mov     eax, [rax + 0x1C]         ; AddressOfFunctions RVA
    add     rax, rdi
    mov     eax, [rax + rdx*4]        ; function RVA
    add     rax, rdi                   ; function VA
    jmp     GetProcAddressH_end
.no_match:
    pop     rax                        ; clean up saved export dir ptr
.no_export:
    xor     rax, rax
GetProcAddressH_end
    pop     r12
    pop     rbx
    pop     rdi
    ret
; HELPER
; Compute ror13 hash over a byte buffer
; rdx = pointer to byte data
; rcx = max byte count
; r11 = flags (ROR13_UPPERCASE=1, ROR13_NULLTERM=2)
; Returns: r12d = hash
; Clobbers: rax, rcx, rdx
Ror13Hash:
    xor     r12d, r12d
.loop:
    test    ecx, ecx
    jz      .done
    movzx   eax, byte [rdx]
    test    r11b, ROR13_NULLTERM
    jz      .no_nullcheck
    test    al, al
    jz      .done
.no_nullcheck:
    test    r11b, ROR13_UPPERCASE
    jz      .no_upper
    cmp     al, 'a'
    jb      .no_upper
    cmp     al, 'z'
    ja      .no_upper
    sub     al, 0x20
.no_upper:
    ror     r12d, 13
    add     r12d, eax
    inc     rdx
    dec     ecx
    jmp     .loop
.done:
    ret