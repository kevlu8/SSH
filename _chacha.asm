section .data
    swap_endian: db 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12
    p: dq 0xfffffffffffffffb, 0xffffffffffffffff, 0x3
    clamp: dq 0x0ffffffc0fffffff, 0x0ffffffc0ffffffc

section .text
global __inc_nonce
global __chacha_block
global _poly1305_mac

__inc_nonce:
    push rbp
    mov rbp, rsp
    ; increment the first dword of the nonce
    inc dword [rdi + 15 * 4]
    ; add to second word if first word overflowed
    adc dword [rdi + 14 * 4], 0
    ; repeat
    adc dword [rdi + 13 * 4], 0
    pop rbp
    ret

__chacha_block:
    push rbp
    mov rbp, rsp
    ; 10 "double" rounds
    ; 20 "single" rounds

    ; initialize state with 4 xmm registers (each representing a row)
    movdqu xmm0, [rdi]
    movdqu xmm1, [rdi + 16]
    movdqu xmm2, [rdi + 32]
    movdqu xmm3, [rdi + 48]

    %ifdef BIG_ENDIAN ; i hate endianness
        ; swap endianness of state
        pshufb xmm0, [swap_endian]
        pshufb xmm1, [swap_endian]
        pshufb xmm2, [swap_endian]
        pshufb xmm3, [swap_endian]
    %endif

    ; initialize counter for loop
    mov r8b, 10
    .double_round:
        ; column round
        ; a += b
        paddd xmm0, xmm1
        ; d ^= a
        pxor xmm3, xmm0
        ; d <<<= 16
        movdqu xmm4, xmm3
        pslld xmm3, 16
        psrld xmm4, 16
        por xmm3, xmm4
        ; c += d
        paddd xmm2, xmm3
        ; b ^= c
        pxor xmm1, xmm2
        ; b <<<= 12
        movdqu xmm4, xmm1
        pslld xmm1, 12
        psrld xmm4, 20
        por xmm1, xmm4
        ; a += b
        paddd xmm0, xmm1
        ; d ^= a
        pxor xmm3, xmm0
        ; d <<<= 8
        movdqu xmm4, xmm3
        pslld xmm3, 8
        psrld xmm4, 24
        por xmm3, xmm4
        ; c += d
        paddd xmm2, xmm3
        ; b ^= c
        pxor xmm1, xmm2
        ; b <<<= 7
        movdqu xmm4, xmm1
        pslld xmm1, 7
        psrld xmm4, 25
        por xmm1, xmm4
        ; transform state to prepare for diagonal round
        pshufd xmm1, xmm1, 0b00111001
        pshufd xmm2, xmm2, 0b01001110
        pshufd xmm3, xmm3, 0b10010011
        ; diagonal round
        ; a += b
        paddd xmm0, xmm1
        ; d ^= a
        pxor xmm3, xmm0
        ; d <<<= 16
        movdqu xmm4, xmm3
        pslld xmm3, 16
        psrld xmm4, 16
        por xmm3, xmm4
        ; c += d
        paddd xmm2, xmm3
        ; b ^= c
        pxor xmm1, xmm2
        ; b <<<= 12
        movdqu xmm4, xmm1
        pslld xmm1, 12
        psrld xmm4, 20
        por xmm1, xmm4
        ; a += b
        paddd xmm0, xmm1
        ; d ^= a
        pxor xmm3, xmm0
        ; d <<<= 8
        movdqu xmm4, xmm3
        pslld xmm3, 8
        psrld xmm4, 24
        por xmm3, xmm4
        ; c += d
        paddd xmm2, xmm3
        ; b ^= c
        pxor xmm1, xmm2
        ; b <<<= 7
        movdqu xmm4, xmm1
        pslld xmm1, 7
        psrld xmm4, 25
        por xmm1, xmm4
        ; transform state back to column form
        pshufd xmm1, xmm1, 0b10010011
        pshufd xmm2, xmm2, 0b01001110
        pshufd xmm3, xmm3, 0b00111001
        ; loop
        dec r8b
        jnz .double_round

    %ifndef BIG_ENDIAN ; i still hate endianness
        ; load original state into xmm4
        movdqu xmm4, [rdi]
        ; add original state to current state
        paddd xmm0, xmm4
        ; load first 16 bytes of the block into xmm4
        movdqu xmm4, [rsi]
        ; xor the result with the first 16 bytes of the block
        pxor xmm0, xmm4
        ; store the result in the first 16 bytes of the block
        movdqu [rsi], xmm0

        ; repeat 3 more times
        movdqu xmm4, [rdi + 16]
        paddd xmm1, xmm4
        movdqu xmm4, [rsi + 16]
        pxor xmm1, xmm4
        movdqu [rsi + 16], xmm1

        movdqu xmm4, [rdi + 32]
        paddd xmm2, xmm4
        movdqu xmm4, [rsi + 32]
        pxor xmm2, xmm4
        movdqu [rsi + 32], xmm2

        movdqu xmm4, [rdi + 48]
        paddd xmm3, xmm4
        movdqu xmm4, [rsi + 48]
        pxor xmm3, xmm4
        movdqu [rsi + 48], xmm3
    %else ; maybe even more than before
        ; honestly i have no clue whats going on here

        ; load original state into xmm4
        movdqu xmm4, [rdi]
        ; swap endianness of original state
        pshufb xmm4, [swap_endian]
        ; add original state to current state
        paddd xmm0, xmm4
        ; load first 16 bytes of the block into xmm4
        movdqu xmm4, [rsi]
        ; swap endianness of first 16 bytes of the block
        pshufb xmm4, [swap_endian]
        ; xor the result with the first 16 bytes of the block
        pxor xmm0, xmm4
        ; swap endianness of result
        pshufb xmm0, [swap_endian]
        ; store the result in the first 16 bytes of the block
        movdqu [rsi], xmm0

        ; repeat 3 more times
        movdqu xmm4, [rdi + 16]
        pshufb xmm4, [swap_endian]
        paddd xmm1, xmm4
        movdqu xmm4, [rsi + 16]
        pshufb xmm4, [swap_endian]
        pxor xmm1, xmm4
        pshufb xmm1, [swap_endian]
        movdqu [rsi + 16], xmm1

        movdqu xmm4, [rdi + 32]
        pshufb xmm4, [swap_endian]
        paddd xmm2, xmm4
        movdqu xmm4, [rsi + 32]
        pshufb xmm4, [swap_endian]
        pxor xmm2, xmm4
        pshufb xmm2, [swap_endian]
        movdqu [rsi + 32], xmm2

        movdqu xmm4, [rdi + 48]
        pshufb xmm4, [swap_endian]
        paddd xmm3, xmm4
        movdqu xmm4, [rsi + 48]
        pshufb xmm4, [swap_endian]
        pxor xmm3, xmm4
        pshufb xmm3, [swap_endian]
        movdqu [rsi + 48], xmm3
    %endif
    pop rbp
    ret

_poly1305_mac:
    push rbp
    mov rbp, rsp
    ; 0x00..0x0f = r
    ; 0x10..0x1f = s
    ; 0x20..0x2f 0x30..0x3f = scratch
    sub rsp, 0x40
    ; load and clamp r
    movdqu xmm0, [rel clamp]
    pand xmm0, [rdx]
    movdqu [rsp], xmm0
    ; load s
    movdqu xmm0, [rdx + 0x10]
    movdqu [rsp + 0x10], xmm0
    ; zero acc (in output, with extra 1 byte in r9)
    pxor xmm0, xmm0
    movdqu [rcx], xmm0
    xor r9b, r9b
    .process_msg:
        ; add next 16 bytes of the message to acc
        mov rax, [rdi]
        add [rcx], rax
        mov rax, [rdi + 0x8]
        adc [rcx + 0x8], rax
        adc r9b, 1 ; the extra 1 bit is added here
        ; multiply acc by r (this is quite complex)
        ; copy r to first part of scratch (we will be aggressively shifting this part)
        movdqu xmm0, [rsp]
        movdqu [rsp + 0x20], xmm0
        ; zero second part of scratch (we will be accumulating the result here)
        pxor xmm0, xmm0
        movdqu [rsp + 0x30], xmm0
        xor r8b, r8b
        ; ; test multiplication
        ; mov qword [rcx], 0x4eadbeef
        ; shl qword [rcx], 32
        ; mov qword [rcx + 0x8], 0x4eadbeef
        ; shl qword [rcx + 0x8], 32
        ; mov r8b, 0
        ; mov qword [rsp + 0x20], 0x44
        ; mov qword [rsp + 0x28], 0x0
        ; double and add
        .mul_loop:
            ; dont add if lsb of r is 0
            test byte [rsp + 0x20], 1
            jz .no_add
            ; add acc to scratch
            mov rax, [rcx]
            add [rsp + 0x30], rax
            mov rax, [rcx + 0x8]
            adc [rsp + 0x38], rax
            adc r8b, r9b
            .no_add:
            ; shift acc
            shl qword [rcx], 1
            rcl qword [rcx + 0x8], 1
            rcl r9b, 1
            ; shift r
            shr qword [rsp + 0x28], 1
            rcr qword [rsp + 0x20], 1
            ; mod p
            .mod_scratch:
                ; if scratch < p, we are done
                mov al, [rel p + 0x10]
                cmp r8b, al
                ja .mod_scratch_cont
                jb .mod_acc
                mov rax, [rel p + 0x8]
                cmp [rsp + 0x38], rax
                ja .mod_scratch_cont
                jb .mod_acc
                mov rax, [rel p]
                cmp [rsp + 0x30], rax
                jb .mod_acc
                .mod_scratch_cont:
                    ; subtract p from scratch
                    mov rax, [rel p]
                    sub [rsp + 0x30], rax
                    mov rax, [rel p + 0x8]
                    sbb [rsp + 0x38], rax
                    sbb r8b, [rel p + 0x10]
                    jmp .mod_scratch
            .mod_acc:
                ; if acc < p, we are done
                mov al, [rel p + 0x10]
                cmp r9b, al
                ja .mod_acc_cont
                jb .done_mul_iter
                mov rax, [rel p + 0x8]
                cmp [rcx + 0x8], rax
                ja .mod_acc_cont
                jb .done_mul_iter
                mov rax, [rel p]
                cmp [rcx], rax
                jb .done_mul_iter
                .mod_acc_cont:
                    ; subtract p from acc
                    mov rax, [rel p]
                    sub [rcx], rax
                    mov rax, [rel p + 0x8]
                    sbb [rcx + 0x8], rax
                    sbb r9b, [rel p + 0x10]
                    jmp .mod_acc
            .done_mul_iter:
            ; if r is not zero, continue
            mov rax, qword [rsp + 0x28]
            test rax, rax
            jnz .mul_loop
            mov rax, qword [rsp + 0x20]
            test rax, rax
            jnz .mul_loop
            ; copy scratch to acc
            movdqu xmm0, [rsp + 0x30]
            movdqu [rcx], xmm0
            mov r9b, r8b
        ; add 16 to message pointer
        add rdi, 0x10
        ; subtract 16 from message length
        sub rsi, 0x10
        ; if message length is not zero, continue
        ja .process_msg
    ; add s to acc, we now only care about the low 128 bits
    mov rax, [rsp + 0x10]
    add [rcx], rax
    mov rax, [rsp + 0x18]
    adc [rcx + 0x8], rax
    add rsp, 0x40
    pop rbp
    ret

%ifdef BIG_ENDIAN
    vpextrq rl, rh, 0bffffffff
    :
    DB
    .tTeExXtT
    giopaegbewaipj
    fewjiaoejfhei ,j hfewajifophweafi' ijfoepawfhheiopawjif nbifoape
    ; the above is to prevent assembling on big endian machines
    ; i dont have enough energy to implement endianness swapping
%endif
