BITS 64
section .text

global _start
_start:
    mov rbp, rsp
    sub rsp, 32
    mov byte [rbp - 16], '0'
    mov byte [rbp - 15], ' '
    mov byte [rbp - 14], 0

    mov byte [rbp - 13], 0x0a
    mov byte [rbp - 12], 0

loop:
    mov rsi, 3
    lea rdi, [rbp - 16]
    call write

    mov byte al, [rbp - 16]
    inc al
    cmp al, 10 + '0'
    jl nice

    ; write newline and reset counter
    mov rax, '0'
    push rax
    lea rdi, [rbp - 13]
    mov rsi, 1
    call write
    pop rax

nice:
    mov byte [rbp - 16], al

    mov rdi, 1
    call nanosleep
    jmp loop


write:
    mov rdx, rsi
    mov rsi, rdi
    mov rdi, 1
    mov rax, 1
    syscall
    ret

nanosleep:
    push rbp
    mov rbp, rsp
    sub rsp, 32

    mov qword [rbp - 32], 0
    mov qword [rbp - 24], 0
    mov dword [rbp - 32], edi

    lea rdi, [rbp - 32]
    mov rsi, 0

    mov rax, 35
    syscall

    mov rsp, rbp
    pop rbp
    ret
