
# This function will only work if the entry point is set to main
# If set to f, it will crash python (since python will not know where it ends and how to fix the stack)

f:
    mov eax, 0x10
    ret

main:
    call f
    add eax, 0x20
    ret