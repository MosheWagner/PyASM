

start:
    push "Hello world\n"
    call !msvcrt.printf
    add esp, 4

    push 0xcafefefe
    push "%x\n"

    call !msvcrt.printf
    add esp, 8

    push 0
    call !msvcrt.fflush
    add esp, 4

    ret