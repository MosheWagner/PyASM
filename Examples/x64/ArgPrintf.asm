xchg rcx, rdx  # Move arg1 to edx

mov rcx, "%d\n"
call !msvcrt.printf
mov rcx, 0
call !msvcrt.fflush

call !debug
ret