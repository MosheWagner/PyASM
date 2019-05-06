import ctypes

from keystone import *

from AsmGen import assemble_imp, validate_asm_imp, ctypes_strs, asm_entry_exit_fix
from ExecBuffWin import alloc_executable_buff_windows
from Utils import get_platform_pointer_size_bits


assert get_platform_pointer_size_bits() == 64, "This module should only be imported for 64 bit envs"

ASSEMBLER_X64 = Ks(KS_ARCH_X86, KS_MODE_64)

DEBUG_FUNC = None

msvcrt = ctypes.cdll.msvcrt
printf = msvcrt.printf
fflush = msvcrt.fflush


PUSHAQ = """
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
"""

POPAQ = """
    pop rdi    
    pop rsi    
    pop rbp    
    pop rbx    
    pop rdx    
    pop rcx
    pop rax
"""

POPAQ_NO_EAX = """
    pop rdi    
    pop rsi    
    pop rbp    
    pop rbx    
    pop rdx    
    pop rcx
    add rsp, 8 # Instead of popping eax
"""

PUSHRS = """
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
"""

POPRS = """
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
"""

CALL_DIRECT = """
    push r15
    mov r15, {}
    call r15
    pop r15
"""

CALL_W = """
    mov r15, {}
    call call_w
"""

FFLUSH = """
    push rax
    push rbx
    push rcx
    
    sub rsp, 16
    mov rcx, 0                # flush all
    mov rbx, {FFLUSH_PTR_PTR} # Pointer to fflush
    mov rbx, qword ptr [rbx]  # fflush addr
    call rbx                  # Call fflush
    add rsp, 16
    
    pop rcx
    pop rbx
    pop rax
""".format(FFLUSH_PTR_PTR=ctypes.addressof(fflush))


def validate_asm(asm_lines):
    return validate_asm_imp(asm_lines, ASSEMBLER_X64)


def assemble(asm_lines):
    return assemble_imp(asm_lines, ASSEMBLER_X64, CALL_DIRECT, CALL_W, DEBUG_FUNC)


def gen_debug_asm():
    reg_pairs = [('rax', 'rbx'), ('rcx', 'rdx'), ('rdi', 'rsi')]
    reg_pairs_rs = [('r8', 'r9'), ('r10', 'r11'), ('r12', 'r13'), ('r14', 'r15'), ('rsp', 'rip')]

    debug_asm = []
    for r1, r2 in reg_pairs + reg_pairs_rs:
        format_str = ctypes.create_string_buffer('{}: 0x%x {}: 0x%x\n'.format(r1, r2))

        # We must do this to prevent the GC from freeing the c_str and causing cool bugs :-)
        ctypes_strs.append(format_str)

        debug_asm += """
            {PUSHRS}
            {PUSHAQ}   
            {FFLUSH}                  # call fflush           

            mov rax, {ARG1}           # Load arg1
            mov r8, {ARG2}            # Load arg2
            
            mov rcx, {STR_PTR}        # format string
            mov rbx, {PRINTF_PTR_PTR} # pointer to printf
            mov rbx, qword ptr [rbx]  # printf addr
            
            
            push rax
            push rbx
            push rcx
            mov rdx, rax
            call rbx                  # call printf
            pop rcx
            pop rbx
            pop rax
            
            {FFLUSH}                  # call fflush       
            
            {POPAQ}
            {POPRS}
        """.format(PUSHAQ=PUSHAQ, POPAQ=POPAQ, PUSHRS=PUSHRS, POPRS=POPRS,
                   STR_PTR=ctypes.addressof(format_str),
                   ARG1=r1, ARG2=r2,
                   FFLUSH=FFLUSH,
                   PRINTF_PTR_PTR=ctypes.addressof(printf)).splitlines()

    debug_asm += ['ret']

    return alloc_executable_buff_windows(assemble(debug_asm))


def wrap_64_asm(asm_lines, zero_gp_regs=True, zero_arg_regs=False, entry_point=None):
    asm_lines = asm_entry_exit_fix(asm_lines, entry_point)

    PREFIX = """
        {PUSHAQ}
        {PUSHRS}
    """.format(PUSHAQ=PUSHAQ, PUSHRS=PUSHRS).splitlines()

    if zero_gp_regs:
        PREFIX += """
            mov rax, 0
            mov rbx, 0
            mov rdi, 0
            mov r10, 0
            mov r11, 0
            mov r12, 0
            mov r13, 0
            mov r14, 0
        """.splitlines()

    if zero_arg_regs:
        PREFIX += """
            mov rcx, 0
            mov rdx, 0
            mov r8, 0
            mov r9, 0
        """.splitlines()

    SUFFIX = """
    .end_dubug:
        push rax
        push rcx
        mov rcx, "Done running, dumping register state:\\n"
        call !msvcrt.printf
        pop rcx
        pop rax
        
        debug
        
    .end:
        {POPRS}
        {POPAQ_NO_EAX}
        ret
    

    """.format(POPRS=POPRS, POPAQ_NO_EAX=POPAQ_NO_EAX).splitlines()

    PRE_DEF_FUNCS = """
        # Call the function whose pointer is stored where r15 points to 
        #  Return value is in rax. 
        #  All other registers are restored
        call_w:
            {PUSHAQ}
            {PUSHRS}
            push r15
            sub rsp, 32
            mov r15, qword ptr [r15]
            call r15
            add rsp, 32
            pop r15
            {POPRS}
            {POPAQ_NO_EAX}
            ret
    """.format(PUSHAQ=PUSHAQ, POPAQ_NO_EAX=POPAQ_NO_EAX, POPRS=POPRS, PUSHRS=PUSHRS).splitlines()

    return PREFIX + asm_lines + SUFFIX + PRE_DEF_FUNCS


DEBUG_FUNC = gen_debug_asm()


