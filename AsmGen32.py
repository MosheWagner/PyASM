import ctypes

from keystone import *

from AsmGen import assemble_imp, validate_asm_imp, ctypes_strs, asm_entry_exit_fix

from ExecBuffWin import alloc_executable_buff_windows
from Utils import get_platform_pointer_size_bits, Hex


assert get_platform_pointer_size_bits() == 32, "This module should only be imported for x86 32 bit envs"

ASSEMBLER_X86 = Ks(KS_ARCH_X86, KS_MODE_32)

DEBUG_FUNC = None


msvcrt = ctypes.cdll.msvcrt
printf = msvcrt.printf
fflush = msvcrt.fflush


PUSHA = """
    push eax
    push ecx
    push edx
    push ebx
    push ebx
    push ebp
    push esi
    push edi
"""

POPA = """
    pop edi    
    pop esi    
    pop ebp    
    pop ebx    
    pop ebx    
    pop edx    
    pop ecx
    pop eax
"""

POPA_NO_EAX = """
    pop edi    
    pop esi    
    pop ebp    
    pop ebx    
    pop ebx    
    pop edx    
    pop ecx
    add esp, 4 # Instead of popping eax
"""


CALL_DIRECT = """
    push eax
    mov eax, {}
    call eax
    pop eax
"""

CALL_W = """
    mov eax, {}
    mov eax, dword ptr [eax]
    call eax
"""


STACK_MOVE_OFFSET = 0x1000

FFLUSH = """
    pusha
    push 0
    call !fflush
    add esp, 4
    popa
""".format(FFLUSH_PTR_PTR=ctypes.addressof(fflush))


def validate_asm(asm_lines):
    return validate_asm_imp(asm_lines, ASSEMBLER_X86)


def assemble(asm_lines):
    return assemble_imp(asm_lines, ASSEMBLER_X86, CALL_DIRECT, CALL_W, DEBUG_FUNC)


def wrap_32_asm(asm_lines, zero_gp_regs=True, zero_arg_regs=False, entry_point=None):
    asm_lines = asm_entry_exit_fix(asm_lines, entry_point)

    PREFIX = """
        sub esp, {STACK_MOVE_OFFSET}
        {PUSHA}
        add esp, {STACK_MOVE_OFFSET_PLUS_REG_SIZE}
    """.format(PUSHA=PUSHA, STACK_MOVE_OFFSET=Hex(STACK_MOVE_OFFSET),
               STACK_MOVE_OFFSET_PLUS_REG_SIZE=Hex(STACK_MOVE_OFFSET +
                                                   len([l for l in PUSHA.splitlines() if l.strip()] * 4))).splitlines()

    if zero_gp_regs:
        PREFIX += """
            mov eax, 0
            mov ebx, 0
            mov ecx, 0
            mov edx, 0
            mov edi, 0
            mov esi, 0
        """.splitlines()

    if zero_arg_regs:
        print "'zero_arg_regs' should not be used for x86, as it doesn't make any sense"

    SUFFIX = """
    .end_dubug:
        pusha
        push "Done running, dumping register state:\\n"
        call !msvcrt.printf
        add esp, 4
        popa 
        
        debug

    .end:
        sub esp, {STACK_MOVE_OFFSET_PLUS_REG_SIZE}
        {POPA_NO_EAX}
        add esp, {STACK_MOVE_OFFSET}
        ret
    """.format(POPA_NO_EAX=POPA_NO_EAX, STACK_MOVE_OFFSET=Hex(STACK_MOVE_OFFSET),
               STACK_MOVE_OFFSET_PLUS_REG_SIZE=Hex(STACK_MOVE_OFFSET +
                                                   len([l for l in PUSHA.splitlines() if l.strip()] * 4))).splitlines()

    return PREFIX + asm_lines + SUFFIX


def gen_debug_asm():
    gp_reg_pairs = [('eax', 'ebx'), ('ecx', 'edx'), ('edi', 'esi'), ('ebp', 'esp')]

    debug_asm = []
    for r1, r2 in gp_reg_pairs:
        format_str = ctypes.create_string_buffer('{}: 0x%x {}: 0x%x\n'.format(r1, r2))

        # We must do this to prevent the GC from freeing the c_str and causing cool bugs :-)
        ctypes_strs.append(format_str)

        debug_asm += """
            {FFLUSH}                  # call fflush           
            pusha
            
            push {ARG2}               # Load arg2
            push {ARG1}               # Load arg1
            push {STR_PTR}            # format string
            
            mov eax, {PRINTF_PTR_PTR} # pointer to printf
            mov eax, dword ptr [eax]  # printf addr
             
            call eax                  # call printf
            add esp, 0xc              # Fix stack
            
            popa
            {FFLUSH}                  # call fflush       
        """.format(PUSHA=PUSHA, POPA=POPA,
                   STR_PTR=ctypes.addressof(format_str),
                   ARG1=r1, ARG2=r2,
                   FFLUSH=FFLUSH,
                   PRINTF_PTR_PTR=ctypes.addressof(printf)).splitlines()

    debug_asm += ['ret']

    return alloc_executable_buff_windows(assemble(debug_asm))


DEBUG_FUNC = gen_debug_asm()


