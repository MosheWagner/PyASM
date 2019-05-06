import os
import ctypes

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000

PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40


def alloc_executable_buff_windows(buff):
    assert os.name == 'nt', 'This method will only work on windows platforms'

    """Return a pointer to a page-aligned executable buffer filled in with the data of the string provided.
    The pointer should be freed with libc.free() when finished"""

    VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
    VirtualProtect = ctypes.windll.kernel32.VirtualProtect
    RtlMoveMemory = ctypes.windll.kernel32.RtlMoveMemory

    shellcode = bytearray(buff)

    mem_buff = VirtualAlloc(ctypes.c_int(0),
                            ctypes.c_int(len(shellcode)),
                            ctypes.c_int(MEM_COMMIT | MEM_RESERVE),
                            ctypes.c_int(0x40))

    c_buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    old = ctypes.c_long(1)
    VirtualProtect(mem_buff, ctypes.c_int(len(shellcode)), PAGE_EXECUTE_READWRITE, ctypes.byref(old))
    RtlMoveMemory(ctypes.c_int(mem_buff), c_buf, ctypes.c_int(len(shellcode)))

    return mem_buff


def func_ptr_from_mem(mem_buff, ctype_args=None):
    func = ctypes.cast(mem_buff, ctypes.CFUNCTYPE(ctypes.c_void_p))
    func.restype = ctypes.c_int

    if ctype_args:
        func.argtypes = ctype_args
    return func


def gen_executable_func(asm_bytes, args_num=0):
    exec_buff = alloc_executable_buff_windows(asm_bytes)

    ctype_args = None
    if args_num:
        ctype_args = [ctypes.c_int for _ in range(args_num)]

    return func_ptr_from_mem(exec_buff, ctype_args)
