import ctypes

from ExecBuffWin import gen_executable_func
from Utils import get_platform_pointer_size_bits

if get_platform_pointer_size_bits() == 64:
    from AsmGen64 import wrap_64_asm as wrap_asm, assemble, validate_asm
else:
    from AsmGen32 import wrap_32_asm as wrap_asm, assemble, validate_asm


def transform_arg(arg):
    arg = arg.strip()
    if arg.startswith('0x'):
        return int(arg, 16)

    if arg.startswith('0b'):
        return int(arg, 1)

    return int(arg, 10)


def prepare_asm(asm_lines, argnum, entry_point=None):
    if type(asm_lines) in (str, unicode):
        asm_lines = asm_lines.splitlines()

    print "[+] Assembling the ASM code"
    assert validate_asm(asm_lines), "ASM seems invalid!"
    asm_bytes = assemble(wrap_asm(asm_lines, zero_arg_regs=False, zero_gp_regs=True, entry_point=entry_point))
    print "[+] Preparing code for execution"
    return gen_executable_func(asm_bytes, args_num=argnum)


def run_asm_func(asm_func, *args):
    print "[+] Running the ASM code (ptr to code is at: {})".format(hex(ctypes.addressof(asm_func)))
    ret_val = hex(asm_func(*args))
    print "[+] ASM code returned {}".format(ret_val)
    return ret_val


def run_asm(asm_lines, entry_point, *args):
    args = [transform_arg(a) for a in args]

    asm_func = prepare_asm(asm_lines, len(args), entry_point)
    run_asm_func(asm_func, *args)


def read_asm_interactive(funcs, fname):
    asm_lines = []

    print "Enter ASM code line by line (enter two consecutive new lines to finish):"
    print " "

    while len(asm_lines) < 2 or asm_lines[-1] != "" and asm_lines[-2] != "":
        line = raw_input('')
        asm_lines.append(line.strip())

    if not fname:
        fname = 'f_{}'.format(len(funcs))

    funcs[fname] = (prepare_asm(asm_lines, 0), asm_lines, 0)

    print "Your code is now the function {F}. To see it's contents, use 'print {F}'. " \
          "To execute it, use {F}()".format(F=fname)


def do_interactive():
    print """
No file argument was given, so switching to interactive mode.

Type help to see what you can do :-)

"""
    funcs = {}

    while True:
        try:
            command_line = raw_input('>> ').strip()

            if command_line.startswith('exit'):
                return

            elif command_line.startswith('help'):
                print """
            You are in interactive mode. This is what you can do here:
            >> help                  - Show this screen
            >> new [${name}]         - Will let you enter a new asm func [with the chosen name, if given] 
            >> print funcs           - Will show you all existing function names
            >> print ${func_name}    - Print asm contents of the requested function
            >> ${func_name}(args)    - Will execute the given function with the given args
            >> exit                  - Will let you out of here 
    
            """

            elif command_line.startswith('new') or command_line.startswith('asm'):
                name = None
                if len(command_line.split()) > 1:
                    name = command_line.split()[1]

                read_asm_interactive(funcs, name)

            elif command_line.startswith('print'):
                if command_line == 'print funcs':
                    print funcs
                else:
                    name = command_line.split()[-1]
                    print name, funcs[name][1], "expected args: ", funcs[name][2]

            elif '(' in command_line:
                func_name, args_l = command_line.split('(')
                args = [a for a in args_l[:-1].split(',') if a]

                nargs = funcs[func_name][2]
                if len(args) > nargs:
                    correct_nargs = len(args)
                    print "Seems like {} has more args than expected. Adjusting args accordingly".format(func_name)
                    func_lines = funcs[func_name][1]
                    funcs[func_name] = (prepare_asm(func_lines, correct_nargs), func_lines, correct_nargs)

                run_asm_func(funcs[func_name][0], *[transform_arg(a) for a in args])

            else:
                print 'Unknown command "{}". Use help to see what you can do'.format(command_line)

        except Exception as e:
            print repr(e)



