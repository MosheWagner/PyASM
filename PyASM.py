import sys
import argparse
from argparse import RawTextHelpFormatter
from AsmExec import do_interactive, run_asm

# TODO: Create git repo and upload to github


# TODO: Add linux support
#   TODO: Check what ctypes.cdll has for linux


DESCRIPTION = """
Play with ASM from python.

This program will assemble your ASM lines, create an executable buffer, and run your code.

Execution will start from the first assembly line, unless a start label is specifically given in the 'entry_point' arg.

I added some convenience 'cheat' functions. You can call these using 'call !funcname' . 
Use --magic-funcs to see a list of available functions. 

In addition, you can allocate and get a reference to a string by simply using 'mov reg, "str"'. 

See the example ASM dir for examples of all this. 

"""


def print_magic_help():
    print """
You can call magic function at any point using 'call !func' (notice the bang before the function's name).

These function are either built-in function by me, or function exported by ctyptes.cdll .

To call cdll functions, you should use 'call !dllname.dllfunc' for instance, calling printf is 'call !msvcrt.printf'
Don't forget the calling convention is probably cdecl in these cases.

Available built-in funcs are:
    - void debug(void) - Will use printf to dump the register state at the given point


You can find available cdll funcs by iterating over ctypes.cdll (for instance, try dir(ctypes.cdll.msvcrt)   
    """


def main():
    # Check for keystone installation:
    try:
        import keystone
    except ImportError:
        raise Exception("Keystone is required for assembling text. "
                        "You can get it from here: "
                        "http://www.keystone-engine.org/download/#python-module-for-windows---binaries--")

    parser = argparse.ArgumentParser(description=DESCRIPTION, formatter_class=RawTextHelpFormatter)

    parser.add_argument('-f', '--file', default=None,
                        help='File containing ASM text to run')

    parser.add_argument('-e', '--entry-point', default=None,
                        help='Label to start execution from. '
                             'Note: If you use an entry point, make sure the first ret after that label is where the program ends. '
                             'Otherwise python will crash on return')

    parser.add_argument('--magic-funcs', action='store_true',
                        help='Print help about using magic functions and exists')

    parser.add_argument('-a', '--asm-args', nargs='+', default=[],
                        help='Arguments to pass to the assembly function')

    args = parser.parse_args()

    if args.magic_funcs:
        print_magic_help()
        sys.exit(0)

    if args.file:
        run_asm(open(args.file, 'r').readlines(), args.entry_point, *args.asm_args)
    else:
        do_interactive()


if __name__ == '__main__':
    main()
