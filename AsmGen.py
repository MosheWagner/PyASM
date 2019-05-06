import re
import ctypes
from keystone import *

ctypes_strs = []


def gen_c_string(text):
    str_obj = ctypes.create_string_buffer(text.replace('\\n', '\n'))

    # Prevent the GC from killing our string
    ctypes_strs.append(str_obj)

    return ctypes.addressof(str_obj)


def asm_entry_exit_fix(asm_lines, entry_point):
    asm_lines = [line.strip() for line in asm_lines if line.strip()]

    ret_line = None
    if entry_point:
        # The function will be executed from the beginning of the block,
        #  so we want to put our prefix, and then jump to the entry point
        asm_lines = ['jmp {}'.format(entry_point)] + asm_lines

        entry_point_found = False
        for i, line in enumerate(asm_lines):
            if entry_point in line and line.endswith(':'):
                entry_point_found = True

            if not entry_point_found:
                continue

            if line == 'ret' and entry_point_found:
                ret_line = i

    else:
        # If there is no entry point, the last ret is the one we want to replace with 'jmp .end'
        ret_line = len(asm_lines)-1

    if ret_line and asm_lines[ret_line] == 'ret':
        asm_lines = asm_lines[:ret_line] + ["jmp .end"] + asm_lines[ret_line:]

    return asm_lines


def _transform_asm(asm_lines, call_direct_boilerplate, wrapped_call_boilerplate, debug_func):
    clean_lines = []
    for line in asm_lines:
        line = line.split('//')[0]
        line = line.split('#')[0]
        line = line.strip()
        if not line:
            continue

        # TODO: This should support a list
        if line == 'debug' or re.match('call.?\s+[!]?debug', line):
            # Pseudo call to debug
            line = call_direct_boilerplate.format(debug_func)

        if '"' in line:
            # Generate a string object, and change the string literal to the pointer to it
            assert len(line.split('"')) == 3
            string_literal = line.split('"')[1]
            line = line.replace('"{}"'.format(string_literal), '{}'.format(gen_c_string(string_literal)))

        if line.strip().startswith('call') and '!' in line:
            # Pseudo call to ctype function
            pseudo_call_site = line.split('!')[1].split(' ')[0]

            if '.' not in pseudo_call_site:
                pseudo_call_site = 'msvcrt.' + pseudo_call_site

            dll, funcname = pseudo_call_site.split('.')
            ctypes_dll = getattr(ctypes.cdll, dll)
            ctypes_dll_funcs = [f for f in dir(ctypes_dll) if '_' not in f]
            if funcname not in ctypes_dll_funcs:
                raise Exception('Could not find {} in ctypes.cdll.{}. Options are: {}'.format(funcname, dll, ctypes_dll_funcs))

            func_addr = ctypes.addressof(getattr(ctypes_dll, funcname))
            line = wrapped_call_boilerplate.format(func_addr)

        clean_lines.append(line)

    return clean_lines


def validate_asm_imp(asm_lines, assembler):
    # Due to a keystone bug, it won't raise an error if there is an invalid line followed by a valid one.
    # To solve this, we will try to ASM line by line.
    # Obviously, we can't trust missing label errors in this case, so we will simply test location exceptions ourselves

    asm_lines = _transform_asm(asm_lines, "", "", "")

    for line in asm_lines:
        line = line.split('//')[0]
        line = line.split('#')[0]

        try:
            assembler.asm(line)
        except keystone.KsError as e:
            # import pdb; pdb.set_trace()
            if e.message == 'Cannot find a symbol (KS_ERR_ASM_SYMBOL_MISSING)':
                symbol = line.split()[e.stat_count]
                assert re.search(symbol + '\s*' + ':', '\n'.join(asm_lines)), "Could not find symbol {} in ASM lines!".format(symbol)
            else:
                print "ASM error of type", repr(e), "on line ", line
                print "Maybe the error is at '{}'".format(line.split()[e.stat_count])
                return False

    return True


def assemble_imp(asm_lines, assembler, call_direct_boilerplate, wrapped_call_boilerplate, debug_func):
    lines = _transform_asm(asm_lines, call_direct_boilerplate, wrapped_call_boilerplate, debug_func)

    # print '\n'.join(lines)

    try:
        opcodes = assembler.asm('\n'.join(lines))[0]
    except keystone.KsError:
        print "Error assembling the code! Trying line by line, hopefully this will help spot the issue:"
        for l in lines:
            print l
            assembler.asm(l)
        return

    return ''.join([chr(c) for c in opcodes])
