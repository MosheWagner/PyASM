# PyASM
Fiddle with x86 and x64 asm from python.

This project simply assembles the given code with keystone, calls VirtualProtect on the buffer, and lets you execute it.

Currently only work on Windows {x86, x64}.

# But why?
Because I can.

# Seriously, why not just use a real assembler? or gcc's \_\_asm\_\_?
There is no really good answer here. 
If you are comfortable with gcc's inline asm, or like using your favorite assembler - go ahead!

I personally find it very convenient to be able to simply type in some asm line, add some printf magic, and call the buffer with arguments.
Especially if I want to script the arguments (hence the python).

Also, sometimes you just need to execute that friggin buffer. From python.

