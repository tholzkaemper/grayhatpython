from pydbg import *
from pydbg.defines import *

import struct
import random

# User defined callback function
def printf_randomizer(dbg):

    # Read in the value of the counter at ESP + 0x8 as a DWORD
    parameter_address = dbg.context.Esp + 0x8
    counter = dbg.read_process_memory(parameter_address, 4)

    # # When we use read_process_memory, it returns a packed binary
    # string. We must first unpack it before we can use it further.
    # size = struct.calcsize("L")
    counter = struct.unpack("L", counter)[0]
    print "Counter: %d" % int(counter)

    # Generate a random number and pack it into binary format
    # so that it is written correctly back into the process
    random_counter = random.randint(1, 100)
    random_counter = struct.pack("L", random_counter)[0]

    # Now swap in our random number and resume the process
    dbg.write_process_memory(parameter_address, random_counter)

    return DBG_CONTINUE

# Instantiate the pydbg class
dbg = pydbg()

# Enter the PID of the printf_loop.py process
pid = raw_input("Enter the prinf_loop.py PID: ")

# Attach the debugger to that process
dbg.attach(int(pid))

# Set the breakpoint with the printf_randomizer function defined as a callback
printf_address = dbg.func_resolve("msvcrt", "printf")
dbg.bp_set(printf_address,description="printf_address",handler=printf_randomizer)

# Resume the process
dbg.run()