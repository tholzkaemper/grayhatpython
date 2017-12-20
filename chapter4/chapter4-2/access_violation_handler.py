from pydbg import *
from pydbg.defines import *

# Utility libs included with pydbg
import utils

# This is the access violation handler
def check_accessv(dbg):

    #skip first chance exception
    if dbg.dbg.u.Exception.dwFirstChance:
        return DBG_EXCEPTION_HANDLED

    crash_bin = utils.crash_binning.crash_binning()
    crash_bin.record_crash(dbg)
    print crash_bin.crash_synopsis()

    dbg.terminate_process()

    return DBG_EXCEPTION_NOT_HANDLED

pid = raw_input("Enter the process ID: ")

dbg = pydbg()
dbg.attach(int(pid))
dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, check_accessv)
dbg.run()