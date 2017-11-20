import my_debugger
from my_debugger_defines import *
import os.path

debugger = my_debugger.debugger()

pid = input("Enter the PID of the process to attach to: ")

debugger.attach(int(pid))

# list = debugger.enumerate_threads()
#
# # For each thread in the list we want to
# # grab the value of each of the registers
# for thread in list:
#     thread_context = debugger.get_thread_context(thread)
#     # Now let's output the contents of some of the registers
#     print("[*] Dumping registers for thread ID: 0x%08x" % thread)
#     print("[**] RSI: 0x%08x" % thread_context.Rsi)
#     print("[**] RDI: 0x%08x" % thread_context.Rdi)
#     print("[**] RBP: 0x%08x" % thread_context.Rbp)
#     print("[**] RAX: 0x%08x" % thread_context.Rax)
#     print("[**] RBX: 0x%08x" % thread_context.Rbx)
#     print("[**] RCX: 0x%08x" % thread_context.Rcx)
#     print("[**] RDX: 0x%08x" % thread_context.Rdx)
# print("[*] END DUMP")

printf_address = debugger.func_resolve("msvcrt.dll".encode('ascii'), "printf".encode('ascii'))

print("[*] Address of printf: 0x%08x" % printf_address)

# debugger.bp_set(printf_address)
debugger.bp_set_hw(printf_address, 1, HW_EXECUTE)

debugger.run()

#debugger.detach()