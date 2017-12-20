from immlib import *

def main(args):
    imm = Debugger()

    bad_char_found = False

    # First argument is the address to begin our search
    address = int(args[0], 16)

    # Shell code to verify
    shellcode = "<<COPY AND PASTE YOUR SHELL CODE HERE>>"
    shellcode_length = len(shellcode)

    debug_shellcode = imm.readMemory(address, shellcode_length)
    debug_shellcode = debug_shellcode.encode("HEX")

    imm.log("Adress: 0x%0x8" % address)
    imm.log("Shellcode length: %d" % shellcode_length)

    imm.log("Attack shell code: %s" % shellcode[:512])
    imm.log("In Memory shell code: %s" % debug_shellcode[:512])

    # Begin a byte-by-byte comparision of the two shellcode buffers
    count = 0
    while count <= shellcode_length:
        if debug_shellcode[count] != shellcode[count]:
            imm.log("Bad char detected at offset %d" % count)
            bad_char_found = True
            break

        count += 1

    if bad_char_found:
        imm.log("[*****]")
        imm.log("Bad character found: %s" % debug_shellcode[count])
        imm.log("Bad character original: %s" % shellcode[count])
        imm.log("[*****]")

    return "[*] !badchar finished, check log window."