#!/usr/bin/python3
# Shane Parslow 2022

import util

from unicorn import *
from unicorn.x86_const import *

trace_next_instr = False

def mem_invalid(uc, access, address, size, value, user_data):
    print("\n========================================================")
    print("Memory access at {} failed".format(hex(address)))
    util.print_context(uc)

def trace(uc, address, size, user_data):
    global trace_next_instr
    instr = uc.mem_read(address, size)
    opcode = int.from_bytes(instr[0:2], 'little')
    # opcode: 0xff mod/rm: xx010xxx
    # mask: 0xff 00111000 = 0x3 0x8
    # call value: 0xff 00010000 = 0x10
    # (mask, value)
    calls = [(0x38ff, 0x10ff), # ff /2 call
             (0x00ff, 0x00e8)] # e8 call
    jumps = [(0x38ff, 0x20ff)] # ff /3 jump
    for call in calls:
        if (opcode & call[0] == call[1]):
            print(">>> {}: CALL ".format(hex(address)), end='')
            # Print the address of the next instruction when it runs
            trace_next_instr = True
    for jump in jumps:
        if (opcode & jump[0] == jump[1]):
            print(">>> {}: JMP ".format(hex(address)), end='')
            trace_next_instr = True

def trace_next(uc, address, size, user_data):
    global trace_next_instr
    if trace_next_instr == True:
        trace_next_instr = False
        print("to {}".format(hex(address)))

def interesting(uc, address, size, user_data):
    interesting = [b'\x0f\x31', # rdtsc
                   b'\xa2\x0f'] # cpuid
    instr = uc.mem_read(address, size)
    for i in interesting:
        # Length hack
        if (bytearray(i) == instr[0:2]):
            print(">>> {}: Interesting instruction!".format(hex(address)))

# TODO: Can be consolidated into trace
def ret(uc, address, size, user_data):
    instr = uc.mem_read(address, 1)
    opcode = int.from_bytes(instr, 'little')
    if opcode == 0xc3:
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret_addr = int.from_bytes(uc.mem_read(rsp, 0x8), 'little')
        # Can use trace_next for this
        print(">>> {}: RET to {}".format(hex(address), hex(ret_addr)))
