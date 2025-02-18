#!/usr/bin/python3
# Shane Parslow 2022

import pe_util
import util

from unicorn import *
from unicorn.x86_const import *

def mem_invalid(uc, access, address, size, value, env):
    print("\n========================================================")
    print("ERROR: Memory access at {} failed".format(hex(address)))
    util.print_context(env)

def trace(uc, address, size, env):
    instr = uc.mem_read(address, size)
    # HACK: Only using first 2 bytes of instruction (usually opcode + modrm)
    opcode = int.from_bytes(instr[0:2], 'little')
    # opcode: 0xff mod/rm: xx010xxx
    # mask: 0xff 00111000 = 0x3 0x8
    # call value: 0xff 00010000 = 0x10
    # (mask, value)
    calls = [(0x38ff, 0x10ff), # ff /2 call
             (0x00ff, 0x00e8)] # e8 call
    jumps = [(0x38ff, 0x20ff)] # ff /3 jump
    rets =  [(0x00ff, 0x00c3),
             (0x00ff, 0x00c2),
             (0x00ff, 0x00cb),
             (0x00ff, 0x00ca)]
    for call in calls:
        if (opcode & call[0] == call[1]):
            print(">>> {}: CALL ".format(hex(address)), end='')
            # Print the address of the next instruction when it runs
            env.trace_next_instr = True
    for jump in jumps:
        if (opcode & jump[0] == jump[1]):
            print(">>> {}: JMP ".format(hex(address)), end='')
            env.trace_next_instr = True
    for ret in rets:
        if opcode & ret[0] == ret[1]:
            print(">>> {}: RET ".format(hex(address)), end='')
            env.trace_next_instr = True

def trace_next(uc, address, size, env):
    if env.trace_next_instr == True:
        env.trace_next_instr = False
        print("to {}".format(hex(address)))

def interesting(uc, address, size, env):
    interesting = [(b'\x0f\x31', 'rdstc'),
                   (b'\x0f\xa2', 'cpuid')]
    instr = uc.mem_read(address, size)
    for i in interesting:
        # Length hack
        if (bytearray(i[0]) == instr[0:2]):
            print(">>> {}: Interesting instruction: {}!".format(hex(address), i[1]))

# TODO: Can be consolidated into trace
def ret(uc, address, size, env):
    instr = uc.mem_read(address, 1)
    opcode = int.from_bytes(instr, 'little')
    if opcode == 0xc3:
        rsp = uc.reg_read(env.SP)
        ret_addr = int.from_bytes(uc.mem_read(rsp, 0x8), 'little')
        # Can use trace_next for this
        print(">>> {}: RET to {}".format(hex(address), hex(ret_addr)))

def uninitialized_memory_read(uc, access, address, size, value, env):
    # Was this address initialized with data from the binary?
    initially_initialized_segment_address = pe_util.in_initialized(address, env.pe)

    # Is this address in the stack?
    # HUH: why is this required again? why isn't this captured by initialized_addresses?
    # oh, because the size of the stack changes and things go in and out of scope
    rsp = uc.reg_read(env.SP)
    in_stack = rsp <= address < env.stack_low_addr + env.stack_size - env.initial_rsp

    # Was this address written to previously?
    newly_initialized_address = address in env.initialized_addresses

    # If none of the above, the program is reading from uninitialized memory!
    if not initially_initialized_segment_address and not in_stack and not newly_initialized_address:
        rip = uc.reg_read(env.IP)
        #import code
        #code.interact(local=dict(globals(), **locals()))
        print("========================================================")
        print("WARNING: Uninitialized memory read ({})".format(hex(address)))
        util.print_context(env)
        print("========================================================")

# Add these addresses to a list of now-initialized addresses
# TODO: implement size
# TODO: detect writes to invalid addresses after automatic mapping
def uninitialized_memory_write(uc, access, address, size, value, env):
    # Was this address initialized with data from the binary?
    initially_initialized_segment_address = pe_util.in_initialized(address, env.pe)

    # Is this address in the stack?
    rsp = uc.reg_read(env.SP)
    in_stack = rsp <= address < env.stack_low_addr + env.stack_size - env.initial_rsp

    # Was this address written to previously?
    newly_initialized_address = address in env.initialized_addresses

    # If none of the above, the program is writing to previously-uninialized memory. This address is now valid to read from.
    if not initially_initialized_segment_address and not in_stack and not newly_initialized_address:
        env.initialized_addresses.append(address)
