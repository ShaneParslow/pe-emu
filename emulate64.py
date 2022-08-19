#!/usr/bin/python3
# Shane Parslow 2022

import hooks
import pe_util
import util

from pefile import *
import sys
from unicorn import *
from unicorn.x86_const import *

# Various bits of data about the emulation environment
class emu_env:
    # Unicorn context
    uni = None
    # pefile context
    pe = None
    # Stack addresses
    stack_low_addr = None
    stack_size = None
    initial_rsp = None
    # Should the next instruction address be printed?
    trace_next_instr = False
    # List of initially-uninitialized addresses that have been written to, and are now safe for the program to read.
    initialized_addresses = []

def main():
    env = emu_env()
    env.uni = Uc(UC_ARCH_X86, UC_MODE_64)
    env.pe = PE(sys.argv[1])

    pe_util.load(env.uni, env.pe)
    
    # Set up a stack
    env.stack_low_addr = 0x232000
    env.stack_size = 0xfe000
    print("Allocating {} bytes for stack at {}\n".format(hex(env.stack_size), hex(env.stack_low_addr)))
    env.uni.mem_map(env.stack_low_addr, env.stack_size)

    # WARNING: all other registers left uninitialized, add hook to check uninitialized reads that may change program flow?
    # TEMP: Offset to stack to allow reads/writes above initial rsp, this should be handled by the future memory mapper hook
    env.initial_rsp = env.stack_low_addr + env.stack_size - 0x1000
    env.uni.reg_write(UC_X86_REG_RSP, env.initial_rsp)

    # Add convenience hooks
    env.uni.hook_add(UC_HOOK_MEM_INVALID, hooks.mem_invalid, user_data=env)
    # This MUST be before hook_trace to make sure that it is not run immediately after hook_trace while still on the same instruction
    # Ideally it is the first hook
    env.uni.hook_add(UC_HOOK_CODE, hooks.trace_next, user_data=env)
    env.uni.hook_add(UC_HOOK_CODE, hooks.interesting, user_data=env)
    env.uni.hook_add(UC_HOOK_CODE, hooks.trace, user_data=env)
    env.uni.hook_add(UC_HOOK_CODE, hooks.ret, user_data=env)

    env.uni.hook_add(UC_HOOK_MEM_READ, hooks.uninitialized_memory_read, user_data=env)
    env.uni.hook_add(UC_HOOK_MEM_WRITE, hooks.uninitialized_memory_write, user_data=env)

    entry = env.pe.OPTIONAL_HEADER.ImageBase + env.pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print("Starting emulation at {}".format(hex(entry)))
    try:
        env.uni.emu_start(entry, 0xffffffffff)
    except UcError as e:
        print("========================================================")
        print("ERROR: %s" % e)
        util.dump_all_segments(env.uni, env.pe)
        util.dump_stack(env.uni, env.stack_low_addr + env.stack_size)

main()
