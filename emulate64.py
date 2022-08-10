#!/usr/bin/python3
# Shane Parslow 2022

import hooks
import pe_util
import util

from pefile import *
import sys
from unicorn import *
from unicorn.x86_const import *

def main():
    uni = Uc(UC_ARCH_X86, UC_MODE_64)
    pe = PE(sys.argv[1])
    # Hack to use pe in hooks
    hooks.current_pe = pe

    pe_util.load(uni, pe)
    
    # Set up a stack
    stack_low_addr = 0x232000
    hooks.stack_low = stack_low_addr
    stack_size = 0xfe000
    hooks.stack_size = stack_size
    print("Allocating {} bytes for stack at {}\n".format(hex(stack_size), hex(stack_low_addr)))
    uni.mem_map(stack_low_addr, stack_size)

    # WARNING: all other registers left uninitialized, add hook to check uninitialized reads that may change program flow?
    uni.reg_write(UC_X86_REG_RSP, stack_low_addr + stack_size)

    # Add convenience hooks
    uni.hook_add(UC_HOOK_MEM_INVALID, hooks.mem_invalid)
    # This MUST be before hook_trace to make sure that it is not run immediately after hook_trace while still on the same instruction
    # Ideally it is the first hook
    uni.hook_add(UC_HOOK_CODE, hooks.trace_next)
    uni.hook_add(UC_HOOK_CODE, hooks.interesting)
    uni.hook_add(UC_HOOK_CODE, hooks.trace)
    uni.hook_add(UC_HOOK_CODE, hooks.ret)

    uni.hook_add(UC_HOOK_MEM_READ, hooks.uninitialized_memory_read)
    uni.hook_add(UC_HOOK_MEM_WRITE, hooks.uninitialized_memory_write)

    entry = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print("Starting emulation at {}".format(hex(entry)))
    try:
        uni.emu_start(entry, 0xffffffffff)
    except UcError as e:
        print("========================================================")
        print("ERROR: %s" % e)
        util.dump_all_segments(uni, pe)
        util.dump_stack(uni, stack_low_addr + stack_size)

main()
