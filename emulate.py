#!/usr/bin/env python
# Shane Parslow 2022

import hooks
import pe_util
import util

from pefile import *
import sys
from capstone import *
from unicorn import *
from unicorn.x86_const import *

# Various bits of data about the emulation environment
class emu_env:
    # Load a PE
    def load(self, pe):
        self.pe = pe
        pe_util.load(self.uni, self.pe)
    
    # Add convenience hooks
    def add_hooks(self):
        u = self.uni
        
        u.hook_add(UC_HOOK_MEM_INVALID, hooks.mem_invalid, user_data=env)
        # This MUST be before hook_trace to make sure that it is not run immediately after hook_trace while still on the same instruction
        # Ideally it is the first hook
        u.hook_add(UC_HOOK_CODE, hooks.trace_next, user_data=env)
        u.hook_add(UC_HOOK_CODE, hooks.interesting, user_data=env)
        u.hook_add(UC_HOOK_CODE, hooks.trace, user_data=env)
        u.hook_add(UC_HOOK_CODE, hooks.ret, user_data=env)

        u.hook_add(UC_HOOK_MEM_READ, hooks.uninitialized_memory_read, user_data=env)
        u.hook_add(UC_HOOK_MEM_WRITE, hooks.uninitialized_memory_write, user_data=env)

    def __init__(self, mode):
        ### Instance vars
        # List of initially-uninitialized addresses that have been written to, and are now safe for the program to read.
        self.initialized_addresses = []
        self.cur_mnemonic = None
        self.pe = None
        # Stack stuff
        self.stack_low_addr = 0x232000
        self.stack_size = 0xfe000
        
        ### Contexts
        # Unicorn context
        self.uni = Uc(UC_ARCH_X86, mode)
        # Capstone context
        cs_mode = CS_MODE_64 if mode == UC_MODE_64 else CS_MODE_32
        self.cs = Cs(CS_ARCH_X86, cs_mode)
        
        ### Mode-independent defs
        self.IP = UC_X86_REG_RIP if mode == UC_MODE_64 else UC_X86_REG_EIP
        self.SP = UC_X86_REG_RSP if mode == UC_MODE_64 else UC_X86_REG_ESP
        self.BP = UC_X86_REG_RBP if mode == UC_MODE_64 else UC_X86_REG_EBP
        self.AX = UC_X86_REG_RAX if mode == UC_MODE_64 else UC_X86_REG_EAX
        self.BX = UC_X86_REG_RBX if mode == UC_MODE_64 else UC_X86_REG_EBX
        self.CX = UC_X86_REG_RCX if mode == UC_MODE_64 else UC_X86_REG_ECX
        self.DX = UC_X86_REG_RDX if mode == UC_MODE_64 else UC_X86_REG_EDX
        self.SI = UC_X86_REG_RSI if mode == UC_MODE_64 else UC_X86_REG_ESI
        self.DI = UC_X86_REG_RDI if mode == UC_MODE_64 else UC_X86_REG_EDI

        ### Emulation init
        # WARNING: all other registers left uninitialized, add hook to check uninitialized reads that may change program flow?
        # TEMP: Offset to stack to allow reads/writes above initial rsp, this should be handled by the future memory mapper hook
        self.initial_rsp = self.stack_low_addr + self.stack_size - 0x1000
        self.uni.reg_write(self.SP, self.initial_rsp)
        print("Allocating {} bytes for stack at {}\n".format(hex(self.stack_size), hex(self.stack_low_addr)))
        self.uni.mem_map(self.stack_low_addr, self.stack_size)

def main():
    mode = UC_MODE_32 if "-32b" in sys.argv else UC_MODE_64
    
    print("Preparing emulation in *{}* mode".format("32-bit mode" if mode == UC_MODE_32 else "64-bit mode"))
    env = emu_env(mode)
    env.load(PE(sys.argv[1]))

    entry = env.pe.OPTIONAL_HEADER.ImageBase + env.pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print("Starting emulation at {}".format(hex(entry)))
    try:
        env.uni.emu_start(entry, 0xffffffffff)
    except UcError as e:
        print("========================================================")
        print("ERROR: %s" % e)
        # TODO: specific dump directory + reassemble to PE or elf
        util.dump_all_segments(env)
        util.dump_stack(env)

main()
