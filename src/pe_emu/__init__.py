import unicorn
from unicorn.x86_const import *
from unicorn.unicorn_const import *

from capstone import *

from . import pe_util
from . import hooks

# Various bits of data about the emulation environment
class Emu:
    # Load a PE
    def load(self, pe):
        self.pe = pe
        pe_util.load(self.uni, self.pe)
    
    # Add convenience hooks
    def add_hooks(self):
        u = self.uni
        
        u.hook_add(UC_HOOK_MEM_INVALID, hooks.mem_invalid, user_data=self)
        # This MUST be before hook_trace to make sure that it is not run immediately after hook_trace while still on the same instruction
        # Ideally it is the first hook
        u.hook_add(UC_HOOK_CODE, hooks.trace_next, user_data=self)
        self.trace_next_instr = False
        u.hook_add(UC_HOOK_CODE, hooks.interesting, user_data=self)
        u.hook_add(UC_HOOK_CODE, hooks.trace, user_data=self)
        u.hook_add(UC_HOOK_CODE, hooks.ret, user_data=self)

        u.hook_add(UC_HOOK_MEM_READ, hooks.uninitialized_memory_read, user_data=self)
        u.hook_add(UC_HOOK_MEM_WRITE, hooks.uninitialized_memory_write, user_data=self)

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
        self.uni = unicorn.Uc(UC_ARCH_X86, mode)
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
        self.add_hooks()
