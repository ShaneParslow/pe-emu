#!/usr/bin/python3
# Shane Parslow 2022
import sys
from unicorn import *
from unicorn.x86_const import *
from pefile import *

# Should the next instruction be recorded?
# Used for determining branch targets
# Ew, a global variable
# I don't feel like figuring out how the hook user_data works
trace_next_instr = False

def write_mem(uc, pe):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    pe_mem = pe.get_memory_mapped_image(ImageBase=image_base)
    # WARNING: rounds to 4kb
    size = (len(pe_mem) + 0x1000) & ~0xFFF
    print("Allocating {} bytes for PE at {}".format(hex(size), hex(image_base)))
    uc.mem_map(image_base, size)
    print("Writing PE, len: {} bytes".format(hex(len(pe_mem))))
    uc.mem_write(image_base, bytes(pe_mem))

def hook_mem_invalid(uc, access, address, size, value, user_data):
    print("\n========================================================")
    print(">>> Memory access at {} failed".format(hex(address)))
    
    rip = uc.reg_read(UC_X86_REG_RIP)
    print(">>> --- RIP: {}".format(hex(rip)))
    
    reg = uc.reg_read(UC_X86_REG_RSP)
    print(">>> --- RSP: {}".format(hex(reg)))

    reg = uc.reg_read(UC_X86_REG_RBP)
    print(">>> --- RBP: {}".format(hex(reg)))

    reg = uc.reg_read(UC_X86_REG_RAX)
    print(">>> --- RAX: {}".format(hex(reg)))
    
    reg = uc.reg_read(UC_X86_REG_RBX)
    print(">>> --- RBX: {}".format(hex(reg)))
    
    reg = uc.reg_read(UC_X86_REG_RCX)
    print(">>> --- RCX: {}".format(hex(reg)))
    
    reg = uc.reg_read(UC_X86_REG_RDX)
    print(">>> --- RDX: {}".format(hex(reg)))

    reg = uc.reg_read(UC_X86_REG_RSI)
    print(">>> --- RSI: {}".format(hex(reg)))

    reg = uc.reg_read(UC_X86_REG_RDI)
    print(">>> --- RDI: {}".format(hex(reg)))

    try:
        code = uc.mem_read(rip, 16)
        # This is gross but it makes the output pretty ._.
        print(">>> --- code: {}".format(" ".join(hex(b)[2:].zfill(2) for b in code)))
    except UcError as e:
        print(">>> --- Could not get code, is RIP off the rails?")

    # TODO: add more registers and stack unwind

def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))

# TODO: destination of calls and jumps
def hook_trace(uc, address, size, user_data):
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

def hook_trace_next(uc, address, size, user_data):
    global trace_next_instr
    if trace_next_instr == True:
        trace_next_instr = False
        print("to {}".format(hex(address)))

def hook_interesting(uc, address, size, user_data):
    interesting = [b'\x0f\x31', # rdtsc
                   b'\xa2\x0f'] # cpuid
    instr = uc.mem_read(address, size)
    for i in interesting:
        # Length hack
        if (bytearray(i) == instr[0:2]):
            print(">>> {}: Interesting instruction!".format(hex(address)))

def hook_ret(uc, address, size, user_data):
    instr = uc.mem_read(address, 1)
    opcode = int.from_bytes(instr, 'little')
    if opcode == 0xc3:
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret_addr = int.from_bytes(uc.mem_read(rsp, 0x8), 'little')
        # Can use trace_next for this
        print(">>> {}: RET to {}".format(hex(address), hex(ret_addr)))

def dump_memory(uc, start, size, filename):
    mem = uc.mem_read(start, size)
    with open(filename, "wb") as f:
        f.write(mem)

def dump_stack(uc, stack_high):
    rsp = uc.reg_read(UC_X86_REG_RSP)
    print("Dumping stack to 'mem_dump_stack', starting at RSP={} and going to top of stack ({})".format(hex(rsp), hex(stack_high)))
    dump_memory(uc, rsp, stack_high - rsp, "mem_dump_stack")

def main():
    uni = Uc(UC_ARCH_X86, UC_MODE_64)
    pe = PE(sys.argv[1])

    write_mem(uni, pe)
    
    # Set up a stack
    stack_low_addr = 0x232000
    stack_size = 0xfe000
    print("Allocating {} bytes for stack at {}\n".format(hex(stack_size), hex(stack_low_addr)))
    uni.mem_map(stack_low_addr, stack_size)

    # WARNING: all other registers left uninitialized, add hook to check uninitialized reads that may change program flow?
    uni.reg_write(UC_X86_REG_RSP, stack_low_addr + stack_size)

    # Add convenience hooks
    uni.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
    uni.hook_add(UC_HOOK_CODE, hook_interesting)
    # This MUST be before hook_trace to make sure that it is not run immediately after hook_trace while still on the same instruction
    uni.hook_add(UC_HOOK_CODE, hook_trace_next)
    uni.hook_add(UC_HOOK_CODE, hook_trace)
    uni.hook_add(UC_HOOK_CODE, hook_ret)

    entry = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print("Starting emulation at {}".format(hex(entry)))
    try:
        uni.emu_start(entry, 0xffffffffff)
    except UcError as e:
        print("========================================================")
        print("ERROR: %s" % e)
        for sec in pe.sections:
            sec_name = sec.Name.decode('utf-8').strip('\x00')
            abs_sec_addr = pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress
            print("Dumping section {} to 'mem_dump{}'".format(sec_name, sec_name))
            dump_memory(uni, abs_sec_addr, sec.Misc_VirtualSize, "mem_dump{}".format(sec_name))
        dump_stack(uni, stack_low_addr + stack_size)

main()
