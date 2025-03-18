import os

from unicorn import *
from unicorn.x86_const import *

def print_context(env):
    uc = env.uni
    # There is probably a better way to do this
    rip = uc.reg_read(env.IP)
    print("--- RIP: {}".format(hex(rip)))
    
    reg = uc.reg_read(env.SP)
    print("--- RSP: {}".format(hex(reg)))

    reg = uc.reg_read(env.BP)
    print("--- RBP: {}".format(hex(reg)))

    reg = uc.reg_read(env.AX)
    print("--- RAX: {}".format(hex(reg)))
    
    reg = uc.reg_read(env.BX)
    print("--- RBX: {}".format(hex(reg)))
    
    reg = uc.reg_read(env.CX)
    print("--- RCX: {}".format(hex(reg)))
    
    reg = uc.reg_read(env.DX)
    print("--- RDX: {}".format(hex(reg)))

    reg = uc.reg_read(env.SI)
    print("--- RSI: {}".format(hex(reg)))

    reg = uc.reg_read(env.DI)
    print("--- RDI: {}".format(hex(reg)))

    try:
        code = uc.mem_read(rip, 16)
        # This is gross but it makes the output pretty ._.
        print("--- code: {}".format(" ".join(hex(b)[2:].zfill(2) for b in code)))
    except UcError:
        print("--- Could not get code, is RIP off the rails?")
    # TODO: add more registers and stack unwind

def dump_memory(uc, start, size, filename):
    mem = uc.mem_read(start, size)
    with open(filename, "wb") as f:
        f.write(mem)

def dump_stack(env):
    rsp = env.uni.reg_read(env.SP)
    stack_high = env.stack_low_addr + env.stack_size
    print("Dumping stack to 'dumps/stack.bin', starting at RSP={} and going to top of stack ({})".format(hex(rsp), hex(stack_high)))
    dump_memory(env.uni, rsp, stack_high - rsp, "./dumps/stack.bin")

# TODO: give a sane name to unnamed sections
# TODO: check if section is different
def dump_segment(uc, sec, image_base):
    sec_name = sec.Name.decode('utf-8').strip('\x00')
    file_name = sec_name.strip('.') + ".bin"
    abs_sec_addr = image_base + sec.VirtualAddress
    print("Dumping section {} to 'dumps/{}'".format(sec_name, file_name))
    dump_memory(uc, abs_sec_addr, sec.Misc_VirtualSize, "./dumps/" + file_name)

def dump_all_segments(env):
    pe = env.pe
    for sec in pe.sections:
        dump_segment(env.uni, sec, pe.OPTIONAL_HEADER.ImageBase)

def dump_all(env):
    try:
        os.mkdir("dumps")
    except FileExistsError:
        pass
    print("Created 'dumps' directory")
    dump_all_segments(env)
    dump_stack(env)
