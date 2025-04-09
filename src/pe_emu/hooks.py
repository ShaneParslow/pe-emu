from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET

from . import pe_util
from . import util

def mem_invalid(uc, access, address, size, value, env):
    print("\n========================================================")
    print("ERROR: Memory access at {} failed".format(hex(address)))
    util.print_context(env)

def pre_analysis(uc, address, size, env):
    instr = uc.mem_read(address, size)
    env.cur_disasm = next(env.cs.disasm(instr, address))
    env.cur_mnemonic = env.cur_disasm.mnemonic
    #print(env.cur_mnemonic)

def trace(uc, address, size, env):
    # Instruction groups to print info on
    trace_groups = {CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET}
    # Set intersection
    if trace_groups & set(env.cur_disasm.groups):
        # Uppercase and pad mnemonic for output alignment
        print(">>> {}: {:<3} to ".format(hex(address), env.cur_mnemonic.upper()), end='')
        # Print the address of the next instruction when it runs
        env.trace_next_instr = True

def trace_next(uc, address, size, env):
    if env.trace_next_instr == True:
        env.trace_next_instr = False
        print(hex(address))

# TODO: capstone
# TODO: msrs
def interesting(uc, address, size, env):
    interesting = [(b'\x0f\x31', 'rdstc'),
                   (b'\x0f\xa2', 'cpuid')]
    instr = uc.mem_read(address, size)
    for i in interesting:
        # Length hack
        if (bytearray(i[0]) == instr[0:2]):
            print(">>> {}: Interesting instruction: {}!".format(hex(address), i[1]))

# TODO: Can be consolidated into trace - done
# TODO 2: verify that trace picks up everything that this does
def ret(uc, address, size, env):
    instr = uc.mem_read(address, 1)
    opcode = int.from_bytes(instr, 'little')
    if opcode == 0xc3:
        rsp = uc.reg_read(env.SP)
        ret_addr = int.from_bytes(uc.mem_read(rsp, 0x8), 'little')
        # Can use trace_next for this
        print(">>> {}: RET to {}".format(hex(address), hex(ret_addr)))

# All this uninitialized memory stuff needs to be redone
# Have to consider that some sections are zero init'd by loader
# One case: SizeOfRawData is less than VirtualSize (https://onlyf8.com/pe-format, also the MS PE spec)
# Maybe if IMAGE_SCN_CNT_UNINITIALIZED_DATA is set? Not seeing a source for that one.

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
