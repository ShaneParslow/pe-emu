import sys

from pefile import PE
from unicorn import UC_MODE_32, UC_MODE_64

from . import Emu
from . import util

# TODO: argparse
mode = UC_MODE_32 if "-32b" in sys.argv else UC_MODE_64
print("Preparing emulation in *{}* mode".format("32-bit mode" if mode == UC_MODE_32 else "64-bit mode"))

env = Emu(mode)
env.load(PE(sys.argv[1]))

entry = env.pe.OPTIONAL_HEADER.ImageBase + env.pe.OPTIONAL_HEADER.AddressOfEntryPoint
print("Starting emulation at {}".format(hex(entry)))
try:
    # Docs say timeout is ms but it's actually us
    ret = env.uni.emu_start(entry, 0xffffffffff, timeout=10000000)
except UcError as e:
    print("\n========================================================")
    print("ERROR: %s" % e)

print("\n========================================================")
util.print_context(env)
print("========================================================")

# TODO: reassemble to PE or elf coredump
util.dump_all(env)
