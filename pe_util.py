#!/usr/bin/python3
# Shane Parslow 2022

def load(uc, pe):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    pe_mem = pe.get_memory_mapped_image(ImageBase=image_base)
    # WARNING: rounds to 4kb
    size = (len(pe_mem) + 0x1000) & ~0xFFF
    print("Allocating {} bytes for PE at {}".format(hex(size), hex(image_base)))
    uc.mem_map(image_base, size)
    print("Writing PE, len: {} bytes".format(hex(len(pe_mem))))
    uc.mem_write(image_base, bytes(pe_mem))
    