#!/usr/bin/env python

from binformats import elf

efile = elf.ELF('test-binaries/libc-2.19.so')
print("Segments:")
for segment in efile.segments:
    print(segment.type, hex(segment.vaddr))

print()
print('Sections:')
for section in efile.sections:
    print(section.name, elf.SHT(section.header.sh_type).name)


print()
print('Symbols:')
for section in efile.sections:
    if elf.SHT(section.header.sh_type) in (elf.SHT.DYNSYM, elf.SHT.SYMTAB):
        print(section.name, ', '.join([sym.name+' '+elf.STT(sym.type).name+' '+hex(sym.header.st_value)+' '+hex(sym.header.st_value + sym.header.st_size) for sym in section.symbols if sym.header.st_shndx == 12]))
