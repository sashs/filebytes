#!/usr/bin/env python

from binformats import elf

efile = elf.ELF('test-binaries/ls-x86')
print("Segments:")
for segment in efile.segments:
    print(segment.type, hex(segment.vaddr))

print()
print('Sections:')
for section in efile.sections:
    print(section.name, elf.SHT(section.header.sh_type).name)

print()
print('Symbols:')
print(efile.symbols)