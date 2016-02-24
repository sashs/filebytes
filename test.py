#!/usr/bin/env python

from binformats import elf,pe

efile = elf.ELF('test-binaries/ls-x86')
print("Segments:")
for segment in efile.segments:
    print(segment.type, hex(segment.vaddr))

print()
print('Sections:')
for section in efile.sections:
    if elf.SHT(section.header.sh_type) == elf.SHT.DYNAMIC:
        print(section.name, len(section.content), section.content)

print()
print('############## PE FILE ###############')

pefile = pe.PE('test-binaries/cmd-x86.exe')
print(hex(pefile.imageNtHeaders.header.OptionalHeader.ImageBase))

for section in pefile.sections:
    print(section.name)

# print()
# print('Symbols:')
# for section in efile.sections:
#     if elf.SHT(section.header.sh_type) in (elf.SHT.DYNSYM, elf.SHT.SYMTAB):
#        print(section.name, '\n'.join([sym.name+' '+elf.STT(sym.type).name+' '+hex(sym.header.st_value)+' '+hex(sym.header.st_value + sym.header.st_size) for sym in section.symbols if sym.header.st_shndx == 12]))
