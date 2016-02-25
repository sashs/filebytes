#!/usr/bin/env python

from filebytes import elf,pe,mach_o

efile = elf.ELF('test-binaries/ls-x86')
print("Segments:")
for segment in efile.segments:
    print(segment.type, hex(segment.vaddr))

print()
print('Sections:')
for section in efile.sections:
    if section.header.sh_type == elf.SHT.DYNAMIC:
        print(section.name, len(section.content), section.content)

print()
print('############## PE FILE ###############')

pefile = pe.PE('test-binaries/cmd-x86.exe')
print(hex(pefile.imageNtHeaders.header.OptionalHeader.ImageBase))

for section in pefile.sections:
    print(section.name)

print()
for dataDirectory in pefile.dataDirectory:
    print(dataDirectory)


print()
export = pefile.dataDirectory[pe.ImageDirectoryEntry.EXPORT.value]
if export:
    print(export.name)
    for func in export.functions:
        print(func.name, hex(func.rva))


machfile = mach_o.MachO('test-binaries/ls-macho-x86_64')
print()
print(machfile.machHeader)
for loadCommand in machfile.loadCommands:
    if loadCommand.header.cmd == mach_o.LC.SEGMENT or loadCommand.header.cmd == mach_o.LC.SEGMENT_64:
        print(loadCommand.sections)
# print()
# print('Symbols:')
# for section in efile.sections:
#     if elf.SHT(section.header.sh_type) in (elf.SHT.DYNSYM, elf.SHT.SYMTAB):
#        print(section.name, '\n'.join([sym.name+' '+elf.STT(sym.type).name+' '+hex(sym.header.st_value)+' '+hex(sym.header.st_value + sym.header.st_size) for sym in section.symbols if sym.header.st_shndx == 12]))
