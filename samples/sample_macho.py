#!/usr/bin/env python
from filebytes.mach_o import *

def print_header_information(macho_file):
    mach_header = macho_file.machHeader.header

    print('Header:')
    print('CPU Type:', CpuType[mach_header.cputype])
    print('Number of Commands:', mach_header.ncmds)
    print()
    print()

def print_section_information(macho_file):
    print('Sections:')
    for load_command in macho_file.loadCommands:
        if load_command.header.cmd == LC.SEGMENT_64:
            print('Section count for %s:' % load_command.name, load_command.header.nsects)
            for section in load_command.sections:
                shdr = section.header
                print(shdr.sectname, '\t', hex(shdr.addr), '\t', hex(shdr.size))

    print()
    print()

def get_code_bytes(elf_file):
    # as bytesarray
    text_section = [section for section in elf_file.sections if section.name == '.text']
    return text_section.bytes
    # as c_ubyte_array
    # return text_section.raw

def print_load_commands(macho_file):
    print('LoadCommands:')
    for load_command in macho_file.loadCommands:
        print(LC[load_command.header.cmd])
    print()
    print()

def main():
    macho_file = MachO('test-binaries/ls-macho-x86_64')
    # also
    b = open('test-binaries/ls-macho-x86_64','rb').read()
    macho_file = MachO('any name', b)

    print_header_information(macho_file)
    print_load_commands(macho_file)
    print_section_information(macho_file)




if __name__ == '__main__':
    main()



