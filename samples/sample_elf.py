#!/usr/bin/env python
from filebytes.elf import *

def print_header_information(elf_file):
    elf_header = elf_file.elfHeader.header

    print('Header:')
    print('Type:', ET[elf_header.e_type])
    print('Entry:', hex(elf_header.e_entry))
    print('Version:', elf_header.e_version)
    print()
    print()

def print_section_information(elf_file):
    print('Sections:')
    for section in elf_file.sections:
        print(section.name, '\t' ,SHT[section.header.sh_type], '\t', hex(section.header.sh_addr), '\t', hex(section.header.sh_offset))

    print()
    print()

def get_code_bytes(elf_file):
    # as bytesarray
    text_section = [section for section in elf_file.sections if section.name == '.text']
    return text_section.bytes
    # as c_ubyte_array
    # return text_section.raw

def print_executable_segments_information(elf_file):
    
    for segment in elf_file.segments:
        if segment.header.p_flags & PF.EXEC > 0:
            print(segment.type, '\t', hex(segment.vaddr), hex(segment.offset), hex(segment.header.p_memsz), PF.shortString(segment.header.p_flags))

            # get executable bytes
            # as bytesarray
            # segment.bytes
            # as c_ubyte_array
            # segment.raw 

def main():
    elf_file = ELF('test-binaries/ls-x86')

    print_header_information(elf_file)
    print_section_information(elf_file)
    print_executable_segments_information(elf_file)




if __name__ == '__main__':
    main()



