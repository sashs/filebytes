#!/usr/bin/env python
from __future__ import print_function
from filebytes.pe import *

def print_header_information(pe_file):
    image_dos_header = pe_file.imageDosHeader
    image_nt_header = pe_file.imageNtHeaders
    optional_header = image_nt_header.header.OptionalHeader

    print('Header:')
    print('ImageBase:', hex(optional_header.ImageBase))
    print('SizeOfCode:', hex(optional_header.SizeOfCode))
    print('DllCharacteristics:', hex(optional_header.SizeOfCode))
    print()
    print()

def print_section_information(pe_file):
    print('Sections:')
    for section in pe_file.sections:
        print(section.name, '\t' ,hex(section.header.VirtualAddress))
        # get referenced bytes
        # as bytearray
        # section.bytes 
        # as c_ubyte_array
        # section.raw

    print()
    print()

def print_exports(pe_file):
    exports = pe_file.dataDirectory[ImageDirectoryEntry.EXPORT]
    print('Exports:')
    if exports:
        print(exports.name)
        for function in exports.functions:
            print(function.name, hex(function.ordinal), hex(function.rva))
    else:
        print('No exports')
    print()
    print()

def print_imports(pe_file):
    imports = pe_file.dataDirectory[ImageDirectoryEntry.IMPORT]
    print('Imports:')
    if imports:
        for import_ in imports:
            print(import_.dllName+':', 'function count:',len(import_.importNameTable))
            for func in import_.importNameTable:
                if func.importByName:
                    print(hex(func.rva), func.importByName.name)
                else:
                    print(hex(func.rva), hex(func.ordinal))
            print()
    else:
        print('No imports')
    print()
    print()


def main():
    pe_file = PE('test-binaries/cmd-x86.exe')
    # also
    b = open('test-binaries/cmd-x86.exe','rb').read()
    pe_file = PE('any name', b)

    print_header_information(pe_file)
    print_section_information(pe_file)
    print_exports(pe_file)
    print_imports(pe_file)




if __name__ == '__main__':
    main()



