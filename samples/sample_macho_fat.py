#!/usr/bin/env python
from __future__ import print_function
from filebytes.mach_o import *

from sample_macho import *

def main():
    macho_file = MachO('test-binaries/dummy-macho-universal-x86-x86_64')

    print('Is Fat:', macho_file.isFat)
    print('Number of Architectures:', len(macho_file.fatArches))

    print()
    print()

    for arch in macho_file.fatArches:
        print_header_information(arch)
        print_load_commands(arch)
        print_section_information(arch)


if __name__ == '__main__':
    main()
