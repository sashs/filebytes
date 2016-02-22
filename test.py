#!/usr/bin/env python

from binformats import elf

efile = elf.ELF('test-binaries/ls-x86')
for segment in efile.segments:
    print(segment.type, hex(segment.vaddr))