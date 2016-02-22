#!/usr/bin/env python

from binformats import elf

efile = elf.ELF('test-binaries/ls-x86')
print(efile.phdrs)