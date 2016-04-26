FileBytes
================

Classes/Types to read and edit the following file formats:
- Executable and Linking Format (ELF),
- Portable Executable (PE) and
- MachO
- OAT (Android Runtime)

Install
-------

Install FileBytes

    $ python setup.py install

Or install with PyPi

    $ pip install filebytes

Samples
-------

Parsing ELF file
```python
from filebytes.elf import *
elf_file = ELF('test-binaries/ls-x86')

elf_header = elf_file.elfHeader
sections = elf_file.sections
segments = elf_file.segments # elf_file.programHeaders does the same
```

Parsing PE file
```python
from filebytes.pe import *
pe_file = PE('test-binaries/cmd-x86.exe')

image_dos_header = pe_file.imageDosHeader
image_nt_headers = pe_file.imageNtHeaders
sections = pe_file.sections
data_directory = pe_file.dataDirectory

import_directory = data_directory[ImageDirectoryEntry.IMPORT]
export_directory = data_directory[ImageDirectoryEntry.EXPORT]
```

Parsing MachO file
```python
from filebytes.mach_o import *
macho_file = MachO('test-binaries/ls-macho-x86_64')

mach_header = macho_file.machHeader
load_commands = macho_file.loadCommands
```

Parsing OAT file, read DEX files and save them
```python
from filebytes.oat import *

oat = OAT('test-binaries/boot.oat')

for odh in oat.oatDexHeader:
    name = odh.name.split('/')[-1]
    with open(name, 'wb') as dex:
        dex.write(odh.dexBytes)
```

For further samples look at the sample folder.

Contributions
----------------------
If you would like contribute, here some ideas:
- Implementation of parsing of missing LoadCommand types for MachO files
- Implementation of parsing of the missing section types for ELF files
- Implementation of parsing of the missing data directory fields for PE files

But any kind of contribution is welcome. :)


Project page & Examples
------------------------------------
- https://scoding.de/filebytes-introduction
- https://scoding.de/filebytes-edit-files
