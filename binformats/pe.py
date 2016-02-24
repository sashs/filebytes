# coding=utf-8
#
# Copyright 2016 Sascha Schirra
#
# This file is part of Ropper.
#
# This is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from enum import Enum
from .binary import *

###################### PE General #################

class IMAGE_FILE_MACHINE(Enum):
    UKNOWN = 0
    AM33 = 0x1d3
    AMD64 = 0x8664
    ARM = 0x1c0
    ARMV = 0x1c4
    EBC = 0xebc
    I386 = 0x14c
    IA64 = 0x200
    M32R = 0x9041
    MIPS16 = 0x266
    MIPSFPU = 0x366
    MIPSFPU16 = 0x466
    POWERPC = 0x1f0
    POWERPCFP = 0x1f1
    THUMB = 0x1c2
    WCEMIPSV2 = 0x169

class IMAGE_SCN(Enum):
    TYPE_NO_PAD = 0x00000008
    CNT_CODE = 0x00000020
    CNT_INITIALIZED_DATA = 0x00000040
    CNT_UNINITIALIZED_DATA = 0x00000080
    LNK_OTHER = 0x00000100
    LNK_INFO = 0x00000200
    LNK_REMOVE = 0x00000800
    LNK_COMDAT = 0x00001000
    GPREL = 0x00008000
    MEM_PURGEABLE = 0x00020000
    MEM_LOCKED = 0x00040000
    MEM_PRELOAD = 0x00080000
    ALIGN_1BYTES = 0x00100000
    ALIGN_2BYTES = 0x00200000
    ALIGN_4BYTES = 0x00300000
    ALIGN_8BYTES = 0x00400000
    ALIGN_16BYTES = 0x00500000
    ALIGN_32BYTES = 0x00600000
    ALIGN_64BYTES = 0x00700000
    ALIGN_128BYTES = 0x00800000
    ALIGN_256BYTES = 0x00900000
    ALIGN_512BYTES = 0x00A00000
    ALIGN_1024BYTES = 0x00B00000
    ALIGN_2048BYTES = 0x00C00000
    ALIGN_4096BYTES = 0x00D00000
    ALIGN_8192BYTES = 0x00E00000
    LNK_NRELOC_OVFL = 0x01000000
    MEM_WRITE = 0x80000000
    MEM_READ = 0x4000000



class ImageDllCharacteristics(Enum):
    DYNAMIC_BASE = 0x0040
    FORCE_INTEGRITY = 0x0080
    NX_COMPAT = 0x0100
    NO_ISOLATION = 0x0200
    NO_SEH = 0x0400
    NO_BIND = 0x0800
    WDM_DRIVER = 0x2000
    TERMINAL_SERVER_AWARE = 0x8000
    CONTROL_FLOW_GUARD = 0xc000


class ImageDirectoryEntry(Enum):
    EXPORT = 0
    IMPORT = 1
    RESOURCE = 2
    EXCEPTION = 3
    SECURITY = 4
    BASERELOC = 5
    DEBUG = 6
    COPYRIGHT = 7
    GLOBALPTR = 8
    TLS = 9
    LOAD_CONFIG = 10
    BOUND_IMPORT = 11
    IAT = 12
    DELAY_IMPORT = 13
    COM_DESCRIPTOR = 14
    NUMBEROF_DIRECTORY_ENTRIES = 16


class IMAGE_DOS_HEADER(Structure):
    _fields_ = [('e_magic', c_char * 2),
                ('e_cblp', c_ushort),
                ('e_cp', c_ushort),
                ('e_crlc', c_ushort),
                ('e_cparhdr', c_ushort),
                ('e_minalloc', c_ushort),
                ('e_maxalloc', c_ushort),
                ('e_ss', c_ushort),
                ('e_sp', c_ushort),
                ('e_csum', c_ushort),
                ('e_ip', c_ushort),
                ('e_cs', c_ushort),
                ('e_lfarlc', c_ushort),
                ('e_ovno', c_ushort),
                ('e_res', c_ushort * 4),
                ('e_oemid', c_ushort),
                ('e_oeminfo', c_ushort),
                ('e_res2', c_ushort * 10),
                ('e_lfanew', c_uint)]       # Offset zum PE-Header


class IMAGE_FILE_HEADER(Structure):
    _fields_ = [('Machine', c_ushort),
                ('NumberOfSections', c_ushort),
                ('TimeDateStamp', c_uint),
                ('PointerToSymbolTable', c_uint),
                ('NumberOfSymbols', c_uint),
                ('SizeOfOptionalHeader', c_ushort),
                ('Characteristics', c_ushort)
                ]


class IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [('VirtualAddress', c_uint),
                ('Size', c_uint)]


class IMAGE_SECTION_HEADER(Structure):
    _fields_ = [('Name', c_char * 8),
                ('PhysicalAddress_or_VirtualSize', c_uint),
                ('VirtualAddress', c_uint),
                ('SizeOfRawData', c_uint),
                ('PointerToRawData', c_uint),
                ('PointerToRelocations', c_uint),
                ('PointerToLinenumbers', c_uint),
                ('NumberOfRelocations', c_ushort),
                ('NumberOfLinenumbers', c_ushort),
                ('Characteristics', c_uint)]


class IMAGE_IMPORT_BY_NAME(Structure):
    _fields_ = [('Hint', c_ushort),
                ('Name', c_char)]


class IMAGE_THUNK_DATA(Union):
    _fields_ = [('ForwarderString', c_uint),
                ('Function', c_uint),
                ('Ordinal', c_uint),
                ('AddressOfData', c_uint)]


class IMAGE_IMPORT_DESCRIPTOR(Structure):
    _fields_ = [('OriginalFirstThunk', c_uint),
                ('TimeDateStamp', c_uint),
                ('ForwarderChain', c_uint),
                ('Name', c_uint),
                ('FirstThunk', c_uint)]

##################### PE32 ########################

class IMAGE_OPTIONAL_HEADER(Structure):
    _fields_ = [('Magic', c_ushort),
                ('MajorLinkerVersion', c_byte),
                ('MinorLinkerVersion', c_byte),
                ('SizeOfCode', c_uint),
                ('SizeOfInitializedData', c_uint),
                ('SizeOfUninitializedData', c_uint),
                ('AddressOfEntryPoint', c_uint),
                ('BaseOfCode', c_uint),
                ('BaseOfData', c_uint),
                ('ImageBase', c_uint),
                ('SectionAlignment', c_uint),
                ('FileAlignment', c_uint),
                ('MajorOperatingSystemVersion', c_ushort),
                ('MinorOperatingSystemVersion', c_ushort),
                ('MajorImageVersion', c_ushort),
                ('MinorImageVersion', c_ushort),
                ('MajorSubsystemVersion', c_ushort),
                ('MinorSubsystemVersion', c_ushort),
                ('Win32VersionValue', c_uint),
                ('SizeOfImage', c_uint),
                ('SizeOfHeaders', c_uint),
                ('CheckSum', c_uint),
                ('Subsystem', c_ushort),
                ('DllCharacteristics', c_ushort),
                ('SizeOfStackReserve', c_uint),
                ('SizeOfStackCommit', c_uint),
                ('SizeOfHeapReserve', c_uint),
                ('SizeOfHeapCommit', c_uint),
                ('LoaderFlags', c_uint),
                ('NumberOfRvaAndSizes', c_uint),
                ('DataDirectory', IMAGE_DATA_DIRECTORY * 16)]


class PE32_IMAGE_NT_HEADERS(Structure):
    _fields_ = [('Signature', c_char * 4),
                ('FileHeader', IMAGE_FILE_HEADER),
                ('OptionalHeader', IMAGE_OPTIONAL_HEADER)]

class PE32(object):
    IMAGE_NT_HEADERS = PE32_IMAGE_NT_HEADERS

######################### PE64 ########################

class IMAGE_OPTIONAL_HEADER_PE32_PLUS(Structure):
    _fields_ = [('Magic', c_ushort),
                ('MajorLinkerVersion', c_ubyte),
                ('MinorLinkerVersion', c_ubyte),
                ('SizeOfCode', c_uint),
                ('SizeOfInitializedData', c_uint),
                ('SizeOfUninitializedData', c_uint),
                ('AddressOfEntryPoint', c_uint),
                ('BaseOfCode', c_uint),
                ('ImageBase', c_ulonglong),
                ('SectionAlignment', c_uint),
                ('FileAlignment', c_uint),
                ('MajorOperatingSystemVersion', c_ushort),
                ('MinorOperatingSystemVersion', c_ushort),
                ('MajorImageVersion', c_ushort),
                ('MinorImageVersion', c_ushort),
                ('MajorSubsystemVersion', c_ushort),
                ('MinorSubsystemVersion', c_ushort),
                ('Win32VersionValue', c_uint),
                ('SizeOfImage', c_uint),
                ('SizeOfHeaders', c_uint),
                ('CheckSum', c_uint),
                ('Subsystem', c_ushort),
                ('DllCharacteristics', c_ushort),
                ('SizeOfStackReserve', c_ulonglong),
                ('SizeOfStackCommit', c_ulonglong),
                ('SizeOfHeapReserve', c_ulonglong),
                ('SizeOfHeapCommit', c_ulonglong),
                ('LoaderFlags', c_uint),
                ('NumberOfRvaAndSizes', c_uint),
                ('DataDirectory', IMAGE_DATA_DIRECTORY * 16)]


class PE64_IMAGE_NT_HEADERS(Structure):
    _fields_ = [('Signature', c_char * 4),
                ('FileHeader', IMAGE_FILE_HEADER),
                ('OptionalHeader', IMAGE_OPTIONAL_HEADER_PE32_PLUS)]

class PE64(object):
    IMAGE_NT_HEADERS = PE64_IMAGE_NT_HEADERS

##################### Container ###################

class ImageImportDescriptorData(Container):

    """
    header = IMAGE_IMPORT_DESCRIPTOR
    dll = string (dll name)
    functions = list (imported function names)
    """

class ImageDosHeaderData(Container):
    """
    header = IMAGE_DOS_HEADER
    """

class ImageNtHeaderData(Container):
    """
    header = IMAGE_NT_HEADERS
    """

class SectionData(Container):
    """
    header = IMAGE_SECTION_HEADER
    name = name of the section (str)
    bytes = bytes of section (bytearray)
    raw = bytes of section (c_ubyte_array)
    """

class DataDirectoryData(Container):
    """
    header = IMAGE_DATA_DIRECTORY
    """

class PE(Binary):

    def __init__(self, fileName, fileContent=None):
        super(PE, self).__init__(fileName, fileContent)


        
        self.__imageDosHeader = self._parseImageDosHeader(self._bytes)
        self.__peClasses = self._getSuitablePeClasses(self._bytes, self.imageDosHeader)

        if not self.__peClasses:
            raise BinaryError('Bad architecture')

        self.__imageNtHeaders = self._parseImageNtHeaders(self._bytes, self.imageDosHeader)
        self.__sections = self._parseSections(self._bytes, self.imageDosHeader, self.imageNtHeaders)

        self.__dataDirectory = self._parseDataDirectory(self._bytes, self.sections, self.imageNtHeaders)
        
        
    @property
    def _peClasses(self):
        return self.__peClasses
    
    @property
    def imageDosHeader(self):
        return self.__imageDosHeader
    
    @property
    def imageNtHeaders(self):
        return self.__imageNtHeaders

    @property
    def sections(self):
        return self.__sections
    

    @property
    def entryPoint(self):
        return self.imageNtHeaders.OptionalHeader.ImageBase + self.imageNtHeaders.OptionalHeader.AddressOfEntryPoint

    @property
    def type(self):
        return 'PE'

    def _getSuitablePeClasses(self, data, imageDosHeader):
        classes = None
        machine = IMAGE_FILE_MACHINE(c_ushort.from_buffer(data,imageDosHeader.header.e_lfanew+4).value)

        if machine == IMAGE_FILE_MACHINE.I386:
            classes = PE32
        elif machine == IMAGE_FILE_MACHINE.AMD64:
            classes = PE64

        return classes


        

    @property
    def executableSections(self):
    #    toReturn = [self.sections['.text']]
        toReturn = []
        for section in self.sectionHeader:
            if section.Characteristics & IMAGE_SCN.CNT_CODE > 0:
                if section.Name in self.sections:
                    toReturn.append(self.sections[section.Name])
                else:
                    p_tmp = c_void_p(self._bytes_p.value + section.PointerToRawData)
                    size = section.PhysicalAddress_or_VirtualSize
                    ibytes = cast(p_tmp, POINTER(c_ubyte * size)).contents
                    s = Section(section.Name, ibytes, section.VirtualAddress + self.imageBase, section.VirtualAddress)
                    self.sections[section.Name] = s
                    toReturn.append(s)
        return toReturn

    @property
    def dataSections(self):
        toReturn = []
        for section in self.sectionHeader:
            if section.Characteristics & IMAGE_SCN.CNT_INITIALIZED_DATA or section.Characteristics & IMAGE_SCN.CNT_UNINITIALIZED_DATA:
                p_tmp = c_void_p(self._bytes_p.value + section.PointerToRawData)
                size = section.PhysicalAddress_or_VirtualSize
                ibytes = cast(p_tmp, POINTER(c_ubyte * size)).contents
                s = Section(section.Name, ibytes, section.VirtualAddress + self.imageBase, section.VirtualAddress)

                toReturn.append(s)
        return toReturn


    def getWriteableSection(self):
        for section in self.sectionHeader:
            if section.Characteristics & IMAGE_SCN.MEM_WRITE:
                p_tmp = c_void_p(self._bytes_p.value + section.PointerToRawData)
                size = section.PhysicalAddress_or_VirtualSize
                ibytes = cast(p_tmp, POINTER(c_ubyte * size)).contents
                s = Section(section.Name, ibytes, section.VirtualAddress + self.imageBase, section.VirtualAddress)

                return s

    def getSection(self, name):
        
        for section in self.sectionHeader:
            if str(section.Name) == name:
                p_tmp = c_void_p(self._bytes_p.value + section.PointerToRawData)
                size = section.PhysicalAddress_or_VirtualSize
                ibytes = cast(p_tmp, POINTER(c_ubyte * size)).contents
                s = Section(section.Name, ibytes, section.VirtualAddress + self.imageBase, section.VirtualAddress)

                return s
        raise RopperError('No such secion: %s' % name)        

    def _getImageBase(self):
        return self.imageNtHeaders.OptionalHeader.ImageBase

    def _parseSections(self, data, imageDosHeader, imageNtHeaders):
        sections = []
        offset = imageDosHeader.header.e_lfanew + sizeof(self._peClasses.IMAGE_NT_HEADERS) # start reading behind the dos- and ntheaders 
        image_section_header_size = sizeof(IMAGE_SECTION_HEADER)

        for sectionNo in range(imageNtHeaders.header.FileHeader.NumberOfSections):
            ishdr = IMAGE_SECTION_HEADER.from_buffer(data, offset)
            size = ishdr.PhysicalAddress_or_VirtualSize
            raw = (c_ubyte * size).from_buffer(data, ishdr.PointerToRawData)

            sections.append(SectionData(header=ishdr, name=str(ishdr.Name, 'ASCII'), bytes=bytearray(raw), raw=raw))

            offset += image_section_header_size

        return sections

    def _parseDataDirectory(self, data, sections, imageNtHeaders):
        pass


    def __loadThunks(self, addr):
        p_thunk = c_void_p(addr)
        thunks = []
        while True:
            self.assertFileRange(p_thunk.value)
            thunk = cast(
                p_thunk, POINTER(self.__pe_module.IMAGE_THUNK_DATA)).contents
            p_thunk.value += sizeof(self.__pe_module.IMAGE_THUNK_DATA)
            if thunk.Ordinal == 0:
                break
            thunks.append(thunk)

        return thunks

    def __parseThunkContent(self, thunks, diff, thunkRVA):
        contents = []
        tmpRVA = thunkRVA
        for thunk in thunks:
            if 0xf0000000 & thunk.AddressOfData == 0x80000000:
                contents.append((thunk.AddressOfData & 0x0fffffff,'', tmpRVA))
                tmpRVA += sizeof(self.__pe_module.IMAGE_THUNK_DATA)
                continue
            p_thunk_address_of_data = c_void_p(thunk.AddressOfData - diff)

            ibn = cast(
                p_thunk_address_of_data, POINTER(self.__pe_module.IMAGE_IMPORT_BY_NAME)).contents
            p_thunk_address_of_data.value += 2
            self.assertFileRange(p_thunk_address_of_data.value)
            name = cast(p_thunk_address_of_data, c_char_p)
            contents.append((ibn.Hint, name.value, tmpRVA))
            tmpRVA += sizeof(self.__pe_module.IMAGE_THUNK_DATA)
        return contents

    def __parseCode(self, section, p_bytes, size):
        ibytes = cast(p_bytes, POINTER(c_ubyte * size)).contents
        s = Section(section.Name, ibytes, section.VirtualAddress + self.imageBase, section.VirtualAddress)
        self.sections[s.name] = s

    def __parseImports(self, section, p_bytes, size):
        ibytes = cast(p_bytes, POINTER(c_ubyte * size)).contents
        s = Section('.idata', ibytes, section.VirtualAddress + self.imageBase, section.VirtualAddress)
        self.sections[s.name] = s
        s.importDescriptorTable = []
        s.importNameTable = []
        s.importAddressTable = []
        s.importHintsAndNames = []
        s.contents = {}
        idataRVA = section.VirtualAddress
        idataFAddr = section.PointerToRawData + self._bytes_p.value
        s.header = section

        while True:

            self.assertFileRange(p_bytes.value)
            importDescriptor = cast(
                p_bytes, POINTER(self.__pe_module.IMAGE_IMPORT_DESCRIPTOR)).contents
            p_bytes.value += sizeof(self.__pe_module.IMAGE_IMPORT_DESCRIPTOR)
            if importDescriptor.OriginalFirstThunk == 0:
                break

            else:
                dllNameAddr = c_void_p(
                    importDescriptor.Name - idataRVA + idataFAddr)
                dllName = cast(dllNameAddr, c_char_p)
                importNameTable = self.__loadThunks(
                    importDescriptor.OriginalFirstThunk - idataRVA + idataFAddr)
                importAddressTable = self.__loadThunks(
                    importDescriptor.FirstThunk - idataRVA + idataFAddr)
                functions = self.__parseThunkContent(
                    importNameTable, idataRVA - idataFAddr, importDescriptor.FirstThunk)
                s.importDescriptorTable.append(ImageImportDescriptorData(
                    struct=importDescriptor, dll=dllName.value, functions=functions, importNameTable=importNameTable, importAddressTable=importAddressTable))

    def _parseImageDosHeader(self, data):
        ioh = IMAGE_DOS_HEADER.from_buffer(data)
        if ioh.e_magic != b'MZ':
            raise BinaryError('No valid PE/COFF file')

        return ImageDosHeaderData(header=ioh)

    def _parseImageNtHeaders(self, data, imageDosHeader):
        inth = self._peClasses.IMAGE_NT_HEADERS.from_buffer(data, imageDosHeader.header.e_lfanew)

        if inth.Signature != b'PE':
            raise BinaryError('No valid PE/COFF file')

        return ImageNtHeaderData(header=inth)


    def __parse(self, p_bytes):
        
        importVaddr = self.imageNtHeaders.OptionalHeader.DataDirectory[ImageDirectoryEntry.IMPORT].VirtualAddress
        for section in self.sectionHeader:
            if importVaddr > section.VirtualAddress and importVaddr < (section.VirtualAddress + section.SizeOfRawData) :
                p_tmp.value = p_bytes.value + (importVaddr - section.VirtualAddress + section.PointerToRawData)
                size = self.imageNtHeaders.OptionalHeader.DataDirectory[
                    ImageDirectoryEntry.IMPORT].Size
                self.__parseImports(section, p_tmp, size)
                idata = True
            if section.Characteristics & IMAGE_SCN.CNT_CODE > 0:
                p_tmp.value = p_bytes.value + section.PointerToRawData
                size = section.PhysicalAddress_or_VirtualSize
                self.__parseCode(section, p_tmp, size)
                textsection = section

    @classmethod
    def isSupportedContent(cls, fileContent):
        """Returns if the files are valid for this filetype"""
        return bytearray(fileContent)[:2] == b'MZ'
