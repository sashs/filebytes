# coding=utf-8
#
# Copyright 2016 Sascha Schirra
#
# This file is part of filebytes.
#
# filebytes is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# filebytes is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from .binary import *
from .elf import ELF
from .enum import Enum

class OatClassType(Enum):
    kOatClassAllCompiled = 0   
    kOatClassSomeCompiled = 1  
    kOatClassNoneCompiled = 2  
    kOatClassMax = 3

class DexHeader(Structure):
    _fields_ = [('magic', c_char*8),
                ('checksum', c_uint),
                ('signature', c_ubyte * 20),
                ('fileSize', c_uint),
                ('headerSize', c_uint),
                ('endianTag', c_uint),
                ('linkSize', c_uint),
                ('linkOff', c_uint),
                ('mapOff', c_uint),
                ('stringIdsSize', c_uint),
                ('stringIdsOff', c_uint),
                ('typeIdsSize', c_uint),
                ('typeIdsOff', c_uint),
                ('protoIdsSize', c_uint),
                ('protoIdsOff', c_uint),
                ('fieldIdsSize', c_uint),
                ('fieldIdsOff', c_uint),
                ('methodIdsSize', c_uint),
                ('methodIdsOff', c_uint),
                ('classDefsSize', c_uint),
                ('classDefsOff', c_uint),
                ('dataSize', c_uint),
                ('dataOff', c_uint)
                ]


class OatHeader(Structure):
    _fields_ = [('magic', c_char*4),
                ('version', c_char*4),
                ('adler32Checksum', c_uint),
                ('instructionSet', c_uint),
                ('instructionSetFeatures', c_uint),
                ('dexFileCount', c_uint),
                ('executableOffset', c_uint),
                ('interpreterToInterpreterBridgeOffset', c_uint),
                ('interpreterToCompiledCodeBridgeOffset', c_uint),
                ('jniDlsymLookupOffset', c_uint),
                ('quickGenericJniTrampolineOffset', c_uint),
                ('quickImtConflictTrampolineOffset', c_uint),
                ('quickResolutionTrampolineOffset', c_uint),
                ('quickToInterpreterBridgeOffset', c_uint),
                ('imagePatchDelta', c_uint),
                ('imageFileLocationOatChecksum', c_uint),
                ('imageFileLocationOatDataBegin', c_uint),
                ('keyValueStoreSize', c_uint)
                ]

class OatClass(Structure):
    _pack_ = 1
    _fields_ = [('status', c_ushort),
                ('type', c_ushort),
                ('methodsPointer', c_uint)
                ]

def create_oat_class_with_bitmap_class(size):
    class OatClassWithBitmap(Structure):
        _pack_ = 1
        _fields_ = [('status', c_ushort),
                    ('type', c_ushort),
                    ('bitmapSize', c_uint),
                    ('bitmap', c_ubyte * size),
                    ('methodsPointer', c_uint)
                    ]

    return OatClassWithBitmap

def create_oat_dex_file_class(size):
    class OatDexFileHeader(Structure):
        _pack_ = 1
        _fields_ = [('dexFileLocationSize', c_uint),
                    ('dexFileLocation', c_char*size),
                    ('dexFileChecksum', c_uint),
                    ('dexFileOffset', c_uint)
                    ]
    return OatDexFileHeader

################################## Container ##############################

class OatHeaderData(Container):
    """
    header = OatHeader
    keyValueStoreRaw = c_ubyte_array
    keyValueStore = dict 
    """

class OatDexFileHeaderData(Container):
    """
    header = OatDexFileHeader w/o dexFileLocationSize and dexFileLocation
    name = name of Dexfile str
    classOffsets = c_uint_array
    dexHeader = DexHeader
    dexRaw = c_ubyte_array
    dexBytes = bytearray
    oatClasses = list of OatClasses
    """

################################# OAT class ###############################

class OAT(ELF):

    def __init__(self, fileName, fileContent=None):
        super(OAT, self).__init__(fileName, fileContent)

        self._oatBytes = self._getOatBytes(self._bytes)
        self.__oatHeader = self._parseOatHeader(self._oatBytes)
        self.__oatDexHeader = self._parseOatDexHeader(self._oatBytes, self.oatHeader)

    @property
    def oatHeader(self):
        return self.__oatHeader

    @property
    def oatDexHeader(self):
        return self.__oatDexHeader
    
    def _getOatBytes(self, data):
        rodata_sec = None
        text_sec = None

        for section in self.sections:
            if section.name == '.rodata':
                rodata_sec = section
            elif section.name == '.text':
                text_sec = section

        oat_size = (rodata_sec.header.sh_size + text_sec.header.sh_size)

        return (c_ubyte * oat_size).from_buffer(data, rodata_sec.header.sh_offset)

    def _parseOatHeader(self, data):
        """Returns the OatHeader"""
        header = OatHeader.from_buffer(data)
        if header.magic != b'oat\n':
            raise BinaryError('No valid OAT file')

        key_value_store_bytes = (c_ubyte * header.keyValueStoreSize).from_buffer(data, sizeof(OatHeader))
        key_value_store = self.__parseKeyValueStore(key_value_store_bytes)

        return OatHeaderData(header=header, keyValueStoreRaw=key_value_store_bytes, keyValueStore=key_value_store)

    def __parseKeyValueStore(self, data):
        """Returns a dictionary filled with the keys and values of the key value store"""
        offset = 0
        key_value_store = {}
        while offset != len(data):
            key = get_str(data, offset)
            offset += len(key)+1

            value = get_str(data, offset)
            offset += len(value)+1

            key_value_store[key] = value

        return key_value_store

    def _parseOatDexHeader(self, data, oatHeader):
        oat_dex_files = []

        offset = sizeof(OatHeader) + oatHeader.header.keyValueStoreSize
        for i in range(oatHeader.header.dexFileCount):
            size = c_uint.from_buffer(data, offset).value
            oat_dex_file_header_struct = create_oat_dex_file_class(size)

            odfh = oat_dex_file_header_struct.from_buffer(data, offset)
          
            offset += sizeof(oat_dex_file_header_struct)

            dex_file = DexHeader.from_buffer(data, odfh.dexFileOffset)
            dex_raw = (c_ubyte*dex_file.fileSize).from_buffer(data, odfh.dexFileOffset)
            class_offsets = None
            oat_classes = None
            if dex_file.classDefsSize > 0:
                class_offsets = (c_uint*dex_file.classDefsSize).from_buffer(data, offset) 
                oat_classes = self._parseOatClasses(data, class_offsets)
            offset += dex_file.classDefsSize*4

            oat_dex_files.append((OatDexFileHeaderData(header=odfh, classOffsets=class_offsets, name=odfh.dexFileLocation.decode('ASCII'), dexHeader=dex_file, dexRaw=dex_raw, dexBytes=bytearray(dex_raw), oatClasses=oat_classes)))
        return oat_dex_files

    def _parseOatClasses(self, data, classOffsets):
        oat_classes = []

        for class_offset in classOffsets:
            
            oat_class = OatClass.from_buffer(data, class_offset)

            if oat_class.type != OatClassType.kOatClassNoneCompiled:
                if oat_class.type == OatClassType.kOatClassSomeCompiled:
                    oat_class_with_bitmap_struct = create_oat_class_with_bitmap_class(oat_class.methodsPointer)
                    oat_class = oat_class_with_bitmap_struct.from_buffer(data, class_offset)
        
            oat_classes.append(oat_class)

        return oat_classes


