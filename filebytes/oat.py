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
from .enum import Enum

class DexHeader(Structure):
    ('_fields_', c_uint)
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
                ('version', c_uint),
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