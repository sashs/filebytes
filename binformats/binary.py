# coding=utf-8
#
# Copyright 2016 Sascha Schirra
#
# This file is part of Ropper.
#
# Ropper is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ropper is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from .ctypes_helper import * 
from struct import pack_into

import ctypes

class DataContainer(object):

    def __init__(self, **args):
        setattr = super(DataContainer, self).__setattr__
        for key, value in args.items():
            setattr(key, value)


class Section(object):

    def __init__(self, name, sectionbytes, virtualAddress, offset, struct=None):
        if type(name) == bytes:
            name = name.decode('ascii')
        self.name = name
        self.bytes = sectionbytes
        self.virtualAddress = virtualAddress
        self.offset = offset
        self.struct = struct

    @property
    def size(self):
        return len(self.bytes)

class BinaryMeta(type):

    def __call__(cls, *args, **kwargs):
        o = super(BinaryMeta, cls).__call__(*args, **kwargs)
        o.__initialize__()
        return o


class Binary(metaclass=BinaryMeta):
    ___meta__ = BinaryMeta
    def __init__(self, fileName):
        
        self._bytes = None
        self.__fileName = fileName

    def __initialize__(self):
        self._bytes = self._readFile()

    @property
    def fileName(self):
        """
        Returns the filename
        """
        return self.__fileName

    @property
    def entryPoint(self):
        return 0x0

    @property
    def imageBase(self):
        return 0x0

    def _readFile(self):
        """
        Returns the bytes of the file.
        """
        with open(self.fileName, 'rb') as binFile:
            b = binFile.read()
            bs = (ctypes.c_ubyte * len(b))()
            pack_into('%ds' % len(b), bs, 0, b)

        return bs

    def assertFileRange(self, value):
        file_data_pointer = cast_to_void_ptr(self._bytes)
        assert value >= file_data_pointer.value and value <= (
            file_data_pointer.value + len(self._bytes)), 'Pointer not in file range'


class BinaryError(BaseException):
    pass

