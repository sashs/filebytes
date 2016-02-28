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
# filebytes software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from .ctypes_helper import * 
from struct import pack_into

from ctypes import *

class Container(object):

    def __init__(self, **args):
        setattr = super(Container, self).__setattr__
        for key, value in args.items():
            setattr(key, value)


class Binary(object):
    def __init__(self, fileName, fileContent=None):
        
        self._bytes = to_ubyte_array(fileContent) if fileContent else self._readFile(fileName)
        if not self.__class__.isSupportedContent(self._bytes):
            raise BinaryError('Not a suitable filetype')

        self.__fileName = fileName
        

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

    @property
    def type(self):
        return 'ELF'

    def _readFile(self, fileName):
        """
        Returns the bytes of the file.
        """
        with open(fileName, 'rb') as binFile:
            b = binFile.read()
            return to_ubyte_array(b)

    def assertFileRange(self, value):
        if type(value) == c_void_p:
            value = value.value

        file_data_pointer = get_ptr(self._bytes)
        assert value >= (file_data_pointer.value) and value <= (
            file_data_pointer.value + len(self._bytes)), 'Pointer not in file range'

    @classmethod
    def isSupportedFile(cls, fileName):
        try:
            with open(fileName, 'rb') as f:
                return cls.isSupportedContent(f.read())
        except BaseException as e:
            raise BinaryError(e)

    @classmethod
    def isSupportedContent(cls, fileContent):
        return False


class BinaryError(BaseException):
    pass

