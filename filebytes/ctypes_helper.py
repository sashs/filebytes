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

from struct import pack_into
import ctypes

def get_ptr(data, offset=None, ptr_type=ctypes.c_void_p):
    """Returns a void pointer to the data"""
    ptr = ctypes.cast(ctypes.pointer(data), ctypes.c_void_p)

    if offset:
        ptr = ctypes.c_void_p(ptr.value + offset)

    if ptr_type != ctypes.c_void_p:
        ptr = ctypes.cast(ptr, ptr_type)

    return ptr

def get_str(data, offset=None):
    return get_ptr(data, offset, ctypes.c_char_p).value.decode('ASCII')

def to_ubyte_array(barray):
    """Returns a c_ubyte_array filled with the given data of a bytearray or bytes"""
    bs = (ctypes.c_ubyte * len(barray))()
    pack_into('%ds' % len(barray), bs, 0, barray)

    return bs

