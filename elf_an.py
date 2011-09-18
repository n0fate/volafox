#!/usr/bin/python
# -*- coding: utf-8 -*-
#  -*- mode: python; -*-
#
# elf_an - elf file format analysis
# Copyright by n0fate - rapfer@gmail.com, n0fate@live.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       Kyeongsik Lee
@license:      GNU General Public License 2.0 or later
@contact:      rapfer@gmail.com n0fate@live.com
"""

"""Module for dealing with x86 architecture stuff
"""

import sys
import binascii
import struct

# define
ELF_SIG = '7f454c46' # ELF Signature
SYMBOL_SIZE = 16


# Let's map the elf file format types
#Elf32_Addr = c_uint # unsigned program address
#Elf32_Half = c_ushort # unsigned medium integer
#Elf32_Off = c_uint # unsigned file offset
#Elf32_Sword = c_int # signed large integer
#Elf32_Word = c_uint # Unsigned large integer
#
#class ELF32HEADER(Structure):
#    _fields_ = [
#        ("e_type", Elf32_Half),
#        ("e_machine", Elf32_Half),
#        ("e_version", Elf32_Word),
#        ("e_entry", Elf32_Addr),
#        ("e_phoff", Elf32_Off),
#        ("e_shoff", Elf32_Off),
#        ("e_flags", Elf32_Word),
#        ("e_ehsize", Elf32_Half),
#        ("e_phentsize", Elf32_Half),
#        ("e_phnum", Elf32_Half),
#        ("e_shentsize", Elf32_Half),
#        ("e_shnum", Elf32_Half),
#        ("e_shstrndx", Elf32_Half)
#    ]


###############################################################################
#
# Class: elf32_an() - 2010-11-01
# Description: This analysis module can support Intel X86 Architecture
#              We need to have more research time ;)
#
###############################################################################
class elf32_an():
    def __init__(self, filename):
        self.filename = filename
        self.buf = ""
        self.fp = 0
        self.header = []
        
    def load(self):
        self.fp = open(self.filename, 'rb')
        self.buf = self.fp.read()
        if ELF_SIG != binascii.b2a_hex(self.buf[0:4]):
            return 0
        return 1
    
    def close(self):
        self.fp.close()
    
    def getheader(self):
        self.header = struct.unpack('=16sHHIIIIIHHHHHH', self.buf[0:52])
        return self.header
    
    def getmachine(self):
        machine = int(self.header[2])
        return machine
    
    def getshoff(self):
        shoff = int(self.header[6])
        return shoff
    
    def getshsize(self):
        shsize = int(self.header[11])
        return shsize
    
    def getshcount(self):
        shcount = int(self.header[12])
        return shcount
    
    #### section header ####
    def getsecheader(self, offset, size, count):
        return header
    
    def getstrsec(self, offset, size, count):
        for i in range(0, count):
            pos = offset + size*i
            section_header = struct.unpack('=IIIIIIIIII', self.buf[pos:pos+size])
            if section_header[1] == 0x03 and section_header[0] == 0x09:
                return section_header
    
    def getsymsec(self, offset, size, count):
        for i in range(0, count):
            pos = offset + size*i
            section_header = struct.unpack('=IIIIIIIIII', self.buf[pos:pos+size])
            if section_header[1] == 0x02:
                return section_header
    
    #### get symbol list (dictionary) ####
    def getsymbol(self, offset, size, str_offset, str_size):
        symbol_list = {}
        strtable = self.buf[str_offset:str_offset+str_size]
        
        for i in range(0, size, SYMBOL_SIZE):
            pos = offset + i
            symbol = struct.unpack('=IIIBBH', self.buf[pos:pos+SYMBOL_SIZE])
            symbolname = strtable[symbol[0]:symbol[0]+strtable[symbol[0]:].index('\x00')]
            if symbol[1] == 0:
                continue
            symbol_list[symbolname] = symbol[1]
            #print 'symbolname: %s, address: %x'%(symbolname, int(symbol[1]))
        return symbol_list       
        

def main():
    elf = elf32_an(sys.argv[1])
    nret = elf.load()
    if 0 == nret:
        return 0
    
    header = elf.getheader()
    shoff = elf.getshoff()
    if 0 == shoff:
        return 0
    
    shsize = elf.getshsize()
    shcount = elf.getshcount()

    section_header = elf.getsymsec(shoff, shsize, shcount)
    strtab_header = elf.getstrsec(shoff, shsize, shcount)
    
    symbol_list = elf.getsymbol(section_header[4], section_header[5], strtab_header[4], strtab_header[5])
    print '%x'%symbol_list['IdlePTD']
    
    

if __name__ == "__main__":
    main()
