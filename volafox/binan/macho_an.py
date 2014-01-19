#!c:\python\python.exe
# -*- coding: utf-8 -*-
#  -*- mode: python; -*-
#
# mach_an - mach-o file format analysis class
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

import sys
import os
import binascii
import struct

# define
MH_CIGAM = 'cafebabe'
MH_MAGIC_X86 = 'cefaedfe'
MH_MAGIC_X64 = 'cffaedfe'
FAT_HEADER_SIZE = 8
FAT_ARCH_SIZE = 20
MACH_HEADER_SIZE = 28
MACH_HEADER_SIZE_64 = 32 # 32bit header + 4byte reserved value
LOAD_CMD_SIZE = 8
SYMTAB_CMD_SIZE = 24
NLIST_SIZE = 12
NLIST_SIZE_64 = 16

# cpu_type
ARCH_PPC = 18
ARCH_I386 = 7
ARCH_X86_64 = 16777223


###############################################################################
#
# Class: macho_an() - 2010-09-30
# Description: This analysis module can support Intel X86 Architecture
#              We need to have more research time ;)
#
###############################################################################
class macho_an():
    def __init__(self, filename):
        self.filename = filename
        self.buf = ""
        self.fp = 0
        self.symbol_diclist = {}
        self.ARCH_PPC = 18
        self.ARCH_I386 = 7
        self.ARCH_X86_64 = 16777223

    def close(self):
        self.fp.close()
        
    def load(self):
        self.fp = open(self.filename, 'rb')
        self.buf = self.fp.read()
        #print binascii.b2a_hex(self.buf[0:4])
        if MH_CIGAM != binascii.b2a_hex(self.buf[0:4]):
            return -1
        arch_count = int(binascii.b2a_hex(self.buf[4:8]), 16)
        return arch_count

    def getfilesize(self):
        return os.fstat(self.fp.fileno()).st_size
#struct mach_header_64
#{
#   uint32_t magic;
#   cpu_type_t cputype;
#   cpu_subtype_t cpusubtype;
#   uint32_t filetype;
#   uint32_t ncmds;
#   uint32_t sizeofcmds;
#   uint32_t flags;
#   uint32_t reserved;
#};
    def get_header(self, arch_count, architecture):
        header_list = []
        header_area = self.buf[FAT_HEADER_SIZE:(FAT_ARCH_SIZE*arch_count)+FAT_HEADER_SIZE]
        for i in range(0, arch_count):
            header = struct.unpack('>IIIII', header_area[i*FAT_ARCH_SIZE:(i+1)*FAT_ARCH_SIZE])
            #print header[0]
            if architecture == header[0]:
                return header
    
    def macho_getsymbol_x86(self, offset, size):
        self.macho_file = self.buf[offset:offset+size]
        #print binascii.b2a_hex(self.macho_file[0:4])
        if MH_MAGIC_X86 != binascii.b2a_hex(self.macho_file[0:4]):
            print 'Invalid mach header'
            return -1
        self.mach_header = struct.unpack('IIIIII', self.macho_file[4:MACH_HEADER_SIZE])
        ncmds = self.mach_header[3]
        sizeofcmds = self.mach_header[4]
        #print ncmds
        #print sizeofcmds
        
        self.load_cmds = self.macho_file[MACH_HEADER_SIZE:MACH_HEADER_SIZE+sizeofcmds]
        
        i=0
        while 1:
            cmd = struct.unpack('II', self.load_cmds[i:i+LOAD_CMD_SIZE])
            if cmd[0] == 0x02: # DY_SYM == 0x02
                #print 'find!'
                #print 'Symbol command size:', cmd[1]
                
                # Defines the attributes of the LC_SYMTAB load command.
                # Describes the size and location of the symbol table
                # data structures. Declared in /usr/include/mach-o/loader.h.
                
                self.symtab_cmds = self.load_cmds[i:i+SYMTAB_CMD_SIZE]
                symtab = struct.unpack('IIIIII', self.symtab_cmds)
                symoff = symtab[2] # symbol table offset
                nsyms = symtab[3] # number of entries in symbol table
                stroff = symtab[4] # string table offset
                strsize = symtab[5] # string size
                
                # print 'symbol table offset: ', symoff
                self.sym_table = self.macho_file[symoff:symoff + (nsyms*NLIST_SIZE)] # symbol table
                self.symbol_str = self.macho_file[stroff:stroff+strsize] # symbol str
                
                sym_table_count = 0
                for sym_table_count in range(0, nsyms):
                    nlist = struct.unpack('=IBBHI', self.sym_table[sym_table_count*NLIST_SIZE:(sym_table_count*NLIST_SIZE)+NLIST_SIZE])
                    n_un = nlist[0]
                    n_type = nlist[1]
                    n_sect = nlist[2]
                    n_desc = nlist[3]
                    n_value = nlist[4]

                    #if n_type == 15: # we need this symbol 'SECT'
                    symbol_name = self.symbol_str[n_un:n_un+self.symbol_str[n_un:].index('\x00')]
                    self.symbol_diclist[symbol_name] = n_value
                    #print 'symbol_name: %s, address: %x'%(symbol_name, n_value)
                break
                
            i += cmd[1] # index + load_command.cmd_size
            if i >= sizeofcmds:
                break

        return self.symbol_diclist

    def macho_getsymbol_x64(self, offset, size):
        self.macho_file = self.buf[offset:offset+size]
        #print binascii.b2a_hex(self.macho_file[0:4])
        if MH_MAGIC_X64 != binascii.b2a_hex(self.macho_file[0:4]):
            print 'Invalid mach header'
            return -1
        self.mach_header = struct.unpack('IIIIIII', self.macho_file[4:MACH_HEADER_SIZE_64])
        ncmds = self.mach_header[3]
        sizeofcmds = self.mach_header[4]
        #print 'ncmds: %x'%ncmds
        #print 'sizeofcmds: %x'%sizeofcmds
        
        self.load_cmds = self.macho_file[MACH_HEADER_SIZE_64:MACH_HEADER_SIZE_64+sizeofcmds]
        
        i=0
        while 1:
            cmd = struct.unpack('II', self.load_cmds[i:i+LOAD_CMD_SIZE])
            #print 'cmd: %d, ncmd: %d'%(cmd[0], cmd[1])
            if cmd[0] == 0x02: # DY_SYM == 0x02
                #print 'find!'
                #print 'Symbol command size:', cmd[1]
                
                # Defines the attributes of the LC_SYMTAB load command.
                # Describes the size and location of the symbol table
                # data structures. Declared in /usr/include/mach-o/loader.h.

                #print 'offset: %x'%i                
                self.symtab_cmds = self.load_cmds[i:i+SYMTAB_CMD_SIZE]
                symtab = struct.unpack('IIIIII', self.symtab_cmds)
                symoff = symtab[2] # symbol table offset
                nsyms = symtab[3] # number of entries in symbol table
                stroff = symtab[4] # string table offset
                strsize = symtab[5] # string size
                
                #print 'symbol table offset: %x'%symoff
                self.sym_table = self.macho_file[symoff:symoff + (nsyms*NLIST_SIZE_64)] # symbol table
                self.symbol_str = self.macho_file[stroff:stroff+strsize] # symbol str

#struct nlist_64
#{
#    union {
#        uint32_t n_strx;
#    } n_un;
#    uint8_t n_type;
#    uint8_t n_sect;
#    uint16_t n_desc;
#    uint64_t n_value;
#};
                sym_table_count = 0
                for sym_table_count in range(0, nsyms):
                    nlist = struct.unpack('=IBBHQ', self.sym_table[sym_table_count*NLIST_SIZE_64:(sym_table_count*NLIST_SIZE_64)+NLIST_SIZE_64])
                    n_un = nlist[0]
                    n_type = nlist[1]
                    n_sect = nlist[2]
                    n_desc = nlist[3]
                    n_value = nlist[4]

                    #if n_type == 15: # 'SECT'
                    symbol_name = self.symbol_str[n_un:n_un+self.symbol_str[n_un:].index('\x00')]
                    self.symbol_diclist[symbol_name] = n_value
                    #print 'symbol_name: %s, address: %x'%(symbol_name, n_value)
                break
                
            i += cmd[1] # index + load_command.cmd_size
            if i >= sizeofcmds:
                break

        return self.symbol_diclist

def main():
    macho = macho_an(sys.argv[1])
    arch_count = macho.load()
    #print arch_count
    #header = macho.get_header(arch_count, ARCH_I386) # only support Intel x86
    #symbol_list = macho.macho_getsymbol_x86(header[2], header[3])
    #print '%x'%symbol_list['_IdlePDPT']

    header = macho.get_header(arch_count, ARCH_X86_64) # 64bit symbol
    #print 'offset: %x, size: %x'%(header[2], header[3])
    symbol_list = macho.macho_getsymbol_x64(header[2], header[3])
    print '%x'%symbol_list['_IdlePDPT']
    macho.close()

if __name__ == "__main__":
    main()
