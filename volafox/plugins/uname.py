import sys
import struct


# 2013.04.05 test
######################################
class uname:
    def __init__(self, x86_mem_pae, arch, os_version, build, base_address):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.os_version = os_version
        self.build = build
        self.base_address = base_address
    
    def getuname(self, sym_addr):
        if not(self.x86_mem_pae.is_valid_address(sym_addr+self.base_address)):
            return 1
        
        uname_str = ''
        
        bufcount = 0
        while 1:
            buf_raw = self.x86_mem_pae.read(sym_addr+self.base_address+bufcount, 1)
            buf = struct.unpack('=1s', buf_raw)[0]
            #print buf
            uname_str = uname_str + buf
            if buf == '\x00':
                break
            bufcount = bufcount + 1
            
        return uname_str

def get_uname(x86_mem_pae, sym_addr, arch, os_version, build, base_address):
    UNAMECLASS = uname(x86_mem_pae, arch, os_version, build, base_address)
    uname_str = UNAMECLASS.getuname(sym_addr)
    return uname_str