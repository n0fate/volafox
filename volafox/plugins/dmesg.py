import sys
import struct


# 2013.04.05 test
######################################
class dmesg:
    def __init__(self, x86_mem_pae, arch, os_version, build, base_address):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.os_version = os_version
        self.build = build
        self.base_address = base_address
    
    def getdmesg(self, sym_addr):
        if not(self.x86_mem_pae.is_valid_address(sym_addr+self.base_address)):
            return 1
        
        dmesg_str = ''
        
        bufcount = 0
        while 1:
            buf_raw = self.x86_mem_pae.read(sym_addr+self.base_address+bufcount, 1024)
            buf = struct.unpack('=1024s', buf_raw)[0]
            #print buf
            dmesg_str = dmesg_str + buf
            if buf[-1] == '\x00':
                break
            bufcount = bufcount + 1024
            
        return dmesg_str.replace('\x00','')

def get_dmesg(x86_mem_pae, sym_addr, arch, os_version, build, base_address):
    DMESGCLASS = dmesg(x86_mem_pae, arch, os_version, build, base_address)
    dmesg_str = DMESGCLASS.getdmesg(sym_addr)
    return dmesg_str