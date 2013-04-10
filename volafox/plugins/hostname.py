import sys
import struct


# 2013.04.05 test
######################################
class hostname:
    def __init__(self, x86_mem_pae, arch, os_version, build, base_address):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.os_version = os_version
        self.build = build
        self.base_address = base_address
    
    def gethostnamelength(self, sym_addr):
        if not(self.x86_mem_pae.is_valid_address(sym_addr+self.base_address)):
            return -1
        
        buf_raw = self.x86_mem_pae.read(sym_addr+self.base_address, 4)
        hostnamelength = struct.unpack('=I', buf_raw)[0]
        
        return hostnamelength
        
    def gethostname(self, sym_addr, length):
        if not(self.x86_mem_pae.is_valid_address(sym_addr+self.base_address)):
            return 1
        
        hostname_str = ''
        
        #bufcount = 0
        #while 1:
        buf_raw = self.x86_mem_pae.read(sym_addr+self.base_address, length)
        unpack_argument = '=%ds'%length
        hostname_str = struct.unpack(unpack_argument, buf_raw)[0]
            #print buf
            #hostname_str = hostname_str + buf
            #if buf == '\x00':
            #    break
            #bufcount = bufcount + 1
            
        return hostname_str

def get_hostname(x86_mem_pae, sym_addr, sym_addr_len, arch, os_version, build, base_address):
    HOSTNAMECLASS = hostname(x86_mem_pae, arch, os_version, build, base_address)
    hostnamelen = HOSTNAMECLASS.gethostnamelength(sym_addr_len)
    if hostnamelen == -1:
        return ''
    hostname_str = HOSTNAMECLASS.gethostname(sym_addr, hostnamelen)
    return hostname_str