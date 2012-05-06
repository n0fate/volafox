import sys
import struct

from tableprint import columnprint

# SN/Lion 32bit, SN/Lion 64bit
DATA_SYSCALL_TABLE_STRUCTURE = [24, '=hbbIIIII', 40, '=hbbQQQII']


class systab_manager():
    def __init__(self, x86_mem_pae, arch):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch

    def get_syscall_table(self, sym_addr): # 11.11.23 64bit suppport
        syscall_list = []
        if self.arch == 32:
            nsysent = self.x86_mem_pae.read(sym_addr, 4) # .data _nsysent
            data = struct.unpack('I', nsysent) # uint32
    
            sysentaddr = sym_addr - (data[0] * 24) # sysent structure size + 2bytes
    
            for count in range(0, data[0]):
                sysent = self.x86_mem_pae.read(sysentaddr + (count*24), 24); # .data _nsysent
                data = struct.unpack('hbbIIIII', sysent) # uint32
    
                syscall_list.append(data)
        else:
            nsysent = self.x86_mem_pae.read(sym_addr, 8) # .data _nsysent
            data = struct.unpack('Q', nsysent)
    
            sysentaddr = sym_addr - (data[0] * 40) # sysent structure size
    
            for count in range(0, data[0]):
                sysent = self.x86_mem_pae.read(sysentaddr + (count*40), 40); # .data _nsysent
                data = struct.unpack('hbbQQQII', sysent) # uint32
    
                syscall_list.append(data)
    
        return syscall_list

#################################### PUBLIC FUNCTIONS ####################################

def print_syscall_table(data_list, symbol_list):
    #data_list = m_volafox.systab(symbol_list['_nsysent'])
    sym_name_list = symbol_list.keys()
    sym_addr_list = symbol_list.values()
    print '[+] Syscall List'
    headerlist = ["NUM","ARG_COUNT", "RESV", "FLAGS", "CALL_PTR", "ARG_MUNGE32_PTR", "ARG_MUNGE64_PTR", "RET_TYPE", "ARG_BYTES", "HOOK_FINDER"]
    #print 'number\tsy_narg\tsy_resv\tsy_flags\tsy_call_ptr\tsy_arg_munge32_ptr\tsy_arg_munge64_ptr\tsy_ret_type\tsy_arg_bytes\tValid Function Address'
    contentlist = []
    
    count = 0
    for data in data_list:
        symflag = 0
        line = ['%d'%count]
        line.append('%d'%data[0])
        line.append('%d'%data[1])
        line.append('%d'%data[2])
        i = 0
        for sym_addr in sym_addr_list:
            if data[3] == sym_addr:
                line.append('%s'%sym_name_list[i])
                symflag = 1
            i += 1
        if symflag != 1:
            line.append('0x%.8X'%data[3])
        line.append('0x%.8X'%data[4])
        line.append('0x%.8X'%data[5])
        line.append('%d'%data[6])
        line.append('%d'%data[7])
        if symflag == 1:
            line.append('VALID SYSCALL')
        else:
            line.append('SYSCALL HOOKING')
        count += 1
        contentlist.append(line)

    mszlist = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1]
    columnprint(headerlist, contentlist, mszlist) 

def get_system_call_table_list(x86_mem_pae, sym_addr, arch, os_version, build):
    SYSCALLMan = systab_manager(x86_mem_pae, arch)
    syscall_list = SYSCALLMan.get_syscall_table(sym_addr)
    return syscall_list
