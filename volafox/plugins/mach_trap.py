import sys
import struct

from tableprint import columnprint

# SN 32bit, SN 64bit, LION 32bit, LION 64bit
DATA_MACH_TRAP_TABLE_STRUCTURE = [[16, '=IIII'], [40, '=QQQQQ'], [8, '=II'], [16, '=QQ']]


class Mach_Trap_Table():
    def __init__(self, x86_mem_pae, arch, os_version, base_address):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.osversion = os_version
        self.base_address = base_address
    
    def get_mach_trap_table_count(self, table_count):
        
        mtt_count = 0
        ncount = self.x86_mem_pae.read(table_count + self.base_address, 4)
        mtt_count = struct.unpack('=I', ncount)[0]
        return mtt_count
    
    def get_mach_trap_table(self, table_ptr, table_count):
        mach_trap_table_list = []
        if self.arch == 32:
            if self.osversion == 10:
                MACH_TRAP_TABLE = DATA_MACH_TRAP_TABLE_STRUCTURE[0]
            else:
                MACH_TRAP_TABLE = DATA_MACH_TRAP_TABLE_STRUCTURE[2]
        else:
            if self.osversion == 10:
                MACH_TRAP_TABLE = DATA_MACH_TRAP_TABLE_STRUCTURE[1]
            else:
                MACH_TRAP_TABLE = DATA_MACH_TRAP_TABLE_STRUCTURE[3]
            
        for count in range(0, table_count):
            mtt_buf = self.x86_mem_pae.read(table_ptr + (count*MACH_TRAP_TABLE[0]) + self.base_address, MACH_TRAP_TABLE[0])
            mtt_buf_parse = struct.unpack(MACH_TRAP_TABLE[1], mtt_buf)

            mach_trap_table_list.append(mtt_buf_parse)
    
        return mach_trap_table_list

#################################### PUBLIC FUNCTIONS ####################################

def print_mach_trap_table(data_list, symbol_list, os_version, base_address):
    sym_name_list = symbol_list.keys()
    sym_addr_list = symbol_list.values()
    if os_version == 10:
        print '[+] Mach Trap Table'
        headerlist = ["NUM","ARG_COUNT", "CALL_NAME", "CALL_PTR", "ARG_MUNGE32_PTR", "ARG_MUNGE64_PTR", "HOOK_FINDER"]
        contentlist = []
        
        count = 0
        for data in data_list:
            symflag = 0
            line = ['%d'%count]
            line.append('%d'%data[0])
            i = 0
            for sym_addr in sym_addr_list:
                if data[1] == sym_addr:
                    line.append('%s'%sym_name_list[i])
                    symflag = 1
                    break
                i += 1
            if symflag != 1:
                line.append('0x%.8X'%data[1])
            
            line.append('0x%.8X'%data[1])
            line.append('0x%.8X'%data[2])
            line.append('0x%.8X'%data[3])
            if symflag == 1:
                line.append('True')
            else:
                line.append('Maybe hooked')
            count -= 1
            contentlist.append(line)
    
        mszlist = [-1, -1, -1, -1, -1, -1, -1]
        columnprint(headerlist, contentlist, mszlist) 

    else:
        print '[+] Mach Trap Table'
        headerlist = ["NUM","ARG_COUNT", "CALL_NAME", "CALL_PTR", "HOOK_FINDER"]
        contentlist = []
        
        count = 0
        for data in data_list:
            symflag = 0
            line = ['%d'%count]
            line.append('%d'%data[0])
            i = 0
            for sym_addr in sym_addr_list:
                if data[1] == sym_addr + base_address:
                    line.append('%s'%sym_name_list[i])
                    symflag = 1
                    break
                i += 1
            if symflag != 1:
                line.append('0x%.8X'%data[1])
            
            line.append('0x%.8X'%data[1])
            if symflag == 1:
                line.append('True')
            else:
                line.append('Maybe hooked')
            count -= 1
            contentlist.append(line)
    
        mszlist = [-1, -1, -1, -1, -1]
        columnprint(headerlist, contentlist, mszlist) 

def get_mach_trap_table_list(x86_mem_pae, mtt_ptr, mtt_count, arch, os_version, build, base_address):
    MTT = Mach_Trap_Table(x86_mem_pae, arch, os_version, base_address)
    ncount = MTT.get_mach_trap_table_count(mtt_count)
    mach_trap_table_list = MTT.get_mach_trap_table(mtt_ptr, ncount)
    return mach_trap_table_list
