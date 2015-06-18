import sys
import struct

from tableprint import columnprint

# 32bit, 64bit
Pointer_Structure = [[4, '=I'], [8, '=Q']]


class notifier():
    def __init__(self, x86_mem_pae, arch, build, base_address):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.build = build
        self.base_address = base_address

    def get_notifier_table(self, sym_addr): # 11.11.23 64bit suppport
        notifier_list = []
        if self.arch == 32:
            Pointer = Pointer_Structure[0]
        elif self.arch == 64:
            Pointer = Pointer_Structure[1]

        offset = 0
        while 1:
            if not(self.x86_mem_pae.is_valid_address(sym_addr+self.base_address + (offset*Pointer[0]))):
                break
            func_ptr = self.x86_mem_pae.read(sym_addr + self.base_address + (offset*Pointer[0]), Pointer[0])
            func_address = struct.unpack(Pointer[1], func_ptr)[0]

            if func_address == 0:
                break

            notifier_list.append(func_address)

            offset = offset + 1
    
        return notifier_list

#################################### PUBLIC FUNCTIONS ####################################

def print_notifier_list(data_list, symbol_list, base_address, NotifierName):
    sym_name_list = symbol_list.keys()
    sym_addr_list = symbol_list.values()
    
    print '%s Method Total Count : %d'%(NotifierName, len(data_list))
    print '--------------------------------------------------------------------------------'
    headerlist = ["NUM", "NAME", "CALL_PTR", "HOOK_FINDER"]

    contentlist = []
    
    count = 0
    for data in data_list:
        symflag = 0
        line = ['%d'%count]
        i = 0
        for sym_addr in sym_addr_list:
            if data == sym_addr+base_address:
                line.append('%s'%sym_name_list[i])
                symflag = 1
            i += 1
        if symflag != 1:
            line.append('0x%.8X'%data)
        line.append('0x%.8X'%data)
        if symflag == 1:
            line.append('True')
        else:
            line.append('Maybe hooked')
        count += 1
        contentlist.append(line)

    mszlist = [-1, -1, -1, -1]
    columnprint(headerlist, contentlist, mszlist) 
    print ''

def get_notifier_table(x86_mem_pae, sym_addr, arch, os_version, build, base_address):
    notifierclass = notifier(x86_mem_pae, arch, build, base_address)
    notifier_list = notifierclass.get_notifier_table(sym_addr+0x10)
    return notifier_list
