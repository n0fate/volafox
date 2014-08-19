# Copyright by n0fate
# License : GPLv2

# Main Idea : Back to the 'root' of Incident Response, FIRST 2014, Boston
# This plugin is only available to 64bit kernel

import systab
from tableprint import columnprint

# check assemble code
### FBT disable ###
# 55        PUSH  RBP
# 48 89 E5  MOV   RBP, RSP
FBT_DISABLE = '554889E5'
##################
### FBT enable ###
# PUSH  RBP
# MOV   EBP, ESP
FBT_ENABLE = '558BEC'
##################

CHECK_FBT_SIZE = 4


class FBT():
    def __init__(self, x86_mem_pae, arch, base_address):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.base_address = base_address

    def checkfbt(self, funcaddr):
        buf = self.x86_mem_pae.read(funcaddr, CHECK_FBT_SIZE)
        if FBT_ENABLE.decode('hex') == buf:
            #print Decode(funcaddr, buf, Decode64Bits)
            return 1
        return 0


def print_fbt_syscall(data_list, symbol_list, base_address):
    if len(data_list) == 0:
        print 'No FBT Hook Function'
        return

    contentlist = []
    headerlist = ["NUM","ARG_COUNT", "NAME", "CALL_PTR", "ARG_MUNGE32_PTR", "ARG_MUNGE64_PTR", "RET_TYPE", "ARG_BYTES", "FBT HOOK"]

    sym_name_list = symbol_list.keys()
    sym_addr_list = symbol_list.values()

    count = 0
    for data in data_list:
        symflag = 0
        line = ['%d'%count]
        line.append('%d'%data[0])
        i = 0
        for sym_addr in sym_addr_list:
            if data[1] == sym_addr+base_address:
                line.append('%s'%sym_name_list[i])
                symflag = 1
            i += 1
        if symflag != 1:
            line.append('0x%.8X'%data[1])
        line.append('0x%.8X'%data[1])
        line.append('0x%.8X'%data[2])
        line.append('0x%.8X'%data[3])
        line.append('%d'%data[4])
        line.append('%d'%data[5])
        line.append('O')
        count += 1
        contentlist.append(line)

    mszlist = [-1, -1, -1, -1, -1, -1, -1, -1, -1]
    columnprint(headerlist, contentlist, mszlist)


def check_fbt_syscall(x86_mem_pae, sym_addr, arch, os_version, build, base_address):
    syscall_list = systab.get_system_call_table_list(x86_mem_pae, sym_addr, arch, os_version, build, base_address)
    #print syscall_list # argcount, call pointer

    fbt_list = []
    fbt = FBT(x86_mem_pae, arch, base_address)
    for syscall in syscall_list:
        #print u'{0:x}'.format(syscall[1])
        isFBT = fbt.checkfbt(syscall[1])   # address
        if isFBT:
            fbt_list.append(syscall)

    return fbt_list


