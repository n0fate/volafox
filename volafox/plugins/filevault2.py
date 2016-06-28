# -*- coding: utf-8 -*-

"""
@mainauthor:       Thomas White
@license:      GNU General Public License 2.0
@contact:      thomas@tribalchicken.com.au
@organization:
"""

# mainsourcecode:   https://github.com/tribalchicken/volatility-filevault2/blob/master/plugins/mac/filevault2.py
# modified for volafox by n0fate

import struct
from ps import process_manager

from volafox.vatopa.addrspace import FileAddressSpace
from volafox.vatopa.ia32_pml4 import IA32PML4MemoryPae

class FileVault2:
    def __init__(self, x86_mem_pae, arch, os_version, build, base_address, nprocs):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.os_version = os_version
        self.build = build
        self.base_address = base_address
        self.processmanager = process_manager(self.x86_mem_pae, self.arch, self.os_version, self.build, self.base_address, nprocs)

        self.candidate_key_list = []

    def search_for_keys_in_task_memory(self, vmaddr, pm_cr3, mempath):
        proc_pae = IA32PML4MemoryPae(FileAddressSpace(mempath), pm_cr3)

        print '[*] Search for keys in range 0x%.8x-0x%.8x'%(vmaddr[0], vmaddr[1])

        if proc_pae.is_valid_address(vmaddr[0]):
            fvVer = struct.unpack('=I', proc_pae.read(vmaddr[0], 4))[0] # maybe 2
            keylen = struct.unpack('=I', proc_pae.read(vmaddr[0]+4, 4))[0] # maybe 0x10
            if not keylen == 0x10:
                return
            
            Key = struct.unpack('=16s', proc_pae.read(vmaddr[0]+8, keylen))[0] # maybe 0x10

            Vmk1 = proc_pae.read(vmaddr[0]+0x90, 16)
            Vmk2 = proc_pae.read(vmaddr[0]+0x430+0x90, 16)

            if not Key or Key != Vmk1[:keylen]:
                return
            if Vmk1 == Vmk2:
                self.candidate_key_list.append(proc_pae.read(vmaddr[0]+0x90, 16*11))

    def search_for_keys_in_vm(self, vm_map_ptr, user_stack_ptr, full_dump_flag, mempath):
        retData = self.processmanager.get_proc_region(vm_map_ptr, user_stack_ptr, full_dump_flag)

        vm_list = retData[0]
        vm_struct = retData[1]

        pm_cr3 = self.processmanager.get_proc_cr3(vm_list, vm_struct)

        for count in xrange(len(vm_list)):#vm_address in vm_list:
            if not str(vm_list[count][2]) == 'r--':
                continue
            #print '%x'%vm_list[count][0]
            self.search_for_keys_in_task_memory(vm_list[count], pm_cr3, mempath)

        print '[*] Complete. Filevault Master Key : %d'%len(self.candidate_key_list)

        return self.candidate_key_list

    def search_for_keys_in_process(self, sym_addr):
        proclist = []
        ret = self.processmanager.get_proc_list(sym_addr, proclist, -1)
        if not len(proclist):
            return 1

        for proc in proclist:
            if proc[14] == 'kernel_task':
                print '[*] Find the Kernel Task Process'
                task_struct = self.processmanager.get_task(proc, proc[2])
                return task_struct

        return 1


################## PUBLIC FUNCTION ###################################

def dump_filevault_key(x86_mem_pae, sym_addr, arch, os_version, build, base_address, mempath, nprocs):
    DumpFvkey = FileVault2(x86_mem_pae, arch, os_version, build, base_address, nprocs)
    task_struct = DumpFvkey.search_for_keys_in_process(sym_addr)

    candidate_key_list = DumpFvkey.search_for_keys_in_vm(task_struct[3], 0, 0, mempath)

    return candidate_key_list

def print_fvmkey(candidate_key_list):
    if len(candidate_key_list) == 0:
        print '[*] Can not found master key candidates'
        return

    for candidate_key in candidate_key_list:
        key = ''
        for i in range(16):
            try:
                key += '%02X'%ord(candidate_key[i])
            except TypeError:
                pass
        if len(key):
            print '[*] FileVault Master Key : %s'%key
        
        extendedkey = ''
        for i in xrange(11):
            for offset in xrange(16):
                try:
                    extendedkey += '%02X'%ord(candidate_key[i*16+offset])
                except TypeError:
                    pass
            extendedkey += '\n'
        if len(extendedkey):
            print '[*] Extended FileVault Master Key :\n%s'%extendedkey
