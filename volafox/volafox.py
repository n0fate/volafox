# -*- coding: utf-8 -*-
#  -*- mode: python; -*-

BUILD = "1.0"	# LSOF: global to track research builds

'''

_______________________SUPPORT_________________________
      OSX: Lion (10.7.x), Snow Leopard (10.6.x)
	 Arch: i386, x86_64
	Image: *.vmem (VMware), *.mmr (flattened, x86 ONLY)
'''

# volafox
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
import binascii
import pickle # added by CL
import os

# LSOF: most research functionality consolidated here
from plugins.lsof import getfilelist, printfilelist
from plugins.imageinfo import get_imageinfo # user defined class > CL
from plugins.system_profiler import get_system_profile
from plugins.ps import get_proc_list, get_proc_dump
from plugins.kextstat import get_kext_list, kext_dump, print_kext_list
from plugins.systab import get_system_call_table_list, print_syscall_table
from plugins.mach_trap import get_mach_trap_table_list, print_mach_trap_table
from plugins.mount import get_mount_list, print_mount_list
from plugins.netstat import get_network_hash, print_network_list, get_network_list
from plugins.pe_state import get_pe_state, print_pe_state, get_boot_args, print_boot_args
from plugins.efiinfo import get_efi_system_table, print_efi_system_table, get_efi_runtime_services, print_efi_runtime_services
from vatopa.machaddrspace import MachoAddressSpace, isMachoVolafoxCompatible, is_universal_binary

from vatopa.x86 import *
from vatopa.ia32_pml4 import * # user-defined class -> n0fate

###############################################################################
#
# Class: volafox() - 2010-09-30 ~ now
# Description: This analysis module can support Intel Architecture
#
#
###############################################################################
class volafox():
    def __init__(self, mempath):
        self.mempath = mempath
        self.arch = 32 # default value is 32bit
        self.data_list = []
        self.os_version = 0
        self.build = ''# psdump -> cr3
	self.symbol_list = []# symbol list

    def get_read_address(self, address):
	print '%x'%self.x86_mem_pae.vtop(address)
	return
    
    def overlay_loader(self, overlay_path, vflag):
	try:
	    if vflag:
		print '[+] Open overlay file \'%s\''%overlay_path
	    overlay_file = open(overlay_path, 'rb')
	    self.symbol_list = pickle.load(overlay_file)
	    overlay_file.close()
	    return 0
	except IOError:
	    print '[+] WARNING: volafox can\'t open \'%s\''%overlay_path
	    print '[+] WARNING: You can create overlay file running \'overlay_generator.py\''
	    return 1
    
    def get_kernel_version(self, vflag):
	ret_data = get_imageinfo(self.mempath, vflag)
	self.arch = ret_data[1]
	self.build = ret_data[2]
	self.os_version = ret_data[3]
	
	## open overlay file
	return 'overlays/%sx%d.overlay'%(self.build, self.arch)
    
    def init_vatopa_x86_pae(self, vflag): # 11.11.23 64bit suppport
        if self.mempath == '':
            return 1

        self.idlepdpt = self.symbol_list['_IdlePDPT']
        self.idlepml4 = self.symbol_list['_IdlePML4']
        
        if self.arch is 32:
            if vflag:
                print '[+] Loading Intel 32bit(PAE Enabled) Paging Table'
            if isMachoVolafoxCompatible(self.mempath):
                self.x86_mem_pae = IA32PagedMemoryPae(MachoAddressSpace(self.mempath), self.idlepdpt)
            else:
                self.x86_mem_pae = IA32PagedMemoryPae(FileAddressSpace(self.mempath), self.idlepdpt)
        else: # 64
            if vflag:
                print '[+] Loading Intel IA-32e(PAE Enabled) Paging Table'
            if isMachoVolafoxCompatible(self.mempath):
                self.x86_mem_pae = IA32PML4MemoryPae(MachoAddressSpace(self.mempath), self.idlepml4)
            else:
                self.x86_mem_pae = IA32PML4MemoryPae(FileAddressSpace(self.mempath), self.idlepml4)
        return 0


    def get_system_profiler(self): # 11.11.23 64bit suppport
	
	os_version = self.symbol_list['_osversion']
	machine_info = self.symbol_list['_machine_info']
	try:
	    boottime = self.symbol_list['_clock_boottime']
	except KeyError:
	    boottime = 0
	sleeptime = self.symbol_list['_gIOLastSleepTime']
	waketime = self.symbol_list['_gIOLastWakeTime']
        get_system_profile(self.x86_mem_pae, os_version, machine_info, boottime, sleeptime, waketime)
	
	return
	#return data

    def kextstat(self): # 11.11.23 64bit suppport
        sym_addr = self.symbol_list['_kmod']
	sym_addr2 = self.symbol_list['_g_kernel_kmod_info']
        kext_list = get_kext_list(self.x86_mem_pae, sym_addr, sym_addr2, self.arch, self.os_version, self.build)
	print_kext_list(kext_list)

    def kextdump(self, KID):
        sym_addr = self.symbol_list['_kmod']
        sym_addr2 = self.symbol_list['_g_kernel_kmod_info']
        kext_dump(self.x86_mem_pae, sym_addr, sym_addr2, self.arch, self.os_version, self.build, KID)
    
    def mount(self): # 11.11.23 64bit suppport(Lion)
        sym_addr = self.symbol_list['_mountlist']
        mount_list = get_mount_list(self.x86_mem_pae, sym_addr, self.arch, self.os_version, self.build)
        print_mount_list(mount_list)

    def get_ps(self): # 11.11.23 64bit suppport
        sym_addr = self.symbol_list['_kernproc']
        get_proc_list(self.x86_mem_pae, sym_addr, self.arch, self.os_version, self.build)


    # LSOF: new lsof module (stub)
    def lsof(self, pid, vflag):
	sym_addr = self.symbol_list['_kernproc']
	if self.arch == 32:
	    # read 4 bytes from kernel executable or overlay starting at symbol _kernproc
	    kernproc = self.x86_mem_pae.read(sym_addr, 4);

	    # unpack pointer to the process list, only need the first member returned
	    proc_head = struct.unpack('I', kernproc)[0]
	
	else: # 64-bit
	    kernproc = self.x86_mem_pae.read(sym_addr, 8);
	    proc_head = struct.unpack('Q', kernproc)[0]
	
	printfilelist(getfilelist(self.x86_mem_pae, self.arch, self.os_version, proc_head, pid, vflag))

    def systab(self): # 11.11.23 64bit suppport
        sym_addr = self.symbol_list['_nsysent']
        syscall_list = get_system_call_table_list(self.x86_mem_pae, sym_addr, self.arch, self.os_version, self.build)
        print_syscall_table(syscall_list, self.symbol_list)

    def mtt(self):
        mtt_ptr = self.symbol_list['_mach_trap_table']
	mtt_count = self.symbol_list['_mach_trap_count']
	print mtt_ptr, mtt_count
        mtt_list = get_mach_trap_table_list(self.x86_mem_pae, mtt_ptr, mtt_count, self.arch, self.os_version, self.build)
        print_mach_trap_table(mtt_list, self.symbol_list, self.os_version)

    def proc_dump(self, pid, fflag):
        sym_addr = self.symbol_list['_kernproc']
        
        dump_param = get_proc_dump(self.x86_mem_pae, sym_addr, self.arch, self.os_version, self.build, pid, fflag)
        
        pm_cr3 = dump_param[0]
        vm_list = dump_param[1]
        process_name = dump_param[2]
        
        proc_pae = 0
        
        print '[+] Resetting the Page Mapping Table: 0x%x'%pm_cr3
        
        if isMachoVolafoxCompatible(self.mempath):
            proc_pae = IA32PML4MemoryPae(MachoAddressSpace(self.mempath), pm_cr3)
        else:
            proc_pae = IA32PML4MemoryPae(FileAddressSpace(self.mempath), pm_cr3)
        
        print '[+] Process Dump Start'
        
        for vme_info in  vm_list:
            #print vme_info[0]
            #print vme_info[1]
            
            nop_code = 0x00 # 11.10.11 n0fate test
            pk_nop_code = struct.pack('=B', nop_code) # 11.10.11 n0fate test
            nop = pk_nop_code*0x1000
            
            file = open('%s-%x-%x'%(process_name, vme_info[0], vme_info[1]), mode="wb")
            
            nop_flag = 0 # 11.10.11 n0fate test
            for i in range(vme_info[0], vme_info[1], 0x1000):
                raw_data = 0x00
                if not(proc_pae.is_valid_address(i)):
                    if nop_flag == 1:
                        raw_data = nop
                        file.write(raw_data)
                    continue
                raw_data = proc_pae.read(i, 0x1000)
                if raw_data is None:
                    if nop_flag == 1:
                        raw_data = nop
                        file.write(raw_data)
                    continue
                file.write(raw_data)
                nop_flag = 1
            file.close()
            size = os.path.getsize('%s-%x-%x'%(process_name, vme_info[0], vme_info[1]))
            if size == 0:
               os.remove('%s-%x-%x'%(process_name, vme_info[0], vme_info[1]))
            else:
                print ' [-] [DUMP] Image Name: %s-%x-%x'%(process_name, vme_info[0], vme_info[1])
        print '[+] Process Dump End'
        return
	
    # 2011.08.08
    # network information (inpcbinfo.hashbase, test code)
    # it can dump real network information. if rootkit has hiding technique.
    #################################################
    def netstat(self):
        tcb_symbol_addr = self.symbol_list['_tcbinfo']
        udb_symbol_addr = self.symbol_list['_udbinfo']
        
        if isMachoVolafoxCompatible(self.mempath):
            net_pae = IA32PML4MemoryPae(MachoAddressSpace(self.mempath), self.idlepml4) 
        else:
            net_pae = IA32PML4MemoryPae(FileAddressSpace(self.mempath), self.idlepml4)
        network_list = get_network_hash(net_pae, tcb_symbol_addr, udb_symbol_addr, self.arch, self.os_version, self.build)
        print_network_list(network_list[0], network_list[1])

    # 2011.08.30 test code(plist chain)
    #################################################
    def netstat_test(self):
        tcb_symbol_addr = self.symbol_list['_tcbinfo']
        udb_symbol_addr = self.symbol_list['_udbinfo']
	
        if isMachoVolafoxCompatible(self.mempath):
            net_pae = IA32PML4MemoryPae(MachoAddressSpace(self.mempath), self.idlepml4)
        else:
            net_pae = IA32PML4MemoryPae(FileAddressSpace(self.mempath), self.idlepml4)
        
        network_list = get_network_list(net_pae, tcb_symbol_addr, udb_symbol_addr, self.arch, self.os_version, self.build)
        print_network_list(network_list[0], network_list[1])

    # 2012.06.22 test code(EFI Runtime & SystemTable Analysis)
    #################################################
    def pe_state(self):
        pe_state_symbol_addr = self.symbol_list['_PE_state']
        #print '0x%.8x'%self.x86_mem_pae.vtop(pe_state_symbol_addr)
        pe_state_info = get_pe_state(self.x86_mem_pae, pe_state_symbol_addr, self.arch, self.os_version, self.build)
        print_pe_state(pe_state_info, self.arch, self.os_version, self.build)
        
        boot_args_ptr = pe_state_info[13]
        
        #print '0x%.8x'%self.x86_mem_pae.vtop(boot_args_ptr)
        
        boot_args_info = get_boot_args(self.x86_mem_pae, boot_args_ptr, self.arch, self.os_version, self.build)
        print_boot_args(boot_args_info, self.arch, self.os_version, self.build)
    
    def efi_system_table(self):
        efi_system_symbol_addr = self.symbol_list['_gPEEFISystemTable']
        #print '0x%.8x'%self.x86_mem_pae.vtop(efi_system_symbol_addr)
        efi_system_table_info, configuration_table = get_efi_system_table(self.x86_mem_pae, efi_system_symbol_addr, self.arch, self.os_version, self.build)
        print_efi_system_table(efi_system_table_info, configuration_table, self.arch, self.os_version, self.build)

        efi_runtime_symbol_addr = self.symbol_list['_gPEEFIRuntimeServices']
        efi_runtime_info = get_efi_runtime_services(self.x86_mem_pae, efi_runtime_symbol_addr, self.arch, self.os_version, self.build)
        print_efi_runtime_services(efi_runtime_info, self.arch, self.os_version, self.build)
        