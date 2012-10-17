# -*- coding: utf-8 -*-
import sys
import struct
import binascii
from ps import process_manager, proc_print

from volafox.vatopa.addrspace import FileAddressSpace
from volafox.vatopa.ia32_pml4 import IA32PML4MemoryPae

KEY_SIZE = 24


class keychaindump:
	def __init__(self, x86_mem_pae, arch, os_version, build, base_address):
		self.x86_mem_pae = x86_mem_pae
		self.arch = arch
		self.os_version = os_version
		self.build = build
		self.base_address = base_address
		self.processmanager = process_manager(self.x86_mem_pae, self.arch, self.os_version, self.build, self.base_address)
	
	def search_for_keys_in_task_memory(self, malloc_tiny_list, pm_cr3, mempath):
		proc_pae = IA32PML4MemoryPae(FileAddressSpace(mempath), pm_cr3)
		
		candidate_key_list = []
		
		ptr_size = 0
		unpack_int = ''
		
		if self.arch == 32:
			ptr_size = 4
			unpack_int = '=I'
		elif self.arch == 64:
			ptr_size = 8
			unpack_int = '=Q'
		else:
			ptr_size = 4
			unpack_int = '=I'
		
		print ''
		
		for vm_address in malloc_tiny_list:
			print '[*] Search for keys in range 0x%.8x-0x%.8x'%(vm_address[0], vm_address[1]),
			
			for vm_offset in range(vm_address[0], vm_address[1], ptr_size):
				
				if proc_pae.is_valid_address(vm_offset):
					signature = proc_pae.read(vm_offset, ptr_size)
					
					if 0x18 == struct.unpack(unpack_int, signature)[0]: # find specific hex code(0x00000018)
						#print signature.encode('hex')
						key_buf = proc_pae.read(vm_offset+ptr_size, ptr_size)
						key_buf_ptr = struct.unpack(unpack_int, key_buf)[0]
						
						if key_buf_ptr >= vm_address[0] and key_buf_ptr <= vm_address[1]: # check vma between vm.start and vm.stop
							candidate_key = proc_pae.read(key_buf_ptr, KEY_SIZE)
							candidate_key_list.append(candidate_key) # append to candidate key list
			
			print 'complete. master key candidates : %d'%len(candidate_key_list)
		
		return candidate_key_list
							
				
		
	
	def search_for_keys_in_vm(self, vm_map_ptr, user_stack_ptr, full_dump_flag):
		retData = self.processmanager.get_proc_region(vm_map_ptr, user_stack_ptr, full_dump_flag)
		vm_list = retData[0]
		vm_struct = retData[1]
		
		malloc_tiny_list = []
		
		print ''
		print '[+] Find MALLOC_TINY heap range (guess)'
		
		for vm_address in vm_list:
			if vm_address[0] <= 0x00007f0000000000 or vm_address[1] >= 0x00007fff00000000:
				continue
			elif 0x100000 != (vm_address[1] - vm_address[0]):
				continue
			print ' [-] range 0x%.8x-0x%.8x'%(vm_address[0], vm_address[1])
			malloc_tiny_list.append(vm_address)
		
		pm_cr3 = self.processmanager.get_proc_cr3(vm_list, vm_struct)
		
		return malloc_tiny_list, pm_cr3
	
	def search_for_keys_in_process(self, sym_addr):
	    proclist = []
	    ret = self.processmanager.get_proc(sym_addr, proclist, -1)
	    if ret == 1:
		return 1
	    
	    for proc in proclist:
		if proc[12] == 'securityd':
			securityd_proc = proc
			break
	    
	    if securityd_proc[12] != 'securityd':
		    return 1
	
	    task_struct = self.processmanager.get_task(securityd_proc, securityd_proc[2])
	    
	    return task_struct


################## PUBLIC FUNCTION ###################################

def dump_master_key(x86_mem_pae, sym_addr, arch, os_version, build, base_address, mempath):
	dump_key = keychaindump(x86_mem_pae, arch, os_version, build, base_address)
	if dump_key.build[0:2] < 11:
		print 'keychaindump is compatible on more than Mac OS X Lion(12.0)'
		return 1
	task_struct = dump_key.search_for_keys_in_process(sym_addr)
	
	malloc_tiny_list, pm_cr3 = dump_key.search_for_keys_in_vm(task_struct[3], 0, 0)
	
	candidate_key_list = dump_key.search_for_keys_in_task_memory(malloc_tiny_list, pm_cr3, mempath)
	
	return candidate_key_list
	
def print_master_key(candidate_key_list):
	print ''
	
	if len(candidate_key_list) == 0:
		print '[*] Can not found master key candidates'
		return
	
	for candidate_key in candidate_key_list:
		key = ''
		for i in range(24):
			key += '%02X'%ord(candidate_key[i])
		print '[*] master key candidate: %s'%key