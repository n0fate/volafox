# -*- coding: utf-8 -*-
import sys
import struct
import time
import binascii
from ps import process_manager, proc_print

from volafox.vatopa.addrspace import FileAddressSpace
from volafox.vatopa.ia32_pml4 import IA32PML4MemoryPae

from tableprint import columnprint


class bash_history:
	def __init__(self, x86_mem_pae, arch, os_version, build, base_address):
		self.x86_mem_pae = x86_mem_pae
		self.arch = arch
		self.os_version = os_version
		self.build = build
		self.base_address = base_address
		self.processmanager = process_manager(self.x86_mem_pae, self.arch, self.os_version, self.build, self.base_address)
	
	def search_for_history_in_task_memory(self, malloc_tiny_list, pm_cr3, mempath):
		proc_pae = IA32PML4MemoryPae(FileAddressSpace(mempath), pm_cr3)
		
		history_list = []
		
		ptr_size = 8
		unpack_int = '=QQ'
		
		#print ''
		
		for vm_address in malloc_tiny_list:
			#print '[*] Search for keys in range 0x%.8x-0x%.8x'%(vm_address[0], vm_address[1])
			
			for vm_offset in range(vm_address[0], vm_address[1], ptr_size*2):
				
				if proc_pae.is_valid_address(vm_offset):
					pointer_set = proc_pae.read(vm_offset, ptr_size*2)
					value = struct.unpack(unpack_int, pointer_set)
					
					# brute-force
					# value[0] = line pointer, value[1] = timestamp pointer
					if ((value[0] & value[1]) >= vm_address[0]) and ((value[0] & value[1]) < vm_address[1]):
						#print 'timestamp: %x, line: %x'%(value[1], value[0])
						try:
							csharp = struct.unpack('c', proc_pae.read(value[1], 1))[0]
						except struct.error:
							continue
						if '#' == csharp: # timestamp signature
							#print 'got it'
							# get timestamp
							timebuf = ''
							linebuf = ''
							temp_list = []
							for byte in range(value[1]+1, vm_address[1], 1): # remove singature '#'
								buf = proc_pae.read(byte, 1)
								if struct.unpack('b', buf)[0] == 0:
									break
								timebuf += struct.unpack('c', buf)[0]

							if timebuf != '':
								for byte in range(value[0], vm_address[1], 1):
									buf = proc_pae.read(byte, 1)
									if struct.unpack('b', buf)[0] == 0:
										break
									linebuf += struct.unpack('c', buf)[0]
							temp_list.append(long(timebuf))
							temp_list.append(linebuf)

							history_list.append(temp_list)
			
			#print history_list
		
		return history_list
	
	def search_malloc_tiny_in_vm(self, vm_map_ptr, user_stack_ptr, full_dump_flag):
		retData = self.processmanager.get_proc_region(vm_map_ptr, user_stack_ptr, full_dump_flag)
		vm_list = retData[0]
		vm_struct = retData[1]
		
		malloc_tiny_list = []
		
		#print ''
		#print '[+] Find MALLOC_TINY heap range (guess)'
		
		for vm_address in vm_list:
			if vm_address[0] <= 0x00007f0000000000 or vm_address[1] >= 0x00007fff00000000:
				continue
			elif 0x100000 != (vm_address[1] - vm_address[0]):
				continue
			#print ' [-] range 0x%.8x-0x%.8x'%(vm_address[0], vm_address[1])
			malloc_tiny_list.append(vm_address)
		
		pm_cr3 = self.processmanager.get_proc_cr3(vm_list, vm_struct)
		
		return malloc_tiny_list, pm_cr3
	
	def search_bash_process(self, sym_addr):
		proclist = []
		ret = self.processmanager.get_proc_list(sym_addr, proclist, -1)
		if ret == 1:
			return 1

		task_list = []
		for proc in proclist:
			if proc[14] == 'bash':
				task_struct = self.processmanager.get_task(proc, proc[2])
				basic_struct = [proc[1]]
				basic_struct.append(proc[14])
				basic_struct.append(task_struct)
				task_list.append(basic_struct)
		return task_list


################## PUBLIC FUNCTION ###################################

def dump_bash_history(x86_mem_pae, sym_addr, arch, os_version, build, base_address, mempath):
	bash = bash_history(x86_mem_pae, arch, os_version, build, base_address)
	if bash.build[0:2] < 13:
		print 'bash_history is compatible on more than Mac OS X Mavericks(13.0)'
		return 1

	bash_history_list = []
	task_list = bash.search_bash_process(sym_addr)

	for task in task_list:
		malloc_tiny_list, pm_cr3 = bash.search_malloc_tiny_in_vm(task[2][3], 0, 0) # task structure
		history_list = bash.search_for_history_in_task_memory(malloc_tiny_list, pm_cr3, mempath)
		history_info = [task[0]]
		history_info.append(task[1])
		history_info.append(history_list)
		print '[+] PID : %d, PROCESS: %s, HISTORY COUNT: %d'%(task[0], task[1], len(history_list))
		bash_history_list.append(history_info)
	
	return bash_history_list
	
def print_bash_history(bash_history_list):

	headerlist = ["PID", "PROCESS", "TIME (UTC+0)", "CMD"]
	contentlist = []

	for bash_history in bash_history_list:
		if len(bash_history_list) == 0:
			print '[*] Can not found bash history'
			return

		for history in bash_history[2]:
			line = ['%s'%bash_history[0]] # count
			line.append(bash_history[1])
			line.append('%s'%time.strftime("%a %b %d %H:%M:%S %Y", time.gmtime(history[0])))
			line.append('%s'%history[1])
			contentlist.append(line)
		# use optional max size list here to match default lsof output, otherwise specify
		# lsof +c 0 on the command line to print full name of commands
	mszlist = [-1, -1, -1, -1]
	columnprint(headerlist, contentlist, mszlist)
# EOF