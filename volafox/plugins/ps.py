# -*- coding: utf-8 -*-
import sys
import struct
import time
import os

from tableprint import columnprint

from volafox.vatopa.addrspace import FileAddressSpace
from volafox.vatopa.ia32_pml4 import IA32PML4MemoryPae

# Lion 32bit, SN 32bit, Lion64bit, SN 64bit, Mountain Lion 64bit
DATA_PROC_STRUCTURE = [[476+24+168, '=4xIIIII380xQII20xbbbb52sI164xI', 16, '=IIII', 283, '=IIIIIII255s'],
    [476+168, '=4xIIIII356xQII20xbbbb52sI164xI', 16, '=IIII', 283, '=IIIIIII255s'],
    [752+24+268, '=8xQQQQI628xQQQ16xbbbb52sQ264xI', 32, '=QQQQ', 303, '=IQQIQQQ255s'],
    [1028, '=8xQQQQI612xQQQ16xbbbb52sQ264xI', 32, '=QQQQ', 303, '=IQQIQQQ255s'],
    [752+24+276, '=8xQQQQI628xQQQ16xbbbb52sQ272xI', 32, '=QQQQ', 303, '=IQQIQQQ255s']]

# Lion 32bit, SN 32bit, Lion64bit, SN 64bit, Mountain Lion 64bit
DATA_TASK_STRUCTURE = [[32+460+4, '=8xIIIIII460xI'],
    [36+428+4, '=12xIIIIII428xI'],
    [736, '=16xIII4xQQQ672xQ'],
    [712, '=24xIII4xQQQ640xQ'],
    [720, '=16xIII4xQQQ656xQ']]

# Lion 32bit, SN 32bit, Lion64bit, SN 64bit
DATA_VME_STRUCTURE = [[162+12, '=12xIIQQII8x4xIQ16xIII42xIIIIIIIII', 52, '=IIQQ24xI'],
    [162, '=12xIIQQIIIQ16xIII42xIIIIIIIII', 40, '=IIQQ12xI'],
    [194, '=16xQQQQII16xQQ16xIII42xIIIIIIIII', 80, '=QQQQ40xQ'],
    [178, '=16xQQQQIIQQ16xIII42xIIIIIIIII', 56, '=QQQQ16xQ']]

# 11D50, Lion 32bit, SN 32bit, Lion64bit, SN 64bit
DATA_PMAP_STRUCTURE = [[44, '=36xQ'],
    [12, '=4xQ'],
    [100, '=84xQII'],
    [80, '=72xQ'],
    [16, '=8xQ'],
    [152, '=128xQQQ']]

# 32bit, 64bit
DATA_QUEUE_STRUCTURE = [[8, '=II'],
    [16, '=QQ']]

def unsigned8(n):
  return n & 0xFFL

class process_manager:
    def __init__(self, x86_mem_pae, arch, os_version, build, base_address):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.os_version = os_version
        self.build = build
	self.base_address = base_address

    def get_proc(self, proc_sym_addr, PROC_STRUCTURE):
        proc = []
        proclist = self.x86_mem_pae.read(proc_sym_addr, PROC_STRUCTURE[0])
        data = struct.unpack(PROC_STRUCTURE[1], proclist)
        
        pgrp_t = self.x86_mem_pae.read(data[13], PROC_STRUCTURE[2]); # pgrp structure
        m_pgrp = struct.unpack(PROC_STRUCTURE[3], pgrp_t)

        session_t = self.x86_mem_pae.read(m_pgrp[3], PROC_STRUCTURE[4]); # session structure
        m_session = struct.unpack(PROC_STRUCTURE[5], session_t)

        proc.append(self.x86_mem_pae.vtop(proc_sym_addr))
        proc.append(data[1])
        proc.append(data[2])
        proc.append(data[3])
        proc.append(data[4])
        proc.append(data[5]) # user_stack
        proc.append(data[6]) # vnode of executable
        proc.append(data[7]) # offset in executable vnode
        proc.append(data[8]) # Process Priority
        proc.append(data[9]) # User-Priority based on p_cpu and p_nice
        proc.append(data[10]) # Process 'nice' value
        proc.append(data[11]) # User-Priority based on p_cpu and p_nice
        proc.append(data[12].split('\x00', 1)[0])
        proc.append(str(m_session[7]).strip('\x00'))
        proc.append(data[14])

        return proc, data[0], data[1]

    def get_proc_struct(self):
        if self.arch == 32:
            if self.os_version == 11:
                PROC_STRUCTURE = DATA_PROC_STRUCTURE[0] # Lion 32bit
            else:
                PROC_STRUCTURE = DATA_PROC_STRUCTURE[1] # Snow Leopard 32bit
        else:
            if self.os_version == 11:
                PROC_STRUCTURE = DATA_PROC_STRUCTURE[2] # Lion 64bit
	    elif self.os_version == 12:
		PROC_STRUCTURE = DATA_PROC_STRUCTURE[4]
            else:
                PROC_STRUCTURE = DATA_PROC_STRUCTURE[3] # Snow Leopard 64bit

        return PROC_STRUCTURE

    def get_kernel_task_addr(self, sym_addr):
        if self.arch == 32:
    	    kernproc = self.x86_mem_pae.read(sym_addr+self.base_address, 4); # __DATA.__common _kernproc
    	    proc_sym_addr = struct.unpack('I', kernproc)[0]
        else:
            kernproc = self.x86_mem_pae.read(sym_addr+self.base_address, 8); # __DATA.__common _kernproc
            proc_sym_addr = struct.unpack('Q', kernproc)[0]

        return proc_sym_addr
    
    def get_proc_list(self, sym_addr, proc_list, pid):
        if not(self.x86_mem_pae.is_valid_address(sym_addr+self.base_address)):
            return 1

        PROC_STRUCTURE = self.get_proc_struct()

        proc_sym_addr = self.get_kernel_task_addr(sym_addr)
	    
        while 1:
            #break
            if proc_sym_addr == 0:
                break
            if not(self.x86_mem_pae.is_valid_address(proc_sym_addr)):
                break
            try:
                proc = []

                proc, next_proc_addr, pid_in_proc = self.get_proc(proc_sym_addr, PROC_STRUCTURE)
                
                proc_sym_addr = next_proc_addr
                if pid == -1: # All Process
                    proc_list.append(proc)
                else: # Process Dump or filtering
                    if pid_in_proc == pid:
                        proc_list.append(proc)
                        return 0
            
            except struct.error:
                break
    
    def get_queue(self, ptr):
	if self.arch == 32:
	    QUEUE_STRUCTURE = DATA_QUEUE_STRUCTURE[0]
	elif self.arch == 64:
	    QUEUE_STRUCTURE = DATA_QUEUE_STRUCTURE[1]
	else:
	    return queue
	
	queue_ptr = self.x86_mem_pae.read(ptr+self.base_address, QUEUE_STRUCTURE[0])
	queue = struct.unpack(QUEUE_STRUCTURE[1], queue_ptr)
	return queue # next, prev
    
    def get_task_queue(self, sym_addr, count, task_list):
	queue = self.get_queue(sym_addr)
	
	print '[+] Task Count at Kernel Symbol: %d'%count
	
	#print 'Queue Next: %.8x, prev: %.8x'%(self.x86_mem_pae.vtop(queue[0]),self.x86_mem_pae.vtop(queue[1]))
	
	#print '[+] Get Task Queue'
	
	task_ptr = queue[0] # next
	
	i = 0
	
	while i < count:
	    task = [] # temp
            
	    if task_ptr == 0:
                break
            if not(self.x86_mem_pae.is_valid_address(task_ptr)):
                break
	      
	    task_struct = self.get_task("", task_ptr)
	    
	    task.append(i) # count
	    task.append(self.x86_mem_pae.vtop(task_ptr)) # physical address
	    task.append(task_ptr) # virtual address
	    task.append(task_struct) # task structure
	    task.append(task_struct[6]) # task.bsd_info physical address
	    
	    task_list.append(task)
	    task_ptr = task_struct[4] # task_queue_t
	    i += 1
	
	return i
	
    
    def get_task(self, proc, task_ptr):
        #print '[+] Gathering Process Information'
        #print '====== task.h --> osfmk\\kern\\task.h'
        if self.arch == 32:
            if self.os_version == 11:
                TASK_STRUCTURE = DATA_TASK_STRUCTURE[0]
            else:
                TASK_STRUCTURE = DATA_TASK_STRUCTURE[1]
        else:
            if self.os_version == 11:
                TASK_STRUCTURE = DATA_TASK_STRUCTURE[2]
	    elif self.os_version == 12:
		TASK_STRUCTURE = DATA_TASK_STRUCTURE[4]
            else:
                TASK_STRUCTURE = DATA_TASK_STRUCTURE[3]
                
        task_info = self.x86_mem_pae.read(task_ptr, TASK_STRUCTURE[0])
        task_struct = struct.unpack(TASK_STRUCTURE[1], task_info)
	
	#if proc:
	#  print ' [-] User Stack Address: 0x%.8X'%proc[5]
	#  print ' [-] Vnode of Executable Address: 0x%.8X'%proc[6]
	#  print ' [-] Offset in executable vnode: 0x%.8X'%proc[7]
        
        #print 'task_t'
        #print ' [-] Reference Count: %x'%task_struct[0]
        #print ' [-] Process Active: %x'%task_struct[1]
        #print ' [-] Process Halting: %x'%task_struct[2]
        #print 'uni and smp lock: %d'%task_struct[4]
        #print 'vm_map_t: %x'%self.x86_mem_pae.vtop(task_struct[3])
        #print 'tasks: %x'%task_struct[4]
        #print 'userdata: %x'%task_struct[5]
        return task_struct
    
    def get_proc_region(self, task_ptr, user_stack, fflag):
        
        vm_list = []
        vm_struct = []
        
        if self.arch == 32:
            if self.os_version >= 11: # Lion
                VME_STRUCTURE = DATA_VME_STRUCTURE[0]
            else:
                VME_STRUCTURE = DATA_VME_STRUCTURE[1]
        else:
            if self.os_version >= 11: # Lion
                VME_STRUCTURE = DATA_VME_STRUCTURE[2]
            else:
                VME_STRUCTURE = DATA_VME_STRUCTURE[3]
                
        vm_info = self.x86_mem_pae.read(task_ptr, VME_STRUCTURE[0])
        vm_struct = struct.unpack(VME_STRUCTURE[1], vm_info)
        
        if vm_struct[6] == 0: # pmap_t
            return vm_list, vm_struct

        if not(self.x86_mem_pae.is_valid_address(vm_struct[6])):
            return vm_list, vm_struct
        
### 11.09.28 end n0fate
        #print '======= vm_map_t --> osfmk\\vm\\vm_map.h ========'
        #print 'prev: %x'%vm_struct[0]
        #print 'next: %x'%self.x86_mem_pae.vtop(vm_struct[1])
	print ''
        print '[+] Virtual Memory Map Information'
        print ' [-] Virtual Address Start Point: 0x%x'%vm_struct[2]
        print ' [-] Virtual Address End Point: 0x%x'%vm_struct[3]
        print ' [-] Number of Entries: %d'%vm_struct[4] # number of entries
        #print 'entries_pageable: %x'%vm_struct[5]
        #print 'pmap_t: %x'%self.x86_mem_pae.vtop(vm_struct[6])
        #print 'Virtual size: %x\n'%vm_struct[7]
	
	vm_list = []
	
	# process full dump
	if fflag == 1:
	  vm_temp_list = []
	  vm_temp_list.append(vm_struct[2])
	  vm_temp_list.append(vm_struct[3])
	  vm_list.append(vm_temp_list)
	  return vm_list, vm_struct
	
	print ''
        print '[+] Generating Process Virtual Memory Maps'
        entry_next_ptr = vm_struct[1]
        for data in range(0, vm_struct[4]): # number of entries
            vm_list_ptr = self.x86_mem_pae.read(entry_next_ptr, VME_STRUCTURE[2])
            vme_list = struct.unpack(VME_STRUCTURE[3], vm_list_ptr)

            # *prev, *next, start, end
            vm_temp_list = []
            vm_temp_list.append(vme_list[2]) # start
            vm_temp_list.append(vme_list[3]) # end
            vm_list.append(vm_temp_list)
            # get permission on virtual memory ('rwx')
            permission = ''
            max_permission = ''
            
            perm_list = []
            perm = ((vme_list[4]) >> 7 )& 0x003f
            count = 6
            while count >= 0:
                perm_list.append(perm&1)
                perm = perm >> 1
                count = count - 1
                
            if (perm_list[0] == 1 ):
                permission += 'r' # Protection
            else:
                permission += '-'
            if (perm_list[1] == 1 ):
                permission += 'w' # Protection
            else:
                permission += '-'
            if (perm_list[2] == 1 ):
                permission += 'x' # Protection
            else:
                permission += '-'
            if (perm_list[3] == 1 ):
                max_permission += 'r' # Max Protection
            else:
                max_permission += '-'
            if (perm_list[4] == 1 ):
                max_permission += 'w' # Max Protection
            else:
                max_permission += '-'
            if (perm_list[5] == 1 ):
                max_permission += 'x' # Max Protection
            else:
                max_permission += '-'
            ##########################################
            if vme_list[3] == user_stack:
              print ' [-] Region from 0x%x to 0x%x (%s, max %s;), %s'%(vme_list[2], vme_list[3], permission, max_permission, "<UserStack>")
            else:
              print ' [-] Region from 0x%x to 0x%x (%s, max %s;)'%(vme_list[2], vme_list[3], permission, max_permission)
            #print 'next[data]: %x'%self.x86_mem_pae.vtop(vme_list[1])
            entry_next_ptr = vme_list[1]
        
        return vm_list, vm_struct
    
    def get_proc_cr3(self,  vm_list, vm_struct):
	if self.arch == 32:
            if self.build == '11D50': # temporary 12.04.24 n0fate
                PMAP_STRUCTURE = DATA_PMAP_STRUCTURE[0]       
            elif self.os_version >= 11:   # Lion xnu-1699, build version 11D50 has some bug (36xQ)
                PMAP_STRUCTURE = DATA_PMAP_STRUCTURE[1]
            else: # Leopard or Snow Leopard xnu-1456
                PMAP_STRUCTURE = DATA_PMAP_STRUCTURE[2]
        else:
            if self.build == '11D50': # temporary 12.04.24 n0fate
                PMAP_STRUCTURE = DATA_PMAP_STRUCTURE[3]   
            elif self.os_version >= 11:   # Lion xnu-1699, build version 11D50 has some bug (36xQ)
                PMAP_STRUCTURE = DATA_PMAP_STRUCTURE[4]
            else: # Leopard or Snow Leopard xnu-1456
                PMAP_STRUCTURE = DATA_PMAP_STRUCTURE[5]
        
        #print '%x'%self.x86_mem_pae.vtop(vm_struct[6])
        pmap_info = self.x86_mem_pae.read(vm_struct[6], PMAP_STRUCTURE[0])
        pm_cr3 = struct.unpack(PMAP_STRUCTURE[1], pmap_info)[0]
	return pm_cr3
        
    def get_proc_dump(self, vm_list, vm_struct, process_name, mempath):
        
	pm_cr3 = self.get_proc_cr3(vm_list, vm_struct)
        
        proc_pae = 0
        
        print '[+] Resetting the Page Mapping Table: 0x%x'%pm_cr3
        
        proc_pae = IA32PML4MemoryPae(FileAddressSpace(mempath), pm_cr3)
        
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

#################################### PUBLIC FUNCTIONS ####################################

def proc_print(data_list):
    print '[+] Process List'

    headerlist = ["OFFSET(P)", "PID", "PPID", "PRIORITY", "NICE", "PROCESS_NAME", "USERNAME", "CREATE_TIME (GMT +0)"]
    contentlist = []

    for data in data_list:
	line = []
	line.append("0x%.8X"%data[0]) # offset
	line.append('%d'%data[1]) # pid
	line.append('%d'%data[4]) # ppid
	line.append('%d'%unsigned8(data[8])) # Priority
	line.append('%d'%unsigned8(data[10])) # nice
	line.append('%s'%data[12]) # Changed by CL to read null formatted strings
	line.append('%s'%data[13])
	line.append('%s'%time.strftime("%a %b %d %H:%M:%S %Y", time.gmtime(data[14])))
	contentlist.append(line)

    # use optional max size list here to match default lsof output, otherwise specify
    # lsof +c 0 on the command line to print full name of commands
    mszlist = [-1, -1, -1, -1, -1, -1, -1, -1]
    columnprint(headerlist, contentlist, mszlist)
      
def get_proc_list(x86_mem_pae, sym_addr, arch, os_version, build, base_address):
    proclist = []
    ProcMan = process_manager(x86_mem_pae, arch, os_version, build, base_address)
    ret = ProcMan.get_proc_list(sym_addr, proclist, -1)
    
    return proclist

def print_proc_list(proc_list):
    proc_print(proc_list)


def get_proc_dump(x86_mem_pae, sym_addr, arch, os_version, build, pid, base_address, mempath):
    proclist = []
    ProcMan = process_manager(x86_mem_pae, arch, os_version, build, base_address)
    ret = ProcMan.get_proc_list(sym_addr, proclist, pid)
    if ret == 1:
        return 1
    
    dumped_proc = proclist
    
    proc_print(dumped_proc)
    
    task_struct = ProcMan.get_task(dumped_proc[0], dumped_proc[0][2])
    
    retData = ProcMan.get_proc_region(task_struct[3], dumped_proc[0][5], 0)
    
    vm_list = retData[0]
    vm_struct = retData[1]
    
    ProcMan.get_proc_dump(vm_list, vm_struct, str(dumped_proc[0][1])+'-'+dumped_proc[0][12], mempath)
    
    return
  
def get_task_dump(x86_mem_pae, sym_addr, count, arch, os_version, build, task_id, base_address, mempath):
    ProcMan = process_manager(x86_mem_pae, arch, os_version, build, base_address)
    task_list = []
    check_count = ProcMan.get_task_queue(sym_addr, count, task_list) # task queue ptr, task_count, task_list
    
    for task in task_list:
	if task[0] == task_id:
	  task_struct = task
	  break
    
    if len(task_struct) == 0:
      '[+] Could not found TASK ID'
      return

    PROC_STRUCTURE = ProcMan.get_proc_struct()
    proc_matched = ProcMan.get_proc(task[4], PROC_STRUCTURE)[0]
    
    retData = ProcMan.get_proc_region(task_struct[3][3], 0x00, 0) # 
    
    vm_list = retData[0]
    vm_struct = retData[1]
    
    ProcMan.get_proc_dump(vm_list, vm_struct, str(proc_matched[1])+'-'+proc_matched[12], mempath)
    
    return
    
    
    
def get_task_list(x86_mem_pae, sym_addr, count, arch, os_version, build, base_address):
    ProcMan = process_manager(x86_mem_pae, arch, os_version, build, base_address)
    
    task_list = []
    check_count = ProcMan.get_task_queue(sym_addr, count, task_list) # task queue ptr, task_count, task_list
    
    return task_list, check_count

def proc_lookup(proc_list, task_list, x86_mem_pae, arch, os_version, build, base_address):


    ProcMan = process_manager(x86_mem_pae, arch, os_version, build, base_address)
    PROC_STRUCTURE = ProcMan.get_proc_struct()
    
    print '[+] Task List Count at Queue: %d'%len(task_list)
    print '[+] Process List Count: %d'%len(proc_list)
    
    # task list
    unlinked_task = []
    valid_task = []
    
    # comment: task = [count, task_ptr(Physical), task_ptr(Virtual), [task structure], task.bsd_info]
    for task in task_list:
	task_ptr = task[2]
	
	valid_flag = 0
	
	for proc in proc_list:
	    task_ptr_in_proc = proc[2]
	    if task_ptr_in_proc == task_ptr:
		valid_flag = 1
		task.append(proc[1]) # PID
		task.append(proc[12]) # process name
		task.append(proc[13]) # username
		#task.append('O')
		#if task[4] == proc[0]:
		#  task.append('O')
		#else:
		#  task.append('X')
		
		valid_task.append(task)
		break
	
	if valid_flag == 0:
	    for proc in proc_list:
	      if task[4] == proc[0]:
		task.append(proc[1])
		task.append(proc[12])
		task.append(proc[13])
	      else:
                proc_matched = ProcMan.get_proc(task[4], PROC_STRUCTURE)[0]
		task.append(proc_matched[1])
		task.append(proc_matched[12])
		task.append(proc_matched[13])
	    unlinked_task.append(task)
    
    return valid_task, unlinked_task


def task_print(data_list):
    #print '[+] Process List'

    headerlist = ["TASK CNT", "OFFSET(P)", "REF_CNT", "Active", "Halt", "VM_MAP(V)", "PID", "PROCESS", "USERNAME"]
    contentlist = []

    for data in data_list:
	line = ['%d'%data[0]] # count
	line.append("0x%.8X"%data[1]) # offset
	line.append('%d'%data[3][0]) # Number of references to me
	line.append('%d'%data[3][1]) # task has not been terminated
	line.append('%d'%data[3][2]) # task is being halted
	line.append('0x%.8X'%data[3][3]) # VM_MAP
	line.append('%d'%data[5]) # PID
	line.append('%s'%data[6]) # Process Name
	line.append('%s'%data[7]) # User Name
	#line.append('%s'%data[8]) # proc.tasks -> Task ptr
	#line.append('%s'%data[9]) # task.bsd_info -> proc ptr
	
	#line.append('%s'%time.strftime("%a %b %d %H:%M:%S %Y", time.gmtime(data[14])))
	contentlist.append(line)

    # use optional max size list here to match default lsof output, otherwise specify
    # lsof +c 0 on the command line to print full name of commands
    mszlist = [-1, -1, -1, -1, -1, -1, -1, -1, -1]
    columnprint(headerlist, contentlist, mszlist)
