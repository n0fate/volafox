# -*- coding: cp949 -*-
import sys
import struct
import time

from tableprint import columnprint

# Lion 32bit, SN 32bit, Lion64bit, SN 64bit
DATA_PROC_STRUCTURE = [[476+24+168, '=4xIIIII380xQII20xbbbb52sI164xI', 16, '=IIII', 283, '=IIIIIII255s'],
    [476+168, '=4xIIIII356xQII20xbbbb52sI164xI', 16, '=IIII', 283, '=IIIIIII255s'],
    [752+24+268, '=8xQQQQI628xQQQ16xbbbb52sQ264xI', 32, '=QQQQ', 303, '=IQQIQQQ255s'],
    [1028, '=8xQQQQI612xQQQ16xbbbb52sQ264xI', 32, '=QQQQ', 303, '=IQQIQQQ255s']]

# Lion 32bit, SN 32bit, Lion64bit, SN 64bit
DATA_TASK_STRUCTURE = [[32, '=8xIIIIII'],
    [36, '=12xIIIIII'],
    [56, '=16xIII4xQQQ'],
    [64, '=24xIII4xQQQ']]

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

# 32비트 unsigned 형으로 변환하는 함수 정의
def unsigned8(n):
  return n & 0xFFL

class process_manager:
    def __init__(self, x86_mem_pae, arch, os_version, build):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.os_version = os_version
        self.build = build
        
    def get_proc(self, sym_addr, proc_list, pid):
        if not(self.x86_mem_pae.is_valid_address(sym_addr)):
            return 1
        
	if self.arch == 32:
            if self.os_version == 11:
                PROC_STRUCTURE = DATA_PROC_STRUCTURE[0] # Lion 32bit
            else:
                PROC_STRUCTURE = DATA_PROC_STRUCTURE[1] # Snow Leopard 32bit
        else:
            if self.os_version == 11:
                PROC_STRUCTURE = DATA_PROC_STRUCTURE[2] # Lion 64bit
            else:
                PROC_STRUCTURE = DATA_PROC_STRUCTURE[3] # Snow Leopard 64bit
        
        if self.arch == 32:
	    kernproc = self.x86_mem_pae.read(sym_addr, 4); # __DATA.__common _kernproc
	    proc_sym_addr = struct.unpack('I', kernproc)[0]
        else:
            kernproc = self.x86_mem_pae.read(sym_addr, 8); # __DATA.__common _kernproc
	    proc_sym_addr = struct.unpack('Q', kernproc)[0]
	    
        while 1:
            #break
            if proc_sym_addr == 0:
                break
            if not(self.x86_mem_pae.is_valid_address(proc_sym_addr)):
                break
            try:
                proc = []
                proclist = self.x86_mem_pae.read(proc_sym_addr, PROC_STRUCTURE[0])
                data = struct.unpack(PROC_STRUCTURE[1], proclist)
                proc_sym_addr = data[0]
            
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
                #proc.append(data[8])
                
                proc_sym_addr = data[0]
                if pid == -1: # All Process
                    proc_list.append(proc)
                else: # Process Dump or filtering
                    if data[1] == pid:
                        proc_list.append(proc)
                        return 0
            
            except struct.error:
                break
        
    def get_task(self, proc):
        print '[+] Gathering Process Information'
        #print '====== task.h --> osfmk\\kern\\task.h'
        if self.arch == 32:
            if self.os_version == 11:
                TASK_STRUCTURE = DATA_TASK_STRUCTURE[0]
            else:
                TASK_STRUCTURE = DATA_TASK_STRUCTURE[1]
        else:
            if self.os_version == 11:
                TASK_STRUCTURE = DATA_TASK_STRUCTURE[2]
            else:
                TASK_STRUCTURE = DATA_TASK_STRUCTURE[3]
                
        task_info = self.x86_mem_pae.read(proc[2], TASK_STRUCTURE[0])
        task_struct = struct.unpack(TASK_STRUCTURE[1], task_info)

        print ' [-] User Stack Address: 0x%.8X'%proc[5]
        print ' [-] Vnode of Executable Address: 0x%.8X'%proc[6]
        print ' [-] Offset in executable vnode: 0x%.8X'%proc[7]
        
        #print 'task_t'
        print ' [-] Reference Count: %x'%task_struct[0]
        print ' [-] Process Active: %x'%task_struct[1]
        print ' [-] Process Halting: %x'%task_struct[2]
        #print 'uni and smp lock: %d'%task_struct[4]
        #print 'vm_map_t: %x'%self.x86_mem_pae.vtop(task_struct[3])
        #print 'tasks: %x'%task_struct[4]
        #print 'userdata: %x'%task_struct[5]
        return task_struct
    
    def get_proc_region(self, task_ptr, user_stack):
        
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
        print '[+] Virtual Memory Map Information'
        print ' [-] Virtual Address Start Point: 0x%x'%vm_struct[2]
        print ' [-] Virtual Address End Point: 0x%x'%vm_struct[3]
        print ' [-] Number of Entries: %d'%vm_struct[4] # number of entries
        #print 'entries_pageable: %x'%vm_struct[5]
        #print 'pmap_t: %x'%self.x86_mem_pae.vtop(vm_struct[6])
        #print 'Virtual size: %x\n'%vm_struct[7]

        vm_list = []
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
        
    def get_proc_dump(self, vm_list, vm_struct):
        
        if self.arch == 32:
            if self.build == '11D50': # temporary 12.04.24 n0fate
                PMAP_STRUCTURE = DATA_PMAP_STRUCTURE[0]       
            elif self.os_version == 11:   # Lion xnu-1699, build version 11D50 has some bug (36xQ)
                PMAP_STRUCTURE = DATA_PMAP_STRUCTURE[1]
            else: # Leopard or Snow Leopard xnu-1456
                PMAP_STRUCTURE = DATA_PMAP_STRUCTURE[2]
        else:
            if self.build == '11D50': # temporary 12.04.24 n0fate
                PMAP_STRUCTURE = DATA_PMAP_STRUCTURE[3]   
            elif self.os_version == 11:   # Lion xnu-1699, build version 11D50 has some bug (36xQ)
                PMAP_STRUCTURE = DATA_PMAP_STRUCTURE[4]
            else: # Leopard or Snow Leopard xnu-1456
                PMAP_STRUCTURE = DATA_PMAP_STRUCTURE[5]
        
        #print '%x'%self.x86_mem_pae.vtop(vm_struct[6])
        pmap_info = self.x86_mem_pae.read(vm_struct[6], PMAP_STRUCTURE[0])
        pm_cr3 = struct.unpack(PMAP_STRUCTURE[1], pmap_info)[0]

        return pm_cr3


    def proc_print(self, data_list):
        print '[+] Process List'

        headerlist = ["OFFSET(P)", "PID", "PPID", "PRIORITY", "NICE", "PROCESS_NAME", "USERNAME", "CREATE_TIME (GMT +0)"]
        contentlist = []

        for data in data_list:
            line = ["0x%.8X"%data[0]] # offset
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
        
#################################### PUBLIC FUNCTIONS ####################################
def get_proc_list(x86_mem_pae, sym_addr, arch, os_version, build):
    proclist = []
    ProcMan = process_manager(x86_mem_pae, arch, os_version, build)
    ret = ProcMan.get_proc(sym_addr, proclist, -1)
    if ret == 1:
        return 1
    else:
        ProcMan.proc_print(proclist)
        return 0
    
def get_proc_dump(x86_mem_pae, sym_addr, arch, os_version, build, pid):
    proclist = []
    ProcMan = process_manager(x86_mem_pae, arch, os_version, build)
    ret = ProcMan.get_proc(sym_addr, proclist, pid)
    if ret == 1:
        return 1
    ProcMan.proc_print(proclist)
    
    task_struct = ProcMan.get_task(proclist[0])
    
    retData = ProcMan.get_proc_region(task_struct[3], proclist[0][5])
    
    vm_list = retData[0]
    vm_struct = retData[1]
    
    pm_cr3 = ProcMan.get_proc_dump(vm_list, vm_struct)
    
    return pm_cr3, vm_list, proclist[0][12]
