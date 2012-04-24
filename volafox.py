#!/usr/bin/env python						# LSOF: new path
#!c:\python\python.exe
# -*- coding: utf-8 -*-
#  -*- mode: python; -*-

BUILD = "1.0"	# LSOF: global to track research builds

'''
 Original: https://code.google.com/p/volafox/source/browse/?r=52

 Modified: student researcher, osxmem@gmail.com
Last Edit: 22 Mar 2012
  Changes: build submitted to volafox project for consideration

_______________________SUPPORT_________________________
      OSX: Lion (10.7.x), Snow Leopard (10.6.x)
	 Arch: i386, x86_64
	Image: *.vmem (VMware), *.mmr (flattened, x86 ONLY)
  Release: r52

Dependent: addrspace.py
           ia32_pml4.py
           imageinfo.py
           lsof.py
           macho_an.py
           macho.py
           x86.py
           /overlays
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

import pdb # For the debugger


import getopt
import sys
import math

import binascii
import macho_an # user-defined class -> n0fate
from ia32_pml4 import * # user-defined class -> n0fate

from imageinfo import * # user defined class > CL
import pickle # added by CL

# LSOF: most research functionality consolidated here
from lsof import getfilelist, printfilelist

import os

from x86 import *
from addrspace import FileAddressSpace
from macho import MachoAddressSpace, isMachoVolafoxCompatible, is_universal_binary

###############################################################################
#
# Class: volafox() - 2010-09-30
# Description: This analysis module can support Intel X86 Architecture
#              We need to have more research time ;)
#
# Dependency: x86.py in Volatility Framework for VA to PA
#
###############################################################################
class volafox():
    def __init__(self, mempath):
##        self.idlepdpt = pdpt
##        self.idlepml4 = pml4 ### 11.09.28 n0fate
        self.mempath = mempath
        self.arch = 32 # architecture default is 32bit
        self.data_list = []

        self.kern_version = ''

        self.valid_format = 0 # invalid

    # LSOF: added argument for printing verbose debugging information
    #def get_kernel_version(self): # return (valid format(bool), architecture(int), Kernel Version(str))
    def get_kernel_version(self, vflag): # return (valid format(bool), architecture(int), Kernel Version(str))
        f = self.mempath
	returnResult = imageInfo(f)
	difference, build, sixtyfourbit = returnResult.catfishSearch(f)
	
	# LSOF: verbose support
	if vflag:
		print '[+] Get Memory Image Information'
		print " [-] Difference(Catfish Signature):", difference # Catfish offset
		
        if bool(difference):
        	
            # LSOF: verbose support
            if vflag:
            	print ' [-] Maybe Mac Memory Reader Format'
            self.valid_format = 0
            
        else:
        
            # LSOF: verbose support
            if vflag:
            	print ' [-] Valid Mac Linear File Format'
            	
            self.valid_format = 1
	
	if bool(sixtyfourbit):
	    
	    # LSOF: verbose support
            if vflag:
	    	print " [-] 64-bit memory image"
	    self.arch = 64
	    
	else:
            
            # LSOF: verbose support
            if vflag:
            	print " [-] 32-bit memory image"
            self.arch = 32
	
	# LSOF: verbose support
        if vflag:
		print " [-] Build Version in Memory : %s"%build
		
	if build == '10A432':
		self.kern_version = '10.6.0'
	elif build == '10D573' or build == '10D578' or build == '10D572':
		self.kern_version = '10.6.3'
	elif build == '10F659' or build == '10F616':
		self.kern_version = '10.6.4'
	elif build == '10H574' or build == '10H575':
		self.kern_version = '10.6.5'
	elif build == '10J567':
		self.kern_version = '10.6.6'
	elif build == '10J869' or build == '10J3250':
		self.kern_version = '10.6.7'
	elif build == '10K540' or build ==  '10K549':
		self.kern_version = '10.6.8'
	elif build == '11A511':
                self.kern_version = '10.7.0'
        elif build == '11B26':
                self.kern_version = '10.7.1'
        elif build == '11C74':
                self.kern_version = '10.7.2'
                
        # n0fate : bug fix
    	elif build == '11D50b' or build == '11D50' or build == '11D50d':
		self.kern_version = '10.7.3'
		
	# LSOF: 10.6.0 Server support
	elif build == '10A433':
		self.kern_version = '10.6.0'
	
	elif build == 'Darwin ':
		#print ' [-] Wrong Catfish symbol. Memory capture incomplete?'
		self.kern_version = 'Darwin'
	else:
		self.kern_version = 'NotFound'
		
	# LSOF: verbose support
        if vflag:
        	print ' [-] Kernel Version: %s'%self.kern_version
        	
	return self.valid_format, self.arch, self.kern_version, build

    def set_architecture(self, arch_num):
        if (arch_num is not 32) and (arch_num is not 64):
            return 1
        else:
            self.arch = arch_num
            return 0
    
    def init_vatopa_x86_pae(self, pdpt, pml4): # 11.11.23 64bit suppport
        if self.mempath == '':
            return 1

        self.idlepdpt = pdpt
        self.idlepml4 = pml4
        
        if self.arch is 32:
            if isMachoVolafoxCompatible(self.mempath):
                self.x86_mem_pae = IA32PagedMemoryPae(MachoAddressSpace(self.mempath), self.idlepdpt)
            else:
                self.x86_mem_pae = IA32PagedMemoryPae(FileAddressSpace(self.mempath), self.idlepdpt)
        else: # 64
            if isMachoVolafoxCompatible(self.mempath):
                self.x86_mem_pae = IA32PML4MemoryPae(MachoAddressSpace(self.mempath), self.idlepml4)
            else:
                self.x86_mem_pae = IA32PML4MemoryPae(FileAddressSpace(self.mempath), self.idlepml4)
        return 0
    
    def sleep_time(self, sym_addr):
    	sleep_time = self.x86_mem_pae.read(sym_addr, 4);
    	data = struct.unpack('i', sleep_time)
    	return data

    def wake_time(self, sym_addr):
    	wake_time = self.x86_mem_pae.read(sym_addr, 4);
    	data = struct.unpack('i', wake_time)
    	return data   

    def os_info(self, sym_addr): # 11.11.23 64bit suppport
        os_version = self.x86_mem_pae.read(sym_addr, 10) # __DATA.__common _osversion
        data = struct.unpack('10s', os_version)
        return data

    def machine_info(self, sym_addr): # 11.11.23 64bit suppport
        machine_info = self.x86_mem_pae.read(sym_addr, 40); # __DATA.__common _machine_info
        data = struct.unpack('IIIIQIIII', machine_info)
        self.os_version = data[0] # 11.09.28
        return data

    def kernel_kext_info(self, sym_addr): # 11.11.23 64bit suppport
        if self.arch == 32:
            Kext = self.x86_mem_pae.read(sym_addr, 168); # .data _g_kernel_kmod_info
            data = struct.unpack('III64s64sIIIIIII', Kext)
        else: # self.arch == 64
            Kext = self.x86_mem_pae.read(sym_addr, 196); # .data _g_kernel_kmod_info
            data = struct.unpack('=QII64s64sIQQQQQQ', Kext)
        return data

    def kext_info(self, sym_addr): # 11.11.23 64bit suppport
        #print 'symboladdr: %x'%sym_addr
        kext_list = []

        if self.arch == 32:
            Kext = self.x86_mem_pae.read(sym_addr, 4); # .data _kmod
            data = struct.unpack('I', Kext)
	    while(1):
		if data[0] == 0:
		    break
		if not(self.x86_mem_pae.is_valid_address(data[0])):
		    break
                Kext = self.x86_mem_pae.read(data[0], 168); # .data _kmod
                data = struct.unpack('III64s64sIIIIIII', Kext)
		kext_list.append(data)
		
        else: # 64
            Kext = self.x86_mem_pae.read(sym_addr, 8);
            data = struct.unpack('Q', Kext)
	    while(1):
		if data[0] == 0:
		    break
		if not(self.x86_mem_pae.is_valid_address(data[0])):
		    break
		Kext = self.x86_mem_pae.read(data[0], 196); # .data _g_kernel_kmod_info
		data = struct.unpack('=QII64s64sIQQQQQQ', Kext)
		kext_list.append(data)

        return kext_list

    def kextdump(self, offset, size, kext_name):
        if not(self.x86_mem_pae.is_valid_address(offset)):
            print 'Invalid Offset'
            return
        print '[DUMP] FILENAME: %s-%x-%x'%(kext_name, offset, offset+size)

	padding_code = 0x00
	pk_padding = struct.pack('=B', padding_code)
	padding = pk_padding*0x1000


	file = open('%s-%x-%x'%(kext_name, offset, offset+size), 'wb')
	for kext_offset in range(offset, offset+size, 0x1000):
            if not(self.x86_mem_pae.is_valid_address(kext_offset)):
                file.write(padding)
                continue
            data = self.x86_mem_pae.read(kext_offset, 0x1000)
            if data is None:
                file.write(padding)
                continue
            file.write(data)
	file.close()
	print '[DUMP] Complete.'
	return
    
    def mount_info(self, sym_addr): # 11.11.23 64bit suppport(Lion)
        mount_list = []
	if self.arch == 32:
	    mount_t = self.x86_mem_pae.read(sym_addr, 4); # .data _g_kernel_kmod_info
	    data = struct.unpack('I', mount_t)
    
	    while 1:
		if data[0] == 0:
		    break
		if not(self.x86_mem_pae.is_valid_address(data[0])):
		    break
		mount_info = self.x86_mem_pae.read(data[0], 2212);
		data = struct.unpack('=I144x16s1024s1024s', mount_info)
		mount_list.append(data)
	else: #64bit
	    mount_t = self.x86_mem_pae.read(sym_addr, 8); # .data _g_kernel_kmod_info
	    data = struct.unpack('Q', mount_t)
    
	    while 1:
		if data[0] == 0:
		    break
		if not(self.x86_mem_pae.is_valid_address(data[0])):
		    break
		mount_info = self.x86_mem_pae.read(data[0], 2276);
		data = struct.unpack('=Q204x16s1024s1024s', mount_info)
		mount_list.append(data)

        return mount_list

    def process_info(self, sym_addr): # 11.11.23 64bit suppport
        proc_list = []
	if self.arch == 32:
	    kernproc = self.x86_mem_pae.read(sym_addr, 4); # __DATA.__common _kernproc
	    data = struct.unpack('I', kernproc)
    
	    while 1:
		#break
		if data[0] == 0:
		    break
		if not(self.x86_mem_pae.is_valid_address(data[0])):
		    break
		try:
		    if self.os_version >= 11: # Lion
			proclist = self.x86_mem_pae.read(data[0], 476+24);
			data = struct.unpack('4xIIIII392x24xI52sI', proclist) # 24 bytes + 392 bytes padding(49 double value) + 33 bytes process name + pgrp
		    else: # Leopard or Snow Leopard
			proclist = self.x86_mem_pae.read(data[0], 476);
			data = struct.unpack('4xIIIII392xI52sI', proclist) # 24 bytes + 392 bytes padding(49 double value) + 33 bytes process name + pgrp
			
		    pgrp_t = self.x86_mem_pae.read(data[7], 16); # pgrp structure
		    m_pgrp = struct.unpack('IIII', pgrp_t)
    
		    session_t = self.x86_mem_pae.read(m_pgrp[3], 283); # session structure
		    m_session = struct.unpack('IIIIIII255s', session_t)
		    data += (str(m_session[7]).strip('\x00'), )
		    proc_list.append(data)
		except struct.error:
		    break
	else: # 64
	    kernproc = self.x86_mem_pae.read(sym_addr, 8); # __DATA.__common _kernproc
	    data = struct.unpack('Q', kernproc)
	    while 1:
		#break
		if data[0] == 0:
		    break
		if not(self.x86_mem_pae.is_valid_address(data[0])):
		    break
		try:
		    if self.os_version >= 11: # Lion >
			proclist = self.x86_mem_pae.read(data[0], 752+24);
			data = struct.unpack('=8xQQQQI668xI52sQ', proclist)
			#print data[6]
		    else: # Leopard or Snow Leopard # 11.11.23 Test
			proclist = self.x86_mem_pae.read(data[0], 760);
			data = struct.unpack('8xQQQQI652xI52sQ', proclist)
		    pgrp_t = self.x86_mem_pae.read(data[7], 32); # pgrp structure
		    m_pgrp = struct.unpack('=QQQQ', pgrp_t)
    
		    session_t = self.x86_mem_pae.read(m_pgrp[3], 303); # session structure
		    m_session = struct.unpack('=IQQIQQQ255s', session_t)
		    data += (str(m_session[7]).strip('\x00'), )
		    proc_list.append(data)
		except struct.error:
		    break
        return proc_list

    # LSOF: new lsof module (stub)
    def lsof(self, sym_addr, pid, vflag):
	
		if self.arch == 32:
		
			# read 4 bytes from kernel executable or overlay starting at symbol _kernproc
			kernproc = self.x86_mem_pae.read(sym_addr, 4);
	
			# unpack pointer to the process list, only need the first member returned
			proc_head = struct.unpack('I', kernproc)[0]
		
		else: # 64-bit
			kernproc = self.x86_mem_pae.read(sym_addr, 8);
			proc_head = struct.unpack('Q', kernproc)[0]
		
		return getfilelist(self.x86_mem_pae, self.arch, self.os_version, proc_head, pid, vflag)

    def syscall_info(self, sym_addr): # 11.11.23 64bit suppport
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
	    data = struct.unpack('Q', nsysent) # uint32
    
	    sysentaddr = sym_addr - (data[0] * 40) # sysent structure size + 2bytes
    
	    for count in range(0, data[0]):
		sysent = self.x86_mem_pae.read(sysentaddr + (count*40), 40); # .data _nsysent
		data = struct.unpack('hbbQQQII', sysent) # uint32
    
		syscall_list.append(data)

        return syscall_list

    def vaddump(self, sym_addr, pid):
        print '\n-= process: %d=-'%pid
        print 'list_entry_next\tpid\tppid\tprocess name\t\tusername'
	
	if self.arch == 32:
	    kernproc = self.x86_mem_pae.read(sym_addr, 4); # __DATA.__common _kernproc
	    data = struct.unpack('I', kernproc)
	    if self.os_version >= 11: # Lion
		proclist = self.x86_mem_pae.read(data[0], 476+24);
		data = struct.unpack('=4xIIIII392x24xI52sI', proclist)
	    else:
		proclist = self.x86_mem_pae.read(data[0], 476);
		data = struct.unpack('=4xIIIII392xI52sI', proclist) # 24 bytes + 396 bytes padding(49 double value) + 33 bytes process name
	    while 1:
		if data[1] == pid:
		    #print 'list_entry(next): %x'%data[0] # int
		    sys.stdout.write('%.8x\t'%data[0]) # int
		    sys.stdout.write('%d\t'%data[1]) # int
		    sys.stdout.write('%d\t'%data[4]) # int
		    sys.stdout.write('%s\t'%data[6].split('\x00', 1)[0])
		   
		    process_name = data[6].split('\x00', 1)[0]
		   
		    pgrp_t = self.x86_mem_pae.read(data[7], 16); # pgrp structure
		    m_pgrp = struct.unpack('IIII', pgrp_t)
       
		    session_t = self.x86_mem_pae.read(m_pgrp[3], 283); # session structure
		    m_session = struct.unpack('IIIIIII255s', session_t)
		    sys.stdout.write('%s'%m_session[7].replace('\x00',''))
		    sys.stdout.write('\n')
    
		    print '[+] Gathering Process Information'
		    #print 'task_ptr: %x'%self.x86_mem_pae.vtop(data[2])
		    #print '====== task.h --> osfmk\\kern\\task.h'
		    if self.os_version >= 11:
			task_info = self.x86_mem_pae.read(data[2], 32)
			task_struct = struct.unpack('=8xIIIIII', task_info)
		    else:
			task_info = self.x86_mem_pae.read(data[2], 36)
			task_struct = struct.unpack('=12xIIIIII', task_info)
		    #print 'task_t'
		    #print 'ref_count: %x'%task_struct[0]
		    #print 'active: %x'%task_struct[1]
		    #print 'halting: %x'%task_struct[2]
		    #print 'uni and smp lock: %d'%task_struct[4]
		    #print 'vm_map_t: %x'%self.x86_mem_pae.vtop(task_struct[3])
		    #print 'tasks: %x'%task_struct[4]
		    #print 'userdata: %x'%task_struct[5]
    
    #### 11.09.28 start n0fate.
    
    # Mac OS X Snow Leopard
    # struct vm_map_header {
    #	struct vm_map_links	links;		/* first, last, min, max */
    #	int			nentries;	/* Number of entries */
    #	boolean_t		entries_pageable;
    #						/* are map entries pageable? */
    #};
    
    # Mac OS X Lion
    # struct vm_map_header {
    #    struct vm_map_links	links;		/* first, last, min, max */
    #    int			nentries;	/* Number of entries */
    #    boolean_t		entries_pageable; /* are map entries pageable? */
    #    vm_map_offset_t		highest_entry_end_addr;	/* The ending address of the highest allocated vm_entry_t */
		    if self.os_version >= 11: # Lion
			vm_info = self.x86_mem_pae.read(task_struct[3], 162+12)
			vm_struct = struct.unpack('=12xIIQQII8x4xIQ16xIII42xIIIIIIIII', vm_info)
		    else:
			vm_info = self.x86_mem_pae.read(task_struct[3], 162)
			vm_struct = struct.unpack('=12xIIQQIIIQ16xIII42xIIIIIIIII', vm_info)
    
    ### 11.09.28 end n0fate
		    #print '======= vm_map_t --> osfmk\\vm\\vm_map.h ========'
		    #print 'prev: %x'%vm_struct[0]
		    #print 'next: %x'%self.x86_mem_pae.vtop(vm_struct[1])
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
                        if self.os_version >= 11:
##  212         struct vm_map_store     store;
##  213         union vm_map_object     object;         /* object I point to */
##  214         vm_object_offset_t      offset;         /* offset into object */
                            vm_list_ptr = self.x86_mem_pae.read(entry_next_ptr, 52)
                            vme_list = struct.unpack('=IIQQ24xI', vm_list_ptr)
                        else:
##  207         union vm_map_object     object;         /* object I point to */
##  208         vm_object_offset_t      offset;         /* offset into object */
                            vm_list_ptr = self.x86_mem_pae.read(entry_next_ptr, 40)
                            vme_list = struct.unpack('=IIQQ12xI', vm_list_ptr)
			# *prev, *next, start, end
			vm_temp_list = []
			vm_temp_list.append(vme_list[2]) # start
			vm_temp_list.append(vme_list[3]) # end
			vm_list.append(vm_temp_list)
			# get permission at virtual memory ('rwx')
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
			
			print ' [-] Region from 0x%x to 0x%x (%s, max %s;)'%(vme_list[2], vme_list[3], permission, max_permission)
			#print 'next[data]: %x'%self.x86_mem_pae.vtop(vme_list[1])
			entry_next_ptr = vme_list[1]
                        
		    if vm_struct[6] == 0: # pmap_t
			exit(1)
       
		    if not(self.x86_mem_pae.is_valid_address(vm_struct[6])):
			exit(1)
    
    ### 11.09.28 start n0fate
    
    # Mac OS X Lion
    # struct pmap {
    #	decl_simple_lock_data(,lock)	/* lock on map */
    #	pmap_paddr_t    pm_cr3;         /* physical addr */
    #	boolean_t       pm_shared;
    #        pd_entry_t      *dirbase;        /* page directory pointer */
    # #ifdef __i386__
    #	pmap_paddr_t    pdirbase;        /* phys. address of dirbase */
    #	vm_offset_t     pm_hold;        /* true pdpt zalloc addr */
    
		    if self.os_version >= 11:   # Lion xnu-1699
			pmap_info = self.x86_mem_pae.read(vm_struct[6], 12)
			pmap_struct = struct.unpack('=4xQ', pmap_info)
			pm_cr3 = pmap_struct[0]
		    else: # Leopard or Snow Leopard xnu-1456
			pmap_info = self.x86_mem_pae.read(vm_struct[6], 100)
			pmap_struct = struct.unpack('=IQIIII56xQII', pmap_info)
			pm_cr3 = pmap_struct[6]
    
    ### 11.09.28 end n0fate
			
			#print 'pmap_t'
			#print 'page directory pointer: %x'%pmap_struct[0] # int(pointer)
			#print 'phys.address of dirbase: %x'%pmap_struct[1] # uint64_t
			#print 'object to pde: %x'%pmap_struct[2]
			#print 'ref count: %x'%pmap_struct[3]
			#print 'nx_enabled: %x'%pmap_struct[4]
			#print 'task_map: %x'%pmap_struct[5]
	   
			#print 'pm_cr3: %x'%pmap_struct[6]
			#print 'pm_pdpt: %x'%pmap_struct[7]
			#print 'pm_pml4: %x'%pmap_struct[8]
    
		    
		    proc_pae = 0
		    print '[+] Resetting the Page Mapping Table: 0x%x'%pm_cr3
		    #if pmap_struct[5] == 0: # 32bit process
		    #    proc_pae = IA32PagedMemoryPae(FileAddressSpace(self.mempath), pm_cr3)
		    #else: # 64bit process Page Table module(ia32_pml4.py)
		    #    proc_pae = IA32PML4MemoryPae(FileAddressSpace(self.mempath), pm_cr3)
		    
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
		else:
		    if self.os_version >= 11: # Lion
			proclist = self.x86_mem_pae.read(data[0], 476+24);
			data = struct.unpack('=4xIIIII392x24xI52sI', proclist)
		    else:
			proclist = self.x86_mem_pae.read(data[0], 476);
			data = struct.unpack('=4xIIIII392xI52sI', proclist) # 24 bytes + 396 bytes padding(49 double value) + 33 bytes process name

################################# 64bit ################################################################ 11.11.23
	else: 
	    kernproc = self.x86_mem_pae.read(sym_addr, 8); # __DATA.__common _kernproc
	    data = struct.unpack('Q', kernproc)
	    if self.os_version >= 11: # Lion
		proclist = self.x86_mem_pae.read(data[0], 752+24);
		data = struct.unpack('=8xQQQQI668xI52sQ', proclist)
	    else: # Snow Leopard
		proclist = self.x86_mem_pae.read(data[0], 760);
		data = struct.unpack('=8xQQQQI652xI52sQ', proclist) # 24 bytes + 396 bytes padding(49 double value) + 33 bytes process name
	    while 1:
		if data[1] == pid:
		    #print 'list_entry(next): %x'%data[0] # int
		    sys.stdout.write('%.8x\t'%data[0]) # int
		    sys.stdout.write('%d\t'%data[1]) # int
		    sys.stdout.write('%d\t'%data[4]) # int
		    sys.stdout.write('%s\t'%data[6].split('\x00', 1)[0])
		   
		    process_name = data[6].split('\x00', 1)[0]
		   
		    pgrp_t = self.x86_mem_pae.read(data[7], 32); # pgrp structure
		    m_pgrp = struct.unpack('=QQQQ', pgrp_t)
       
		    session_t = self.x86_mem_pae.read(m_pgrp[3], 303); # session structure
		    m_session = struct.unpack('=IQQIQQQ255s', session_t)
		    sys.stdout.write('%s'%m_session[7].replace('\x00',''))
		    sys.stdout.write('\n')
    
		    print '[+] Gathering Process Information'
		    #print 'task_ptr: %x'%self.x86_mem_pae.vtop(data[2])
		    #print '====== task.h --> osfmk\\kern\\task.h'
		    if self.os_version >= 11: # Lion
			task_info = self.x86_mem_pae.read(data[2], 56)
			task_struct = struct.unpack('=16xIII4xQQQ', task_info)
		    else: # Snow Leopard
			task_info = self.x86_mem_pae.read(data[2], 64)
			task_struct = struct.unpack('=24xIII4xQQQ', task_info)
		    #print 'task_t'
		    #print 'ref_count: %x'%task_struct[0]
		    #print 'active: %x'%task_struct[1]
		    #print 'halting: %x'%task_struct[2]
		    #print 'uni and smp lock: %d'%task_struct[4]
		    #print 'vm_map_t: %x'%self.x86_mem_pae.vtop(task_struct[3])
		    #print 'tasks: %x'%task_struct[4]
		    #print 'userdata: %x'%task_struct[5]
    
    #### 11.09.28 start n0fate.
    
    # Mac OS X Snow Leopard
    # struct vm_map_header {
    #	struct vm_map_links	links;		/* first, last, min, max */
    #	int			nentries;	/* Number of entries */
    #	boolean_t		entries_pageable;
    #						/* are map entries pageable? */
    #};
    
    # Mac OS X Lion
    # struct vm_map_header {
    #    struct vm_map_links	links;		/* first, last, min, max */
    #    int			nentries;	/* Number of entries */
    #    boolean_t		entries_pageable; /* are map entries pageable? */
    #    vm_map_offset_t		highest_entry_end_addr;	/* The ending address of the highest allocated vm_entry_t */
		    if self.os_version >= 11: # Lion
			vm_info = self.x86_mem_pae.read(task_struct[3], 182+12)
			vm_struct = struct.unpack('=16xQQQQII16xQQ16xIII42xIIIIIIIII', vm_info)
		    else:
			vm_info = self.x86_mem_pae.read(task_struct[3], 178)
			vm_struct = struct.unpack('=16xQQQQIIQQ16xIII42xIIIIIIIII', vm_info)
    
    ### 11.09.28 end n0fate
		    #print '======= vm_map_t --> osfmk\\vm\\vm_map.h ========'
		    #print 'prev: %x'%vm_struct[0]
		    #print 'next: %x'%self.x86_mem_pae.vtop(vm_struct[1])
		    print ' [-] Virtual Address Start Point: 0x%x'%vm_struct[2]
		    print ' [-] Virtual Address End Point: 0x%x'%vm_struct[3]
		    print ' [-] Number of Entries: %x'%vm_struct[4] # number of entries
		    #print 'entries_pageable: %x'%vm_struct[5]
		    #print 'pmap_t: %x'%self.x86_mem_pae.vtop(vm_struct[6])
		    #print 'Virtual size: %x\n'%vm_struct[7]
    
		    vm_list = []
    
		    entry_next_ptr = vm_struct[1]
		    for data in range(0, vm_struct[4]): # number of entries
                        if self.os_version >= 11:
                            vm_list_ptr = self.x86_mem_pae.read(entry_next_ptr, 80)
                            vme_list = struct.unpack('=QQQQ40xQ', vm_list_ptr)
                        else:
                            vm_list_ptr = self.x86_mem_pae.read(entry_next_ptr, 56)
                            vme_list = struct.unpack('=QQQQ16xQ', vm_list_ptr)
			# *prev, *next, start, end
			vm_temp_list = []
			vm_temp_list.append(vme_list[2]) # start
			vm_temp_list.append(vme_list[3]) # end

			vm_list.append(vm_temp_list)
			# get permission at virtual memory ('rwx')
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
			
			print ' [-] Region from 0x%x to 0x%x (%s, max %s;))'%(vme_list[2], vme_list[3], permission, max_permission)
			#print 'prev: %x, next: %x, start:%x, end:%x'%(vme_list[0], vme_list[1], vme_list[2], vme_list[3])
			entry_next_ptr = vme_list[1]
       
		    if vm_struct[6] == 0: # pmap_t
			exit(1)
       
		    if not(self.x86_mem_pae.is_valid_address(vm_struct[6])):
			exit(1)
    
    ### 11.09.28 start n0fate
    
    # Mac OS X Lion
    # struct pmap {
    #	decl_simple_lock_data(,lock)	/* lock on map */
    #	pmap_paddr_t    pm_cr3;         /* physical addr */
    #	boolean_t       pm_shared;
    #        pd_entry_t      *dirbase;        /* page directory pointer */
    # #ifdef __i386__
    #	pmap_paddr_t    pdirbase;        /* phys. address of dirbase */
    #	vm_offset_t     pm_hold;        /* true pdpt zalloc addr */
    
		    if self.os_version >= 11:   # Lion xnu-1699
			pmap_info = self.x86_mem_pae.read(vm_struct[6], 16)
			pmap_struct = struct.unpack('=8xQ', pmap_info)
			pm_cr3 = pmap_struct[0]
		    else: # Leopard or Snow Leopard xnu-1456
			pmap_info = self.x86_mem_pae.read(vm_struct[6], 152)
			pmap_struct = struct.unpack('=QQ112xQQQ', pmap_info)
			pm_cr3 = pmap_struct[2]
    
    ### 11.09.28 end n0fate
			
			#print 'pmap_t'
			#print 'page directory pointer: %x'%pmap_struct[0] # int(pointer)
			#print 'phys.address of dirbase: %x'%pmap_struct[1] # uint64_t
			#print 'object to pde: %x'%pmap_struct[2]
			#print 'ref count: %x'%pmap_struct[3]
			#print 'nx_enabled: %x'%pmap_struct[4]
			#print 'task_map: %x'%pmap_struct[5]
	   
			#print 'pm_cr3: %x'%pmap_struct[6]
			#print 'pm_pdpt: %x'%pmap_struct[7]
			#print 'pm_pml4: %x'%pmap_struct[8]
    
		    
		    proc_pae = 0
		    print '[+] Resetting the Page Mapping Table: 0x%x'%pm_cr3
		    #if pmap_struct[5] == 0: # 32bit process
		    #    proc_pae = IA32PagedMemoryPae(FileAddressSpace(self.mempath), pm_cr3)
		    #else: # 64bit process Page Table module(ia32_pml4.py)
		    #    proc_pae = IA32PML4MemoryPae(FileAddressSpace(self.mempath), pm_cr3)
		    
		    if isMachoVolafoxCompatible(self.mempath):
			proc_pae = IA32PML4MemoryPae(MachoAddressSpace(self.mempath), pm_cr3)
		    else:
			proc_pae = IA32PML4MemoryPae(FileAddressSpace(self.mempath), pm_cr3)
		    
		    print '[+] Process Dump Start'
		    for vme_info in  vm_list:
			
			zero_code = 0x00 # 11.10.11 n0fate test
			pk_zero_code = struct.pack('=B', zero_code) # 11.10.11 n0fate test
			zero = pk_zero_code*0x1000
			
			file = open('%s-%x-%x'%(process_name, vme_info[0], vme_info[1]), mode="wb")
			
			zero_flag = 0 # 11.10.11 n0fate test
			for i in range(vme_info[0], vme_info[1], 0x1000):
			    raw_data = 0x00
			    if not(proc_pae.is_valid_address(i)):
				if zero_flag == 1:
				    raw_data = zero
				    file.write(raw_data)
				continue
			    raw_data = proc_pae.read(i, 0x1000)
			    if raw_data is None:
				if zero_flag == 1:
				    raw_data = zero
				    file.write(raw_data)
				continue
			    file.write(raw_data)
			    zero_flag = 1
			file.close()
			size = os.path.getsize('%s-%x-%x'%(process_name, vme_info[0], vme_info[1]))
			if size == 0:
			   os.remove('%s-%x-%x'%(process_name, vme_info[0], vme_info[1]))
			else:
			    print ' [-] [DUMP] Image Name: %s-%x-%x'%(process_name, vme_info[0], vme_info[1])
		    print '[+] Process Dump End'
		    return
		else:
		    if self.os_version >= 11: # Lion
			proclist = self.x86_mem_pae.read(data[0], 752+24);
			data = struct.unpack('=8xQQQQI668xI52sQ', proclist)
		    else:
			proclist = self.x86_mem_pae.read(data[0], 760);
			data = struct.unpack('=8xQQQQI652xI52sQ', proclist) # 24 bytes + 396 bytes padding(49 double value) + 33 bytes process name
        return 1

    # http://snipplr.com/view.php?codeview&id=14807
    def IntToDottedIP(self, intip):
        octet = ''
        for exp in [3,2,1,0]:
                octet = octet + str(intip / ( 256 ** exp )) + "."
                intip = intip % ( 256 ** exp )
        return(octet.rstrip('.'))
	
    # 2011.08.08
    # network information (inpcbinfo.hashbase, test code)
    # it can dump real network information. if rootkit has hiding technique.
    #################################################
    def net_info(self, sym_addr, pml4):
        network_list = []
        if isMachoVolafoxCompatible(self.mempath):
            net_pae = IA32PML4MemoryPae(MachoAddressSpace(self.mempath), pml4) 
        else:
            net_pae = IA32PML4MemoryPae(FileAddressSpace(self.mempath), pml4)
        
        if sym_addr == 0:
            return
        if not(net_pae.is_valid_address(sym_addr)):
            return

	if self.arch == 32:
	    #print 'Real Address (inpcbinfo): %x'%net_pae.vtop(sym_addr)
	    inpcbinfo_t = net_pae.read(sym_addr, 40)
	    inpcbinfo = struct.unpack('=IIIIII12xI', inpcbinfo_t)
    
	    if not(net_pae.is_valid_address(inpcbinfo[0])):
		return
    
	    print 'ipi_count: %d'%inpcbinfo[6]
	    #print 'Real Address (inpcbinfo[0]): %x'%net_pae.vtop(inpcbinfo[0])
	    loop_count = inpcbinfo[2]
    
	    #print 'hashsize:%d'%loop_count
    
	    for offset_hashbase in range(0, loop_count):
		inpcb_t = net_pae.read(inpcbinfo[0]+(offset_hashbase*4), 4)
		inpcb = struct.unpack('=I', inpcb_t)
		loop_addr = inpcb[0]
    
		if loop_addr == 0:
		    continue
		
		if not(net_pae.is_valid_address(loop_addr)):
		    break
		
		#print 'Real Address (inpcb): %x'%net_pae.vtop(inpcb[0])
		inpcb = net_pae.read(loop_addr+16, 112)
		in_network = struct.unpack('>HH48xI36xI12xI', inpcb) # fport, lport, flag, fhost, lhost
      #123 struct inpcb {
      #124         LIST_ENTRY(inpcb) inp_hash;     /* hash list */
      #125         int             inp_wantcnt;            /* pcb wanted count. protected by pcb list lock */
      #126         int             inp_state;              /* state of this pcb, in use, recycled, ready for recycling... */
      #127         u_short inp_fport;              /* foreign port */
      #128         u_short inp_lport;              /* local port */
      #129         LIST_ENTRY(inpcb) inp_list;     /* list for all PCBs of this proto */
      #130         caddr_t inp_ppcb;               /* pointer to per-protocol pcb */
      #131         struct  inpcbinfo *inp_pcbinfo; /* PCB list info */
      #132         struct  socket *inp_socket;     /* back pointer to socket */
      #133         u_char  nat_owner;              /* Used to NAT TCP/UDP traffic */
      #134         u_int32_t nat_cookie;           /* Cookie stored and returned to NAT */
      #135         LIST_ENTRY(inpcb) inp_portlist; /* list for this PCB's local port */
      #136         struct  inpcbport *inp_phd;     /* head of this list */
      #137         inp_gen_t inp_gencnt;           /* generation count of this instance */
      #138         int     inp_flags;              /* generic IP/datagram flags */
      #139         u_int32_t inp_flow;
      #140 
      #141         u_char  inp_vflag;      /* INP_IPV4 or INP_IPV6 */
      #142 
      #143         u_char inp_ip_ttl;              /* time to live proto */
      #144         u_char inp_ip_p;                /* protocol proto */
      #145         /* protocol dependent part */
      #146         union {
      #147                 /* foreign host table entry */
      #148                 struct  in_addr_4in6 inp46_foreign;
      #149                 struct  in6_addr inp6_foreign;
      #150         } inp_dependfaddr;
      #151         union {
      #152                 /* local host table entry */
      #153                 struct  in_addr_4in6 inp46_local;
      #154                 struct  in6_addr inp6_local;
      #155         } inp_dependladdr;
      
		network = []
		network.append(in_network[2])
		network.append(self.IntToDottedIP(in_network[3]))
		network.append(self.IntToDottedIP(in_network[4]))
		network.append(in_network[1])
		network.append(in_network[0])
	    
		#print 'Local Address: %s:%d, Foreign Address: %s:%d, flag:%x'%(self.IntToDottedIP(in_network[3]), in_network[1], self.IntToDottedIP(in_network[4]), in_network[0], in_network[2])
		network_list.append(network)

################# 64 bit ################
        else:
	    #print 'Real Address (inpcbinfo): %x'%net_pae.vtop(sym_addr)
	    inpcbinfo_t = net_pae.read(sym_addr, 72)
	    inpcbinfo = struct.unpack('=QQQQQQ16xQ', inpcbinfo_t)
    
	    if not(net_pae.is_valid_address(inpcbinfo[0])):
		return
    
	    print 'ipi_count: %d'%inpcbinfo[6]
	    #print 'Real Address (inpcbinfo[0]): %x'%net_pae.vtop(inpcbinfo[0])
	    loop_count = inpcbinfo[2]
    
	    #print 'hashsize:%d'%loop_count
    
	    for offset_hashbase in range(0, loop_count):
		inpcb_t = net_pae.read(inpcbinfo[0]+(offset_hashbase*8), 8)
		inpcb = struct.unpack('=Q', inpcb_t)
		loop_addr = inpcb[0]
    
		if loop_addr == 0:
		    continue
		
		if not(net_pae.is_valid_address(loop_addr)):
		    break
		
		#print 'Real Address (inpcb): %x'%net_pae.vtop(inpcb[0])
		inpcb = net_pae.read(loop_addr+24, 156)
		in_network = struct.unpack('>HH80xQ36xI20xI', inpcb) # fport, lport, flag, fhost, lhost
      #123 struct inpcb {
      #124         LIST_ENTRY(inpcb) inp_hash;     /* hash list */
      #125         int             inp_wantcnt;            /* pcb wanted count. protected by pcb list lock */
      #126         int             inp_state;              /* state of this pcb, in use, recycled, ready for recycling... */
      #127         u_short inp_fport;              /* foreign port */
      #128         u_short inp_lport;              /* local port */
      #129         LIST_ENTRY(inpcb) inp_list;     /* list for all PCBs of this proto */
      #130         caddr_t inp_ppcb;               /* pointer to per-protocol pcb */
      #131         struct  inpcbinfo *inp_pcbinfo; /* PCB list info */
      #132         struct  socket *inp_socket;     /* back pointer to socket */
      #133         u_char  nat_owner;              /* Used to NAT TCP/UDP traffic */
      #134         u_int32_t nat_cookie;           /* Cookie stored and returned to NAT */
      #135         LIST_ENTRY(inpcb) inp_portlist; /* list for this PCB's local port */
      #136         struct  inpcbport *inp_phd;     /* head of this list */
      #137         inp_gen_t inp_gencnt;           /* generation count of this instance */
      #138         int     inp_flags;              /* generic IP/datagram flags */
      #139         u_int32_t inp_flow;
      #140 
      #141         u_char  inp_vflag;      /* INP_IPV4 or INP_IPV6 */
      #142 
      #143         u_char inp_ip_ttl;              /* time to live proto */
      #144         u_char inp_ip_p;                /* protocol proto */
      #145         /* protocol dependent part */
      #146         union {
      #147                 /* foreign host table entry */
      #148                 struct  in_addr_4in6 inp46_foreign;
      #149                 struct  in6_addr inp6_foreign;
      #150         } inp_dependfaddr;
      #151         union {
      #152                 /* local host table entry */
      #153                 struct  in_addr_4in6 inp46_local;
      #154                 struct  in6_addr inp6_local;
      #155         } inp_dependladdr;
      
		network = []
		network.append(in_network[2])
		network.append(self.IntToDottedIP(in_network[3]))
		network.append(self.IntToDottedIP(in_network[4]))
		network.append(in_network[1])
		network.append(in_network[0])
	    
		#print 'Local Address: %s:%d, Foreign Address: %s:%d, flag:%x'%(self.IntToDottedIP(in_network[3]), in_network[1], self.IntToDottedIP(in_network[4]), in_network[0], in_network[2])
		network_list.append(network)
        return network_list

    # 2011.08.30 test code(plist chain)
    #################################################
    def net_info_test(self, sym_addr, pml4):
        network_list = []
        if isMachoVolafoxCompatible(self.mempath):
            net_pae = IA32PML4MemoryPae(MachoAddressSpace(self.mempath), pml4)
        else:
            net_pae = IA32PML4MemoryPae(FileAddressSpace(self.mempath), pml4)
        
        if sym_addr == 0:
            return
        if not(net_pae.is_valid_address(sym_addr)):
            return

	if self.arch == 32:
	    #print 'Real Address (inpcbinfo): %x'%net_pae.vtop(sym_addr)
	    inpcbinfo_t = net_pae.read(sym_addr, 40)
	    inpcbinfo = struct.unpack('=IIIIII12xI', inpcbinfo_t)
    
	    if not(net_pae.is_valid_address(inpcbinfo[5])):
		return
    
	    #print 'Real Address (inpcbinfo): %x'%net_pae.vtop(inpcbinfo[5])
    
	    temp_ptr = inpcbinfo[5] # base address
	    #list_t = net_pae.read(inpcbinfo[5], 4)
	    #temp_ptr = struct.unpack('=I', list_t)
    
	    #print 'Real Address (inpcbinfo): %x'%net_pae.vtop(temp_ptr)
	    
	    while net_pae.is_valid_address(temp_ptr):
		
		#print 'Real Address (inpcb): %x'%net_pae.vtop(inpcb[0])
		inpcb = net_pae.read(temp_ptr+16, 112)
		in_network = struct.unpack('>HHI44xI36xI12xI', inpcb) # fport, lport, flag, fhost, lhost
		
		network = []
		network.append(in_network[3])
		network.append(self.IntToDottedIP(in_network[4]))
		network.append(self.IntToDottedIP(in_network[5]))
		network.append(in_network[1])
		network.append(in_network[0])
	    
		#print 'Local Address: %s:%d, Foreign Address: %s:%d, flag:%x'%(self.IntToDottedIP(in_network[3]), in_network[1], self.IntToDottedIP(in_network[4]), in_network[0], in_network[2])
		network_list.append(network)
    
		temp_ptr = in_network[2]
	else:
	    #print 'Real Address (inpcbinfo): %x'%net_pae.vtop(sym_addr)
	    inpcbinfo_t = net_pae.read(sym_addr, 72)
	    inpcbinfo = struct.unpack('=QQQQQQ16xQ', inpcbinfo_t)
    
	    if not(net_pae.is_valid_address(inpcbinfo[5])):
		return
    
	    #print 'Real Address (inpcbinfo): %x'%net_pae.vtop(inpcbinfo[5])
    
	    temp_ptr = inpcbinfo[5] # base address
	    #list_t = net_pae.read(inpcbinfo[5], 4)
	    #temp_ptr = struct.unpack('=I', list_t)
    
	    #print 'Real Address (inpcbinfo): %x'%net_pae.vtop(temp_ptr)
	    
	    while net_pae.is_valid_address(temp_ptr):
		
		#print 'Real Address (inpcb): %x'%net_pae.vtop(inpcb[0])
		inpcb = net_pae.read(temp_ptr+24, 160)
		in_network = struct.unpack('>HHI80xQ36xI20xI', inpcb) # fport, lport, flag, fhost, lhost
		
		network = []
		network.append(in_network[3])
		network.append(self.IntToDottedIP(in_network[4]))
		network.append(self.IntToDottedIP(in_network[5]))
		network.append(in_network[1])
		network.append(in_network[0])
	    
		#print 'Local Address: %s:%d, Foreign Address: %s:%d, flag:%x'%(self.IntToDottedIP(in_network[3]), in_network[1], self.IntToDottedIP(in_network[4]), in_network[0], in_network[2])
		network_list.append(network)
    
		temp_ptr = in_network[2]
            
        return network_list

def usage():
    
    # LSOF: this usage statement has been reworked and adds research options
    
    '''
    TODO
    1. Replace existing commands with their CLI equivalents (e.g. proc_info --> ps)
    2. Use more conventional usage format
    3. Make -m/x/p/v suboptions of their respective commands
    4. Print all tables using new lsof print function
    5. kern_kext_info appears to be broken...
    '''
    
    print ''
    print 'volafox: release r52; lsof research build %s' %BUILD		# LSOF: build specification
    print 'project: http://code.google.com/p/volafox'
    print '   lsof: osxmem@gmail.com'
    print 'support: 10.6-7; 32/64-bit kernel'
    print '  input: *.vmem (VMWare memory file), *.mmr (Mac Memory Reader, flattened x86)'
    print '  usage: python %s -i IMAGE [-o COMMAND [-vp PID]][-m KEXT_ID][-x PID]\n' %sys.argv[0]
    
    print 'WARNING: this is an experimental development build adding support for listing'
    print '         open files. The code here is NOT in sync with project trunk.\n'
    
    print 'Options:'
    print '-o CMD : Print kernel information for CMD (below)'
    print '-p PID : List open files for PID (where CMD is "lsof")'
    print '-v     : Print all files, including unsupported types (where CMD is "lsof")'  
    print '-m KID : Dump kernel extension address space for KID'
    print '-x PID : Dump process address space for PID\n'
    print 'COMMANDS:'
    print 'os_version\tMac OS X build version (http://support.apple.com/kb/HT1159)'
    print 'machine_info\tkernel version, CPU, and memory specifications'
    print 'mount_info\tmounted filesystems'
    print 'kern_kext_info\tkernel KEXT (Kernel Extensions) listing'
    print 'kext_info\tKEXT (Kernel Extensions) listing'
    print 'proc_info\tprocess list'
    print 'syscall_info\tsyscall table'
    print 'net_info\tnetwork socket listing (hash table)'
    print 'lsof\t\topen files listing by process (research)'	# LSOF: new lsof command
#    print 'net_info_test\t network information(plist), (experiment)'

def main():
    mempath = ''
    oflag = ''
    pflag = 0			# LSOF: new pid flag
    vflag = 0			# LSOF: show debugging output and experimental options for lsof
    dflag = 0
    mflag = 0
    arch_num = 0
    pid = -1			# LSOF: relocated this definition

    try:
    	# LSOF: added -p flag for pid specification with lsof, -v no longer needs arg
        #option, args = getopt.getopt(sys.argv[1:], 'o:i:x:v:m:')
        option, args = getopt.getopt(sys.argv[1:], 'o:i:s:x:vm:p:')

    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit()

    debug = ""	# LSOF: debug string, print only with -v flag
    
    for op, p, in option:
        if op in '-o':  # data type
        
            # LSOF: add to debug string, no newline so -p can be added
            #print '[+] Information:', p
            debug += "[+] Command: %s" %p
            
            oflag = p
            
            # LSOF: new pid flag
            for i,x in enumerate(option):
            	if x[0] == '-p':
            		pid = int(x[1], 10)
            		pflag = 1;
            		del option[i]
            		debug += " -p %d" %pid
            
            debug += "\n"	# LSOF: replacing newline

        elif op in '-i': # physical memory image file
        	
            # LSOF: add to debug string
            #print '[+] Memory Image:', p
            debug += '[+] Memory Image: %s\n' %p
            
            mempath = p

        # LSOF: reworked this, it appears to have been unused (now shows debug string)
        elif op == '-v': # verbose
            #print 'Verbose:', p
            vflag = 1
       
        elif op =='-x':
        
            # LSOF: add to debug string
            #print '[+] Dump PID: %s'%p
            debug += '[+] Dump PID: %s\n' %p
            
            pid = int(p, 10)
            dflag = 1
        
        elif op =='-m':
        	
            # LSOF: add to debug string
            #print '[+] Dump KEXT: %s'%p
            debug += '[+] Dump KEXT: %s\n' %p
            
            kext_num = int(p, 10)
            mflag = 1
           
        else:
            #print '[+] Command error:', op	# LSOF: not printed, getopt catches this
            usage()
            sys.exit()
            
    # LSOF: all of this information now requires an explicit flag (or command error)
    if vflag:
    	print debug[:-1]

    if mempath == "" and ( oflag == 0 or dflag == 0 or mflag == 0):
        usage()
        sys.exit()

    # Auto switching code for using overlays or original mach-o files.  We should autopickle
    # using the original file.
##    if is_universal_binary(file_image):
##        macho_file = macho_an.macho_an(file_image)
##        arch_count = macho_file.load()
##
##        ## 11.11.22 n0fate
##        if arch_num is not 32 and arch_num is not 64:
##            macho_file.close()
##            sys.exit()
##        elif arch_num is 32:
##            header = macho_file.get_header(arch_count, macho_file.ARCH_I386)
##            symbol_list = macho_file.macho_getsymbol_x86(header[2], header[3])
##            macho_file.close()
##        elif arch_num is 64:
##            header = macho_file.get_header(arch_count, macho_file.ARCH_X86_64)
##            symbol_list = macho_file.macho_getsymbol_x64(header[2], header[3])
##            macho_file.close()
##    else:
##        #Added by CL
##        f = open(file_image, 'rb')
##        symbol_list = pickle.load(f)
##        f.close()
##
    m_volafox = volafox(mempath)

    ## get kernel version, architecture ##
    
    # LSOF: pass the verbose flag so debugging information can be optionally printed
    init_data = m_volafox.get_kernel_version(vflag)
    
    valid_format = init_data[0] # bool
    architecture = init_data[1] # integer
    kernel_version = init_data[2] # string
    build_number = init_data[3] # string

    ## check to valid image format
    if valid_format == 0:
        print '[+] WARNING: Invalid Linear File Format'
        print '[+] WARNING: If you have image using MMR, Converting memory image to linear file format'
        sys.exit()

    ## set architecture
    archRet = m_volafox.set_architecture(architecture)
    if archRet == 1:
        print '[+] WARNING: Invalied Architecture Information'
        sys.exit()

    if kernel_version is 'Darwin' or kernel_version is 'NotFound':
        print '[+] WARNING: Wrong Memory Image'
        sys.exit()

    ## open overlay file
    filepath = 'overlays/%sx%d.overlay'%(build_number, architecture)

    try:
        #print '[+] Open overlay file \'%s\''%filepath
        overlay_file = open(filepath, 'rb')
        symbol_list = pickle.load(overlay_file)
        overlay_file.close()
    except IOError:
        print '[+] WARNING: volafox can\'t open \'%s\''%filepath
        print '[+] WARNING: You can create overlay file running \'overlay_generator.py\''
        sys.exit()

    ## Setting Page Table Map
    nRet = m_volafox.init_vatopa_x86_pae(symbol_list['_IdlePDPT'], symbol_list['_IdlePML4'])
    if nRet == 1:
        print '[+]  WARNING: Memory Image Load Failed'
        sys.exit()

### 11.09.28 start n0fate
    ## Pre-loading Machine Information for storing Major Kernel Version
    ## It is used to code branch according to major kernel version
    m_volafox.machine_info(symbol_list['_machine_info'])
### 11.09.28 end n0fate    

    if mflag == 1:
        data_list = m_volafox.kext_info(symbol_list['_kmod'])
        for data in data_list:
            if data[2] == kext_num:
                print 'find kext, offset: %x, size: %x'%(data[7], data[8])
                m_volafox.kextdump(data[7], data[8], data[3].replace('\x00', '')) # addr, size, name
        sys.exit()
        
    if dflag == 1:
        m_volafox.vaddump(symbol_list['_kernproc'], pid)
        sys.exit()

    if oflag == 'os_version':
        data = m_volafox.os_info(symbol_list['_osversion'])
        sys.stdout.write('[+] Detail Darwin kernel version: %s'%data[0].strip('\x00'))
        sys.stdout.write('\n')
        sys.exit()

    elif oflag == 'machine_info':
    	# LSOF: looks better without newline
        #print '\n[+] Mac OS X Basic Information'
        print '[+] Mac OS X Basic Information'
        
        data = m_volafox.machine_info(symbol_list['_machine_info'])
        print ' [-] Major Version: %d'%data[0]
        print ' [-] Minor Version: %d'%data[1]
        print ' [-] Number of Physical CPUs: %d'%data[2]
        print ' [-] Size of memory in bytes: %d bytes'%data[3]
        print ' [-] Size of physical memory: %d bytes'%data[4]
        print ' [-] Number of physical CPUs now available: %d'%data[5]
        print ' [-] Max number of physical CPUs now possible: %d'%data[6]
        print ' [-] Number of logical CPUs now available: %d'%data[7]
        print ' [-] Max number of logical CPUs now possible: %d'%data[8]
        sys.exit()

    elif oflag == 'kern_kext_info':
        data = m_volafox.kernel_kext_info(symbol_list['_g_kernel_kmod_info'])
        print '\n-= Kernel Extentions(Kext) =-'
        sys.stdout.write( 'kmod_info_ptr\tinfo_version\tid\tname\tversion\treference_count\treference_list\taddress_ptr\tsize\thdr_size\tstart_ptr\tstop_ptr')
        sys.stdout.write('\n')

        sys.stdout.write('%.8x\t'%data[0])
        sys.stdout.write('%d\t'%data[1])
        sys.stdout.write('%d\t'%data[2])
        sys.stdout.write('%s\t'%data[3].strip('\x00'))
        sys.stdout.write('%s\t'%data[4].strip('\x00'))
        sys.stdout.write('%d\t'%data[5])
        sys.stdout.write('%.8x\t'%data[6])
        sys.stdout.write('%.8x\t'%data[7]) # address ptr
        sys.stdout.write('%d\t'%data[8]) # size
        sys.stdout.write('%d\t'%data[9])
        sys.stdout.write('%.8x\t'%data[10])
        sys.stdout.write('%.8x'%data[11])
        sys.exit()

    elif oflag == 'kext_info':
        data_list = m_volafox.kext_info(symbol_list['_kmod'])
        print '\n-= Kernel Extentions(Kext) =-'
        sys.stdout.write( 'kmod_info_ptr\tinfo_version\tid\tname\tversion\treference_count\treference_list\taddress_ptr\tsize\thdr_size\tstart_ptr\tstop_ptr')
        sys.stdout.write('\n')

        for data in data_list:
            sys.stdout.write('%.8x\t'%data[0])
            sys.stdout.write('%d\t'%data[1])
            sys.stdout.write('%d\t'%data[2])
            sys.stdout.write('%s\t'%data[3].strip('\x00'))
            sys.stdout.write('%s\t'%data[4].strip('\x00'))
            sys.stdout.write('%d\t'%data[5])
            sys.stdout.write('%.8x\t'%data[6])
            sys.stdout.write('%.8x\t'%data[7]) # address ptr
            sys.stdout.write('%d\t'%data[8]) # size
            sys.stdout.write('%d\t'%data[9])
            sys.stdout.write('%.8x\t'%data[10])
            sys.stdout.write('%.8x'%data[11])
            sys.stdout.write('\n')
        sys.exit()

    elif oflag == 'mount_info':
        data_list = m_volafox.mount_info(symbol_list['_mountlist'])
        print '\n-= Mount List =-'
        sys.stdout.write('list entry-next\tfstypename\tmount on name\tmount from name')
        sys.stdout.write('\n')
        for data in data_list:
            sys.stdout.write('%.8x\t'%data[0])
            sys.stdout.write('%s\t'%data[1].strip('\x00')) # char[16]
            sys.stdout.write('%s\t'%data[2].strip('\x00')) # char[1024]
            sys.stdout.write('%s'%data[3].strip('\x00')) # char[1024]
            sys.stdout.write('\n')
        sys.exit()

    elif oflag == 'proc_info':
        data_list = m_volafox.process_info(symbol_list['_kernproc'])
        print '\n-= process list =-'
        sys.stdout.write('list_entry_next\tpid\tppid\tprocess name\tusername')
        sys.stdout.write('\n')
        for data in data_list:
            sys.stdout.write('%.8x\t'%data[0]) # int
            sys.stdout.write('%d\t'%data[1]) # int
            sys.stdout.write('%d\t'%data[4]) # int
            sys.stdout.write('%s\t'%data[6].split('\x00', 1)[0]) # Changed by CL to read null formatted strings
            sys.stdout.write('%s\t'%data[8].strip('\x00'))
            sys.stdout.write('\n')

        sys.exit()
        
    # LSOF: lsof command branch
    elif oflag == 'lsof':
    	filelist = m_volafox.lsof(symbol_list['_kernproc'], pid, vflag)
    	if vflag:
    		print ""	# separate output from command specification
    	printfilelist(filelist)
    	sys.exit()

    elif oflag == 'syscall_info':
        data_list = m_volafox.syscall_info(symbol_list['_nsysent'])
        sym_name_list = symbol_list.keys()
        sym_addr_list = symbol_list.values()
        print '\n-= syscall list =-'
        print 'number\tsy_narg\tsy_resv\tsy_flags\tsy_call_ptr\tsy_arg_munge32_ptr\tsy_arg_munge64_ptr\tsy_ret_type\tsy_arg_bytes\tValid Function Address'
        count = 0
        for data in data_list:
            symflag = 0
            sys.stdout.write('%d\t'%count)
            sys.stdout.write('%d\t'%data[0])
            sys.stdout.write('%d\t'%data[1])
            sys.stdout.write('%d\t'%data[2])
            i = 0
            for sym_addr in sym_addr_list:
                if data[3] == sym_addr:
                    sys.stdout.write('%s\t'%sym_name_list[i])
                    symflag = 1
                i += 1
            if symflag != 1:
                sys.stdout.write('%x\t'%data[3])
            sys.stdout.write('%x\t'%data[4])
            sys.stdout.write('%x\t'%data[5])
            sys.stdout.write('%d\t'%data[6])
            sys.stdout.write('%d\t'%data[7])
            if symflag == 1:
                sys.stdout.write('valid function\n')
            else:
                sys.stdout.write('syscall hooking possible\n')
            count += 1

        sys.exit()

    elif oflag == 'net_info':
        print '\n-= NETWORK INFORMATION (hashbase) =-'
        network_list = m_volafox.net_info(symbol_list['_tcbinfo'], symbol_list['_IdlePML4'])
        for network in network_list:
            print '[TCP] Local Address: %s:%d, Foreign Address: %s:%d, flag: %x'%(network[1], network[3], network[2], network[4], network[0])
	    
	network_list = m_volafox.net_info(symbol_list['_udbinfo'], symbol_list['_IdlePML4'])
        for network in network_list:
            print '[UDP] Local Address: %s:%d, Foreign Address: %s:%d, flag: %x'%(network[1], network[3], network[2], network[4], network[0])
        sys.exit()

    elif oflag == 'net_info_test':
        print '\n-= NETWORK INFORMATION (plist) =-'
        network_list = m_volafox.net_info_test(symbol_list['_tcbinfo'], symbol_list['_IdlePML4'])
        for network in network_list:
            print '[TCP] Local Address: %s:%d, Foreign Address: %s:%d, flag: %x'%(network[1], network[3], network[2], network[4], network[0])
	    
	network_list = m_volafox.net_info_test(symbol_list['_udbinfo'], symbol_list['_IdlePML4'])
        for network in network_list:
            print '[UDP] Local Address: %s:%d, Foreign Address: %s:%d, flag: %x'%(network[1], network[3], network[2], network[4], network[0])
        sys.exit()

    else:
        print '[+] WARNING: -o Argument Error\n'
        sys.exit()

if __name__ == "__main__":
    main()
