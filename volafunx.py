#!/usr/bin/python
# -*- coding: utf-8 -*-
#  -*- mode: python; -*-
#
# volafunx
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

"""
@author:       Kyeongsik Lee
@license:      GNU General Public License 2.0 or later
@contact:      rapfer@gmail.com n0fate@live.com
"""

import getopt
import sys
import math
import os

import operator

import binascii

from x86 import *
from addrspace import FileAddressSpace
import elf_an # user-define class -> n0fate

BASE_ADDR = 0xc0000000

###############################################################################
#
# Class: volafunx_bsd() - 2010-09-30
# Dependency: x86.py in Volatility Framework for VA to PA
#
###############################################################################
class volafunx_bsd():
    def __init__(self, ptd, mempath):
        self.idleptd = ptd
        self.mempath = mempath
        self.data_list = []

    def init_vatopa_x86(self):
        if self.mempath == '' or self.idleptd == 0:
            return 1

        self.x86_mem = IA32PagedMemory(FileAddressSpace(self.mempath), self.idleptd)
        return 0

    def dump_kld(self, offset, size, kld_name):
	if not(self.x86_mem.is_valid_address(offset)):
	    print 'Invalid Offset'
	    return
	print '[+] filename: %s-%x-%x'%(kld_name, offset, offset+size)
	file = open('%s-%x-%x'%(kld_name, offset, offset+size), 'wba')
	data = self.x86_mem.read(offset, size);
	file.write(data)
	file.close()
	print '[+] KLD Dump Complete'
	return

    #
    # 2011. 05. 09
    # change to dump style using 'p_hash'
    #
    def dump_process(self, sym_addr, pid):
    	print '[+] Dump Process ID: %d'%pid

        if sym_addr == 0:
            return
        if not(self.x86_mem.is_valid_address(sym_addr)):
            return
        try:
            p_hash_t = self.x86_mem.read(sym_addr+108, 4);
            data = struct.unpack('=I', p_hash_t)
            sym_addr = data[0]
            #print 'Real Address: %.8x'%self.x86_mem.vtop(data[1])
                
        except struct.error:
            print 'Failed to dump PID: %d'%pid
            return

        #  i can't find hash_size value. so i set up to access only 512 bytes. ;p
        for hash_count in range(0, 128):
            hash_offset = self.x86_mem.read(sym_addr+(hash_count*4), 4)
            proc_offset = struct.unpack('=I', hash_offset)
            if proc_offset[0] is 0:
                continue
            elif not(self.x86_mem.is_valid_address(proc_offset[0])):
                continue
            
	    proclist = self.x86_mem.read(proc_offset[0], 540)
	    data = struct.unpack('=4xI92xI16xI88xI300x20sI', proclist)

	    if data[1] == pid:
		print ' [-] process name: %s'%data[4]
		print ' [-] vmspace: %x'%data[3]

		vm_map_entry = self.x86_mem.read(data[3], 200)
		vm_entry = struct.unpack('=II8xII172xI', vm_map_entry)
		#print 'prev: %x'%vm_entry[0]
		#print 'next: %x'%vm_entry[1]
		print ' [-] start: %x'%vm_entry[2]
		print ' [-] end: %x'%vm_entry[3]
		print ' [-] VAD CR3: %x'%vm_entry[4]

		next_addr = vm_entry[1]
		cr3 = self.x86_mem.vtop(vm_entry[4]) # get real address
		print ' [-] PHYS CR3: %x'%cr3

		base_start = vm_entry[2]
		base_end = vm_entry[3]

		vad_list = []

		while 1:
		    if next_addr == 0:
                        break
		    if not(self.x86_mem.is_valid_address(next_addr)):
                        break
		    if vm_entry[0] == vm_entry[1]:
                        temp_list.append(vm_entry[2]) # start
                        temp_list.append(vm_entry[3]) # end
                        vad_list.append(temp_list)
                        break
		    vm_map_entry = self.x86_mem.read(next_addr, 24)
		    vm_entry = struct.unpack('=II8xII', vm_map_entry)
		    
		    next_addr = vm_entry[1]
		    #print 'prev: %x'%vm_entry[0]
		    #print 'next: %x'%vm_entry[1]
		    #print '%x - %x'%(vm_entry[2], vm_entry[3]) # start - end
		    temp_list = []
		    temp_list.append(vm_entry[2]) # start
		    temp_list.append(vm_entry[3]) # end
	
		    vad_list.append(temp_list)
		    
		    next_addr = vm_entry[1]

		    if vm_entry[3] == base_end:
			print '[+] END VAD DUMP LIST'
			break

		x86_proc_mem = IA32PagedMemory(FileAddressSpace(self.mempath), cr3)
		print '[+] VAD DUMP START'
		for vad in vad_list:
		    start_addr = vad[0]
		    end_addr = vad[1]
		    file = open('%s-%x-%x'%(data[4].replace('\x00',''), start_addr, end_addr), mode="wb")
		    print ' [-] [DUMP] Image Name: %s-%x-%x'%(data[4].replace('\x00',''), start_addr, end_addr)
		    #print '[DUMP] start: %x, end: %x'%(start_addr, end_addr)

		    count = 0x00000000
		    for count in range(start_addr, end_addr, 0x1000):
			if not(x86_proc_mem.is_valid_address(count)):
				continue
			raw_data = x86_proc_mem.read(count, 0x1000)
			if raw_data is None:
				continue
			file.write(raw_data)
		    file.close()
		    size = os.path.getsize('%s-%x-%x'%(data[4].replace('\x00',''), start_addr,end_addr))
		    if size == 0:
			os.remove('%s-%x-%x'%(data[4].replace('\x00',''), start_addr,end_addr))
			print ' [-] [DUMP] File Removed (File Size: 0)'
		print '[+] VAD DUMP COMPLETE'
		return
		    

	    
  #416 struct pmap {
  #417         struct mtx              pm_mtx;
  #418         pd_entry_t              *pm_pdir;       /* KVA of page directory */ if PAE: 64bit, else 32bit
  #419         TAILQ_HEAD(,pv_chunk)   pm_pvchunk;     /* list of mappings in pmap */
  #420         u_int                   pm_active;      /* active on cpus */ --> 32bit
  #421         struct pmap_statistics  pm_stats;       /* pmap statistics */ --> 12 bytes
  #422         LIST_ENTRY(pmap)        pm_list;        /* List of all pmaps */ --> 8 bytes
  #423 #ifdef PAE
  #424         pdpt_entry_t            *pm_pdpt;       /* KVA of page director pointer
  #425                                                    table */ --> 32bits
  #426 #endif
  #427         vm_page_t               pm_root;        /* spare page table pages */
  #428 };

    ## structure ######
    # /usr/src/sys/sys/proc.h
    #####################
    def process_info(self, sym_addr):
        proc_list = []

        while 1:
            if sym_addr == 0:
                break
            if not(self.x86_mem.is_valid_address(sym_addr)):
                break
            try:
                proclist = self.x86_mem.read(sym_addr, 540);
                data = struct.unpack('=4xI92xI16xI392x20sI', proclist)
                sym_addr = data[0]
                
                if sym_addr == 0:
                    break

		pgrp_t = self.x86_mem.read(data[4], 16); # pgrp structure
                m_pgrp = struct.unpack('=IIII', pgrp_t)

		i = 0
		m_session = ''
		while 1:
		    session_t = self.x86_mem.read(m_pgrp[3]+20+i, 1); # session structure
		    if session_t == '\x00':
			break
		    m_session = m_session + session_t
		    i = i + 1
                #m_session = struct.unpack('=IIIII', session_t)
                data += (str(m_session), )
                proc_list.append(data)
                
            except struct.error:
                break
        return proc_list

    # Last modified date: 2011. 05. 09
    def process_info_hash(self, sym_addr):
        proc_list = []

        if sym_addr == 0:
            return
        if not(self.x86_mem.is_valid_address(sym_addr)):
            return
        try:
            p_hash_t = self.x86_mem.read(sym_addr+108, 4);
            data = struct.unpack('=I', p_hash_t)
            sym_addr = data[0]
            #print 'Real Address: %.8x'%self.x86_mem.vtop(data[1])
                
        except struct.error:
            return

        #  i can't find hash_size value. so i set up to access only 512 bytes. ;p
        for hash_count in range(0, 128):
            hash_offset = self.x86_mem.read(sym_addr+(hash_count*4), 4)
            proc_offset = struct.unpack('=I', hash_offset)
            if proc_offset[0] is 0:
                continue
            elif not(self.x86_mem.is_valid_address(proc_offset[0])):
                continue           
            try:
                proclist = self.x86_mem.read(proc_offset[0], 540);
                data = struct.unpack('=4xI92xI4x4x8xI392x20sI', proclist)
                #print 'Real Address: %.8x'%self.x86_mem.vtop(proc_offset[0])

                pgrp_t = self.x86_mem.read(data[4], 16); # pgrp structure
                m_pgrp = struct.unpack('=IIII', pgrp_t)

                i = 0
                m_session = ''
                while 1:
                    session_t = self.x86_mem.read(m_pgrp[3]+20+i, 1); # session structure
                    if session_t == '\x00':
                        break
                    m_session = m_session + session_t
                    i = i + 1
                data += (str(m_session), )
                proc_list.append(data)
                    
            except struct.error:
                continue    
        return proc_list
    
    ## structure ######
    # 'thread0' in kernel symbol has start address on thread chain.
    # this function can be find every process hiding skill.
    # /usr/src/sys/sys/proc.h
    #####################
    def thread_info(self, sym_addr):
	thread_list = []

	while 1:
	    if sym_addr == 0:
		break
	    if not(self.x86_mem.is_valid_address(sym_addr)):
		break
	    try:
		thread_t = self.x86_mem.read(sym_addr+4, 36)
		thread = struct.unpack('=I4xI4xI4xI4xI', thread_t)
		sym_addr = thread[3] # Run queue
		print '%x'%self.x86_mem.vtop(sym_addr)
		
		thread_ptr = self.x86_mem.read(sym_addr, 4)
		thread_real = struct.unpack('=I', thread_ptr)
		print '%x'%self.x86_mem.vtop(thread_real[0])
		
		sym_addr = thread_real[0]
		
		thread_list.append(thread[0]) # td_proc
		print 'proc: %x'%thread[0]
	    except struct.error:
		break

	proc_list = []

        for sym_addr in thread_list:
            if sym_addr == 0:
                break
            if not(self.x86_mem.is_valid_address(sym_addr)):
                break
            try:
                proclist = self.x86_mem.read(sym_addr, 540);
                data = struct.unpack('=4xI92xI16xI392x20sI', proclist)
                #sym_addr = data[0]
               
                #if sym_addr == 0:
                #    break

		pgrp_t = self.x86_mem.read(data[4], 16); # pgrp structure
                m_pgrp = struct.unpack('=IIII', pgrp_t)

		i = 0
		m_session = ''
		while 1:
		    session_t = self.x86_mem.read(m_pgrp[3]+20+i, 1); # session structure
		    if session_t == '\x00':
			break
		    m_session = m_session + session_t
		    i = i + 1
                #m_session = struct.unpack('=IIIII', session_t)
                data += (str(m_session), )
                proc_list.append(data)
                
            except struct.error:
                break
        return proc_list

    ## structure #####
    # linker_file structure
    # /usr/src/sys/sys/linker.h
    #############################
    def kld_info(self, sym_addr):
	kld_list = []
	kld_map = {}

	module_list = []
        module_map = {}
	
	if sym_addr == 0:
            return
        if not(self.x86_mem.is_valid_address(sym_addr)):
            return
	kld_ptr = self.x86_mem.read(sym_addr, 4)
	data = struct.unpack('=I', kld_ptr)
	sym_addr = data[0] # get real KLD Listhead
	match_value = sym_addr # for sorting module info
	#print 'Real KLD Address: %x'%self.x86_mem.vtop(sym_addr)
	    
        while 1:
            
            if sym_addr == 0:
                break
            if not(self.x86_mem.is_valid_address(sym_addr)):
                break
            try:
                kld = self.x86_mem.read(sym_addr, 64)
                data = struct.unpack('=4xII4xIIIIIII16xI', kld)
                sym_addr = data[2] # next kld
                #print 'KLD Next Address: %x'%self.x86_mem.vtop(sym_addr)
                #print 'Module Address: %x'%self.x86_mem.vtop(data[9])

		if self.x86_mem.is_valid_address(data[4]):
		    filename = ''
		    i = 0
		    while 1:
			bytefilename = self.x86_mem.read(data[4] + i, 1)
			if bytefilename == '\x00':
			    kld_map[data[4]] = filename
			    break
			filename = filename + bytefilename
			i = i + 1
		flag = 0
		if self.x86_mem.is_valid_address(data[5]):
		    filepath = ''
		    i = 0
		    while 1:
			bytefilename = self.x86_mem.read(data[5] + i, 1)
			if bytefilename == '\x00':
			    kld_map[data[5]] = filepath
			    flag = 1
			    break
			filepath = filepath + bytefilename
			i = i + 1

		if flag == 0:
                    break
                
                kld_list.append(data)

#   49 struct module {
#   50         TAILQ_ENTRY(module)     link;   /* chain together all modules */
#   51         TAILQ_ENTRY(module)     flink;  /* all modules in a file */
#   52         struct linker_file      *file;  /* file which contains this module */
#   53         int                     refs;   /* reference count */
#   54         int                     id;     /* unique id number */
#   55         char                    *name;  /* module name */
#   56         modeventhand_t          handler;        /* event handler */
#   57         void                    *arg;   /* argument for handler */
#   58         modspecific_t           data;   /* module specific data */
#   59 };
		module_ptr = data[9]
                check_addr = 0
                while 1:
                    if not(self.x86_mem.is_valid_address(module_ptr)):
                        break
                    module = self.x86_mem.read(module_ptr, 36)
                    data = struct.unpack('=8xI4xIIIII', module)

                    module_ptr = data[0] # module address
                    
                    #if check_addr == module_ptr:
                        #break
                    
#print 'ModuleAddress: %x'%self.x86_mem.vtop(data[0])
                    if check_addr == 0:
                        check_addr = data[0] # prevent to loop
                    
                    if self.x86_mem.is_valid_address(data[4]): # module name address
                        filename = ''
                        i = 0
                        while 1:
                            bytefilename = self.x86_mem.read(data[4] + i, 1)
                            if bytefilename == '\x00':
                                module_map[data[4]] = filename
                                #print filename
                                break
                            filename = filename + bytefilename
                            i = i + 1
                            
                        module_list.append(data)
		
            except struct.error:
                break
        return kld_list, kld_map, module_list, module_map, match_value

    # http://snipplr.com/view.php?codeview&id=14807
    def IntToDottedIP(self, intip):
        octet = ''
        for exp in [3,2,1,0]:
                octet = octet + str(intip / ( 256 ** exp )) + "."
                intip = intip % ( 256 ** exp )
        return(octet.rstrip('.'))

    # 2011.04.28
    # I study bsd that store network information now.
    # Maybe I'll complete this within next month.
    #
    # 2011.05.09
    # Now, this module can show tcp session information(ip, port).
    # This module has some vulnerability. if rootkit has hiding technique on LIST_REMOVE(listhead)
    #################################################
    def net_info(self, sym_addr):
        network_list = []
        if sym_addr == 0:
            return
        if not(self.x86_mem.is_valid_address(sym_addr)):
            return

        tcbinfo_t = self.x86_mem.read(sym_addr, 8)
        tcbinfo = struct.unpack('=II', tcbinfo_t)
        ipi_count = tcbinfo[1]

        if not(self.x86_mem.is_valid_address(tcbinfo[0])):
            return
        ipi_listhead_t = self.x86_mem.read(tcbinfo[0], 8)
        ipi_listhead = struct.unpack('=II', ipi_listhead_t)

#        print 'Real Address: %x'%self.x86_mem.vtop(ipi_listhead[0])

#  175         /* Local and foreign ports, local and foreign addr. */
#  176         struct  in_conninfo inp_inc;    /* (i/p) list for PCB's local port */

        loop_addr = ipi_listhead[0]
        temp_ipi_count = ipi_count
        while 1:
            if loop_addr == 0:
                if temp_ipi_count > 0:
                    print 'LIST_REMOVE(inpcb) found. You can find hiding network information using "net_info_real" option'
                return network_list
            if not(self.x86_mem.is_valid_address(loop_addr)):
                if temp_ipi_count > 0:
                    print 'LIST_REMOVE(inpcb) found. You can find hiding network information using "net_info_real" option'
                return network_list

            temp_ipi_count = temp_ipi_count - 1
            
            inpcb = self.x86_mem.read(loop_addr, 40)
            in_endpoint = struct.unpack('=8xI4x20xI', inpcb)

            inpcb_net = self.x86_mem.read(loop_addr+88+4, 36)
            in_network = struct.unpack('!HH8x4xI8x4xI', inpcb_net)
            
 #           print 'Real Address: %x'%self.x86_mem.vtop(in_endpoint[0])
            loop_addr = in_endpoint[0]
            inp_flag = in_endpoint[1]

#  101 struct in_conninfo {
#  102         u_int8_t        inc_flags;
#  103         u_int8_t        inc_len;
#  104         u_int16_t       inc_fibnum;     /* XXX was pad, 16 bits is plenty */
#  105         /* protocol dependent part */
#  106         struct  in_endpoints inc_ie;
#  107 };
            network = []
            network.append(self.IntToDottedIP(in_network[3]))
            network.append(self.IntToDottedIP(in_network[2]))
            network.append(in_network[1])
            network.append(in_network[0])
            network.append(inp_flag)
        
#   77 struct in_endpoints {
#   78         u_int16_t       ie_fport;               /* foreign port */
#   79         u_int16_t       ie_lport;               /* local port */
#   80         /* protocol dependent part, local and foreign addr */
#   81         union {
#   82                 /* foreign host table entry */
#   83                 struct  in_addr_4in6 ie46_foreign;
#   84                 struct  in6_addr ie6_foreign;
#   85         } ie_dependfaddr;
#   86         union {
#   87                 /* local host table entry */
#   88                 struct  in_addr_4in6 ie46_local;
#   89                 struct  in6_addr ie6_local;
#   90         } ie_dependladdr;
#   91 };
            #print 'Local Address: %s:%d, Foreign Address: %s:%d, flag: %x'%(self.IntToDottedIP(in_network[3]), in_network[1], self.IntToDottedIP(in_network[2]), in_network[0], inp_flag)
            network_list.append(network)
            
        return network_list

    # 2011.05.09
    # Real network information (tcbinfo.ipi_hashbase)
    # it can find network information. if rootkit has hiding technique.
    #################################################
    def net_info_hash(self, sym_addr):
        network_list = []
        
        if sym_addr == 0:
            return
        if not(self.x86_mem.is_valid_address(sym_addr)):
            return

        #print 'Real Address (tcb_info): %x'%self.x86_mem.vtop(sym_addr)
        tcbinfo_t = self.x86_mem.read(sym_addr+8, 16)
        tcbinfo = struct.unpack('=IIII', tcbinfo_t)

        # struct inpcbhead *ipi_listhead;
        # u_int ipi_count;
        # struct inpcbhead *ipi_hashbase;
        # u_long ipi_hashmask;
        # struct inpcbporthead *ipi_porthashbase
        # u_long ipi_porthashmask;

        if not(self.x86_mem.is_valid_address(tcbinfo[0])):
            return

        # tcbinfo -> struct inpcbinfo
        #print 'Real Address (ipi_hashbase): %x'%self.x86_mem.vtop(tcbinfo[0])
        #print 'tcbinfo.ipi_hashmask (cycle): %d'%tcbinfo[1]
        #print 'Real Address (ipi_porthashbase): %x'%self.x86_mem.vtop(tcbinfo[2])
        #print 'tcbinfo.ipi_porthashmask: %d'%tcbinfo[3]

        loop_count = tcbinfo[1]

        for offset_hashbase in range(0, loop_count + 1):
            inpcb_t = self.x86_mem.read(tcbinfo[0]+(offset_hashbase*4), 4)
            inpcb = struct.unpack('=I', inpcb_t)
            loop_addr = inpcb[0]

            if loop_addr == 0:
                continue
            
            if not(self.x86_mem.is_valid_address(loop_addr)):
                break
            
            inpcb = self.x86_mem.read(loop_addr, 40)
            in_endpoint = struct.unpack('=8xI4x20xI', inpcb)

            inpcb_net = self.x86_mem.read(loop_addr+92, 36)
            in_network = struct.unpack('!HH8x4xI8x4xI', inpcb_net)

            inp_flag = in_endpoint[1]

#  101 struct in_conninfo {
#  102         u_int8_t        inc_flags;
#  103         u_int8_t        inc_len;
#  104         u_int16_t       inc_fibnum;     /* XXX was pad, 16 bits is plenty */
#  105         /* protocol dependent part */
#  106         struct  in_endpoints inc_ie;
#  107 };
            network = []
            network.append(self.IntToDottedIP(in_network[3]))
            network.append(self.IntToDottedIP(in_network[2]))
            network.append(in_network[1])
            network.append(in_network[0])
            network.append(int(inp_flag))
        
#   77 struct in_endpoints {
#   78         u_int16_t       ie_fport;               /* foreign port */
#   79         u_int16_t       ie_lport;               /* local port */
#   80         /* protocol dependent part, local and foreign addr */
#   81         union {
#   82                 /* foreign host table entry */
#   83                 struct  in_addr_4in6 ie46_foreign;
#   84                 struct  in6_addr ie6_foreign;
#   85         } ie_dependfaddr;
#   86         union {
#   87                 /* local host table entry */
#   88                 struct  in_addr_4in6 ie46_local;
#   89                 struct  in6_addr ie6_local;
#   90         } ie_dependladdr;
#   91 };
            #print 'Local Address: %s:%d, Foreign Address: %s:%d, flag: %x'%(self.IntToDottedIP(in_network[3]), in_network[1], self.IntToDottedIP(in_network[2]), in_network[0], inp_flag)
            network_list.append(network)
            
        return network_list

    ## structure ######
    # narg
    # sy_call
    # /usr/src/sys/sys/sysent.h
    #####################
    def sysent_info(self, sym_addr):
        sycall_list = []
        if sym_addr == 0:
            return
        
        if not(self.x86_mem.is_valid_address(sym_addr)):
            return
        
        i = 0
        while 1:
            sysent_t = self.x86_mem.read(sym_addr + (i*28), 28)
            sysent = struct.unpack('=IIIIIII', sysent_t)
            
            if sysent[1] == 0:
                break 
            
            sycall_list.append(sysent)
            i = i + 1
                
        return sycall_list # system call list
    
    def hooking_detect(self, sysent, sym_addr_list):
        i = 0
        for sym_addr in sym_addr_list:
            if sysent[1] == sym_addr:
                return i
            i = i + 1       
        return -1

def usage():
    print 'Memory analyzer for FreeBSD - n0fate'
    print 'Code Generated Time: 2011. 05. 09'
    print 'Contact: rapfer@gmail.com'
    print 'usage: python %s -i MEMORY_IMAGE -s KERNEL_IMAGE -[o INFORMATION][-m module id][-x pid] -v [0 or 1]\n'%sys.argv[0]
    print '-= CAUTION =-'
    print 'This program need to physical memory image, kernel image'
    print 'It support to Intel x86 architecture\n'
    print 'Option:'
    print '-o\t Gathering information using symbol information:'
    print '-m\t Dump module using module id'
    print '-x\t Dump process using pid'
    print '-v\t more information (KLD Module)\n'
    print 'INFORMATION:'
    print 'proc_info\t process list'
    print 'proc_info_hash\t process list(bypass basic hiding technique)'
    print 'syscall_info\t system call list (hooking detection)'
    print 'kld_info\t KLD list'
    print 'net_info\t Network connection'
    print 'net_info_hash\t Network connection(bypass hiding technique)'

def main():
    file_image = ''
    mempath = ''
    oflag = '' # information
    vflag = 0 # verbose
    dflag = 0 # process dump
    mflag = 0 # module dump
    kld_num = 0

    try:
        option, args = getopt.getopt(sys.argv[1:], 'o:i:s:x:v:m:')

    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit()

    for op, p, in option:
        if op in '-o':  # data type
            print '[+] Information:', p
            oflag = p

        elif op in '-i': # physical memory image file
            print '[+] Memory Image:', p
            mempath = p

        elif op == '-s': # physical memory image file
            print '[+] Kernel Image:', p
            file_image = p

        elif op == '-v': # verbose
            print '[+] Verbose:', p
            vflag = 1 # true
        
        elif op =='-x': # Dump PID
            print '[+] Dump PID: %s'%p
            pid = int(p, 10)
            dflag = 1
	
        elif op =='-m': # Dump Module
            print '[+] Dump Module: %s'%p
            kld_num = int(p, 10)
            mflag = 1
            
        else:
            print 'Command error:', op
            usage()
            sys.exit()

    if mempath == "" or file_image == "" and ( oflag == 0 or dflag == 0 or mflag == 0):
        usage()
        sys.exit()

    
    ########## symbol load #############
    print '[+] Loading Kernel Symbol Information - Start'
    elf = elf_an.elf32_an(file_image)
    nret = elf.load()
    if 0 == nret:
        return 0
    
    header = elf.getheader()
    shoff = elf.getshoff()
    if 0 == shoff:
        return 0
    
    shsize = elf.getshsize()
    shcount = elf.getshcount()

    section_header = elf.getsymsec(shoff, shsize, shcount)
    strtab_header = elf.getstrsec(shoff, shsize, shcount)
    
    symbol_list = elf.getsymbol(section_header[4], section_header[5], strtab_header[4], strtab_header[5])
    elf.close()
    print '[+] Loading Kernel Symbol Information - Complete'
    ####################################################
    ## 32bit
    IdlePTD = symbol_list['IdlePTD']
    if IdlePTD == 0:
        print '[+] Can not find IdlePTD symbol'
        sys.exit()
    
    ## read page directory table base address
    physIdlePTD = IdlePTD - BASE_ADDR # BSD 8.0 Based
    file = open(mempath, 'rb')
    file.seek(physIdlePTD)
    ptd_addr = struct.unpack('=I', file.read(4))
    file.close()
    #########################################
    
    # IdlePTD, Memory Path
    m_volafunx = volafunx_bsd(ptd_addr[0], mempath)
    nRet = m_volafunx.init_vatopa_x86()

    ## process
    if nRet == 1:
        print '[+] Memory Image Load Failed'
        sys.exit()
    
    if dflag == 1:
	m_volafunx.dump_process(symbol_list['proc0'], pid)
	sys.exit()
    
    if mflag == 1:
	kld_list = m_volafunx.kld_info(symbol_list['linker_files'])
	
	kld_info = kld_list[0]
	kld_map = kld_list[1]

	for kld in kld_info:
	    if kld[6] == kld_num:
		print '[+] Find kernel module, offset: %x, size: %x'%(kld[7], kld[8])
		m_volafunx.dump_kld(kld[7], kld[8], kld_map[kld[4]]) # offset, size, kld name
	sys.exit()

    if oflag == 'proc_info':
        data_list = m_volafunx.process_info(symbol_list['proc0'])
        print '\n-= PROCESS LIST =-'
        sys.stdout.write('list_entry_next\tpid\tppid\tprocess name\tusername')
        sys.stdout.write('\n')
        
	index1 = operator.itemgetter(1)
	data_list.sort(None, index1)
        temp_list = data_list
        for data in data_list:
            sys.stdout.write('%.8x\t'%data[0]) # next ptr
            sys.stdout.write('%d\t'%data[1]) # pid
            
            ## find ppid ##
            if data[2] == 0:
                sys.stdout.write('%d\t'%data[2]) # ppid
            
            else:
                find_ppid = 0
                for get_ppid in temp_list:
                    if get_ppid[0] == data[2]:
                        find_ppid = 1
                        continue
                    if find_ppid == 1:
                        sys.stdout.write('%d\t'%get_ppid[1]) # ppid
                        break
		if find_ppid == 0:
		    sys.stdout.write('0\t')
            ################
            
            sys.stdout.write('%s\t'%data[3].strip('\x00')) # process name
	    sys.stdout.write('%s\t'%data[5].strip('\x00')) # username
            sys.stdout.write('\n')
        return

    elif oflag == 'proc_info_hash':
        data_list = m_volafunx.process_info_hash(symbol_list['proc0'])
        print '\n-= PROCESS LIST =-'
        sys.stdout.write('list_entry_next\tpid\tppid\tprocess name\tusername')
        sys.stdout.write('\n')
        
	index1 = operator.itemgetter(1)
	data_list.sort(None, index1)
        temp_list = data_list
        for data in data_list:
            sys.stdout.write('%.8x\t'%data[0]) # next ptr
            sys.stdout.write('%d\t'%data[1]) # pid
            
            ## find ppid ##
            if data[2] == 0:
                sys.stdout.write('%d\t'%data[2]) # ppid
            
            else:
                find_ppid = 0
                for get_ppid in temp_list:
                    if get_ppid[0] == data[2]:
                        find_ppid = 1
                        continue
                    if find_ppid == 1:
                        sys.stdout.write('%d\t'%get_ppid[1]) # ppid
                        break
		if find_ppid == 0:
		    sys.stdout.write('0\t')
            ################
            
            sys.stdout.write('%s\t'%data[3].strip('\x00')) # process name
	    sys.stdout.write('%s\t'%data[5].strip('\x00')) # username
            sys.stdout.write('\n')
        return
    
    elif oflag == 'proc_info_thread':
        data_list = m_volafunx.thread_info(symbol_list['thread0'])
        print '\n-= PROCESS LIST =-'
        sys.stdout.write('list_entry_next\tpid\tppid\tprocess name\tusername')
        sys.stdout.write('\n')
        
	index1 = operator.itemgetter(1)
	data_list.sort(None, index1)
        temp_list = data_list
        for data in data_list:
            sys.stdout.write('%.8x\t'%data[0]) # next ptr
            sys.stdout.write('%d\t'%data[1]) # pid
            
            ## find ppid ##
            if data[2] == 0:
                sys.stdout.write('%d\t'%data[2]) # ppid
            
            else:
                find_ppid = 0
                for get_ppid in temp_list:
                    if get_ppid[0] == data[2]:
                        find_ppid = 1
                        continue
                    if find_ppid == 1:
                        sys.stdout.write('%d\t'%get_ppid[1]) # ppid
                        break
		if find_ppid == 0:
		    sys.stdout.write('0\t')
            ################
            
            sys.stdout.write('%s\t'%data[3].strip('\x00')) # process name
	    sys.stdout.write('%s\t'%data[5].strip('\x00')) # username
            sys.stdout.write('\n')
        return
    
    elif oflag == 'syscall_info':
        print '\n-= SYSTEMCALL INFORMATION =-'
        sys.stdout.write('count\targ\tfunction\thooking detection\n')
        sym_name_list = symbol_list.keys()
        
        syscall_list = m_volafunx.sysent_info(symbol_list['sysent'])
        
        count = 0
        for sysent in syscall_list:
            sys.stdout.write('%d\t'%count)
            count = count + 1
            
            sys.stdout.write('%d\t'%sysent[0])
            func = m_volafunx.hooking_detect(sysent, symbol_list.values())
            if func == -1:
                sys.stdout.write('%x\t\t'%sysent[1])
                sys.stdout.write('invalid function')
            else:
                sys.stdout.write('%s\t\t'%sym_name_list[func])
                sys.stdout.write('valid function')
            sys.stdout.write('\n')
    
    elif oflag == 'kld_info':
	print '\n-= KLD INFORMATION =-'
	sys.stdout.write('id\trefs\turefs\tname\tfile path\t\tlkm address\tlkm size\n')
	kld_list = m_volafunx.kld_info(symbol_list['linker_files'])
	
	kld_info = kld_list[0]
	kld_map = kld_list[1]
	module_info = kld_list[2]
	module_map = kld_list[3]
	match_value = kld_list[4]

	for kld in kld_info:
	    sys.stdout.write('%d\t'%kld[6]) # id
	    sys.stdout.write('%d\t'%kld[0]) # reference
	    sys.stdout.write('%d\t'%kld[1]) # user reference
	    sys.stdout.write('%s\t'%kld_map[kld[4]]) # name
	    sys.stdout.write('%s\t'%kld_map[kld[5]]) # path
	    sys.stdout.write('%x\t'%kld[7]) # virtual address
	    sys.stdout.write('%x'%kld[8]) # size
	    sys.stdout.write('\n')
	    
            if vflag == 1:
                for module in module_info:
                    if match_value == module[1]:
                        sys.stdout.write('\tREF: %d\t'%module[2]) # reference
                        sys.stdout.write('ID: %d\t'%module[3]) # id
                        sys.stdout.write('Name: %s\t'%module_map[module[4]]) # name
                        sys.stdout.write('Handler: %x\t'%module[5]) # handler address
                        sys.stdout.write('\n')

            match_value = kld[2]
            
    elif oflag == 'net_info':
        print '\n-= NETWORK INFORMATION (P_LIST) =-'

        network_list = m_volafunx.net_info(symbol_list['tcbinfo'])
        for network in network_list:
            print 'TCP Local Address: %s:%d, Foreign Address: %s:%d, flag: %x'%(network[0], network[2], network[1], network[3], network[4])

        network_list = m_volafunx.net_info(symbol_list['udbinfo'])
        for network in network_list:
            print 'UDP Local Address: %s:%d, Foreign Address: %s:%d, flag: %x'%(network[0], network[2], network[1], network[3], network[4])
            
    elif oflag == 'net_info_hash':
        print '\n-= NETWORK INFORMATION (P_HASH) - It doesn\'t include AF_INET6 socket =-'

        network_list = m_volafunx.net_info_hash(symbol_list['tcbinfo'])
        for network in network_list:
            print 'TCP Local Address: %s:%d, Foreign Address: %s:%d, flag: %x'%(network[0], network[2], network[1], network[3], network[4])

        network_list = m_volafunx.net_info_hash(symbol_list['udbinfo'])
        for network in network_list:
            print 'UDP Local Address: %s:%d, Foreign Address: %s:%d, flag: %x'%(network[0], network[2], network[1], network[3], network[4])
    #############
    else:
        print '\n-o argument error: %s\n'%oflag
        usage()
        sys.exit()


if __name__ == "__main__":
    main()
