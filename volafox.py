#!c:\python\python.exe
# -*- coding: utf-8 -*-
#  -*- mode: python; -*-
#
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

import getopt
import sys
import math

import binascii
import macho_an # user-defined class -> n0fate
from ia32_pml4 import * # user-defined class -> n0fate

from imageinfo import * # user defined class > CL
import pickle # added by CL

import os

from x86 import *
from addrspace import FileAddressSpace
from macho import MachoAddressSpace, isMachoVolafoxCompatible

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
    def __init__(self, pdpt, mempath):
        self.idlepdpt = pdpt
        self.mempath = mempath
        self.data_list = []

    def init_vatopa_x86_pae(self):
        if self.mempath == '' or self.idlepdpt == 0:
            return 1

        if isMachoVolafoxCompatible(self.mempath):
            self.x86_mem_pae = IA32PagedMemoryPae(MachoAddressSpace(self.mempath), self.idlepdpt)
        else:
            self.x86_mem_pae = IA32PagedMemoryPae(FileAddressSpace(self.mempath), self.idlepdpt)
        return 0
    
    def sleep_time(self, sym_addr):
    	sleep_time = self.x86_mem_pae.read(sym_addr, 4);
    	data = struct.unpack('i', sleep_time)
    	return data

    def wake_time(self, sym_addr):
    	wake_time = self.x86_mem_pae.read(sym_addr, 4);
    	data = struct.unpack('i', wake_time)
    	return data   

    ## Chris Leat(chris.leat@gmail.com)'s Idea(Thanks to giving new idea :D)
    ## Source: osfmk/i386/lowmem_vectors.s
    #def get_mem_info(self, sym_addr):
    #    mem_info = self.x86_mem_pae.read(sym_addr, 0x248)
    #    ## 'Catfish', ptr to kernel version str, ptr to kmod, ptr to osversion str
    #    data = struct.unpack('8s20xI4xI16xI', mem_info)
    #    if data[0] is not 'Catfish ':
    #       print'Can not get memory information'
    #       return data
    #    else:
    #       self.x86_mem_pae.read(sym_addr, 10)

    def os_info(self, sym_addr):
        os_version = self.x86_mem_pae.read(sym_addr, 10) # __DATA.__common _osversion
        data = struct.unpack('10s', os_version)
        return data

    def machine_info(self, sym_addr):
        machine_info = self.x86_mem_pae.read(sym_addr, 40); # __DATA.__common _machine_info
        data = struct.unpack('IIIIQIIII', machine_info)
        return data

    def kernel_kext_info(self, sym_addr):
        Kext = self.x86_mem_pae.read(sym_addr, 168); # .data _g_kernel_kmod_info
        data = struct.unpack('III64s64sIIIIIII', Kext)
        return data

    def kext_info(self, sym_addr):
        print 'symboladdr: %x'%sym_addr
        kext_list = []

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

        return kext_list

    def kextdump(self, offset, size, kext_name):
        if not(self.x86_mem_pae.is_valid_address(offset)):
            print 'Invalid Offset'
            return
        print 'dump file name: %s-%x-%x'%(kext_name, offset, offset+size)
	file = open('%s-%x-%x'%(kext_name, offset, offset+size), 'wba')
	data = self.x86_mem_pae.read(offset, size);
	file.write(data)
	file.close()
	print 'module dump complete'
	return
    
    def mount_info(self, sym_addr):
        mount_list = []
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

        return mount_list

    def process_info(self, sym_addr):
        proc_list = []
        kernproc = self.x86_mem_pae.read(sym_addr, 4); # __DATA.__common _kernproc
        data = struct.unpack('I', kernproc)

        while 1:
            #break
            if data[0] == 0:
                break
            if not(self.x86_mem_pae.is_valid_address(data[0])):
                break
            try:
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
        return proc_list

    def syscall_info(self, sym_addr):
        syscall_list = []

        nsysent = self.x86_mem_pae.read(sym_addr, 4) # .data _nsysent
        data = struct.unpack('I', nsysent) # uint32

        sysentaddr = sym_addr - (data[0] * 24) # sysent structure size + 2bytes

        for count in range(0, data[0]):
            sysent = self.x86_mem_pae.read(sysentaddr + (count*24), 24); # .data _nsysent
            data = struct.unpack('hbbIIIII', sysent) # uint32

            syscall_list.append(data)

        return syscall_list

    def vaddump(self, sym_addr, pid):
        print '\n-= process: %d=-'%pid
        kernproc = self.x86_mem_pae.read(sym_addr, 4); # __DATA.__common _kernproc
        data = struct.unpack('I', kernproc)

        print 'list_entry_next\tpid\tppid\tprocess name\t\tusername'
        proclist = self.x86_mem_pae.read(data[0], 476);
        data = struct.unpack('=4xIIIII392xI52sI', proclist) # 24 bytes + 396 bytes padding(49 double value) + 33 bytes process name
        while 1:
            if data[1] == pid:
                #print 'list_entry(next): %x'%data[0] # int
                sys.stdout.write('%.8x\t'%data[0]) # int
                sys.stdout.write('%d\t'%data[1]) # int
                sys.stdout.write('%d\t'%data[4]) # int
                sys.stdout.write('%s\t'%data[6].replace('\x00',''))
               
                process_name = data[6].replace('\x00','')
               
                pgrp_t = self.x86_mem_pae.read(data[7], 16); # pgrp structure
                m_pgrp = struct.unpack('IIII', pgrp_t)
   
                session_t = self.x86_mem_pae.read(m_pgrp[3], 283); # session structure
                m_session = struct.unpack('IIIIIII255s', session_t)
                sys.stdout.write('%s'%m_session[7].replace('\x00',''))
                sys.stdout.write('\n')

                print '[+] Gathering Process Information'
                #print 'task_ptr: %x'%self.x86_mem_pae.vtop(data[2])
                #print '====== task.h --> osfmk\\kern\\task.h'
                task_info = self.x86_mem_pae.read(data[2], 36)
                task_struct = struct.unpack('=12xIIIIII', task_info)
                #print 'lock: %x'%task_struct[0]
                #print 'task_t'
                #print 'ref_count: %x'%task_struct[0]
                #print 'active: %x'%task_struct[1]
                #print 'halting: %x'%task_struct[2]
                #print 'uni and smp lock: %d'%task_struct[4]
                #print 'vm_map_t: %x'%self.x86_mem_pae.vtop(task_struct[3])
                #print 'tasks: %x'%task_struct[4]
                #print 'userdata: %x'%task_struct[5]
   
   
                vm_info = self.x86_mem_pae.read(task_struct[3], 162)
                vm_struct = struct.unpack('=12xIIQQIiIQ16xIII42xIIIIIIIII', vm_info)
                #print 'lock: %x'%vm_struct[0]
                #print '======= vm_map_t --> osfmk\\vm\\vm_map.h ========'
                #print 'prev: %x'%vm_struct[0]
                #print 'next: %x'%self.x86_mem_pae.vtop(vm_struct[1])
                print ' [-] Virtual Address Start Point: 0x%x'%vm_struct[2]
                print ' [-] Virtual Address End Point: 0x%x'%vm_struct[3]
                #print 'neutries: %x'%vm_struct[4] # number of entries
                #print 'entries_pageable: %x'%vm_struct[5]
                #print 'pmap_t: %x'%self.x86_mem_pae.vtop(vm_struct[6])

                vm_list = []

                entry_next_ptr = vm_struct[1]
                for data in range(0, vm_struct[4]): # number of entries
                    vm_list_ptr = self.x86_mem_pae.read(entry_next_ptr, 24)
                    vme_list = struct.unpack('=IIQQ', vm_list_ptr)
                    # *prev, *next, start, end
                    vm_temp_list = []
                    vm_temp_list.append(vme_list[2]) # start
                    vm_temp_list.append(vme_list[3]) # end
                   
                    vm_list.append(vm_temp_list)
                    #print 'prev: %x, next: %x, start:%x, end:%x'%(vme_list[0], vme_list[1], vme_list[2], vme_list[3])
                    entry_next_ptr = vme_list[1]
   
                if vm_struct[6] == 0: # pmap_t
                    exit(1)
   
                if not(self.x86_mem_pae.is_valid_address(vm_struct[6])):
                    exit(1)
   
                pmap_info = self.x86_mem_pae.read(vm_struct[6], 100)
                pmap_struct = struct.unpack('=IQIIII56xQII', pmap_info)
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

                pm_cr3 = pmap_struct[6]
                proc_pae = 0
                print ' [-] Resetting the Page Mapping Table: 0x%x'%pm_cr3
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
                    file = open('%s-%x-%x'%(process_name, vme_info[0], vme_info[1]), mode="wba")
                    for i in range(vme_info[0], vme_info[1], 0x1000):
                        raw_data = 0x00
                        if not(proc_pae.is_valid_address(i)):
                            continue
                        raw_data = proc_pae.read(i, 0x1000)
                        if raw_data is None:
                            continue
                        file.write(raw_data)
                    file.close()
                    size = os.path.getsize('%s-%x-%x'%(process_name, vme_info[0], vme_info[1]))
                    if size == 0:
                       os.remove('%s-%x-%x'%(process_name, vme_info[0], vme_info[1]))
                    else:
                        print ' [-] [DUMP] Image Name: %s-%x-%x'%(process_name, vme_info[0], vme_info[1])
                print '[+] Process Dump End'
                return
            else:
                proclist = self.x86_mem_pae.read(data[0], 476);
                data = struct.unpack('=4xIIIII392xI52sI', proclist) # 24 bytes + 396 bytes padding(49 double value) + 33 bytes process name
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
    # it can dump network information. if rootkit has hiding technique.
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

        #print 'Real Address (inpcbinfo): %x'%net_pae.vtop(sym_addr)
        inpcbinfo_t = net_pae.read(sym_addr, 40)
        inpcbinfo = struct.unpack('=IIIIII12xI', inpcbinfo_t)

        if not(net_pae.is_valid_address(inpcbinfo[5])):
            return

        #print 'Real Address (inpcbinfo): %x'%net_pae.vtop(inpcbinfo[5])

        temp_ptr = inpcbinfo[5] # base address
        #list_t = net_pae.read(inpcbinfo[5], 4)
        #temp_ptr = struct.unpack('=I', list_t)

        print 'Real Address (inpcbinfo): %x'%net_pae.vtop(temp_ptr)
        
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
            
        return network_list

def usage():
    print 'volafox(Memory analyzer for OS X) 0.6 Beta1 fixed - n0fate'
    print 'Contact: rapfer@gmail.com or n0fate@live.com'
    print 'usage: python %s -i MEMORY_IMAGE -s OVERLAY -[o INFORMATION][-m KEXT ID][-x PID]\n'%sys.argv[0]
    print '-= CAUTION =-'
    print 'this program needs to physical memory image(linear format), overay information(symbol list in kernel image)'
    print 'and it supports to Intel x86 Architecture only :(\n'
    print 'Option:'
    print '-o\t: Gathering information using symbol'
    print '-m\t: Dump module using module id'
    print '-x\t: Dump process using pid\n'
    print 'INFORMATION:'
    print 'os_version\t Dawin kernel detail version'
    print 'machine_info\t Kernel version, cpu, memory information'
    print 'mount_info\t Mount information'
    print 'kern_kext_info\t Kernel KEXT(Kernel Extensions) information'
    print 'kext_info\t KEXT(Kernel Extensions) information'
    print 'proc_info\t Process list'
    print 'syscall_info\t Kernel systemcall information'
    print 'net_info\t network information(hash) - test'
    print 'net_info_test\t network information(plist) - test'

def main():
    file_image = ''
    mempath = ''
    oflag = ''
    vflag = 0
    dflag = 0
    mflag = 0

    try:
        option, args = getopt.getopt(sys.argv[1:], 'o:i:s:x:v:m:')

    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit()

    for op, p, in option:
        if op in '-o':  # data type
            print 'Information:', p
            oflag = p

        elif op in '-i': # physical memory image file
            print 'Memory Image:', p
            mempath = p

        elif op == '-s': # physical memory image file
            print 'Kernel Image:', p
            file_image = p

        elif op == '-v': # verbose
            #print 'Verbose:', p
            vflag = 1 # true
       
        elif op =='-x':
            print 'Dump PID: %s'%p
            pid = int(p, 10)
            dflag = 1
        
        elif op =='-m':
            print 'Dump KEXT: %s'%p
            kext_num = int(p, 10)
            mflag = 1
           
        else:
            print 'Command error:', op
            usage()
            sys.exit()

    if file_image == "" and mempath == "" and ( oflag == 0 or dflag == 0 or mflag == 0):
        usage()
        sys.exit()

    #macho = macho_an.macho_an(file_image)
    #arch_count = macho.load()
    #header = macho.get_header(arch_count, macho.ARCH_I386) # only support Intel x86
    #symbol_list = macho.macho_getsymbol_x86(header[2], header[3])
    
    #Added by CL
    f = open(file_image, 'rb')
    symbol_list = pickle.load(f)
    #
    f.close()

    m_volafox = volafox(symbol_list['_IdlePDPT'], mempath)
    nRet = m_volafox.init_vatopa_x86_pae()

    if nRet == 1:
        print 'Memory Image Load Failed'
        sys.exit()

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
        sys.stdout.write('Detail dawin kernel version: %s'%data[0].strip('\x00'))
        sys.stdout.write('\n')
        sys.exit()

    elif oflag == 'machine_info':
        print '\n-= Mac OS X Basic Information =-'
        data = m_volafox.machine_info(symbol_list['_machine_info'])
        print 'Major Version: %d'%data[0]
        print 'Minor Version: %d'%data[1]
        print 'Number of Physical CPUs: %d'%data[2]
        print 'Size of memory in bytes: %d bytes'%data[3]
        print 'Size of physical memory: %d bytes'%data[4]
        print 'Number of physical CPUs now available: %d'%data[5]
        print 'Max number of physical CPUs now possible: %d'%data[6]
        print 'Number of logical CPUs now available: %d'%data[7]
        print 'Max number of logical CPUs now possible: %d'%data[8]
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

    # 0x0083e5c8 kernel extensions
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
        sys.stdout.write('list entry\tfstypename\tmount on name\tmount from name')
        sys.stdout.write('\n')
        for data in data_list:
            sys.stdout.write('%.8x\t'%data[0])
            sys.stdout.write('%s\t'%data[1]) # char[16]
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
            sys.stdout.write('%s\t'%data[6].strip('\x00'))
            sys.stdout.write('%s\t'%data[8].strip('\x00'))
            sys.stdout.write('\n')

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
        print '\n-o argument error: %s\n'%oflag
        usage()
        sys.exit()


if __name__ == "__main__":
    main()
