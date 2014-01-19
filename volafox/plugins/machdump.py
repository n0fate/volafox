# -*- coding: utf-8 -*-
import sys
import struct
import time
import os
import binascii

from tableprint import columnprint

from volafox.vatopa.addrspace import FileAddressSpace
from volafox.vatopa.ia32_pml4 import IA32PML4MemoryPae

# Lion 32bit, SN 32bit, Lion64bit, SN 64bit, Mountain Lion 64bit, Mavericks
DATA_PROC_STRUCTURE = [[476+24+168, '=4xIIIII4xII88xI276xQII20xbbbb52sI164xI', 16, '=IIII', 283, '=IIIIIII255s', 108, '=12xI4x8x64xI12x'],
    [476+168, '=4xIIIII4xII64xI276xQII20xbbbb52sI164xI', 16, '=IIII', 283, '=IIIIIII255s', 108, '=12xI4x8x64xI12x'], 
    [752+24+268, '=8xQQQQI4xII152xQ456xQQQ16xbbbb52sQ264xI', 32, '=QQQQ', 303, '=IQQIQQQ255s', 120, '=24xI4x8x64xI12x'],
    [1028, '=8xQQQQI4xII144xQ448xQQQ16xbbbb52sQ264xI', 32, '=QQQQ', 303, '=IQQIQQQ255s', 120, '=24xI4x8x64xI12x'], 
    [752+24+276, '=8xQQQQI4xII152xQ456xQQQ16xbbbb52sQ272xI', 32, '=QQQQ', 303, '=IQQIQQQ255s', 120, '=24xI4x8x64xI12x'],
    [760+24+268, '=8xQQQQI4xII160xQ456xQQQ16xbbbb52sQ264xI', 32, '=QQQQ', 303, '=IQQIQQQ255s', 120, '=24xI4x8x64xI12x']]
    # Mavericks add new element in proc structure : uint64_t   p_puniqueid;        /* parent's unique ID - set on fork/spawn/vfork, doesn't change if reparented. */

# Lion 32bit, SN 32bit, Lion64bit, SN 64bit, Mountain Lion 64bit
DATA_TASK_STRUCTURE = [[32+460+4, '=8xIIIIII460xI'],
    [36+428+4, '=12xIIIIII428xI'],
    [736, '=16xIII4xQQQ672xQ'],
    [712, '=24xIII4xQQQ640xQ'],
    [744, '=16xIII4xQQQ656x24xQ']]

# http://opensource.apple.com/source/xnu/xnu-xxxx.xx.xx/osfmk/vm/vm_map.h
# Lion 32bit, SN 32bit, Lion64bit, SN 64bit, Mavericks
DATA_VME_STRUCTURE = [[162+12, '=12xIIQQII8x4xIQ16xIII42xIIIIIIIII', 52, '=IIQQ24xI'],
    [162, '=12xIIQQIIIQ16xIII42xIIIIIIIII', 40, '=IIQQ12xI'],
    [194, '=16xQQQQII16xQQ16xIII42xIIIIIIIII', 80, '=QQQQ40xQ'],
    [178, '=16xQQQQIIQQ16xIII42xIIIIIIIII', 56, '=QQQQ16xQ'],
    [202, '=16xQQQQII16x8xQQ16xIII42xIIIIIIIII', 80, '=QQQQ40xQ']]

# http://opensource.apple.com/source/xnu/xnu-xxxx.xx.xx/osfmk/i386/pmap.h
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
        if not(self.x86_mem_pae.is_valid_address(proc_sym_addr)):
            return proc, '', ''

        proclist = self.x86_mem_pae.read(proc_sym_addr, PROC_STRUCTURE[0])
        data = struct.unpack(PROC_STRUCTURE[1], proclist)
        
        pgrp_t = self.x86_mem_pae.read(data[16], PROC_STRUCTURE[2]) # pgrp structure
        m_pgrp = struct.unpack(PROC_STRUCTURE[3], pgrp_t)

        session_t = self.x86_mem_pae.read(m_pgrp[3], PROC_STRUCTURE[4]) # session structure
        m_session = struct.unpack(PROC_STRUCTURE[5], session_t)

        #print '%x'%self.x86_mem_pae.vtop(data[5])
        p_ucred = self.x86_mem_pae.read(data[7], PROC_STRUCTURE[6])
        ucred = struct.unpack(PROC_STRUCTURE[7], p_ucred)

        proc.append(self.x86_mem_pae.vtop(proc_sym_addr))
        proc.append(data[1])
        proc.append(data[2])
        proc.append(data[3])
        proc.append(data[4])
        proc.append(data[5])
        proc.append(data[6])
        proc.append(data[8]) # user_stack
        proc.append(data[9]) # vnode of executable
        proc.append(data[10]) # offset in executable vnode
        proc.append(data[11]) # Process Priority
        proc.append(data[12]) # User-Priority based on p_cpu and p_nice
        proc.append(data[13]) # Process 'nice' value
        proc.append(data[14]) # User-Priority based on p_cpu and p_nice
        proc.append(data[15].split('\x00', 1)[0]) # process name
        proc.append(str(m_session[7]).strip('\x00')) # username
        proc.append(data[17]) # time
        proc.append(ucred[0]) # ruid
        proc.append(ucred[1]) # rgid

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
            elif self.os_version == 13:
                PROC_STRUCTURE = DATA_PROC_STRUCTURE[5]
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

    
    def get_task(self, proc, task_ptr):
        #print '====== task.h --> osfmk\\kern\\task.h'
        if self.arch == 32:
            if self.os_version == 11:
                TASK_STRUCTURE = DATA_TASK_STRUCTURE[0]
            else:
                TASK_STRUCTURE = DATA_TASK_STRUCTURE[1]
        else:
            if self.os_version == 11:
                TASK_STRUCTURE = DATA_TASK_STRUCTURE[2]
            elif self.os_version >= 12:
                TASK_STRUCTURE = DATA_TASK_STRUCTURE[4]
            else:
                TASK_STRUCTURE = DATA_TASK_STRUCTURE[3]
        task_info = self.x86_mem_pae.read(task_ptr, TASK_STRUCTURE[0])
        task_struct = struct.unpack(TASK_STRUCTURE[1], task_info)

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
            if self.os_version == 11: # Lion
                VME_STRUCTURE = DATA_VME_STRUCTURE[2]
            elif self.os_version == 12: # Mountain Lion
                VME_STRUCTURE = DATA_VME_STRUCTURE[2]
            elif self.os_version == 13: # Mavericks
                VME_STRUCTURE = DATA_VME_STRUCTURE[4]
            else:
                VME_STRUCTURE = DATA_VME_STRUCTURE[3]
                
        vm_info = self.x86_mem_pae.read(task_ptr, VME_STRUCTURE[0])
        vm_struct = struct.unpack(VME_STRUCTURE[1], vm_info)
        
        if vm_struct[6] == 0: # pmap_t
            return vm_list, vm_struct

        if not(self.x86_mem_pae.is_valid_address(vm_struct[6])):
            return vm_list, vm_struct

        vm_list = []

        # process full dump
        if fflag == 1:
            vm_temp_list = []
            vm_temp_list.append(vm_struct[2])
            vm_temp_list.append(vm_struct[3])
            vm_list.append(vm_temp_list)
            return vm_list, vm_struct

        #print ''
        #print '[+] Generating Process Virtual Memory Maps'
        entry_next_ptr = vm_struct[1]
        for data in range(0, vm_struct[4]): # number of entries
            try:
                vm_list_ptr = self.x86_mem_pae.read(entry_next_ptr, VME_STRUCTURE[2])
                vme_list = struct.unpack(VME_STRUCTURE[3], vm_list_ptr)
            except:
                break

            # *prev, *next, start, end
            vm_temp_list = []
            vm_temp_list.append(vme_list[2]) # start
            vm_temp_list.append(vme_list[3]) # end
            vm_list.append(vm_temp_list)

            entry_next_ptr = vme_list[1]
            #print '%x'%self.x86_mem_pae.vtop(vme_list[1])
        
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
        
        pmap_info = self.x86_mem_pae.read(vm_struct[6], PMAP_STRUCTURE[0])
        pm_cr3 = struct.unpack(PMAP_STRUCTURE[1], pmap_info)[0]
        return pm_cr3
        
    def get_proc_dump(self, vm_list, vm_struct, pid_process_name, mempath):

        pm_cr3 = self.get_proc_cr3(vm_list, vm_struct)
        
        proc_pae = 0
        
        #print '[+] Resetting the Page Mapping Table: 0x%x'%pm_cr3
        
        proc_pae = IA32PML4MemoryPae(FileAddressSpace(mempath), pm_cr3)
        
        #print '[+] Process Dump Start'
        MH_MAGIC_X86 = 'feedface'
        MH_MAGIC_X64 = 'feedfacf'

        MACHHEADER_32 = 'IIIIIII'
        SIZEOFMACHOHEADER_32 = 28 # bytes
        MACHHEADER_64 = 'IIIIIIII'
        SIZEOFMACHOHEADER_64 = 32 # bytes
        MACHHEADER = MACHHEADER_32
        SIZEOFMACHOHEADER = SIZEOFMACHOHEADER_32

        COMMAND = ''
        COMMAND_32 = 'II16sIIII'
        COMMAND_64 = 'II16sQQQQ'
        SIZEOFCOMMAND = 32
        SIZEOFCOMMAND_32 = 40 # bytes
        SIZEOFCOMMAND_64 = 56 # bytes
        TYPE_SEGMENT = 0x01
        TYPE_SEGMENT64 = 0x19
        FILE_MACH_EXECUTE = 0x02
        dump_start = 0
        dump_end = 0
        difference = 0
        mach_vme_list = []
        for vme_info in  vm_list:
            try:
                machoheader_t = proc_pae.read(vme_info[0], SIZEOFMACHOHEADER) # read 0x1c bytes
                machoheader = struct.unpack(MACHHEADER, machoheader_t)
            except:
                continue
            strHex = '%x'%machoheader[0]
            if MH_MAGIC_X86 == strHex and FILE_MACH_EXECUTE == machoheader[3]:
                print ' [-] Find 32 bit Mach-O signature at %.8x'%vme_info[0]
                COMMAND = COMMAND_32
                SIZEOFCOMMAND = SIZEOFCOMMAND_32
                MACHHEADER = MACHHEADER_32
                SIZEOFMACHOHEADER = SIZEOFMACHOHEADER_32

            elif MH_MAGIC_X64 == strHex and FILE_MACH_EXECUTE == machoheader[3]:
                print ' [-] Find 64 bit Mach-O signature at %.8x'%vme_info[0]
                COMMAND = COMMAND_64
                SIZEOFCOMMAND = SIZEOFCOMMAND_64
                MACHHEADER = MACHHEADER_64
                SIZEOFMACHOHEADER = SIZEOFMACHOHEADER_64

            else:
                continue

            file_offset = vme_info[0]
            dump_start = file_offset
            final_dump_start = 0
            loadcommand_offset = file_offset+SIZEOFMACHOHEADER
            #mach_vme_list.append(vme_info)

            for num_load_command in range(0, machoheader[4]):
                #print 'offset: %x'%loadcommand_offset
                loadcommand_t = proc_pae.read(loadcommand_offset, SIZEOFCOMMAND) # 'II16sII'
                loadcommand = struct.unpack(COMMAND, loadcommand_t)
                if loadcommand[2].split('\x00')[0] == '__PAGEZERO':
                    difference = dump_start - loadcommand[4]
                    loadcommand_offset = loadcommand_offset + loadcommand[1]
                    continue
                #print '%x: %x-%.8x-%x'%(loadcommand[0], loadcommand[1], loadcommand[3], loadcommand[4])
                if loadcommand[0] == TYPE_SEGMENT or loadcommand[0] == TYPE_SEGMENT64:
                    if loadcommand[2].split('\x00')[0] == '__PAGEZERO':
                        difference = dump_start - loadcommand[4]
                        loadcommand_offset = loadcommand_offset + loadcommand[1]
                        continue
                    mach_vme_info = []
                    mach_vme_info.append(loadcommand[3]+difference)
                    mach_vme_info.append(loadcommand[6]+loadcommand[3]+difference)
                    mach_vme_list.append(mach_vme_info)
                    #if final_dump_start < loadcommand[3]:
                    #    final_dump_start = loadcommand[3]
                loadcommand_offset = loadcommand_offset + loadcommand[1]

        # if final_dump_start == 0:
        #     print '[+] Not availiable Mach O File'
        #     return
        # print '%x'%(final_dump_start+difference)

        file = open('%s-%x'%(pid_process_name, dump_start), mode="wb")
        for mach_vme_info in mach_vme_list:
            # if difference+final_dump_start < vme_info[0]:
            #     file.close()
            #     break
            print ' [-] from %.8x to %.8x'%(mach_vme_info[0], mach_vme_info[1])
            nop_code = 0x00
            pk_nop_code = struct.pack('=B', nop_code)
            nop = pk_nop_code*0x1000

            nop_flag = 0
            writebuf = ''
            for i in range(mach_vme_info[0], mach_vme_info[1], 0x1000):
                raw_data = 0x00
                if not(proc_pae.is_valid_address(i)):
                    if nop_flag == 1:
                        raw_data = nop
                        writebuf += raw_data
                    continue
                raw_data = proc_pae.read(i, 0x1000)
                if raw_data is None:
                    if nop_flag == 1:
                        raw_data = nop
                        writebuf += raw_data
                    continue
                writebuf += raw_data
                nop_flag = 1
            file.write(writebuf[:mach_vme_info[1]-mach_vme_info[0]])
        
        file.close()   
        
        print ' [-] [DUMP] Image Name: %s-%x'%(pid_process_name, dump_start)
        print '[+] Process Dump End'
        return

#################################### PUBLIC FUNCTIONS ####################################


def get_macho_dump(x86_mem_pae, sym_addr, arch, os_version, build, pid, base_address, mempath):
    print '[+] Process Dump Start'
    proclist = []
    ProcMan = process_manager(x86_mem_pae, arch, os_version, build, base_address)
    ret = ProcMan.get_proc_list(sym_addr, proclist, pid)
    if ret == 1:
        return 1
    
    dumped_proc = proclist
    
    task_struct = ProcMan.get_task(dumped_proc[0], dumped_proc[0][2])
    
    retData = ProcMan.get_proc_region(task_struct[3], dumped_proc[0][5], 0)
    
    vm_list = retData[0]
    vm_struct = retData[1]
    
    ProcMan.get_proc_dump(vm_list, vm_struct, str(dumped_proc[0][1])+'-'+dumped_proc[0][14], mempath)
    
    return