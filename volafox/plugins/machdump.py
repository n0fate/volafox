# -*- coding: utf-8 -*-
import struct
import ps

from volafox.vatopa.addrspace import FileAddressSpace
from volafox.vatopa.ia32_pml4 import IA32PML4MemoryPae

# Lion 32bit, SN 32bit, Lion64bit, SN 64bit, Mountain Lion 64bit, Mavericks
DATA_PROC_STRUCTURE = [[476+24+168, '=4xIIIII4xII88xI276xQII20xbbbb52sI164xI', 16, '=IIII', 283, '=IIIIIII255s', 108, '=12xI4x8x64xI12x'],
    [476+168, '=4xIIIII4xII64xI276xQII20xbbbb52sI164xI', 16, '=IIII', 283, '=IIIIIII255s', 108, '=12xI4x8x64xI12x'], 
    [752+24+268, '=8xQQQQI4xII152xQ456xQQQ16xbbbb52sQ264xI', 32, '=QQQQ', 303, '=IQQIQQQ255s', 120, '=24xI4x8x64xI12x'],
    [1028, '=8xQQQQI4xII144xQ448xQQQ16xbbbb52sQ264xI', 32, '=QQQQ', 303, '=IQQIQQQ255s', 120, '=24xI4x8x64xI12x'], 
    [752+24+276, '=8xQQQQI4xII152xQ456xQQQ16xbbbb52sQ272xI', 32, '=QQQQ', 303, '=IQQIQQQ255s', 120, '=24xI4x8x64xI12x'],
    [760+24+268, '=8xQQQQI4xII160xQ456xQQQ16xbbbb52sQ264xI', 32, '=QQQQ', 303, '=IQQIQQQ255s', 120, '=24xI4x8x64xI12x'],
    [760+24+268+16, '=8xQQQQI4xII160xQ456xQQQ16xbbbb52sQ264x16xI', 32, '=QQQQ', 303, '=IQQIQQQ255s', 120, '=24xI4x8x64xI12x']]
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
    [202, '=16xQQQQII16x4xIQQ16xIII42xIIIIIIIII', 80, '=QQQQ40xQ']]

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

class machdump:
    def __init__(self, x86_mem_pae, arch, os_version, build, base_address):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.os_version = os_version
        self.build = build
        self.base_address = base_address

    def get_mach_dump(self, vm_list, vm_struct, pid_process_name, mempath, pm_cr3):

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
        for vme_info in vm_list:
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
    ProcMan = ps.process_manager(x86_mem_pae, arch, os_version, build, base_address)
    MachO = machdump(x86_mem_pae, arch, os_version, build, base_address)
    ret = ProcMan.get_proc_list(sym_addr, proclist, pid)
    if ret == 1:
        return 1
    
    dumped_proc = proclist
    
    task_struct = ProcMan.get_task(dumped_proc[0], dumped_proc[0][2])
    
    retData = ProcMan.get_proc_region(task_struct[3], dumped_proc[0][5], 0)
    
    vm_list = retData[0]
    vm_struct = retData[1]

    pm_cr3 = ProcMan.get_proc_cr3(vm_list, vm_struct)
    
    MachO.get_mach_dump(vm_list, vm_struct, str(dumped_proc[0][1])+'-'+dumped_proc[0][14], mempath, pm_cr3)
    
    return