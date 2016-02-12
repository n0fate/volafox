# -*- coding: utf-8 -*-
import struct
import ps

from volafox.vatopa.addrspace import FileAddressSpace
from volafox.vatopa.ia32_pml4 import IA32PML4MemoryPae

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

        COMMAND_32 = 'II16sIIII'
        COMMAND_64 = 'II16sQQQQ'
        SIZEOFCOMMAND_32 = 40 # bytes
        SIZEOFCOMMAND_64 = 56 # bytes
        TYPE_SEGMENT = 0x01
        TYPE_SEGMENT64 = 0x19
        FILE_MACH_EXECUTE = 0x02


        dump_start = 0
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
            loadcommand_offset = file_offset+SIZEOFMACHOHEADER

            for num_load_command in range(0, machoheader[4]):
                loadcommand_t = proc_pae.read(loadcommand_offset, SIZEOFCOMMAND) # 'II16sII'
                loadcommand = struct.unpack(COMMAND, loadcommand_t)
                if loadcommand[2].split('\x00')[0] == '__PAGEZERO':
                    difference = dump_start - loadcommand[4]
                    loadcommand_offset = loadcommand_offset + loadcommand[1]
                    continue
                if loadcommand[0] == TYPE_SEGMENT or loadcommand[0] == TYPE_SEGMENT64:
                    if loadcommand[2].split('\x00')[0] == '__PAGEZERO':
                        difference = dump_start - loadcommand[4]
                        loadcommand_offset = loadcommand_offset + loadcommand[1]
                        continue
                    mach_vme_info = []
                    mach_vme_info.append(loadcommand[3]+difference)
                    mach_vme_info.append(loadcommand[6]+loadcommand[3]+difference)
                    mach_vme_list.append(mach_vme_info)
                loadcommand_offset = loadcommand_offset + loadcommand[1]
            break

        file = open('%s-%x'%(pid_process_name, dump_start), mode="wb")
        for mach_vme_info in mach_vme_list:
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


def get_macho_dump(x86_mem_pae, sym_addr, arch, os_version, build, pid, base_address, mempath, nproc):
    if pid == -1:
        print '[+] Check -x [PID] options'
        return 0
    print '[+] Process Dump Start => PID : %d'%pid
    dumped_proc = []
    ProcMan = ps.process_manager(x86_mem_pae, arch, os_version, build, base_address, nproc)
    ret = ProcMan.get_proc_list(sym_addr, dumped_proc, pid)
    if ret == 1:
        return 1
    
    task_struct = ProcMan.get_task(dumped_proc[0], dumped_proc[0][2])
    
    retData = ProcMan.get_proc_region(task_struct[3], dumped_proc[0][5], 0)
    
    vm_list = retData[0]
    vm_struct = retData[1]

    pm_cr3 = ProcMan.get_proc_cr3(vm_list, vm_struct)
    
    MachO = machdump(x86_mem_pae, arch, os_version, build, base_address)
    MachO.get_mach_dump(vm_list, vm_struct, str(dumped_proc[0][1])+'-'+dumped_proc[0][14], mempath, pm_cr3)
    
    return