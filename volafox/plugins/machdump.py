# -*- coding: utf-8 -*-
import struct
import ps
from ctypes import *

from volafox.vatopa.addrspace import FileAddressSpace
from volafox.vatopa.ia32_pml4 import IA32PML4MemoryPae

class _MACH_HEADER(LittleEndianStructure):
    MH_MAGIC_X86 = 0xfeedface
    MH_MAGIC_X64 = 0xfeedfacf
    _fields_ = [
        ("magic", c_uint),
        ("cputype", c_uint),
        ("cpusubtype", c_uint),
        ("filetype", c_uint),
        ("ncmds", c_uint),
        ("sizeofcmds", c_uint),
        ("flag", c_uint)
    ]

class _MACH_HEADER_64(LittleEndianStructure):
    _fields_ = [
        ("magic", c_uint),
        ("cputype", c_uint),
        ("cpusubtype", c_uint),
        ("filetype", c_uint),
        ("ncmds", c_uint),
        ("sizeofcmds", c_uint),
        ("flag", c_uint),
        ("reserved", c_uint)
    ]

class _LOAD_COMMAND(LittleEndianStructure):
    _fields_ = [
        ("cmd", c_uint),
        ("cmdsize", c_uint)
    ]

class _SEGMENT_COMMAND(LittleEndianStructure):
    _fields_ = [
        ("cmd", c_uint),
        ("cmdsize", c_uint),
        ("segname", c_char*16),
        ("vmaddr", c_uint),
        ("vmsize", c_uint),
        ("fileoff", c_uint),
        ("filesize", c_uint),
        ("maxprot", c_uint),
        ("initprot", c_uint),
        ("nsects", c_uint),
        ("flags", c_uint)
    ]

class _SEGMENT_COMMAND_64(LittleEndianStructure):
    _fields_ = [
        ("cmd", c_uint),
        ("cmdsize", c_uint),
        ("segname", c_char*16),
        ("vmaddr", c_uint64),
        ("vmsize", c_uint64),
        ("fileoff", c_uint64),
        ("filesize", c_uint64),
        ("maxprot", c_uint),
        ("initprot", c_uint),
        ("nsects", c_uint),
        ("flags", c_uint)
    ]

class _SECTION(LittleEndianStructure):
    _fields_ = [
        ("sectname", c_char*16),
        ("segname", c_char*16),
        ("addr", c_uint),
        ("size", c_uint),
        ("offset", c_uint),
        ("align", c_uint),
        ("reloff", c_uint),
        ("nreloc", c_uint),
        ("flags", c_uint),
        ("reserved1", c_uint),
        ("reserved2", c_uint)
    ]

class _SECTION_64(LittleEndianStructure):
    _fields_ = [
        ("sectname", c_char*16),
        ("segname", c_char*16),
        ("addr", c_uint64),
        ("size", c_uint64),
        ("offset", c_uint),
        ("align", c_uint),
        ("reloff", c_uint),
        ("nreloc", c_uint),
        ("flags", c_uint),
        ("reserved1", c_uint),
        ("reserved2", c_uint),
        ("reserved3", c_uint)
    ]


TYPE_SEGMENT = 0x01
TYPE_SEGMENT64 = 0x19
FILE_MACH_EXECUTE = 0x02

def _procmemcpy(mem, offset, fmt):
    #print '%x'%mem.vtop(offset)
    buf = mem.read(offset, sizeof(fmt))
    return cast(c_char_p(buf), POINTER(fmt)).contents

def _memcpy(buf, fmt):
    return cast(c_char_p(buf), POINTER(fmt)).contents

def unsigned8(n):
  return n & 0xFFL

class machdump:
    def __init__(self, x86_mem_pae, arch, os_version, build, base_address):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.os_version = os_version
        self.build = build
        self.base_address = base_address

        self.mach_32bit = 1 # mach o architecture
        self.difference = 0

    def get_mach_dump(self, vm_list, vm_struct, pid_process_name, mempath, pm_cr3):

        #print '[+] Resetting the Page Mapping Table: 0x%x'%pm_cr3
        
        # init page table
        procmem = IA32PML4MemoryPae(FileAddressSpace(mempath), pm_cr3)

        dump_start = 0

        mach_vme_list = []
        for vme_info in vm_list:

            if procmem.is_valid_address(vme_info[0]):
                mach_header = _procmemcpy(procmem, vme_info[0], _MACH_HEADER)
            else:
                continue


            if mach_header.MH_MAGIC_X86 == mach_header.magic and FILE_MACH_EXECUTE == int(mach_header.filetype):
                print ' [-] Find 32 bit Mach-O signature at %.8x'%vme_info[0]
                
                self.mach_32bit = 1

            elif mach_header.MH_MAGIC_X64 == mach_header.magic and FILE_MACH_EXECUTE == int(mach_header.filetype):
                print ' [-] Find 64 bit Mach-O signature at %.8x'%vme_info[0]

                self.mach_32bit = 0

            else:
                print ' [-] Invalid Header at %.8x'%vme_info[0]
                continue

            fileoff = vme_info[0]
            
            # dump start offset
            dump_start = vme_info[0]

            # get load command offset
            loadcmdoff = 0
            if self.mach_32bit:
                loadcmdoff = fileoff + sizeof(_MACH_HEADER)
            else:
                loadcmdoff = fileoff + sizeof(_MACH_HEADER_64)

            #loadcommand_offset = file_offset+SIZEOFMACHOHEADER

            for cmdcount in xrange(0, mach_header.ncmds):
                if self.mach_32bit:
                    segment_command = _procmemcpy(procmem, loadcmdoff, _SEGMENT_COMMAND)
                else:
                    segment_command = _procmemcpy(procmem, loadcmdoff, _SEGMENT_COMMAND_64)

                if str(segment_command.segname).split('\x00')[0] == '__PAGEZERO':
                    self.difference = fileoff - segment_command.vmsize
                    loadcmdoff = loadcmdoff + segment_command.cmdsize
                    continue

                if segment_command.cmd == TYPE_SEGMENT or segment_command.cmd == TYPE_SEGMENT64:
                    if str(segment_command.segname).split('\x00')[0] == '__PAGEZERO':
                        self.difference = fileoff - segment_command.vmsize
                        loadcmdoff = loadcmdoff + segment_command.cmdsize
                        continue
                    
                    #mach_vme_info = []
                    vmstart = segment_command.vmaddr+self.difference
                    vmend = segment_command.vmsize+segment_command.vmaddr+self.difference

                    mach_vme_list.append([vmstart, vmend])

                loadcmdoff = loadcmdoff + segment_command.cmdsize
            break

        dumpfilename = '%s-%x'%(pid_process_name, dump_start)
        file = open(dumpfilename, mode="wb")
        for vme in mach_vme_list:
            print ' [-] from %.8x to %.8x'%(vme[0], vme[1])
            nop_code = 0x00
            pk_nop_code = struct.pack('=B', nop_code)
            nop = pk_nop_code*0x1000

            nop_flag = 1
            writebuf = ''
            for i in xrange(vme[0], vme[1], 0x1000):
                raw_data = 0x00
                if not(procmem.is_valid_address(i)):
                    if nop_flag == 1:
                        raw_data = nop
                        writebuf += raw_data
                    continue
                raw_data = procmem.read(i, 0x1000)
                if raw_data is None:
                    if nop_flag == 1:
                        raw_data = nop
                        writebuf += raw_data
                    continue
                writebuf += raw_data
                nop_flag = 1
            file.write(writebuf[:vme[1] - vme[0]])
        
        file.close()   
        
        print ' [-] [DUMP] Image Name: %s-%x'%(pid_process_name, dump_start)
        print '[+] Process Dump End'

        self.reloc(dumpfilename)

        return

    def reloc(self, dumpfilename):
        print '[+] Start Mach-O Relocation'
        fd = open(dumpfilename, mode='r+b')
        import mmap
        buf = mmap.mmap(fd.fileno(), 0)
        if len(buf) == 0:
            print ' [-] Read Failed'
            fd.close()
            return
        #fd.close()

        if self.mach_32bit:
            print ' [-] 32bit Mach-O File Format'
            mach_header = _memcpy(buf.read(sizeof(_MACH_HEADER_64)), _MACH_HEADER)
        else:
            print ' [-] 64bit Mach-O File Format'
            mach_header = _memcpy(buf.read(sizeof(_MACH_HEADER_64)), _MACH_HEADER_64)

        loadcmdoff = 0
        if self.mach_32bit:
            loadcmdoff = sizeof(_MACH_HEADER)
        else:
            loadcmdoff = sizeof(_MACH_HEADER_64)

        for cmdcount in xrange(0, mach_header.ncmds):
            if self.mach_32bit:
                segment_command = _memcpy(buf[loadcmdoff:], _SEGMENT_COMMAND)
            else:
                segment_command = _memcpy(buf[loadcmdoff:], _SEGMENT_COMMAND_64)

            if int(segment_command.cmd) == TYPE_SEGMENT or segment_command.cmd == TYPE_SEGMENT64:
                if str(segment_command.segname).split('\x00')[0] == '__PAGEZERO':
                    if self.mach_32bit:
                        buf.seek(loadcmdoff+_SEGMENT_COMMAND.vmsize.offset)
                        buf.write(struct.pack("I", segment_command.vmsize + self.difference))
                    else:
                        buf.seek(loadcmdoff+_SEGMENT_COMMAND_64.vmsize.offset)
                        buf.write(struct.pack("Q", segment_command.vmsize + self.difference))

                else:
                    if int(segment_command.cmd) == TYPE_SEGMENT:
                        buf.seek(loadcmdoff+_SEGMENT_COMMAND.vmaddr.offset)
                        buf.write(struct.pack("I", segment_command.vmaddr + self.difference))
                    else:
                        buf.seek(loadcmdoff+_SEGMENT_COMMAND_64.vmaddr.offset)
                        buf.write(struct.pack("Q", segment_command.vmaddr + self.difference))
                    
                    # secoff = loadcmdoff+sizeof(segment_command)
                    
                    # for sectioncount in xrange(0, segment_command.nsects):
                    #     if self.mach_32bit:
                    #         sect = buf[secoff::sizeof(_SECTION)]
                    #         section = _memcpy(sect, _SECTION)

                    #         buf.seek(secoff+_SECTION.addr.offset)
                    #         buf.write(struct.pack("I", section.addr + self.difference))
                    #         secoff += sizeof(_SECTION)
                    #     else:
                    #         sect = buf[secoff+sizeof(segment_command)::sizeof(_SECTION_64)]
                    #         section = _memcpy(sect, _SECTION_64)

                    #         buf.seek(secoff+_SECTION_64.addr.offset)
                    #         buf.write(struct.pack("Q", section.addr + self.difference))
                    #         secoff += sizeof(_SECTION_64)

            loadcmdoff = loadcmdoff + segment_command.cmdsize

        buf.flush()
        fd.close()
        print '[+] End Mach-O Relocation'
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
        print '[+] Process(PID : %d) is not loaded'%pid
        return 1
    
    task_struct = ProcMan.get_task(dumped_proc[0], dumped_proc[0][2])
    
    retData = ProcMan.get_proc_region(task_struct[3], dumped_proc[0][5], 0)
    
    vm_list = retData[0]
    vm_struct = retData[1]

    pm_cr3 = ProcMan.get_proc_cr3(vm_list, vm_struct)
    
    MachO = machdump(x86_mem_pae, arch, os_version, build, base_address)
    MachO.get_mach_dump(vm_list, vm_struct, str(dumped_proc[0][1])+'-'+dumped_proc[0][14], mempath, pm_cr3)
    
    return