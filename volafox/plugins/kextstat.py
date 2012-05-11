import sys
import struct

from tableprint import columnprint

# SN/Lion 32bit, SN/Lion 64bit
DATA_KEXT_STRUCTURE = [168, '=III64s64sIIIIIII', 196, '=QII64s64sIQQQQQQ']

class kext_manager():
    def __init__(self, x86_mem_pae, arch):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        
    def kern_kextstat(self, sym_addr): # 11.11.23 64bit suppport
        kext = []
        if self.arch == 32:
            Kext = self.x86_mem_pae.read(sym_addr, DATA_KEXT_STRUCTURE[0]); # .data _g_kernel_kmod_info
            data = struct.unpack(DATA_KEXT_STRUCTURE[1], Kext)
            
        else: # self.arch == 64
            Kext = self.x86_mem_pae.read(sym_addr, DATA_KEXT_STRUCTURE[2]); # .data _g_kernel_kmod_info
            data = struct.unpack(DATA_KEXT_STRUCTURE[3], Kext)

        kext.append(self.x86_mem_pae.vtop(sym_addr))
        for element in data[1:]:
            kext.append(element)
        return kext

    def get_kextstat(self, sym_addr): # 11.11.23 64bit suppport
        kext_list = []
        if self.arch == 32:
            Kext = self.x86_mem_pae.read(sym_addr, 4); # .data _kmod
            kext_offset = struct.unpack('I', Kext)[0]
	    while(1):
                kext = []
		if kext_offset == 0:
		    break
		if not(self.x86_mem_pae.is_valid_address(kext_offset)):
		    break
                Kext = self.x86_mem_pae.read(kext_offset, DATA_KEXT_STRUCTURE[0]); # .data _kmod
                data = struct.unpack(DATA_KEXT_STRUCTURE[1], Kext)

                kext.append(self.x86_mem_pae.vtop(kext_offset))
                for element in data[1:]:
                    kext.append(element)
                    
		kext_list.append(kext)

		kext_offset = data[0]
		
        else: # 64
            Kext = self.x86_mem_pae.read(sym_addr, 8);
            kext_offset = struct.unpack('Q', Kext)[0]
	    while(1):
                kext = []
		if kext_offset == 0:
		    break
		if not(self.x86_mem_pae.is_valid_address(kext_offset)):
		    break
		Kext = self.x86_mem_pae.read(kext_offset, DATA_KEXT_STRUCTURE[2]); # .data _g_kernel_kmod_info
		data = struct.unpack(DATA_KEXT_STRUCTURE[3], Kext)

                kext.append(self.x86_mem_pae.vtop(kext_offset))
                for element in data[1:]:
                    kext.append(element)
                    
		kext_list.append(kext)

		kext_offset = data[0]

        return kext_list


#################################### PUBLIC FUNCTIONS ####################################

def get_kext_list(x86_mem_pae, sym_addr, sym_addr2, arch, os_version, build):
    kextlist = []
    KEXTMan = kext_manager(x86_mem_pae, arch)
    kext_list = KEXTMan.get_kextstat(sym_addr)
    kern_kext = KEXTMan.kern_kextstat(sym_addr2)
    kext_list.append(kern_kext)
    return kext_list

def print_kext_list(kext_list):
    print '[+] Kernel Extention List'

    headerlist = ["OFFSET(P)", "INFO", "KID", "KEXT_NAME", "VERSION", "REFER_COUNT", "REFER_LIST", "ADDRESS", "SIZE", "HDRSIZE", "START_PTR" ,"STOP_PTR"]
    contentlist = []
    
    for data in kext_list:
        line = ['0x%.8X'%data[0]]
        line.append('%d'%data[1])
        line.append('%d'%data[2])
        line.append('%s'%data[3].split('\x00')[0])
        line.append('%s'%data[4].split('\x00')[0])
        line.append('%d'%data[5])
        line.append('0x%.8X'%data[6])
        line.append('0x%.8X'%data[7]) # address ptr
        line.append('%d'%data[8]) # size
        line.append('%d'%data[9])
        line.append('0x%.8X'%data[10])
        line.append('0x%.8X'%data[11])
        contentlist.append(line)

    # use optional max size list here to match default lsof output, otherwise specify
    # lsof +c 0 on the command line to print full name of commands
    mszlist = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1]
    columnprint(headerlist, contentlist, mszlist)

def kext_dump(x86_mem_pae, sym_addr, sym_addr2, arch, os_version, build, KID):
    kextlist = []
    kext_list = get_kext_list(x86_mem_pae, sym_addr, sym_addr2, arch, os_version, build)

    kextname = ''
    offset = 0
    size = 0
    
    bflag = 0
    
    for data in kext_list:
        if data[2] == KID:
            print '[+] Find KEXT: %s, Virtual Address : 0x%.8X, Size: %d'%(data[3].strip('\x00'), data[7], data[8])
            kextname = data[3].strip('\x00')
            offset = data[7]
            size = data[8]
            bflag = 1
    
    if not(bflag):
        print '[+] Unknown KID or Invalid Offset or Size'
        return 1
    
    if not(x86_mem_pae.is_valid_address(offset)) or not(offset) or not(size):
        print '[+] Invalid Virtual Address : 0x%.8X, Size: %d'%(offset, size)
        return 1
    print '[DUMP] FILENAME: %s-%x-%x'%(kextname, offset, offset+size)

    padding_code = 0x00
    pk_padding = struct.pack('=B', padding_code)
    padding = pk_padding*0x1000


    file = open('%s-%x-%x'%(kextname, offset, offset+size), 'wb')
    for kext_offset in range(offset, offset+size, 0x1000):
        if not(x86_mem_pae.is_valid_address(kext_offset)):
            file.write(padding)
            continue
        data = x86_mem_pae.read(kext_offset, 0x1000)
        if data is None:
            file.write(padding)
            continue
        file.write(data)
    file.close()
    print '[DUMP] Complete.'
    return 0
