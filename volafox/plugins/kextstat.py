import sys
import struct

# SN/Lion 32bit, SN/Lion 64bit
DATA_KEXT_STRUCTURE = [168, '=III64s64sIIIIIII', 196, '=QII64s64sIQQQQQQ']

class kext_manager():
    def __init__(self, x86_mem_pae, arch):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        
    def kern_kextstat(self, sym_addr): # 11.11.23 64bit suppport
        if self.arch == 32:
            Kext = self.x86_mem_pae.read(sym_addr, DATA_KEXT_STRUCTURE[0]); # .data _g_kernel_kmod_info
            data = struct.unpack(DATA_KEXT_STRUCTURE[1], Kext)
        else: # self.arch == 64
            Kext = self.x86_mem_pae.read(sym_addr, DATA_KEXT_STRUCTURE[2]); # .data _g_kernel_kmod_info
            data = struct.unpack(DATA_KEXT_STRUCTURE[3], Kext)
        return data

    def get_kextstat(self, sym_addr): # 11.11.23 64bit suppport
        kext_list = []

        if self.arch == 32:
            Kext = self.x86_mem_pae.read(sym_addr, 4); # .data _kmod
            data = struct.unpack('I', Kext)
	    while(1):
		if data[0] == 0:
		    break
		if not(self.x86_mem_pae.is_valid_address(data[0])):
		    break
                Kext = self.x86_mem_pae.read(data[0], DATA_KEXT_STRUCTURE[0]); # .data _kmod
                data = struct.unpack(DATA_KEXT_STRUCTURE[1], Kext)
		kext_list.append(data)
		
        else: # 64
            Kext = self.x86_mem_pae.read(sym_addr, 8);
            data = struct.unpack('Q', Kext)
	    while(1):
		if data[0] == 0:
		    break
		if not(self.x86_mem_pae.is_valid_address(data[0])):
		    break
		Kext = self.x86_mem_pae.read(data[0], DATA_KEXT_STRUCTURE[2]); # .data _g_kernel_kmod_info
		data = struct.unpack(DATA_KEXT_STRUCTURE[3], Kext)
		kext_list.append(data)

        return kext_list
    
    def print_kext(self):
        print ''


#################################### PUBLIC FUNCTIONS ####################################

def get_kext_list(x86_mem_pae, sym_addr, sym_addr2, arch, os_version, build):
    kextlist = []
    KEXTMan = kext_manager(x86_mem_pae, arch)
    kext_list = KEXTMan.get_kextstat(sym_addr)
    kern_kext = KEXTMan.kern_kextstat(sym_addr2)
    kext_list.append(kern_kext)
    return kext_list

def print_kext_list(kext_list):
    print '\n-= Kernel Extentions(Kext) =-'
    sys.stdout.write( 'kmod_info_ptr\tinfo_version\tid\tname\tversion\treference_count\treference_list\taddress_ptr\tsize\thdr_size\tstart_ptr\tstop_ptr')
    sys.stdout.write('\n')

    for data in kext_list:
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

def kext_dump(x86_mem_pae, sym_addr, sym_addr2, arch, os_version, build, KID):
    kextlist = []
    kext_list = get_kext_list(x86_mem_pae, sym_addr, sym_addr2, arch, os_version, build)
    
    offset = 0
    size = 0
    
    bflag = 0
    
    for data in kext_list:
        if data[2] == KID:
            print '[+] Find KEXT: %s, Offset: %x, Size: %x'%(data[3].strip('\x00'), data[7], data[8])
            offset = data[7]
            size = data[8]
            bflag = 1
    
    if not(bflag):
        print '[+] Unknown KID or Invalid Offset or Size'
        return 1
    
    if not(x86_mem_pae.is_valid_address(offset)) or not(offset) or not(size):
        print '[+] Invalid Offset : %x, Size: %x'%(offset, size)
        return 1
    print '[DUMP] FILENAME: %s-%x-%x'%(data[3].strip('\x00'), offset, offset+size)

    padding_code = 0x00
    pk_padding = struct.pack('=B', padding_code)
    padding = pk_padding*0x1000


    file = open('%s-%x-%x'%(data[3].strip('\x00'), offset, offset+size), 'wb')
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