import sys
import struct

DATA_MOUNT_STRUCTURE = [2212, '=I144x16s1024s1024s', 2276, '=Q204x16s1024s1024s']

class mount_manager():
    def __init__(self, x86_mem_pae, arch):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
    
    
    def mount_list(self, sym_addr): # 11.11.23 64bit suppport(Lion)
        mount_list = []
	if self.arch == 32:
	    mount_t = self.x86_mem_pae.read(sym_addr, 4); # .data _g_kernel_kmod_info
	    data = struct.unpack('I', mount_t)
    
	    while 1:
		if data[0] == 0:
		    break
		if not(self.x86_mem_pae.is_valid_address(data[0])):
		    break
		mount_info = self.x86_mem_pae.read(data[0], DATA_MOUNT_STRUCTURE[0]);
		data = struct.unpack(DATA_MOUNT_STRUCTURE[1], mount_info)
		mount_list.append(data)
	else: #64bit
	    mount_t = self.x86_mem_pae.read(sym_addr, 8); # .data _g_kernel_kmod_info
	    data = struct.unpack('Q', mount_t)
    
	    while 1:
		if data[0] == 0:
		    break
		if not(self.x86_mem_pae.is_valid_address(data[0])):
		    break
		mount_info = self.x86_mem_pae.read(data[0], DATA_MOUNT_STRUCTURE[2]);
		data = struct.unpack(DATA_MOUNT_STRUCTURE[3], mount_info)
		mount_list.append(data)

        return mount_list


#################################### PUBLIC FUNCTIONS ####################################
def get_mount_list(x86_mem_pae, sym_addr, arch, os_version, build):
    MOUNTMan = mount_manager(x86_mem_pae, arch)
    mount_list = MOUNTMan.mount_list(sym_addr)
    return mount_list
    

def print_mount_list(mount_list):
    print '[+] Mount List'
    sys.stdout.write('NEXT ENTRY\tFS TYPE\tMOUNT ON NAME\tMOUNT FROM NAME')
    sys.stdout.write('\n')
    for data in mount_list:
        sys.stdout.write('%.8x\t'%data[0])
        sys.stdout.write('%s\t'%data[1].strip('\x00')) # char[16]
        sys.stdout.write('%s\t'%data[2].strip('\x00')) # char[1024]
        sys.stdout.write('%s'%data[3].strip('\x00')) # char[1024]
        sys.stdout.write('\n')