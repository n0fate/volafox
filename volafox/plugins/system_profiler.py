import struct
import time

class system_profiler:
    def __init__(self, x86_mem_pae):
        self.x86_mem_pae = x86_mem_pae

    def machine_info(self, sym_addr):
        machine_info = self.x86_mem_pae.read(sym_addr, 40); # __DATA.__common _machine_info
        data = struct.unpack('IIIIQIIII', machine_info)
        return data
    
    def sw_vers(self, sym_addr): # 11.11.23 64bit suppport
        os_version = self.x86_mem_pae.read(sym_addr, 10) # __DATA.__common _osversion
        data = struct.unpack('10s', os_version)
        return data
    
    def get_gmtime(self, sym_addr):
        time_val = self.x86_mem_pae.read(sym_addr, 4);
        data = struct.unpack('i', time_val)
        strtime = time.strftime("%a %b %d %H:%M:%S %Y", time.gmtime(data[0]))
        return strtime  


#################################### PUBLIC FUNCTIONS ####################################
def get_system_profile(x86_mem_pae, sw_vers, machine_info, boottime, sleeptime, waketime):
    
    Sys_Profile = system_profiler(x86_mem_pae)
    
    print '[+] Mac OS X Basic Information'
	
    sw_ver_data = Sys_Profile.sw_vers(sw_vers)[0]
    print ' [-] Darwin kernel Build Number: %s'%sw_ver_data.strip('\x00')
    
    data = Sys_Profile.machine_info(machine_info)
    print ' [-] Darwin Kernel Major Version: %d'%data[0]
    print ' [-] Darwin Kernel Minor Version: %d'%data[1]
    print ' [-] Number of Physical CPUs: %d'%data[2]
    print ' [-] Size of memory in bytes: %d bytes'%data[3]
    print ' [-] Size of physical memory: %d bytes'%data[4]
    print ' [-] Number of physical CPUs now available: %d'%data[5]
    print ' [-] Max number of physical CPUs now possible: %d'%data[6]
    print ' [-] Number of logical CPUs now available: %d'%data[7]
    print ' [-] Max number of logical CPUs now possible: %d'%data[8]
    
    if boottime != 0:
        print ' [-] Kernel Boot Time: %s (GMT +0)'%Sys_Profile.get_gmtime(boottime) # n0fate's Idea

    #print ' [-] Kernel Boot Time: %s (GMT +0)'%tsb
    print ' [-] Last Hibernated Sleep Time: %s (GMT +0)'%Sys_Profile.get_gmtime(sleeptime) # CL's Idea
    print ' [-] Last Hibernated Wake Time: %s (GMT +0)'%Sys_Profile.get_gmtime(waketime) # CL's Idea