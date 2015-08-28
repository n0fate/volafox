import sys
import struct

import kextstat

from tableprint import columnprint

from ctypes import *

# base code : check_sysctl and mac module at volatility framework

CTL_MAXNAME = 12

class _sysctl_oid_list(LittleEndianStructure):
	_fields_ = [
		("slh_first", c_int64)
		]

class _slist_entry(LittleEndianStructure):
	_fields_ = [
		("sle_next", c_int64)
		]

class _sysctl_oid(LittleEndianStructure):
	_fields_ = [
		("oid_parents", _sysctl_oid_list),
		("oid_link", _slist_entry),
		("oid_number", c_int32),
		("oid_kind", c_int32),
		("oid_arg1", c_int64),
		("oid_arg2", c_int64),
		("oid_name", c_int64),
		("oid_handler", c_int64),
		("SYSCTL_HANDLER_ARGS", c_int64),
		("oid_fmt", c_int64),
		("oid_refcnt", c_int32),
		("oid_descr", c_int32)
		]

	def get_perms(self):
		ret = ""

		checks = [0x80000000, 0x40000000, 0x00800000]
		perms  = ["R", "W", "L"]

		for (i, c) in enumerate(checks):
			if c & self.oid_kind:
				ret = ret + perms[i]
			else:
				ret = ret + "-"
		return ret

	def get_ctltype(self):
		types = {1: 'CTLTYPE_NODE', 2: 'CTLTYPE_INT', 3: 'CTLTYPE_STRING', 4:'CTLTYPE_QUAD', 5:'CTLTYPE_OPAQUE', 6:'CTLTYPE_UINT', 7:'CTLTYPE_LONG', 8:'CTLTYPE_ULONG'}
		ctltype = self.oid_kind & 0xf

		try:
			return types[ctltype]
		except KeyError:
			return 'INVALID-TYPE'



def _memcpy(buf, fmt):
	return cast(c_char_p(buf), POINTER(fmt)).contents


class _sysctl():
    def __init__(self, x86_mem_pae, symbol_list, arch, os_version, base_address):
        self.mem = x86_mem_pae
        self.arch = arch
        self.base = base_address
        self.symbol = symbol_list
        self.os = os_version

    def _parse_global_variable_sysctls(self, name):
    	known_sysctls = {
    		"hostname"		:	"_hostname",
    		"nisdomainname"	:	"_domainname",
    	}

    	if name in known_sysctls:
    		var_name = known_sysctls[name]
    		var_addr = self.symbol[var_name]

    		var_str = str(self.mem.read(var_addr+self.base, 10).split('\x00')[0])

    		return var_str
    
    def _process(self, prefix, number, offset, r=0):
    	if self.mem.is_valid_address(offset):
    		buf = self.mem.read(offset, sizeof(_sysctl_oid))
	    	sysctl = _memcpy(buf, _sysctl_oid)

    	if r:
    		if self.mem.is_valid_address(sysctl.oid_parents.slh_first):
	    		buf = self.mem.read(sysctl.oid_parents.slh_first, sizeof(_sysctl_oid))
	    		sysctl = _memcpy(buf, _sysctl_oid)

    	while sysctl:
    		name = self.mem.read(sysctl.oid_name, 100)
    		numval = ""
    		try:
    			name = name.split('\x00')[0]
    			if len(name) == 0:
    				break
    			if len(prefix):
	    			name = str(prefix+"."+name)
	    		else:
	    			name = str(name)
	    		
	    		if len(number):
    				numval += str(number+"."+str(int(sysctl.oid_number)))
    			else:
					numval += str(int(sysctl.oid_number))

    		except AttributeError:
    			pass

    		ctltype = sysctl.get_ctltype()

    		if sysctl.oid_arg1 == 0 or not self.mem.is_valid_address(sysctl.oid_arg1):
    			val = self._parse_global_variable_sysctls(name)
    		elif ctltype == 'CTLTYPE_NODE':
    			if sysctl.oid_handler == 0:
    				for info in self._process(name, numval, sysctl.oid_arg1, r=1):
    					yield info

    			val = "Node"
    			#print val

    		elif ctltype in ['CTLTYPE_INT', 'CTLTYPE_QUAD', 'CTLTYPE_OPAQUE']:
    			if ctltype in ['CTLTYPE_INT', 'CTLTYPE_UINT']:
	    			buf = self.mem.read(sysctl.oid_arg1, 4)
	    			val = int(struct.unpack('=I', buf)[0])
	    		else:
	    			buf = self.mem.read(sysctl.oid_arg1, 8)
	    			val = int(struct.unpack('=Q', buf)[0])

    		elif ctltype == 'CTLTYPE_STRING':
    			buf = self.mem.read(sysctl.oid_arg1, 100)
    			val = str(buf.split('\x00')[0])
    			
    		else:
    			val = ctltype

    		yield (sysctl, name, numval, val)

    		if self.mem.is_valid_address(sysctl.oid_link.sle_next):
	    		buf = self.mem.read(sysctl.oid_link.sle_next, sizeof(_sysctl_oid))
	    		sysctl = _memcpy(buf, _sysctl_oid)

	    	else:
	    		sysctl = 0


    
    def calc(self):
    	sysctllist = []

    	sysctl_children_addr = self.symbol['_sysctl__children']
    	buf = self.mem.read(sysctl_children_addr + self.base, sizeof(_sysctl_oid_list))
    	sysctl_oid_list = _memcpy(buf, _sysctl_oid_list)

    	for (sysctl, name, number, val) in self._process("", "", sysctl_oid_list.slh_first):
    		sysctltmp = []
    		sysctltmp.append(name)
    		sysctltmp.append(number)
    		sysctltmp.append(sysctl.get_perms())
    		sysctltmp.append(sysctl.oid_handler)
    		sysctltmp.append(val)
    		sysctllist.append(sysctltmp)

    	return sysctllist


#################################### PUBLIC FUNCTIONS ####################################


def getsysctl(x86_mem_pae, symbol_list, arch, os_version, base_address):
    sysctlclas = _sysctl(x86_mem_pae, symbol_list, arch, os_version, base_address)
    sysctllst = sysctlclas.calc()

    kextlist = kextstat.get_kext_list(x86_mem_pae, symbol_list['_kmod'], symbol_list['_g_kernel_kmod_info'], arch, os_version, base_address)

    print_sysctl(symbol_list, sysctllst, kextlist)
    

def print_sysctl(symbol_list, sysctllist, kextlist):
    headerlist = ["Name", "MIB", "PERMISSION", "Handler", "Value"]
    contentlist = []
    
    for data in sysctllist:
    	if data[4] is 'Node':
    		continue
        line = ['%s'%data[0]]
        line.append('%s'%data[1])
        line.append('%s'%data[2])
        handler = data[3] & 0xffffffffffffffff

        flag = False
        for kext in kextlist:
        	if handler > kext[7] and handler < kext[7]+kext[8]:
        		flag = True
        		line.append(kext[3].split('\x00')[0])
        		break
        if not flag:
        	line.append('0x%08x'%(handler))
        line.append('%s'%data[4])
        contentlist.append(line)
        
    mszlist = [-1, -1, -1, -1, -1]
    columnprint(headerlist, contentlist, mszlist)
