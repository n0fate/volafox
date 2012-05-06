#!/usr/bin/env python

'''
      Author: student researcher, osxmem@gmail.com
   Last Edit: 22 Mar 2012
 Description: Research implementation of file handle support for volafox.

   Dependent: x86.py

Constraints:
  1. NODE field will only be returned for files opened on HFS+ or DEVFS filesystems
  2. Supported filetypes: VNODE
  3. Supported subtypes: REG, DIR, CHR, LINK, FIFO
  4. No unicode support for filenames (8-bit characters only)

Deficiencies:
  1. USER field is not reported correctly for many processes (mismatch with lsof and all
     user-related keywords of ps on the OSX command line)
  3. Files on DEVFS with vnode type of DIR cannot be sized (e.g /dev)

Notes: 
  1. All struct classes MUST have at least one element in their template dictionaries
     (even if not fully implemented during development) or there will be serious
     performance issues as the size is sorted out.
'''

import sys
import struct
import inspect

from sys import stderr

from tableprint import columnprint

from volafox.vatopa.x86 import IA32PagedMemory

# error codes which may be printed in the program output
ECODE = {
	'unsupported': -1,
	'command': -2,
	'pid': -3,
	'fd': -4,
	'type': -5,
	'device': -6,
	'size': -7,
	'node': -8,
	'name': -9
}

####################################### UTILITIES #######################################

# convert dev_t (also first member in struct fsid_t) encoding to major/minor device IDs
def dev_decode(dev_t):
		
	# interpreted from the major(x) and minor(x) macros in bsd/sys/types.h
	maj = (dev_t >> 24) & 255
	min = dev_t & 16777215
	return "%d,%d" %(maj, min)

# print hex representation of a binary string in 8-byte chunks, four to a line
def printhex(binstr):

	hexstr = binstr.encode("hex")
	
	l = len(hexstr)
	i = 0
	while i < l:
		if i+32 < l:
			line = hexstr[i:i+32]
		else:
			line = hexstr[i:]
		out = ""
		j = 0
		for k in xrange(len(line)):
			out += line[k]
			if j == 7:
				out += ' '
				j = 0
			else:
				j += 1	
		print out
		i += 32

# print a string matrix as a formatted table of columns	
##def columnprint(headerlist, contentlist, mszlist=[]):
##	num_columns = len(headerlist)
##	size_list   = []
##	
##	# start sizing by length of column titles
##	for title in headerlist:
##		size_list.append(len(title))
##	
##	# resize based on content
##	for i in xrange(num_columns):
##		for line in contentlist:
##			if len(line) != len(headerlist):
##				stderr.write("ERROR length of header list does not match content.\n")
##				return -1
##			if len(line[i]) > size_list[i]:
##				size_list[i] = len(line[i])
##	
##	# check sizing against optional max size list		
##	if len(mszlist) > 0:
##		if len(mszlist) != len(headerlist):
##			stderr.write("ERROR length of header list does not match max size list.\n")
##			return -1
##		for i in xrange(num_columns):
##			if mszlist[i] < size_list[i] and mszlist[i] > 0:	# -1/0 for unrestricted sz
##				if mszlist[i] < len(headerlist[i]):
##					stderr.write("WARNING max size list and column header length mismatch.\n")
##				size_list[i] = mszlist[i]
##				
##	# prepend header to content list
##	contentlist = [headerlist] + contentlist
##	
##	# build comprehensive, justified, printstring
##	printblock = ""
##	for line in contentlist:
##		printline = ""
##		for i in xrange(num_columns):
##			if i == 0:
##				printline += line[i][:size_list[i]].ljust(size_list[i])
##			elif i == (num_columns-1):
##				printline += " " + line[i][:size_list[i]]
##			else:
##				printline += line[i][:size_list[i]].rjust(size_list[i]+1)
##		printblock += printline + '\n'
##
##	sys.stdout.write('%s' %printblock)

# mtype (enum)
STR = 0		# string: char (8-bit) * size
INT = 1		# int:    32 or 64-bit
SHT = 3		# short:  16-bit

# return unpacked member from a struct given its memory and a member template
def unpacktype(binstr, member, mtype):
	offset = member[1]
	size   = member[2]
	fmt    = ''
	
	if mtype == STR:
		fmt = str(size) + 's'
	elif mtype == INT:
		fmt = 'I' if size == 4 else 'Q'
	elif mtype == SHT:
		fmt = 'H'
	else:
		calling_fxn = sys._getframe(1)
		stderr.write("ERROR %s.%s tried to unpack the unknown type %d.\n" %(callingclass(calling_fxn), calling_fxn.f_code.co_name, mtype))
		return None		
	
	if struct.calcsize(fmt) != len(binstr[offset:size+offset]):
		calling_fxn = sys._getframe(1)
		stderr.write("ERROR %s.%s tried to unpack '%s' (fmt size: %d) from %d bytes.\n" %(callingclass(calling_fxn), calling_fxn.f_code.co_name, fmt, struct.calcsize(fmt), len(binstr[offset:size+offset])))
		return None

	return struct.unpack(fmt, binstr[offset:size+offset])[0]
	
# return the enclosing class when called inside a function (error reporting)
def callingclass(calling_fxn):
	try:
		classname = calling_fxn.f_locals['self'].__class__.__name__
	except KeyError:
		classname = "<unknown>"
	return classname
	
#################################### PRIVATE CLASSES #####################################

# parent from which all structures derive
class Struct(object):

	# static variables common to all structure classes
	TEMPLATES	= None
	mem 		= None
	verb		= False
	arch		= -1
	kvers		= -1
	
	# static variables (subclass-specific)
	template	= None
	ssize		= -1
	
	def validaddr(self, addr):
		if addr == 0:
			calling_fxn = sys._getframe(1)
			stderr.write("WARNING %s.%s was passed a NULL address.\n" %(callingclass(calling_fxn), calling_fxn.f_code.co_name))
			return False
		elif not(Struct.mem.is_valid_address(addr)):
			calling_fxn = sys._getframe(1)
			stderr.write("WARNING %s.%s was passed the invalid address %.8x.\n" %(callingclass(calling_fxn), calling_fxn.f_code.co_name, addr))
			return False
		return True
	
	def __init__(self, addr):
		self.smem = None
	
		if self.__class__.template == None:
		
			# configure template based on architecture and kernel version
			if Struct.arch in self.__class__.TEMPLATES:
				if Struct.kvers in self.__class__.TEMPLATES[Struct.arch]:
					self.__class__.template = self.__class__.TEMPLATES[Struct.arch][Struct.kvers]
				else:
					stderr.write("ERROR %s has no template for x%d Darwin %d.x.\n" %(self.__class__.__name__, Struct.arch, Struct.kvers))
					sys.exit() 
			else:
				stderr.write("ERROR %s does not support %s architecture.\n" %(self.__class__.__name__, str(Struct.arch)))
				sys.exit()
			
			# set size of the structure by iterating over template
			for item in self.__class__.template.values():
				if ( item[1] + item[2] ) > self.__class__.ssize:
					self.__class__.ssize = item[1] + item[2]
					
		if self.validaddr(addr):
			self.smem = Struct.mem.read(addr, self.__class__.ssize);
		else:
			stderr.write("ERROR instance of %s failed to construct with address %.8x.\n" %(self.__class__.__name__, addr))
			
# Cnode --> Filefork
class Filefork(Struct):
	
	TEMPLATES = {
		32:{
			10:{'ff_data':('struct cat_fork',16,96,'',{'cf_size':('off_t',16,8,'SIZE/OFF(LINK)')})}
			, 11:{'ff_data':('struct cat_fork',16,96,'',{'cf_size':('off_t',16,8,'SIZE/OFF(LINK)')})}
		},
		64:{
			10:{'ff_data':('struct cat_fork',32,96,'',{'cf_size':('off_t',32,8,'SIZE/OFF(LINK)')})}
			, 11:{'ff_data':('struct cat_fork',32,96,'',{'cf_size':('off_t',32,8,'SIZE/OFF(LINK)')})}
		}
	}

	def __init__(self, addr):
		super(Filefork, self).__init__(addr)
		
	def getoff(self):
		return unpacktype(self.smem, self.template['ff_data'][4]['cf_size'], INT)

# Vnode --> Cnode
class Cnode(Struct):

	TEMPLATES = {
		32:{
			10:{'c_desc':('struct cat_desc',68,20,'',{'cd_cnid':('cnid_t',80,4,'NODE')}),'c_attr':('struct cat_attr',88,92,'',{'ca_fileid':('cnid_t',88,4,'NODE'),'ca_union2':('union',140,4,'entries->SIZE/OFF(dir)')}),'c_datafork':('struct filefork *',204,4,'->datafork')}
			, 11:{'c_desc':('struct cat_desc',72,20,'',{'cd_cnid':('cnid_t',84,4,'NODE')}),'c_attr':('struct cat_attr',92,92,'',{'ca_fileid':('cnid_t',92,4,'NODE'),'ca_union2':('union',144,4,'entries->SIZE/OFF(dir)')}),'c_datafork':('struct filefork *',208,4,'->datafork')}
		},
		64:{
			10:{'c_desc':('struct cat_desc',104,24,'',{'cd_cnid':('cnid_t',116,4,'NODE')}),'c_attr':('struct cat_attr',128,120,'',{'ca_fileid':('cnid_t',128,4,'NODE'),'ca_union2':('union',204,4,'entries->SIZE/OFF(dir)')}),'c_datafork':('struct filefork *',288,8,'->datafork')}
			, 11:{'c_desc':('struct cat_desc',112,24,'',{'cd_cnid':('cnid_t',124,4,'NODE')}),'c_attr':('struct cat_attr',136,120,'',{'ca_fileid':('cnid_t',136,4,'NODE'),'ca_union2':('union',212,4,'entries->SIZE/OFF(dir)')}),'c_datafork':('struct filefork *',296,8,'->datafork')}
		}
	}

	def __init__(self, addr):
		super(Cnode, self).__init__(addr)
		
	def getnode(self):
		return unpacktype(self.smem, self.template['c_desc'][4]['cd_cnid'], INT)
		
	def getentries(self):		# used to calculate size for DIR files
		return unpacktype(self.smem, self.template['c_attr'][4]['ca_union2'], INT)
		
	def getoff(self):			# returns the size for LINK files
		datafork_ptr = unpacktype(self.smem, self.template['c_datafork'], INT)
		datafork = Filefork(datafork_ptr)
		return datafork.getoff()

# Vnode --> Devnode
class Devnode(Struct):

	TEMPLATES = {
		32:{
			10:{'dn_ino':('ino_t',112,4,'NODE(CHR)')}
			, 11:{'dn_ino':('ino_t',112,4,'NODE(CHR)')}
		},
		64:{
			10:{'dn_ino':('ino_t',192,8,'NODE(CHR)')}
			, 11:{'dn_ino':('ino_t',192,8,'NODE(CHR)')}
		}
	}

	def __init__(self, addr):
		super(Devnode, self).__init__(addr)
		
	def getnode(self):
		return unpacktype(self.smem, self.template['dn_ino'], INT)

# Vnode --> Specinfo
class Specinfo(Struct):

	TEMPLATES = {
		32:{
			10:{'si_rdev':('dev_t',12,4,'->DEVICE(CHR)')}
			, 11:{'si_rdev':('dev_t',12,4,'->DEVICE(CHR)')}
		},
		64:{
			10:{'si_rdev':('dev_t',24,4,'->DEVICE(CHR)')}
			, 11:{'si_rdev':('dev_t',24,4,'->DEVICE(CHR)')}
		}
	}

	def __init__(self, addr):
		super(Specinfo, self).__init__(addr)
		
	def getdev(self):
		dev_t = unpacktype(self.smem, self.template['si_rdev'], INT)
		return dev_decode(dev_t)
			
# Vnode --> Ubcinfo
class Ubcinfo(Struct):
	
	TEMPLATES = {
		32:{
			10:{'ui_size':('off_t',20,8,'SIZE/OFF(REG)')}
			, 11:{'ui_size':('off_t',20,8,'SIZE/OFF(REG)')}
		},
		64:{	# NOTE: 10.6/7x64 offset for ui_size edited manually 32 --> 40
			10:{'ui_size':('off_t',40,8,'SIZE/OFF(REG)')}
			, 11:{'ui_size':('off_t',40,8,'SIZE/OFF(REG)')}
		}
	}

	def __init__(self, addr):
		super(Ubcinfo, self).__init__(addr)
		
	def getoff(self):
		return unpacktype(self.smem, self.template['ui_size'], INT)
		
# Vnode --> Mount
class Mount(Struct):

	TEMPLATES = {
		32:{
			10:{'mnt_vfsstat':('struct vfsstatfs',76,2152,'',{'f_fsid':('fsid_t',132,8,'',{'val[0]':('int32_t',132,4,'->DEVICE'),'val[1]':('int32_t',136,4,'')}),'f_mntonname':('char[]',168,1024,'->NAME')})}
			, 11:{'mnt_vfsstat':('struct vfsstatfs',76,2152,'',{'f_fsid':('fsid_t',132,8,'',{'val[0]':('int32_t',132,4,'->DEVICE'),'val[1]':('int32_t',136,4,'')}),'f_mntonname':('char[]',168,1024,'->NAME')})}
		},
		64:{
			10:{'mnt_vfsstat':('struct vfsstatfs',136,2164,'',{'f_fsid':('fsid_t',196,8,'',{'val[0]':('int32_t',196,4,'->DEVICE'),'val[1]':('int32_t',200,4,'')}),'f_mntonname':('char[]',232,1024,'->NAME')})}
			, 11:{'mnt_vfsstat':('struct vfsstatfs',132,2164,'',{'f_fsid':('fsid_t',192,8,'',{'val[0]':('int32_t',192,4,'->DEVICE'),'val[1]':('int32_t',196,4,'')}),'f_mntonname':('char[]',228,1024,'->NAME')})}
		}
	}

	def __init__(self, addr):
		super(Mount, self).__init__(addr)
		
	def getmount(self):
		return unpacktype(self.smem, Mount.template['mnt_vfsstat'][4]['f_mntonname'], STR).split('\x00', 1)[0].strip('\x00')
		
	def getdev(self):
		dev_t = unpacktype(self.smem, Mount.template['mnt_vfsstat'][4]['f_fsid'][4]['val[0]'], INT)
		return dev_decode(dev_t)

# Proc     --> Vnode (exe)
# Filesesc --> Vnode (cwd)
# Fileglob --> Vnode
# Vnode    --> Vnode (parent)
class Vnode(Struct):
	
	TEMPLATES = {
		32:{
			10:{'v_type':('uint16_t',68,2,'TYPE(vnode)'),'v_tag':('uint16_t',70,2,'vfs-type'),'v_un':('union',76,4,'->ubc_info/specinfo'),'v_name':('const char *',116,4,'NAME'),'v_parent':('vnode_t',120,4,'->vnode(parent)'),'v_mount':('mount_t',136,4,'->mount'),'v_data':('void *',140,4,'->cnode/devnode')}
			, 11:{'v_type':('uint16_t',64,2,'TYPE(vnode)'),'v_tag':('uint16_t',66,2,'vfs-type'),'v_un':('union',72,4,'->ubc_info/specinfo'),'v_name':('const char *',112,4,'NAME'),'v_parent':('vnode_t',116,4,'->vnode(parent)'),'v_mount':('mount_t',132,4,'->mount'),'v_data':('void *',136,4,'->cnode/devnode')}
		},
		64:{
			10:{'v_type':('uint16_t',112,2,'TYPE(vnode)'),'v_tag':('uint16_t',114,2,'vfs-type'),'v_un':('union',120,8,'->ubc_info/specinfo'),'v_name':('const char *',184,8,'NAME'),'v_parent':('vnode_t',192,8,'->vnode(parent)'),'v_mount':('mount_t',224,8,'->mount'),'v_data':('void *',232,8,'->cnode/devnode')}
			, 11:{'v_type':('uint16_t',104,2,'TYPE(vnode)'),'v_tag':('uint16_t',106,2,'vfs-type'),'v_un':('union',112,8,'->ubc_info/specinfo'),'v_name':('const char *',176,8,'NAME'),'v_parent':('vnode_t',184,8,'->vnode(parent)'),'v_mount':('mount_t',216,8,'->mount'),'v_data':('void *',224,8,'->cnode/devnode')}
		}
	}
	
	# NOTE 1: type LINK below is called just "LNK" in the source but lsof uses "LINK"
	# NOTE 2: 10.7 version of lsof appears to be broken for LINK types, it outputs the
	#         undocumented type "0012" instead
	# NOTE 3: these static lists defined in bsd/sys/vnode.h but modified for printing
	VNODE_TYPE = ["NON", "REG", "DIR", "BLK", "CHR", "LINK", "SOCK", "FIFO", "BAD", "STR", "CPLX"]
	VNODE_TAG = ['NON', 'UFS', 'NFS', 'MFS', 'MSDOSFS', 'LFS', 'LOFS', 'FDESC', 'PORTAL', 'NULL', 'UMAP', 'KERNFS', 'PROCFS', 'AFS', 'ISOFS', 'UNION', 'HFS', 'ZFS', 'DEVFS', 'WEBDAV', 'UDF', 'AFP', 'CDDA', 'CIFS', 'OTHER']
	
	def __init__(self, addr):
		super(Vnode, self).__init__(addr)
		self.vtype	= None
		self.tag 	= None
		self.xnode	= None	# cnode, devnode
		self.mount	= None
		
	def getnode(self):
	
		if self.xnode == None:
			x_node_ptr = unpacktype(self.smem, self.template['v_data'], INT)
	
			if self.tag == None:
				self.tag = unpacktype(self.smem, self.template['v_tag'], SHT)
			
			if self.tag == 16:		# VT_HFS
				self.xnode = Cnode(x_node_ptr)

			elif self.tag == 18:	# VT_DEVFS
				self.xnode = Devnode(x_node_ptr)
						
			else:
				if self.tag < len(Vnode.VNODE_TAG):
					s_tag = Vnode.VNODE_TAG[self.tag]
				else:
					s_tag = str(self.tag)
				stderr.write("WARNING Vnode.getnode(): unsupported FS tag %s, returning %d.\n" %(s_tag, ECODE['node']))
				return ECODE['node']
				
		return self.xnode.getnode()
	
	def getname(self):
		name_ptr = unpacktype(self.smem, self.template['v_name'], INT)
		
		if name_ptr == 0 or not(Struct.mem.is_valid_address(name_ptr)):
			return None
			
		# NOTE: this may be trouble for the 255 UTF-16 filename characters HFS+ allows
		name_addr = Struct.mem.read(name_ptr, 255)
		name = struct.unpack('255s', name_addr)[0]
		return name.split('\x00', 1)[0].strip('\x00')
		
	def getparent(self):
		parent_ptr = unpacktype(self.smem, self.template['v_parent'], INT)
		
		if parent_ptr == 0 or not(Struct.mem.is_valid_address(parent_ptr)):
			return None
		return parent_ptr
		
	def getdev(self):
	
		if self.tag == None:
			self.tag = unpacktype(self.smem, self.template['v_tag'], SHT)
	
		if self.tag == 18:	# CHR
			vu_specinfo = unpacktype(self.smem, self.template['v_un'], INT)
			
			# this pointer is invalid for /dev (special case DIR using VT_DEVFS)
			if not(vu_specinfo == 0) and Struct.mem.is_valid_address(vu_specinfo):
				specinfo = Specinfo(vu_specinfo)
				return specinfo.getdev()
			
		# default return for REG/DIR/LINK
		if self.mount == None:
			mount_ptr = unpacktype(self.smem, self.template['v_mount'], INT)
			
			if mount_ptr == 0 or not(Struct.mem.is_valid_address(mount_ptr)):
				stderr.write("WARNING Vnode.getdev(): v_mount pointer invalid, returning %d.\n" %ECODE['device'])
				return ECODE['device']

			self.mount = Mount(mount_ptr)

		return self.mount.getdev()
	
	def getpath(self):
		path 		= ""
		mntonname	= ""
		parent		= self
		
		if self.tag == None:
			self.tag = unpacktype(self.smem, self.template['v_tag'], SHT)
			
		if self.mount == None:
			mount_ptr = unpacktype(self.smem, self.template['v_mount'], INT)
			
			if mount_ptr == 0 or not(Struct.mem.is_valid_address(mount_ptr)):
				stderr.write("WARNING Vnode.getpath(): v_mount pointer invalid, returning %d.\n" %ECODE['name'])
				mntonname = str(ECODE['name'])
				
			else:
				self.mount = Mount(mount_ptr)
				
		if self.mount != None:
			mntonname = self.mount.getmount()
			
		while True:
			parent_ptr = parent.getparent()
			if parent_ptr == 0 or not(Struct.mem.is_valid_address(parent_ptr)):
				break
		
			name = parent.getname()
			if name == None:
				break
				
			path = name + "/" + path
			parent = Vnode(parent_ptr)
		
		if len(path) < 2:					# file is root
			return mntonname				
			
		if len(mntonname) == 1:				# mount is root, delete trailing slash
			return mntonname + path[:-1]
		
		return mntonname + "/" + path[:-1]	# mount + path, delete trailing slash
		
	def gettype(self):
	
		if self.vtype == None:
			self.vtype = unpacktype(self.smem, self.template['v_type'], SHT)
			
		if self.vtype < len(Vnode.VNODE_TYPE):
			return Vnode.VNODE_TYPE[self.vtype]
		
		return -1	# check for this in the Vnode_pager validation
		
	def getoff(self, fileglob_offset):
	
		if self.vtype == None:
			self.vtype = unpacktype(self.smem, self.template['v_type'], SHT)
		if self.tag == None:
			self.tag = unpacktype(self.smem, self.template['v_tag'], SHT)
		
		# NOTE: UBC information not valid for vnodes marked as VSYSTEM
		if self.vtype == 1:			# REG
			ubcinfo_ptr = unpacktype(self.smem, self.template['v_un'], INT)
			
			if ubcinfo_ptr == 0 or not(Struct.mem.is_valid_address(ubcinfo_ptr)):
				stderr.write("WARNING Vnode.getoff(): v_un pointer invalid, returning %d.\n" %(ECODE['size']))
				return ECODE['size']
				
			ubcinfo = Ubcinfo(ubcinfo_ptr)
			return ubcinfo.getoff()
			
		elif self.tag == 16:		# VT_HFS
			if self.xnode == None:
				x_node_ptr = unpacktype(self.smem, self.template['v_data'], INT)
				self.xnode = Cnode(x_node_ptr)
				
			if self.vtype == 2:		# DIR
				entries = self.xnode.getentries()
				return (entries + 2) * 34	# AVERAGE_HFSDIRENTRY_SIZE: bsd/hfs/hfs.h
				
			elif self.vtype == 5:	# LINK
				return self.xnode.getoff()
				
			elif self.vtype == 7:	# FIFO
				return "0t%i" %fileglob_offset
				
		elif self.tag == 18:		# VT_DEVFS
			if self.vtype == 4:		# CHR
				return "0t%i" %fileglob_offset
				
			elif self.vtype == 2:	# /dev
				return "-1"			# not returning ECODE because this deficiency known
			
		if self.tag < len(Vnode.VNODE_TAG):
			s_tag = Vnode.VNODE_TAG[self.tag]
		else:
			s_tag = str(self.tag)
		if self.vtype < len(Vnode.VNODE_TYPE):
			s_type = Vnode.VNODE_TYPE[self.vtype]
		else:
			s_type = str(self.vtype)	
		stderr.write("WARNING Vnode.getoff(): unsupported type %s, tag %s. Returning %d.\n" %(s_type, s_tag, ECODE['size']))
		return ECODE['size']
		
# Fileproc --> Fileglob
class Fileglob(Struct):

	TEMPLATES = {
		32:{
			10:{'fg_flag':('int32_t',16,4,'MODE'),'fg_type':('file_type_t',20,4,'FTYPE'),'fg_offset':('off_t',40,8,'SIZE/OFF'),'fg_data':('caddr_t',48,4,'->vnode')}
			, 11:{'fg_flag':('int32_t',16,4,'MODE'),'fg_type':('file_type_t',20,4,'FTYPE'),'fg_offset':('off_t',40,8,'SIZE/OFF'),'fg_data':('caddr_t',48,4,'->vnode')}
		},
		64:{
			10:{'fg_flag':('int32_t',32,4,'MODE'),'fg_type':('file_type_t',36,4,'FTYPE'),'fg_offset':('off_t',64,8,'SIZE/OFF'),'fg_data':('caddr_t',72,8,'->vnode')}
			, 11:{'fg_flag':('int32_t',32,4,'MODE'),'fg_type':('file_type_t',36,4,'FTYPE'),'fg_offset':('off_t',64,8,'SIZE/OFF'),'fg_data':('caddr_t',72,8,'->vnode')}
		}
	}
	
	# global defined in bsd/sys/file_internal.h but modified to match lsof output
	FILE_TYPE = ["-1", "VNODE", "SOCKET", "PSXSHM", "PSXSEM", "KQUEUE", "PIPE", "FSEVENT"]
	MODE      = ["  ", "r ", "w ", "u "]
	
	def __init__(self, addr):
		super(Fileglob, self).__init__(addr)
		self.ftype = None
		
	def getmode(self, fd):
		self.ftype = unpacktype(self.smem, self.template['fg_type'], INT)
		filemode = "  "
	
		# NOTE: in limited lsof testing types known to include file mode reporting are:
		#       VNODE, SOCKET, PSXSHM, PSXSEM, and KQUEUE. Others do not append any
		#       character to the FD identifier.
		if self.ftype in xrange(1,6):
			flag = unpacktype(self.smem, self.template['fg_flag'], INT)
			filemode = Fileglob.MODE[flag & 3]

		return str(fd)+filemode
		
	def gettype(self):
	
		if self.ftype == None:
			self.ftype = unpacktype(self.smem, self.template['fg_type'], INT)
			
		if self.ftype < 0 or self.ftype > ( len(Fileglob.FILE_TYPE) -1 ):
			stderr.write("WARNING Fileglob.gettype(): unknown file type %d, excluding this result.\n" %self.ftype)
			return -1		# check for this in the getfilelistbyproc()
			
		return Fileglob.FILE_TYPE[self.ftype]
		
	def getoff(self):
		return unpacktype(self.smem, self.template['fg_offset'], INT)
		
	def getdata(self):
		data_ptr = unpacktype(self.smem, self.template['fg_data'], INT)
		
		if self.validaddr(data_ptr):
			return data_ptr
		return None
		
# Filedesc --> Fileproc
class Fileproc(Struct):

	TEMPLATES = {
		32:{
			10:{'f_fglob':('struct fileglob *',8,4,'->fileglob')}
			, 11:{'f_fglob':('struct fileglob *',8,4,'->fileglob')}
		},
		64:{
			10:{'f_fglob':('struct fileglob *',8,8,'->fileglob')}
			, 11:{'f_fglob':('struct fileglob *',8,8,'->fileglob')}
		}
	}
	
	def __init__(self, addr):
		super(Fileproc, self).__init__(addr)
		
	def getfglob(self):
		fileglob_ptr = unpacktype(self.smem, self.template['f_fglob'], INT)
		
		if self.validaddr(fileglob_ptr):
			return fileglob_ptr
		return None

# Proc --> Filedesc
class Filedesc(Struct):
	
	TEMPLATES = {
		32:{
			10:{'fd_ofiles':('struct fileproc **',0,4,'->fileproc[]'),'fd_cdir':('struct vnode *',8,4,'->CWD'),'fd_lastfile':('int',20,4,'->fileproc[LAST_INDEX]')}
			, 11:{'fd_ofiles':('struct fileproc **',0,4,'->fileproc[]'),'fd_cdir':('struct vnode *',8,4,'->CWD'),'fd_lastfile':('int',20,4,'->fileproc[LAST_INDEX]')}
		},
		64:{
			10:{'fd_ofiles':('struct fileproc **',0,8,'->fileproc[]'),'fd_cdir':('struct vnode *',16,8,'->CWD'),'fd_lastfile':('int',36,4,'->fileproc[LAST_INDEX]')}
			, 11:{'fd_ofiles':('struct fileproc **',0,8,'->fileproc[]'),'fd_cdir':('struct vnode *',16,8,'->CWD'),'fd_lastfile':('int',36,4,'->fileproc[LAST_INDEX]')}
		}
	}
	
	def __init__(self, addr):
		super(Filedesc, self).__init__(addr)
	
	def getcwd(self):
		cwd_ptr = unpacktype(self.smem, self.template['fd_cdir'], INT)
		if self.validaddr(cwd_ptr):
			return cwd_ptr
		return None
		
	def getfglobs(self):
	
		# sometimes the fd is valid, but this array address is not (e.g. kernel_task)
		ofiles_ptr = unpacktype(self.smem, Filedesc.template['fd_ofiles'], INT)
		if ofiles_ptr == 0 or not(Struct.mem.is_valid_address(ofiles_ptr)):
			return None
		
		# construct a list of addresses from the fd_ofiles array
		fd_lastfile	= unpacktype(self.smem, Filedesc.template['fd_lastfile'], INT)
		ptr_size	= 4 if (Struct.arch == 32) else 8
		fmt			= 'I' if (Struct.arch == 32) else 'Q'
		fglobs		= {}
		for i in xrange(fd_lastfile+1):
		
			# **fd_ofiles is an array of pointers, read address at index i
			fileproc_ptr = Struct.mem.read(ofiles_ptr+(i*ptr_size), ptr_size)
			fileproc_addr = struct.unpack(fmt, fileproc_ptr)[0]
		
			# not every index points to a valid file
			if fileproc_addr == 0 or not(Struct.mem.is_valid_address(fileproc_addr)):
				continue
				
			fileproc = Fileproc(fileproc_addr)
			fileglob_ptr = fileproc.getfglob()
			
			if fileglob_ptr != None:
				fglobs[i] = fileglob_ptr
			
		return fglobs

# Vm_object --> Vnode_pager
class Vnode_pager(Struct):

	TEMPLATES = {
		32:{
			10:{'vnode_handle':('struct vnode *',16,4,'->txt')}
			, 11:{'vnode_handle':('struct vnode *',16,4,'->txt')}
		},
		64:{	# NOTE: 10.6/7x64 offset for vnode_pager edited manually 24 --> 32
			10:{'vnode_handle':('struct vnode *',32,8,'->txt')}
			, 11:{'vnode_handle':('struct vnode *',32,8,'->txt')}
		}
	}

	def __init__(self, addr):
		super(Vnode_pager, self).__init__(addr)
	
	def gettxt(self):
		txt_ptr = unpacktype(self.smem, self.template['vnode_handle'], INT)
		
		# self may not actually be a vnode pager (there are other valid types), need to
		# run several tests without generating warnings to be sure.
		if txt_ptr == 0 or not(Struct.mem.is_valid_address(txt_ptr)):
			return None
		
		# this pointer test ensures the target memory matches the vnode template
		vnode = Vnode(txt_ptr)
		if vnode.gettype() == -1 or vnode.getname() == None:
			return None
		
		# return the pointer rather than vnode because duplicates will occur as a result
		# of recursive calls in Vm_object
		return txt_ptr

# Vm_map_entry --> Vm_object
class Vm_object(Struct):

	TEMPLATES = {
		32:{
			10:{'memq':('queue_head_t',0,8,'',{'next':('struct queue_entry *',4,4,'type test(vm_object)'),'prev':('struct queue_entry *',0,4,'type test(vm_object)')}),'shadow':('struct vm_object *',52,4,'->vm_object(recurse)'),'pager':('memory_object_t',64,4,'->pager')}
			, 11:{'memq':('queue_head_t',0,8,'',{'next':('struct queue_entry *',4,4,'type test(vm_object)'),'prev':('struct queue_entry *',0,4,'type test(vm_object)')}),'shadow':('struct vm_object *',52,4,'->vm_object(recurse)'),'pager':('memory_object_t',64,4,'->pager')}
		},
		64:{
			10:{'memq':('queue_head_t',0,16,'',{'next':('struct queue_entry *',8,8,'type test(vm_object)'),'prev':('struct queue_entry *',0,8,'type test(vm_object)')}),'shadow':('struct vm_object *',72,8,'->vm_object(recurse)'),'pager':('memory_object_t',88,8,'->pager')}
			, 11:{'memq':('queue_head_t',0,16,'',{'next':('struct queue_entry *',8,8,'type test(vm_object)'),'prev':('struct queue_entry *',0,8,'type test(vm_object)')}),'shadow':('struct vm_object *',72,8,'->vm_object(recurse)'),'pager':('memory_object_t',88,8,'->pager')}
		}
	}

	def __init__(self, addr):
		super(Vm_object, self).__init__(addr)
		self.map = None
		
		# this test determines wether self matches the struct vm_object template, or the
		# vm_map template.
		ptr1 = unpacktype(self.smem, self.template['memq'][4]['next'], INT)
		ptr2 = unpacktype(self.smem, self.template['memq'][4]['prev'], INT)
		if ptr1 == 0 or ptr2 == 0 \
			or not(Struct.mem.is_valid_address(ptr1)) \
			or not(Struct.mem.is_valid_address(ptr2)):
			
				# on failure, create map instance to be called recursively
				self.map = Vm_map(addr)

	def gettxt(self):
	
		# recurse on vm_map type
		if self.map != None:
			return self.map.gettxt()
	
		pager_ptr = unpacktype(self.smem, self.template['pager'], INT)
		
		# objects for memory-mapped files keep the pager in the shadow object rather
		# than the original, this test determines which self is.
		if pager_ptr == 0 or not(Struct.mem.is_valid_address(pager_ptr)):
			
			shadow_ptr = unpacktype(self.smem, self.template['shadow'], INT)
			if shadow_ptr == 0 or not(Struct.mem.is_valid_address(shadow_ptr)):
				return []	# Vm_map expects an empty list, never None
				
			# make recursive call on shadow object
			shadow = Vm_object(shadow_ptr)
			return shadow.gettxt()
			
		# the default case here wraps the return in a list for compatibility with the
		# recursive map case.
		pager = Vnode_pager(pager_ptr)
		return [ pager.gettxt() ]		# NOTE: this may return [ None ] without error

# Vm_map_entry --> Vm_map_entry
# Vm_map       --> Vm_map_entry
class Vm_map_entry(Struct):

	TEMPLATES = {
		32:{
			10:{'links':('struct vm_map_links',0,24,'',{'prev':('struct vm_map_entry *',0,4,''),'next':('struct vm_map_entry *',4,4,'->vm_map_entry')}),'object':('union vm_map_object',24,4,'->vm_object')}
			, 11:{'links':('struct vm_map_links',0,24,'',{'prev':('struct vm_map_entry *',0,4,''),'next':('struct vm_map_entry *',4,4,'->vm_map_entry')}),'object':('union vm_map_object',36,4,'->vm_object')}
		},
		64:{
			10:{'links':('struct vm_map_links',0,32,'',{'prev':('struct vm_map_entry *',0,8,''),'next':('struct vm_map_entry *',8,8,'->vm_map_entry')}),'object':('union vm_map_object',32,8,'->vm_object')}
			, 11:{'links':('struct vm_map_links',0,32,'',{'prev':('struct vm_map_entry *',0,8,''),'next':('struct vm_map_entry *',8,8,'->vm_map_entry')}),'object':('union vm_map_object',56,8,'->vm_object')}
		}
	}

	def __init__(self, addr):
		super(Vm_map_entry, self).__init__(addr)

	def getnext(self):
		return unpacktype(self.smem, self.template['links'][4]['next'], INT)
	
	def gettxt(self):
		vmobject_ptr = unpacktype(self.smem, self.template['object'], INT)
		
		# some entries lack an object, check manually to prevent error
		if vmobject_ptr == 0 or not(Struct.mem.is_valid_address(vmobject_ptr)):
			return []	# Vm_map expects an empty list, never None
			
		vm_object = Vm_object(vmobject_ptr)
		return vm_object.gettxt()
		
# Vm_object --> Vm_map
# Task      --> Vm_map
class Vm_map(Struct):

	TEMPLATES = {
		32:{
			10:{'hdr':('struct vm_map_header',12,32,'',{'links':('struct vm_map_links',12,24,'',{'prev':('struct vm_map_entry *',12,4,''),'next':('struct vm_map_entry *',16,4,'->vm_map_entry')}),'nentries':('int',36,4,'no. nodes')})}
			, 11:{'hdr':('struct vm_map_header',12,44,'',{'links':('struct vm_map_links',12,24,'',{'prev':('struct vm_map_entry *',12,4,''),'next':('struct vm_map_entry *',16,4,'->vm_map_entry')}),'nentries':('int',36,4,'no. nodes')})}
		},
		64:{
			10:{'hdr':('struct vm_map_header',16,40,'',{'links':('struct vm_map_links',16,32,'',{'prev':('struct vm_map_entry *',16,8,''),'next':('struct vm_map_entry *',24,8,'->vm_map_entry')}),'nentries':('int',48,4,'no. nodes')})}
			, 11:{'hdr':('struct vm_map_header',16,56,'',{'links':('struct vm_map_links',16,32,'',{'prev':('struct vm_map_entry *',16,8,''),'next':('struct vm_map_entry *',24,8,'->vm_map_entry')}),'nentries':('int',48,4,'no. nodes')})}
		}
	}

	def __init__(self, addr):
		super(Vm_map, self).__init__(addr)

	def gettxt(self):
		vmmapentry_ptr = unpacktype(self.smem, self.template['hdr'][4]['links'][4]['next'], INT)
		nentries = unpacktype(self.smem, self.template['hdr'][4]['nentries'], INT)
		ret_ptrs = []
		
		# iterate over map entries in the linked-list and collect any backing vnode ptrs
		for i in xrange(nentries):

			if self.validaddr(vmmapentry_ptr):
				vm_map_entry = Vm_map_entry(vmmapentry_ptr)
				txt_ptrs = vm_map_entry.gettxt()
				
				for txt_ptr in txt_ptrs:
				
					# filter duplicates and check for null returns
					if txt_ptr != None and not(txt_ptr in ret_ptrs):
						ret_ptrs.append(txt_ptr)
				
			vmmapentry_ptr = vm_map_entry.getnext()
		
		# unique list of verified vnode pointers
		return ret_ptrs

# Proc --> Task
class Task(Struct):

	TEMPLATES = {
		32:{
			10:{'map':('vm_map_t',24,4,'->vm_map')}
			, 11:{'map':('vm_map_t',20,4,'->vm_map')}
		},
		64:{	
			10:{'map':('vm_map_t',40,8,'->vm_map'),}	# NOTE: 10.6x64 offset for vm_map edited manually 36 --> 40
			, 11:{'map':('vm_map_t',32,8,'->vm_map')}	# NOTE: 10.7x64 offset for vm_map edited manually 28 --> 32
		}
	}

	def __init__(self, addr):
		super(Task, self).__init__(addr)

	def gettxt(self):
		vmmap_ptr = unpacktype(self.smem, self.template['map'], INT)
		
		if self.validaddr(vmmap_ptr):
			vm_map = Vm_map(vmmap_ptr)
			return vm_map.gettxt()

		return None
		
# Pgrp --> Session
class Session(Struct):

	TEMPLATES = {
		32:{
			10:{'s_login':('char[]',28,255,'USER')}
			, 11:{'s_login':('char[]',28,255,'USER')}
		},
		64:{
			10:{'s_login':('char[]',48,255,'USER')}
			, 11:{'s_login':('char[]',48,255,'USER')}
		}
	}
	
	def __init__(self, addr):
		super(Session, self).__init__(addr)
		
	def getuser(self):
		return unpacktype(self.smem, self.template['s_login'], STR).split('\x00', 1)[0].strip('\x00')
	
# Proc --> Pgrp
class Pgrp(Struct):

	TEMPLATES = {
		32:{
			10:{'pg_session':('struct session *',12,4,'->session')}
			, 11:{'pg_session':('struct session *',12,4,'->session')}
		},
		64:{
			10:{'pg_session':('struct session *',24,8,'->session')}
			, 11:{'pg_session':('struct session *',24,8,'->session')}
		}
	}

	def __init__(self, addr):
		super(Pgrp, self).__init__(addr)

	# skipped the full validator here because pg_session is the only pointer/target
	def getuser(self):
		session_ptr = unpacktype(self.smem, self.template['pg_session'], INT)
		
		if self.validaddr(session_ptr):
			session = Session(session_ptr)
			return session.getuser()
			
		return None

# _kernproc --> Proc
class Proc(Struct):

	TEMPLATES = {
		32:{
			10:{'p_list':('LIST_ENTRY(proc)',0,8,'',{'le_next':('struct proc *',0,4,''),'le_prev':('struct proc **',4,4,'->next')}),'p_pid':('pid_t',8,4,'PID'),'task':('void *',12,4,'->task'),'p_fd':('struct filedesc *',104,4,'->filedesc'),'p_textvp':('struct vnode *',388,4,'->proc(exe)'),'p_comm':('char[]',420,17,'COMMAND'),'p_pgrp':('struct pgrp *',472,4,'->pgrp')}
			, 11:{'p_list':('LIST_ENTRY(proc)',0,8,'',{'le_next':('struct proc *',0,4,''),'le_prev':('struct proc **',4,4,'->next')}),'p_pid':('pid_t',8,4,'PID'),'task':('void *',12,4,'->task'),'p_fd':('struct filedesc *',128,4,'->filedesc'),'p_textvp':('struct vnode *',412,4,'->proc(exe)'),'p_comm':('char[]',444,17,'COMMAND'),'p_pgrp':('struct pgrp *',496,4,'->pgrp')}
		},
		64:{
			10:{'p_list':('LIST_ENTRY(proc)',0,16,'',{'le_next':('struct proc *',0,8,''),'le_prev':('struct proc **',8,8,'->next')}),'p_pid':('pid_t',16,4,'PID'),'task':('void *',24,8,'->task'),'p_fd':('struct filedesc *',200,8,'->filedesc'),'p_textvp':('struct vnode *',664,8,'->proc(exe)'),'p_comm':('char[]',700,17,'COMMAND'),'p_pgrp':('struct pgrp *',752,8,'->pgrp')}
			, 11:{'p_list':('LIST_ENTRY(proc)',0,16,'',{'le_next':('struct proc *',0,8,''),'le_prev':('struct proc **',8,8,'->next')}),'p_pid':('pid_t',16,4,'PID'),'task':('void *',24,8,'->task'),'p_fd':('struct filedesc *',216,8,'->filedesc'),'p_textvp':('struct vnode *',680,8,'->proc(exe)'),'p_comm':('char[]',716,17,'COMMAND'),'p_pgrp':('struct pgrp *',768,8,'->pgrp')}
		}
	}
	
	head = None
	
	def __init__(self, addr):
		super(Proc, self).__init__(addr)
		
		if Proc.head == None:
			Proc.head = addr
			
		self.self_ptr		= addr	# store this for cycle detection by getfilelist()
		self.filedesc_ptr	= None
		self.exe_ptr		= None
		self.pgrp_ptr		= None
		self.pid			= -1
			
	def next(self):
		nxt_proc = unpacktype(self.smem, Proc.template['p_list'][4]['le_prev'], INT)
		
		if nxt_proc == Proc.head:
			stderr.write("ERROR %s.%s encountered a circular list.\n" %(self.__class__.__name__, sys._getframe().f_code.co_name))
			return None
			
		elif nxt_proc != 0 and Struct.mem.is_valid_address(nxt_proc):
			return Proc(nxt_proc)
		
		return None
		
	# this method has evolved to check ALL requisite proc structure pointers
	def valid(self):
		
		# check *p_fd
		filedesc_ptr = unpacktype(self.smem, self.template['p_fd'], INT)
		if filedesc_ptr == 0 or not(Struct.mem.is_valid_address(filedesc_ptr)):
			return False
		
		# check *p_textvp
		exe_ptr = unpacktype(self.smem, self.template['p_textvp'], INT)
		if exe_ptr == 0 or not(Struct.mem.is_valid_address(exe_ptr)):
			return False
		
		# check *p_pgrp
		pgrp_ptr = unpacktype(self.smem, self.template['p_pgrp'], INT)
		if pgrp_ptr == 0 or not(Struct.mem.is_valid_address(pgrp_ptr)):
			return False
			
		self.filedesc_ptr	= filedesc_ptr
		self.exe_ptr  		= exe_ptr
		self.pgrp_ptr		= pgrp_ptr
		return True
		
	def setpid(self, pid):
		self.pid = unpacktype(self.smem, Proc.template['p_pid'], INT)
		
		while self.pid != pid:
			nxt_proc = unpacktype(self.smem, Proc.template['p_list'][4]['le_prev'], INT)
			
			if nxt_proc == Proc.head:
				stderr.write("ERROR %s.%s encountered a circular list.\n" %(self.__class__.__name__, sys._getframe().f_code.co_name))
				return False
			elif nxt_proc != 0 and Struct.mem.is_valid_address(nxt_proc):
				self.smem = Struct.mem.read(nxt_proc, Proc.ssize);
				self.pid = unpacktype(self.smem, Proc.template['p_pid'], INT)
			else:
				return False
		
		filedesc_ptr = unpacktype(self.smem, self.template['p_fd'], INT)
		if filedesc_ptr == 0:
			print "\nPID: %d (%s) has no open files." %(pid, self.getcmd())
			sys.exit()
		if not(Struct.mem.is_valid_address(filedesc_ptr)):
			print "\nPID: %d (%s) has an invalid file descriptor." %(pid, self.getcmd())
			sys.exit()
		if not self.valid():
			print "\tPID: %d appears in the in process list, but is not compatible with lsof." %pid
			sys.exit()
		
		return True
		
	def getfd(self):
		return self.filedesc_ptr
		
	def getpid(self):
		if self.pid < 0:
			return unpacktype(self.smem, Proc.template['p_pid'], INT)
		return self.pid
		
	def getcmd(self):
		return unpacktype(self.smem, self.template['p_comm'], STR).split('\x00', 1)[0].replace(' ', '\\x20').strip('\x00')
		
	def getuser(self):
		pgrp = Pgrp(self.pgrp_ptr)
		return pgrp.getuser()

	def gettxt(self):
		task_ptr = unpacktype(self.smem, self.template['task'], INT)
		task = Task(task_ptr)
		txt_ptrs = task.gettxt()
		
		if not(self.exe_ptr in txt_ptrs):
			txt_ptrs.append(self.exe_ptr)

		return txt_ptrs

################################### PRIVATE FUNCTIONS ####################################

# given a validated proc stucture, return a list of open files
def getfilelistbyproc(proc):
	
	filedesc	= Filedesc(proc.getfd())
	fglobs		= filedesc.getfglobs()
	filelist	= []
	
	if fglobs == None:
		return []
	
	cwd = Vnode(filedesc.getcwd())
	if cwd:
		filelist.append( (proc.getcmd(), proc.getpid(), proc.getuser(), "cwd  ",
			cwd.gettype(), cwd.getdev(), cwd.getoff(-1), cwd.getnode(), cwd.getpath())
		)
		
	txt_ptrs = proc.gettxt()
	for txt_ptr in txt_ptrs:
		txt = Vnode(txt_ptr)
		filelist.append( (proc.getcmd(), proc.getpid(), proc.getuser(), "txt  ",
			txt.gettype(), txt.getdev(), txt.getoff(-1), txt.getnode(), txt.getpath())
		)
	
	# iterate over fileglob structures, note: items() is unsorted by default
	for fd, fglob in sorted(fglobs.items()):
	
		# this has been observed as an invalid pointer even when fileproc is not
		if fglob == 0 or not Struct.mem.is_valid_address(fglob):
			continue
		
		fileglob = Fileglob(fglob)
		
		# full support for VNODE (1) only, otherwise, just print ftype for verbose
		ftype = fileglob.gettype()
		
		# exclude file if type cannot be resolved
		if ftype == -1:
			continue
		
		if ftype != 'VNODE':
			if Struct.verb:
				filelist.append( (proc.getcmd(), proc.getpid(), proc.getuser(),
					fileglob.getmode(fd), ftype, -1, -1, -1, -1)
				)
			continue
		
		vnode_ptr = fileglob.getdata()
		if vnode_ptr == None:
			continue
			
		vnode = Vnode(vnode_ptr)
		filelist.append( (proc.getcmd(), proc.getpid(), proc.getuser(),
			fileglob.getmode(fd), vnode.gettype(), vnode.getdev(),
			vnode.getoff(fileglob.getoff()), vnode.getnode(), vnode.getpath())
		)
		
	return filelist
	
#################################### PUBLIC FUNCTIONS ####################################
	
# build list of processes with open files, and return the aggregate listing
def getfilelist(mem, arch, kvers, proc_head, pid, vflag):

	Struct.mem 		= mem
	Struct.arch		= arch
	Struct.kvers	= kvers
	Struct.verb		= bool(vflag)
	
	proc = Proc(proc_head)
	if pid > -1:
		if proc.setpid(pid):	# returns True on success
			return getfilelistbyproc(proc)
		print "\tPID: %d not found in process list." %pid
		sys.exit()

	ptr_list = []	# this list catches cycles in the linked list (known to occur)
	proclist = []
	while proc:
	
		if proc.self_ptr in ptr_list:	# test for cycle
			stderr.write("ERROR getfilelist(): proc linked-list cycles, results may be incomplete.\n")
			break
		ptr_list.append(proc.self_ptr)
		
		if proc.valid():
			proclist.append(proc)
		proc = proc.next()
	
	fullfilelisting = []
	for proc in proclist:
		fullfilelisting += getfilelistbyproc(proc)

	return fullfilelisting
	
# given the output of getfilelist(), build a string matrix as input to columnprint()
def printfilelist(filelist):
	headerlist = ["COMMAND", "PID", "USER", "  FD  ", "TYPE", "DEVICE", "SIZE/OFF", "NODE", "NAME"]
	contentlist = []
	
	for file in filelist:
		line = ["%s" %file[0]]
		line.append("%d" %file[1])
		line.append("%s" %file[2])
		line.append("%s" %file[3])
		line.append("%s" %file[4])
		line.append("%s" %file[5])
		line.append("%s" %file[6])
		line.append("%d" %file[7])
		line.append("%s" %file[8])
		contentlist.append(line)
		
	#columnprint(headerlist, contentlist)
	
	# use optional max size list here to match default lsof output, otherwise specify
	# lsof +c 0 on the command line to print full name of commands
	mszlist = [9, -1, -1, -1, -1, -1, -1, -1, -1]
	columnprint(headerlist, contentlist, mszlist)
