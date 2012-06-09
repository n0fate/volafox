#!/usr/bin/python

##### Horrible code below. Sorry.
##### chris.leat@gmail.com
#####

import re
import binascii
import struct
import sys


class imageInfo:
	def __init__(self, f):
		self.f = f
		self.Catfishmagic = binascii.unhexlify('4361746669736820')
		self.Darwinkernelmagic = binascii.unhexlify('44617277696E204B65726E656C2056657273696F6E')
		self.OffsetedK = 1024
		self.Offseted = 0
		self.OffsetSegment = 0
		self.chunk_size = 1024
		
		
	def read_in_chunks(self, file_object):
		while True:
			data = file_object.read(self.chunk_size)
			if not data:
				break
			yield data

	def catfishSearch(self, f):
		filename = open(f, 'rb')
		for piece in self.read_in_chunks(filename):
			if re.search(self.Catfishmagic, piece):
				page = self.Offseted
				segment = piece.find(self.Catfishmagic)
				CatfishLocation = page + segment
				break
			self.Offseted = self.Offseted + self.chunk_size
		for piece in self.read_in_chunks(filename):	
			if re.search(self.Darwinkernelmagic, piece):
				pageK = self.OffsetedK
				segmentK = piece.find(self.Darwinkernelmagic)
				DarwinKernelLocation = pageK + segmentK
				locationOfDarwinString = DarwinKernelLocation + CatfishLocation
				break
			self.OffsetedK = self.OffsetedK + self.chunk_size

		
		pointerLocationOfDarwinString = CatfishLocation + 28 # 28 as 0x201C Pointer to kernel version string
		filename.seek(pointerLocationOfDarwinString)
		dataOfDarwinStringPointer = filename.read(4)
		pointerOfDarwinString = struct.unpack("i", dataOfDarwinStringPointer)[0]
		
		####### x86_64 read
		if pointerOfDarwinString == 0:
			pointerLocationOfDarwinString = CatfishLocation + 48 # 48 as +0x030 Pointer to kernel version string
			filename.seek(pointerLocationOfDarwinString)
			dataOfDarwinStringPointer = filename.read(8)
			pointerOfDarwinStringOrig = struct.unpack("Q", dataOfDarwinStringPointer)[0]
			pointerOfDarwinString = pointerOfDarwinStringOrig % 0xFFFFFF80
			
			locationOfOSBuildNumber = CatfishLocation + 2336 # 2336 because the OSVersionString pointer is +0x920 from the Catfish eyecatcher
			filename.seek(locationOfOSBuildNumber)
			dataOfOSBuildString = filename.read(8)
			pointerOfOSVersionStringOrig = struct.unpack("Q", dataOfOSBuildString)[0]
			pointerOfOSVersionString = pointerOfOSVersionStringOrig % 0xFFFFFF80
			sixtyfourbit = True
			
		######## x86 read
		else:
			locationOfOSBuildNumber = CatfishLocation + 1172 # 1172 because the OSVersionString pointer is 0x494 from the Catfish eyecatcher
			filename.seek(locationOfOSBuildNumber)
			dataOfOSBuildString = filename.read(4)
			pointerOfOSVersionString = struct.unpack("i", dataOfOSBuildString)[0]
			sixtyfourbit = False


		#return the pointer for the Darwin Kernel version
		difference = (pointerOfDarwinString - locationOfDarwinString)
		
		filename.seek(pointerOfOSVersionString - difference, 0)
		getOSBuildNumberRead = filename.read(7) # null terminiated string so we can read 7 bytes.
		return difference, getOSBuildNumberRead.replace('\x00', ''), sixtyfourbit


#################################### PUBLIC FUNCTIONS ####################################

def get_imageinfo(mempath, vflag):
    returnResult = imageInfo(mempath)
    difference, build, sixtyfourbit = returnResult.catfishSearch(mempath)
    os_version = 0
    # LSOF: verbose support
    if vflag:
	print '[+] Get Memory Image Information'
	print " [-] Difference(Catfish Signature):", difference # Catfish offset
	    
    if bool(difference):
	# LSOF: verbose support
	if vflag:
	    print ' [-] Maybe Mac Memory Reader Format'
	valid_format = 0
	
    else:
    
	# LSOF: verbose support
	if vflag:
	    print ' [-] Valid Mac Linear File Format'    
	valid_format = 1
    
    if bool(sixtyfourbit):
	
	# LSOF: verbose support
	if vflag:
	    print " [-] 64-bit memory image"
	arch = 64
	
    else:
	# LSOF: verbose support
	if vflag:
	    print " [-] 32-bit memory image"
	arch = 32
    
    # LSOF: verbose support
    if vflag:
	    print " [-] Build Version in Memory : %s"%build
	    
    os_version = int(build[:2])
#
#    elif build == '10D573' or build == '10D578' or build == '10D572':
#	    kern_version = '10.6.3'
#	    os_version = int(build[:2])
#	    
#    elif build == '10F659' or build == '10F616':
#	    kern_version = '10.6.4'
#	    os_version = int(build[:2])
#
#    elif build == '10H574' or build == '10H575':
#	    kern_version = '10.6.5'
#	    os_version = int(build[:2])
#
#    elif build == '10J567':
#	    kern_version = '10.6.6'
#	    os_version = int(build[:2])
#
#    elif build == '10J869' or build == '10J3250':
#	    kern_version = '10.6.7'
#	    os_version = int(build[:2])
#
#    elif build == '10K540' or build ==  '10K549':
#	    kern_version = '10.6.8'
#	    os_version = int(build[:2])
#
#    elif build == '11A511':
#	    kern_version = '10.7.0'
#	    os_version = int(build[:2])
#
#    elif build == '11B26':
#	    kern_version = '10.7.1'
#	    os_version = int(build[:2])
#
#    elif build == '11C74':
#	    kern_version = '10.7.2'
#	    os_version = int(build[:2])
#	    
#    # n0fate : bug fix
#    elif build == '11D50b' or build == '11D50' or build == '11D50d':
#	    kern_version = '10.7.3'
#	    os_version = int(build[:2])
#	    
#    # LSOF: 10.6.0 Server support
#    elif build == '10A433':
#	    kern_version = '10.6.0'
#	    os_version = int(build[:2])
#	    
#    # osxmem: 10.7.4 support
#    elif build == '11E53':
#	    kern_version = '10.7.4'
#	    os_version = int(build[:2])
#    
#    elif build == 'Darwin ':
#	    #print ' [-] Wrong Catfish symbol. Memory capture incomplete?'
#	    kern_version = 'Darwin'
#    else:
#	    kern_version = 'NotFound'
#	    
    # LSOF: verbose support
#    if vflag:
#	    print ' [-] Kernel Version: %s'%os_version

    return valid_format, arch, build, os_version
#
#def main():
#	f = sys.argv[1]
#	returnResult = imageInfo(f)
#	difference, build, sixtyfourbit = returnResult.catfishSearch(f)
#	print "Difference:", difference
#	print build
#	if bool(sixtyfourbit):
#		print "64-bit image"
#	else:
#		print "32-bit image"
#
#	if build == '10A432':
#		print 'Suggested profile 10.6.0'
#	elif build == '10D573' or build == '10D578' or build == '10D572':
#		print 'Suggested profile 10.6.3'
#	elif build == '10F659' or build == '10F616':
#		print 'Suggested profile 10.6.4'
#	elif build == '10H574' or build == '10H575':
#		print 'Suggested profile 10.6.5'
#	elif build == '10J567':
#		print 'Suggested profile 10.6.6'
#	elif build == '10J869' or build == '10J3250':
#		print 'Suggested profile 10.6.7'
#	elif build == '10K540' or build ==  '10K549':
#		print 'Suggested profile 10.6.8'
#	elif build == '11A511':
#                print 'Suggested profile 10.7.0'
#        elif build == '11B26':
#                print 'Suggested profile 10.7.1'
#        elif build == '11C74':
#                print 'Suggested profile 10.7.2'
#	elif build == 'Darwin ':
#		print 'Wrong Catfish symbol. Memory capture incomplete?'
#	else:
#		print 'Suggested profile not found'
#	
#	
#if __name__ == "__main__":
#   main()


