#!/usr/bin/python
import os
import sys
import struct

# -----------------------------------------------------------------------------
# Base utilities
# -----------------------------------------------------------------------------

def getuint(fhandle, offset):
    try:
        fhandle.seek(offset)
        ret = struct.unpack("@I", fhandle.read(4))
        return ret[0]
    except struct.error:
        if offset+4 > len(fhandle):
           print "Error:  mach-o header is incomplete."
        else: 
            print "Error: [%d:%d] - %s" % (offset, offset+4, error)
        exit(0)

def getuint64(fhandle, offset):
    fhandle.seek(offset)
    ret = struct.unpack("@Q", fhandle.read(8))
    return ret[0]

# -----------------------------------------------------------------------------
# Header accessors
# -----------------------------------------------------------------------------

def getmagic(fhandle):
    return getuint(fhandle, 0)

def _getcputype(fhandle):
    return  getuint(fhandle, 4)

def getcputype(fhandle):
    cpu = _getcputype(fhandle)
    if cpu == -1:
        return "ANY"
    elif cpu == 1:
        return "VAX"
    elif cpu == 6:
        return "MC680x0"
    elif cpu == 7:
        return "X86"
    elif cpu == 7 | 0x01000000:
        return "X86_64"
    elif cpu == 10:
        return "MC98000"
    elif cpu == 11:
        return "HPPA"
    elif cpu == 12:
        return "ARM"
    elif cpu == 13:
        return "MC88000"
    elif cpu == 14:
        return "SPARC"
    elif cpu == 15:
        return "I860"
    elif cpu == 18:
        return "POWERPC"
    elif cpu == 18 | 0x01000000:
        return "POWERPC64"
    else:
        return "UNKNOWN"

def getcpusubtype(fhandle):
    return getuint(fhandle, 8)

def _getfiletype(fhandle):
    return getuint(fhandle, 12)

def getfiletype(fhandle):
    filetype = _getfiletype(fhandle)
    if filetype == 0x1:
        return "OBJECT"
    elif filetype == 0x2:
        return "EXECUTE"
    elif filetype == 0x3:
        return "FVMLIB"
    elif filetype == 0x4:
        return "CORE"
    elif filetype == 0x5:
        return "PRELOAD"
    elif filetype == 0x6:
        return "DYLIB"
    elif filetype == 0x7:
        return "DYLINKER"
    elif filetype == 0x8:
        return "BUNDLE"
    elif filetype == 0x9:
        return "DYLIB_STUB"
    elif filetype == 0xa:
        return "DSYM"

def getncmds(fhandle):
    return getuint(fhandle, 16)

def getsizeofcmds(fhandle):
    return getuint(fhandle, 20)

def getflags(fhandle):
    return getuint(fhandle, 24)

# -----------------------------------------------------------------------------
# Load Command utilities
# -----------------------------------------------------------------------------

def _loadcommandlookup(type):
    if type == 0x1:
        return "SEGMENT"
    elif type == 0x2:
        return "SYMTAB"
    elif type == 0x3:
        return "SYMSEG"
    elif type == 0x4:
        return "THREAD"
    elif type == 0x5:
        return "UNIXTHREAD"
    elif type == 0x6:
        return "LOADFVMLIB"
    elif type == 0x7:
        return "IDFVMLIB"
    elif type == 0x8:
        return "IDENT"
    elif type == 0x9:
        return "FVMFILE"
    elif type == 0xa:
        return "PREPAGE"
    elif type == 0xb:
        return "DSYMTAB"
    elif type == 0xc:
        return "LOAD_DYLIB"
    elif type == 0xd:
        return "ID_DYLIB"
    elif type == 0xe:
        return "LOAD_DYLINKER"
    elif type == 0xf:
        return "ID_DYLINKER"
    elif type == 0x10:
        return "PREBOUND_DYLINKER"
    elif type == 0x11:
        return "ROUTINES"
    elif type == 0x12:
        return "SUB_FRAMEWORK"
    elif type == 0x13:
        return "SUB_UMBRELLA"
    elif type == 0x14:
        return "SUB_CLIENT"
    elif type == 0x15:
        return "SUB_LIBRARY"
    elif type == 0x16:
        return "TWOLEVELHINTS"
    elif type == 0x17:
        return "PREBIND_CKSUM"
    elif type == 0x18:
        return "LOAD_WEAK_DYLIB"
    elif type == 0x19:
        return "SEGMENT_64"
    elif type == 0x1a:
        return "LC_ROUTINES_64"
    elif type == 0x1b:
        return "UUID"
    elif type == (0x1c | 0x80000000):
        return "RPATH"
    elif type == 0x1d:
        return "CODE_SIGNATURE"
    elif type == 0x1e:
        return "SEGMENT_SPLIT_INFO"
    else:
        print "FATAL ERROR:  UNKNOWN LOAD COMMAND TYPE %d" % type
        exit(0)


def _readloadcommand(fhandle, offset):
    loadtype = _loadcommandlookup(getuint(fhandle, offset))
    size = getuint(fhandle, offset+4)
    return loadtype, size 


def loadcommand(fhandle, index):
    ret = []

    offset = 0
    if is32(fhandle):
        offset = 28  
    elif is64(fhandle):
        offset = 32 
    else: 
        print "Fatal error.  File type is unknown."
        exit(0)

    i = 0
    while i != index:
        cmd, cmdsize = _readloadcommand(fhandle, offset)

        if cmd == "SEGMENT_64":
            segment64 = Segment64(fhandle, offset)
            ret.append(segment64)
        elif cmd == "SEGMENT":
            segment = Segment(fhandle, offset)
            ret.append(segment)
        else:
            print "Command %s is unhandled." % cmd
            exit(0)
        i += 1
        offset += cmdsize 
    return ret


class Segment64:

    def __init__(self, fhandle, offset):
        self.cmd, self.cmdsize = _readloadcommand(fhandle, offset)
        fhandle.seek(0)
        fhandle.seek(offset+8)
        self.segname    = fhandle.read(16).rstrip('\0')
        self.vmaddr     = getuint64(fhandle, offset+24)
        self.vmsize     = getuint64(fhandle, offset+32)
        self.fileoff    = getuint64(fhandle, offset+40)
        self.filesize   = getuint64(fhandle, offset+48)
        self.maxprot    = getuint(fhandle, offset+56) 
        self.initprot   = getuint(fhandle, offset+60)
        self.nsects     = getuint(fhandle, offset+64)
        self.flags      = getuint(fhandle, offset+68)

    def __str__(self):
        return "%-10s %016x %016x" % (self.segname, self.vmaddr, (self.vmsize / 4096))


class Segment:

    def __init__(self, fhandle, offset):
        self.cmd, self.cmdsize = _readloadcommand(fhandle, offset)
        fhandle.seek(0)
        fhandle.seek(offset+8)
        self.segname    = fhandle.read(16).rstrip('\0')
        self.vmaddr     = getuint(fhandle, offset+24)
        self.vmsize     = getuint(fhandle, offset+28)
        self.fileoff    = getuint(fhandle, offset+32)
        self.filesize   = getuint(fhandle, offset+36)
        self.maxprot    = getuint(fhandle, offset+40)
        self.initprot   = getuint(fhandle, offset+44)
        self.nsects     = getuint(fhandle, offset+48)
        self.flags      = getuint(fhandle, offset+52)

    def __str__(self):
        return "%-10s %016x %016x" % (self.segname, self.vmaddr, (self.vmsize / 4096))


def find_lcmd(lcmds, addr):
    for seg in lcmds:
        if addr >= seg.vmaddr and addr < (seg.vmaddr+seg.vmsize):
            return seg

    return None

def getoffset(lcmds, addr):
    seg = find_lcmd(lcmds, addr)
    if seg == None:
        raise Exception("Address not found.")    

    offset = addr - seg.vmaddr 

    return seg.fileoff+offset


class MachoAddressSpace:
    
    def __init__(self, fname, mode='r+b'):
        self.fhandle    = open(fname, mode)
        #self.map        = mmap.mmap(self.fhandle.fileno(), os.path.getsize(fname))
        #self.map        = mmap.mmap(self.fhandle.fileno(), 4096*16)

        # Should check magic, cputype, etc
        self.segs       = loadcommand(self.fhandle, getncmds(self.fhandle))
        
    def read(self, addr, length):

        #print "MachoAddressSpace.read()"
        # Bad things will happen if the memory request spans different lcmds:
        if(find_lcmd(self.segs, addr) != find_lcmd(self.segs, addr+length-1)):
            print "Starting Address: %x" % addr
            print "Ending Address:   %x" % (addr+length-1)
            print "Starting segment: %s" % find_lcmd(self.segs, addr)
            print "Ending segment:   %s" % find_lcmd(self.segs, addr+length-1)
            raise Error("Memory request spans segments.  This is not supported.") 

        offset = getoffset(self.segs, addr)
        self.fhandle.seek(offset)
        ret = self.fhandle.read(length) 
        if len(ret) != length:
            raise Exception("Read returned buffer of different size than requested.  %d bytes requested, %d returned." % (len(ret), length))

        if ret == None:
            raise Exception("Returning None on MachoAddressSpace.read()")

        #print "Returning buffer of length: %d %d" % (length, len(ret))

        return ret

    def zread(self, addr, length):
        return self.read(addr, len)

    def read_long(self, addr):
        string = self.read(addr, 4)
        (longval, ) = struct.unpack('=L', string)
        return longval

    # What is this supposed to do?
    def get_address_range(self):
        return None

    # Again, what should this do?
    def get_available_addresses(self):
        return None

    def is_valid_address(self, addr):
        if addr == None:
            return False

        if find_lcmd(self.segs, addr) == None:
            return False 

        return True

    def close():
        self.fhandle.close()

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------

def is_universal_binary(filename):
    fin = open(filename, 'r')
    buffer = fin.read(4)
    ret = struct.unpack("@I", buffer)
    if ret[0] == 0xbebafeca or ret[0] == 0xcafebabe:
        return True
    else:
        return False

def ismacho(fin):
    if isinstance(fin, str):
        fin = open(fin, 'r')

    if isinstance(fin, file):
        fin.seek(0)
        buffer = fin.read(4)
        ret = struct.unpack("@I", buffer)
        #print "magic value is: %x" % ret[0]
        if ret[0] == 0xfeedface or ret[0] == 0xfeedfacf:
            return True
        else:
            return False
    else:
        magic   = getmagic(fin)
        if magic == 0xfeedface or magic == 0xfeedfacf:
            return True
        else:
            return False

def is32(fin):
    magic = getmagic(fin)
    if magic == 0xfeedface:
       return True
    else:
        return False
    
def is64(fin):
    magic = getmagic(fin)
    #print magic == 0xfeedfacf
    if magic == 0xfeedfacf:
        return True
    else:
        return False

def isMachoVolafoxCompatible(fname):
    fin = open(fname, 'r+b')
    #map = mmap.mmap(fin.fileno(), 4096)
    if not ismacho(fin):
        fin.close()
        return False
    if is64(fin):
        fin.close()
        return False

    fin.close()
    # We're assuming it's the proper cpu type
    return True
