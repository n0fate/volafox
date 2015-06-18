__author__ = 'n0fate'

# Reference : https://github.com/google/rekall/blob/master/rekall/plugins/darwin/compressor.py
# Paper : Golden G. Richard, Andrew Case, In lieu of swap: Analyzing compressed RAM in Mac OS X and
# Linux, DFRWS2014, http://www.dfrws.org/2014/proceedings/DFRWS2014-1.pdf

from sys import stderr
import struct
import sys
import os
from WKdm import WKdm_decompress_apple

# mtype (enum)
STR = 0  # string: char (8-bit) * size
INT = 1  # int:    32 or 64-bit
SHT = 3  # short:  16-bit

# return unpacked member from a struct given its memory and a member template
def unpacktype(binstr, member, mtype):
    offset = member[1]
    size = member[2]
    fmt = ''

    if mtype == STR:
        fmt = str(size) + 's'
    elif mtype == INT:
        fmt = 'I' if size == 4 else 'Q'
    elif mtype == SHT:
        fmt = 'H'
    else:
        calling_fxn = sys._getframe(1)
        stderr.write("ERROR %s.%s tried to unpack the unknown type %d.\n" % (
        callingclass(calling_fxn), calling_fxn.f_code.co_name, mtype))
        return None

    if struct.calcsize(fmt) != len(binstr[offset:size + offset]):
        calling_fxn = sys._getframe(1)
        stderr.write("ERROR %s.%s tried to unpack '%s' (fmt size: %d) from %d bytes.\n" % (
        callingclass(calling_fxn), calling_fxn.f_code.co_name, fmt, struct.calcsize(fmt),
        len(binstr[offset:size + offset])))
        return None

    return struct.unpack(fmt, binstr[offset:size + offset])[0]

#################################### PRIVATE CLASSES #####################################

# return the enclosing class when called inside a function (error reporting)
def callingclass(calling_fxn):
    try:
        classname = calling_fxn.f_locals['self'].__class__.__name__
    except KeyError:
        classname = "<unknown>"
    return classname

# parent from which all structures derive
class Struct(object):
    # static variables common to all structure classes
    TEMPLATES = None
    mem = None
    verb = False
    arch = -1
    kvers = -1

    # static variables (subclass-specific)
    template = None
    ssize = -1

    def validaddr(self, addr):
        if addr == 0:
            calling_fxn = sys._getframe(1)
            stderr.write(
                "WARNING %s.%s was passed a NULL address.\n" % (callingclass(calling_fxn), calling_fxn.f_code.co_name))
            return False
        elif not (Struct.mem.is_valid_address(addr)):
            calling_fxn = sys._getframe(1)
            stderr.write("WARNING %s.%s was passed the invalid address %.8x.\n" % (
            callingclass(calling_fxn), calling_fxn.f_code.co_name, addr))
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
                    stderr.write("ERROR %s has no template for x%d Darwin %d.x.\n" % (
                    self.__class__.__name__, Struct.arch, Struct.kvers))
                    sys.exit()
            else:
                stderr.write(
                    "ERROR %s does not support %s architecture.\n" % (self.__class__.__name__, str(Struct.arch)))
                sys.exit()

            # set size of the structure by iterating over template
            for item in self.__class__.template.values():
                if ( item[1] + item[2] ) > self.__class__.ssize:
                    self.__class__.ssize = item[1] + item[2]

        if self.validaddr(addr):
            self.smem = Struct.mem.read(addr, self.__class__.ssize);
        else:
            stderr.write(
                "ERROR instance of %s failed to construct with address %.8x.\n" % (self.__class__.__name__, addr))

class C_Slot(Struct):
    TEMPLATES = {
        64: {
            14: {
                 'c_offset': ('uint64_t', 0x00, 8, 'offset'),
                 }
            }
        }

    PAGE_SIZE = 4096

    def __init__(self, addr):
        super(C_Slot, self).__init__(addr)
        value = unpacktype(self.smem, self.template['c_offset'], INT)
        self.c_offset, self.c_size, self.c_packed_ptr = self.unpack(value)

    def UnpackCSize(self, c_size):
        if c_size == self.PAGE_SIZE - 1:
            return self.PAGE_SIZE
        else:
            return c_size

    def unpack(self, value):
        c_offset = value & 0x000000000000FFFF
        c_size = (value & 0x000000000FFF0000) >> 16
        c_packed_ptr = (value & 0xFFFFFFFFF0000000) >> 28
        return c_offset, c_size, c_packed_ptr

    def getpackedptr(self):
        return self.c_packed_ptr

    def getsize(self):
        return self.UnpackCSize(self.c_size)

    def getoff(self):
        return self.c_offset

class C_Segment(Struct):
    TEMPLATES = {
        64: {
            14: {'c_age_list': ('queue_chain_t', 0x10, 16, '', {'next': ('unsigned int*', 0x10, 8, '->next'), 'prev': ('unsigned int*', 0x18, 8, '->prev')}),
                 'c_list': ('queue_chain_t', 0x20, 16, '', {'next': ('unsigned int*', 0x20, 8, '->next'), 'prev': ('unsigned int*', 0x28, 8, '->prev')}),
                 'c_generation_id': ('uint64_t', 0x30, 8, 'GID'),
                 'c_bytes_used': ('int32_t', 0x38, 4, 'UsedBytes'),
                 'c_bytes_unused': ('int32_t', 0x3C, 4, 'UnusedBytes'),
                 'c_mysegno': ('uint32_t', 0x40, 4, 'SegInfo'),
                 'c_firstemptyslot': ('uint16_t', 0x44, 2, ''),
                 'c_nextslot': ('uint16_t', 0x46, 2, ''),
                 'c_nextoffset': ('uint32_t', 0x48, 4, 'NextOffset'),
                 'c_populated_offset': ('uint32_t', 0x4C, 4, ''),
                 'c_creation_ts': ('uint32_t', 0x50, 4, ''),
                 'c_swappedin_ts': ('uint32_t', 0x54, 4, ''),
                 'c_buffer': ('uint32_t*', 0x58, 8, '->buffer'),
                 'c_slots0': ('struct c_slot*', 0x60, 8, '->c_slot'),
                 'c_slots1': ('struct c_slot*', 0x68, 8, '->c_slot'),
                 'c_slots2': ('struct c_slot*', 0x70, 8, '->c_slot'),
                 'c_slots3': ('struct c_slot*', 0x78, 8, '->c_slot'),
                 'c_slots4': ('struct c_slot*', 0x80, 8, '->c_slot'),
                 'c_slots5': ('struct c_slot*', 0x88, 8, '->c_slot')}
            }
        }

    C_SEG_SLOT_ARRAY_SIZE = 64
    PAGE_SIZE = 4096
    C_SEG_SLOT_ARRAYS = 6

    def __init__(self, addr):
        super(C_Segment, self).__init__(addr)

    def isswapout(self):
        try:
            c_mysegno = unpacktype(self.smem, self.template['c_mysegno'], INT)
        except TypeError:
            return 1
        if (c_mysegno & 0x00000C20):  # c_ondisk, c_on_swapout_q, c_on_swappedout_q
            return 1
        else:
            return 0

    def getbufferptr(self):
        return unpacktype(self.smem, self.template['c_buffer'], INT)

    def getbuffer(self):
        #print 'buffer : %x, size(%d)'%(self.getbufferptr(), self.getnextoffset()*4)
        return self.mem.read(self.getbufferptr(), self.getnextoffset()*4)

    def getnextoffset(self):
        return unpacktype(self.smem, self.template['c_nextoffset'], INT)

    def getnext(self):
        return unpacktype(self.smem, self.template['c_age_list'][4]['next'], INT)

    def getnextslot(self):
        return unpacktype(self.smem, self.template['c_nextslot'], SHT)

    def getcslotlist(self):
        c_slot_arrays = []
        for i in xrange(self.C_SEG_SLOT_ARRAYS):
            cslotlist = []
            #hexdump(self.smem)
            cslotaddr = unpacktype(self.smem, self.template['c_slots%1d'%i], INT)
            if cslotaddr == 0:
                for cslotoffset in xrange(self.C_SEG_SLOT_ARRAY_SIZE):
                    cslotlist.append(0)
                c_slot_arrays.append(cslotlist)
                continue
            # try:
            #     print 'CSlot Address: %x, %x'%(self.mem.vtop(cslotaddr), cslotaddr)
            # except:
            #     print '%x'%cslotaddr
            #     sys.exit(0)

            for cslotoffset in xrange(self.C_SEG_SLOT_ARRAY_SIZE):
                if cslotaddr+cslotoffset*8 == 0:
                    cslotlist.append(0)
                    continue
                cslot = C_Slot(cslotaddr+cslotoffset*8)
                #print '%d cslot offset : %x'%(cslotoffset, cslot.getoff())
                cslotlist.append(cslot)
            c_slot_arrays.append(cslotlist)
        return c_slot_arrays


class dumpcomppage():
    def __init__(self, x86_mem_pae, arch, os_version, base_address, symbollist, dump_dir):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.os_version = os_version
        self.base_address = base_address
        self.symbol_list = symbollist
        self.dump_dir = dump_dir

    def process(self):
        pages = self.getsegmentcount(self.symbol_list['_c_segment_count'])

        print 'Total Segment Number : %s Segments'%pages

        c_segment_list = []
        segbaseaddr = struct.unpack('=Q', self.x86_mem_pae.read(self.symbol_list['_c_segments'] + self.base_address, 8))[0]
        #print 'Base Address: %x, %x'%(self.x86_mem_pae.vtop(segbaseaddr), segbaseaddr)
        addr = struct.unpack('=Q', self.x86_mem_pae.read(segbaseaddr, 8))[0]
        #print 'Address: %x, %x'%(self.x86_mem_pae.vtop(addr), addr)

        for i in xrange(pages):
            nextsegoff = segbaseaddr + (i * 8)
            addr = struct.unpack('=Q', self.x86_mem_pae.read(nextsegoff, 8))[0]
            if self.x86_mem_pae.is_valid_address(addr) == 0 or (addr & 0x0F):
                continue
            c_segment = C_Segment(addr)
            c_segment_list.append([i, c_segment])

        for segcount, c_segment in c_segment_list:
            print 'Dump a Segment (%d/%d)'%(segcount, pages-1)
            if c_segment.isswapout():
                #print 'swapout'
                continue

            if self.x86_mem_pae.is_valid_address(c_segment.getbufferptr()) == 0:
                #print 'invalid buffer offset'
                continue

            seg_buffer = c_segment.getbuffer()
            if seg_buffer is None:
                continue

            c_slot_arrays = c_segment.getcslotlist()
            #print 'c_slot_arrays Length: %d'%len(c_slot_arrays)
            #print 'nextslot : %d'%c_segment.getnextslot()

            for c_slot_array in c_slot_arrays:
                for slot_nr in xrange(c_segment.getnextslot()):
                    #c_slot_array = c_slot_arrays[slot_nr/c_segment.C_SEG_SLOT_ARRAYS]
                    c_slot = c_slot_array[slot_nr % c_segment.C_SEG_SLOT_ARRAY_SIZE]

                    if c_slot == 0:
                        continue

                    if not(c_slot.c_offset and c_slot.c_size):
                        continue

                    c_size = c_slot.getsize()

                    if (c_slot.c_offset*4 + c_size) >= len(seg_buffer):
                        continue

                    data = seg_buffer[c_slot.c_offset*4:c_slot.c_offset*4 + c_size]

                    offset_alignment_mask = 0x3

                    c_rounded_size = (c_size + offset_alignment_mask)
                    c_rounded_size &= ~offset_alignment_mask

                    if (c_rounded_size == C_Segment.PAGE_SIZE):
                        continue

                    try:
                        decompressed = WKdm_decompress_apple(data)
                        if decompressed:
                            dirname = os.path.join(self.dump_dir, "segment%d"%segcount)
                            try:
                                os.mkdir(dirname)
                            except OSError:
                                pass

                            fd = open(dirname+"/slot%d.dmp"%slot_nr, "wb")
                            fd.write(decompressed)
                            fd.close()

                    except Exception as e:
                        print str(e)


    def getsegmentcount(self, c_segment_count):
        return struct.unpack('=I', self.x86_mem_pae.read(c_segment_count+self.base_address, 4))[0]



def dumpcompressedpage(x86_mem_pae, symbollist, arch, majorversion, base_address, dump_dir):
    Struct.mem = x86_mem_pae
    Struct.arch = arch
    Struct.kvers = majorversion
    Struct.verb = False

    try:
        os.mkdir(dump_dir)
    except OSError:
        pass

    dump = dumpcomppage(x86_mem_pae, arch, majorversion, base_address, symbollist, dump_dir)
    dump.process()