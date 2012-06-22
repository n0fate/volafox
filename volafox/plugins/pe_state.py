import sys
import struct

from tableprint import columnprint

# 32bit, 64bit
DATA_PE_STATE_STRUCTURE = [[116, '=IIIIIII64xIIBB2xIII'],
                           [168, '=QQQQQQQ64xQQBB6xQQQ']
                           ]

# Lion, SN
DATA_BOOT_ARGS_STRUCTURE = [[1160, '=HHBB2x1024sIIIIIIIIIIIIIIIIQIIIIIIQQQQ'],
    [1116, '=HH1024sIIIIIIIIIIIIIIIIIB3xIIQ']
    ]

    # kPEGraphicMode(1), PETextMode(2), PETextScreen(3), PEAcquireScreen(4), PEReleaseScreen(5)
    # PEEnableScreen(5), PEDisableScreen(6)
PE_VIDEO_DIS_MODE = ['kPEGraphicMode', 'PETextMode', 'PETextScreen', 'PEAcquireScreen', 'PEReleaseScreen', 'PEEnableScreen', 'PEDisableScreen', 'kPEBaseAddressChange']
BOOT_VIDEO_DIS_MODE = ['FB_TEXT_MODE', 'FB_GRAPHIC_MODE']
ROTATE_MODE = ['normal', 'right 90', 'left 180', 'left 90']

#===============================================================================
# pexpert/pexert/pexert.h
# typedef struct PE_state {
#        boolean_t       initialized;
#        PE_Video        video;
#        void               *deviceTreeHead;
#        void               *bootArgs; 
# 
# } PE_state_t;
# 
#===============================================================================
# struct PE_Video {
#        unsigned long   v_baseAddr;     /* Base address of video memory */
#        unsigned long   v_rowBytes;     /* Number of bytes per pixel row */
#        unsigned long   v_width;        /* Width */
#        unsigned long   v_height;       /* Height */
#        unsigned long   v_depth;        /* Pixel Depth */
#        unsigned long   v_display;      /* Text or Graphics */
#    char        v_pixelFormat[64];
#    unsigned long    v_offset;    /* offset into video memory to start at */
#    unsigned long    v_length;    /* length of video memory (0 for v_rowBytes * v_height) */
#    unsigned char    v_rotate;    /* Rotation: 0:normal, 1:right 90, 2:left 180, 3:left 90 */
#    unsigned char    v_scale;    /* Scale Factor for both X & Y */
#    char        reserved1[2];
# #ifdef __LP64__
#    long        reserved2;
# #else
#    long        v_baseAddrHigh;
# #endif
# };
#===============================================================================
#===============================================================================

class PE_State:
    def __init__(self, x86_mem_pae, arch, os_version, build):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.os_version = os_version
        self.build = build
        
    def get_info(self, sym_addr):
        if not(self.x86_mem_pae.is_valid_address(sym_addr)):
            return 1
        
        if self.arch == 32:
            PE_STATE_STRUCTURE = DATA_PE_STATE_STRUCTURE[0]
        elif self.arch == 64:
            PE_STATE_STRUCTURE = DATA_PE_STATE_STRUCTURE[1]
            
        ps_state_info = self.x86_mem_pae.read(sym_addr, PE_STATE_STRUCTURE[0]) # pe_state
        pe_state = struct.unpack(PE_STATE_STRUCTURE[1], ps_state_info)
        return pe_state


#===============================================================================
# http://opensource.apple.com/source/xnu/xnu-1699.22.73/pexpert/pexpert/i386/boot.h
# /* Boot argument structure - passed into Mach kernel at boot time.
# * "Revision" can be incremented for compatible changes
# */
# #define kBootArgsRevision        0
# #define kBootArgsVersion        2
# 
# /* Snapshot constants of previous revisions that are supported */
# #define kBootArgsVersion1        1
# #define kBootArgsVersion2        2
# #define kBootArgsRevision2_0        0
#===============================================================================
#===============================================================================
# http://opensource.apple.com/source/xnu/xnu-1699.22.73/pexpert/pexpert/i386/boot.h
# typedef struct boot_args {
#    uint16_t    Revision;    /* Revision of boot_args structure */
#    uint16_t    Version;    /* Version of boot_args structure */
# 
#    uint8_t     efiMode;    /* 32 = 32-bit, 64 = 64-bit */
#    uint8_t     debugMode;  /* Bit field with behavior changes */
#    uint8_t     __reserved1[2];
# 
#    char        CommandLine[BOOT_LINE_LENGTH];    /* Passed in command line */
# 
#    uint32_t    MemoryMap;  /* Physical address of memory map */
#    uint32_t    MemoryMapSize;
#    uint32_t    MemoryMapDescriptorSize;
#    uint32_t    MemoryMapDescriptorVersion;
# 
#    Boot_Video    Video;        /* Video Information */
# 
#    uint32_t    deviceTreeP;      /* Physical address of flattened device tree */
#    uint32_t    deviceTreeLength; /* Length of flattened tree */
# 
#    uint32_t    kaddr;            /* Physical address of beginning of kernel text */
#    uint32_t    ksize;            /* Size of combined kernel text+data+efi */
# 
#    uint32_t    efiRuntimeServicesPageStart; /* physical address of defragmented runtime pages */
#    uint32_t    efiRuntimeServicesPageCount;
#    uint64_t    efiRuntimeServicesVirtualPageStart; /* virtual address of defragmented runtime pages */
# 
#    uint32_t    efiSystemTable;   /* physical address of system table in runtime area */
#    uint32_t    __reserved2;
# 
#    uint32_t    performanceDataStart; /* physical address of log */
#    uint32_t    performanceDataSize;
# 
#    uint32_t    keyStoreDataStart; /* physical address of key store data */
#    uint32_t    keyStoreDataSize;
#    uint64_t    bootMemStart;
#    uint64_t    bootMemSize;
#    uint64_t    PhysicalMemorySize;
#    uint64_t    FSBFrequency;
#    uint32_t    __reserved4[734];
# 
# } boot_args;
#===============================================================================
#===============================================================================
# struct Boot_Video {
#    uint32_t    v_baseAddr;    /* Base address of video memory */
#    uint32_t    v_display;    /* Display Code (if Applicable */
#    uint32_t    v_rowBytes;    /* Number of bytes per pixel row */
#    uint32_t    v_width;    /* Width */
#    uint32_t    v_height;    /* Height */
#    uint32_t    v_depth;    /* Pixel Depth */
# };
#===============================================================================

class boot_args:
    def __init__(self, x86_mem_pae, arch, os_version, build):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.os_version = os_version
        self.build = build

    def get_info(self, sym_addr):
        if not(self.x86_mem_pae.is_valid_address(sym_addr)):
            return 1
        if self.os_version >= 11:
            BOOT_ARGS_STRUCTURE = DATA_BOOT_ARGS_STRUCTURE[0]
        else:
            BOOT_ARGS_STRUCTURE = DATA_BOOT_ARGS_STRUCTURE[1]
            
        boot_args_info = self.x86_mem_pae.read(sym_addr, BOOT_ARGS_STRUCTURE[0]) # boot_args
        boot_args = struct.unpack(BOOT_ARGS_STRUCTURE[1], boot_args_info)
        return boot_args

## PUBLIC FUNCTIOn ##

def get_pe_state(x86_mem_pae, sym_addr, arch, os_version, build):
    PESTATE_CLASS = PE_State(x86_mem_pae, arch, os_version, build)
    state_info = PESTATE_CLASS.get_info(sym_addr)
    return state_info

def print_pe_state(pe_state, arch, os_version, build):
    print '[+] PE_State'
    print ' [-] Initialized: %d'%pe_state[0]
    print ' [+] PE_Video'
    print '  [-] v_baseAddr: 0x%.8x'%pe_state[1]
    print '  [-] v_rowBytes: %d'%pe_state[2]
    print '  [-] v_width: %d'%pe_state[3]
    print '  [-] v_height: %d'%pe_state[4]
    print '  [-] v_depth: %d'%pe_state[5]
    
    # v_display
    # kPEGraphicMode(1), PETextMode(2), PETextScreen(3), PEAcquireScreen(4), PEReleaseScreen(5)
    # PEEnableScreen(5), PEDisableScreen(6)
    print '  [-] v_display: %s'%PE_VIDEO_DIS_MODE[pe_state[6]]
    
    print '  [-] v_offset: 0x%.8x'%pe_state[7]
    print '  [-] v_length: %d'%pe_state[8]
    print '  [-] v_rotate: %s'%ROTATE_MODE[pe_state[9]]
    print '  [-] v_scale: %d'%pe_state[10]
    print '  [-] v_baseAddrHigh: 0x%.8x'%pe_state[11]
    
    print ' [-] DeviceTreesHead: 0x%.8x'%pe_state[12]
    print ' [-] bootArgs: 0x%.8x'%pe_state[13]
    
def get_boot_args(x86_mem_pae, boot_args_ptr, arch, os_version, build):
    BOOTARGS_CLASS = boot_args(x86_mem_pae, arch, os_version, build)
    state_info = BOOTARGS_CLASS.get_info(boot_args_ptr)
    return state_info

def print_boot_args(bootargs, arch, os_version, build):
    if os_version >= 11:
        print '[+] boot args'
        print ' [-] Revision of boot_args structure: %d'%bootargs[0]
        print ' [-] Version of boot_args structure: %d'%bootargs[1]
        # 0x40 --> 64bit, 0x20 --> 32bit
        print ' [-] EFI Mode: %d Bits'%bootargs[2]
        print ' [-] Debug Mode: %d'%bootargs[3]
        print ' [-] CommandLine: %s'%bootargs[4].split('\x00')[0]
        print ' [-] Physical address of memory map: 0x%.8x'%bootargs[5]
        print ' [-] Size of memory map: %d'%bootargs[6]
        print ' [-] Descriptor Size of memory map: %d'%bootargs[7]
        print ' [-] Descriptor Version of memory map: %d'%bootargs[8]
        print ' [+] Boot_Video Structure'
        print '  [-] Base Address of Video Memory: 0x%.8x'%bootargs[9]
        
        # v_display : FB_TEXT_MODE(0x00), FB_GRAPHIC_MODE(0x01)
        print '  [-] v_display: %s'%BOOT_VIDEO_DIS_MODE[bootargs[10]]
        print '  [-] v_rowBytes: %d'%bootargs[11]
        print '  [-] v_width: %d'%bootargs[12]
        print '  [-] v_height: %d'%bootargs[13]
        print '  [-] v_depth: %d'%bootargs[14]
        
        
        print ' [-] Device Tree Pointer: 0x%.8x'%bootargs[15]
        print ' [-] Device Tree Length: %d'%bootargs[16]
        
        print ' [-] Kernel Text Address: 0x%.8x'%bootargs[17]
        print ' [-] Size of combined kernel text+data+efi: 0x%.8x'%bootargs[18]
        
        print ' [-] EFI Runtime Services Page Start(defragmented runtime pages): 0x%.8x'%bootargs[19]
        print ' [-] EFI Runtime Services Page Count: %d'%bootargs[20]
        
        print ' [-] EFI System Table Pointer: 0x%.8x'%bootargs[21]
    
        print ' [-] EFI Runtime SErvice Virtual Page Start: 0x%.8x'%bootargs[22]
        print '  --> Virtual Address of defragmented runtime pages'
        
    else: # Snow Leopard
        print '[+] boot args'
        print ' [-] Revision of boot_args structure: %d'%bootargs[0]
        print ' [-] Version of boot_args structure: %d'%bootargs[1]
        print ' [-] CommandLine: %s'%bootargs[2].split('\x00')[0]
        print ' [-] Physical address of memory map: 0x%.8x'%bootargs[3]
        print ' [-] Size of memory map: %d'%bootargs[4]
        print ' [-] Descriptor Size of memory map: %d'%bootargs[5]
        print ' [-] Descriptor Version of memory map: %d'%bootargs[6]
        print ' [+] Boot_Video Structure'
        print '  [-] Base Address of Video Memory: 0x%.8x'%bootargs[7]
        
        # v_display : FB_TEXT_MODE(0x00), FB_GRAPHIC_MODE(0x01)
        print '  [-] v_display: %s'%BOOT_VIDEO_DIS_MODE[bootargs[8]]
        print '  [-] v_rowBytes: %d'%bootargs[9]
        print '  [-] v_width: %d pixel'%bootargs[10]
        print '  [-] v_height: %d pixel'%bootargs[11]
        print '  [-] v_depth: %d Bits'%bootargs[12]
        
        
        print ' [-] Device Tree Pointer: 0x%.8x'%bootargs[13]
        print ' [-] Device Tree Length: %d'%bootargs[14]
        
        print ' [-] Kernel Text Address: 0x%.8x'%bootargs[15]
        print ' [-] Size of combined kernel text+data+efi: 0x%.8x'%bootargs[16]
        
        print ' [-] EFI Runtime Services Page Start(defragmented runtime pages): 0x%.8x'%bootargs[17]
        print ' [-] EFI Runtime Services Page Count: %d'%bootargs[18]
        
        print ' [-] EFI System Table Pointer: 0x%.8x'%bootargs[19]
        # 0x40 --> 64bit, 0x20 --> 32bit
        print ' [-] EFI Mode: %d Bits'%bootargs[20]
        print ' [-] Physical Address of log: 0x%.8x'%bootargs[21]
        print ' [-] Size of log: 0x%.8x'%bootargs[22]
        print ' [-] EFI Runtime Service Virtual Page Start: 0x%.8x'%bootargs[23]
        print '  --> Virtual Address of defragmented runtime pages'
    