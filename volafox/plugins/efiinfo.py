import sys
import struct
import uuid


#===============================================================================
# typedef struct {
#  EFI_UINT64  Signature;
#  EFI_UINT32  Revision;
#  EFI_UINT32  HeaderSize;
#  EFI_UINT32  CRC32;
#  EFI_UINT32  Reserved;
# } __attribute__((aligned(8))) EFI_TABLE_HEADER;
# 
# typedef struct EFI_SYSTEM_TABLE_32 {
#  EFI_TABLE_HEADER              Hdr;
# 
#  EFI_PTR32                     FirmwareVendor;
#  EFI_UINT32                    FirmwareRevision;
# 
#  EFI_HANDLE32                  ConsoleInHandle;
#  EFI_PTR32                     ConIn;
# 
#  EFI_HANDLE32                  ConsoleOutHandle;
#  EFI_PTR32                     ConOut;
# 
#  EFI_HANDLE32                  StandardErrorHandle;
#  EFI_PTR32                     StdErr;
# 
#  EFI_PTR32                     RuntimeServices;
#  EFI_PTR32                     BootServices;
# 
#  EFI_UINT32                    NumberOfTableEntries;
#  EFI_PTR32                     ConfigurationTable;
# 
# } __attribute__((aligned(8))) EFI_SYSTEM_TABLE_32;
# 
# typedef struct EFI_SYSTEM_TABLE_64 {
#  EFI_TABLE_HEADER              Hdr;
# 
#  EFI_PTR64                     FirmwareVendor;
#  EFI_UINT32                    FirmwareRevision;
# 
#  EFI_UINT32                    __pad;
# 
#  EFI_HANDLE64                  ConsoleInHandle;
#  EFI_PTR64                     ConIn;
# 
#  EFI_HANDLE64                  ConsoleOutHandle;
#  EFI_PTR64                     ConOut;
# 
#  EFI_HANDLE64                  StandardErrorHandle;
#  EFI_PTR64                     StdErr;
# 
#  EFI_PTR64                     RuntimeServices;
#  EFI_PTR64                     BootServices;
# 
#  EFI_UINT64                    NumberOfTableEntries;
#  EFI_PTR64                     ConfigurationTable;
# 
# } __attribute__((aligned(8))) EFI_SYSTEM_TABLE_64;
#===============================================================================

## 32bit, 64bit
DATA_EFI_SYSTEM_TABLE = [
                         [72, '=8sIIIIIIIIIIIIIIII'],
                         [120, '=8sIIIIQI4xQQQQQQQQQQ']
                         ]

DATA_EFI_CONF_TABLE = [
                       [20, '=16sI'],
                       [24, '=16sQ']
                       ]

class EFISystemTable:
    def __init__(self, x86_mem_pae, arch, os_version, build, base_address):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.os_version = os_version
        self.build = build
        self.base_address = base_address
        
    def get_info(self, sym_addr):
        if not(self.x86_mem_pae.is_valid_address(sym_addr+self.base_address)):
            return 1
        
        if self.arch == 32:
            sym_addr_ptr = self.x86_mem_pae.read(sym_addr+self.base_address, 4)
            sym_addr = struct.unpack('=I', sym_addr_ptr)[0]
            
            EFI_SYSTEM_TABLE = DATA_EFI_SYSTEM_TABLE[0]
            EFI_CONF_TABLE = DATA_EFI_CONF_TABLE[0]
        elif self.arch == 64:
            sym_addr_ptr = self.x86_mem_pae.read(sym_addr+self.base_address, 8)
            sym_addr = struct.unpack('=Q', sym_addr_ptr)[0]
            
            EFI_SYSTEM_TABLE = DATA_EFI_SYSTEM_TABLE[1]
            EFI_CONF_TABLE = DATA_EFI_CONF_TABLE[1]
        
        #print '0x%.8x'%sym_addr
        
        if not(self.x86_mem_pae.is_valid_address(sym_addr)):
            print 'Invalid System Table Pointer'
            return 1
                   
        efi_system_table_info = self.x86_mem_pae.read(sym_addr, EFI_SYSTEM_TABLE[0])
        efi_system_table = struct.unpack(EFI_SYSTEM_TABLE[1], efi_system_table_info)
        
        ret_table = []
        
        index = 0
        for element in efi_system_table:
            data = element
            if(index == 5):
                if not(self.x86_mem_pae.is_valid_address(data)):
                    data = 'Not Found'
                else:
                    firmwarevendor_buf = self.x86_mem_pae.read(data, 12)
                    data = struct.unpack('=12s', firmwarevendor_buf)[0]
            ret_table.append(data)
            index += 1
        
        numberoftableentry = ret_table[15]
        configurationtable = ret_table[16]
        
        if not(self.x86_mem_pae.is_valid_address(configurationtable)):
            print 'Unavailable configuration table'
            return ret_table, 1
        
        configuration_table = []
        
        for i in range(0, numberoftableentry):
            efi_conf_table_info = self.x86_mem_pae.read(configurationtable+EFI_CONF_TABLE[0]*i, EFI_CONF_TABLE[0])
            efi_conf_table = struct.unpack(EFI_CONF_TABLE[1], efi_conf_table_info)
            configuration_table.append(efi_conf_table)
        
        return ret_table, configuration_table


def get_efi_system_table(x86_mem_pae, efi_system_ptr, arch, os_version, build, base_address):
    EFISYSTEMCLASS = EFISystemTable(x86_mem_pae, arch, os_version, build, base_address)
    efi_system_info, configuration_table = EFISYSTEMCLASS.get_info(efi_system_ptr)
    
    if efi_system_info == 1:
        return 1
    
    elif efi_system_info == 1 and configuration_table == 1:
        return efi_system_info, 1
    
    return efi_system_info, configuration_table

def efi_vendor_guid(uuid):
    if uuid == '05ad34ba-6f02-4214-952e-4da0398e2bb9':
        return "EFI_DXE_SERVICS_TABLE_GUID"
    elif uuid == '7739f24c-93d7-11d4-9a3a-0090273fc14d':
        return "EFI_HOB_LIST_GUID"
    elif uuid == '4c19049f-4137-4dd3-9c10-8b97a83ffdfa':
        return "EFI_MEMORY_TYPE_INFORMATION"
    elif uuid == '49152e77-1ada-4764-b7a2-7afefed95e8b':
        return "EFI_IMAGE_DEBUG_INFO_TABLE"
    elif uuid == 'eb9d2d31-2d88-11d3-9a16-0090273fc14d':
        return "SMBIOS_TABLE_GUID"
    elif uuid == 'eb9d2d30-2d88-11d3-9a16-0090273fc14d':
        return "EFI_ACPI_TABLE_GUID"
    elif uuid == '8868e871-e4f1-11d3-bc22-0080c73c8881':
        return "ACPI_20_TABLE_GUID"
    elif uuid == 'eb9d2d32-2d88-11d3-9a16-0090273fc14d':
        return "SAL_SYSTEM_TABLE_GUID"
    else:
        return "UNKNOWN GUID"

def print_efi_system_table(system_table, configuration_table, arch, os_version, build):
    print '[+] EFI System Table'
    print ' [+] EFI Table Header'
    print '  [-] Signature: %s'%system_table[0]
    print '  [-] revision: 0x%.8x'%system_table[1]
    print '  [-] Header Size: %d'%system_table[2]
    print '  [-] CRC32: 0x%.8x'%system_table[3]
    print '  [-] Reserved: %d'%system_table[4]
    print ' [-] FirmwareVendor: %s'%system_table[5]
    print ' [-] Firmware Revision: 0x%.8x'%system_table[6]
    print ' [-] ConsoleInHandle: 0x%.8x'%system_table[7]
    print ' [-] Console Input: 0x%.8x'%system_table[8]
    print ' [-] Console Output Handle: 0x%.8x'%system_table[9]
    print ' [-] Console Output: 0x%.8x'%system_table[10]
    print ' [-] Standard Error Handle: 0x%.8x'%system_table[11]
    print ' [-] Standard Error: 0x%.8x'%system_table[12]
    print ' [-] Runtime Services: 0x%.8x'%system_table[13]
    print ' [-] Boot Services: 0x%.8x'%system_table[14]
    print ' [-] Number of Entries: %d'%system_table[15]
    print ' [-] Configuration Table: 0x%.8x'%system_table[16]
    print ''

    if configuration_table != 1:
        print '[+] Configuration Table'
        for table in configuration_table:
            print ' [-] Vendor GUID : %s (%s)'%(efi_vendor_guid(str(uuid.UUID(bytes_le=table[0]))), uuid.UUID(bytes_le=table[0]))
            print ' [-] Vendor Table Pointer: 0x%.8x'%table[1]
            print ''


#===============================================================================
# typedef struct {
#  EFI_TABLE_HEADER              Hdr;
# 
#  //
#  // Time services
#  //
#  EFI_PTR32                     GetTime;
#  EFI_PTR32                     SetTime;
#  EFI_PTR32                     GetWakeupTime;
#  EFI_PTR32                     SetWakeupTime;
# 
#  //
#  // Virtual memory services
#  //
#  EFI_PTR32                     SetVirtualAddressMap;
#  EFI_PTR32                     ConvertPointer;
# 
#  //
#  // Variable services
#  //
#  EFI_PTR32                     GetVariable;
#  EFI_PTR32                     GetNextVariableName;
#  EFI_PTR32                     SetVariable;
# 
#  //
#  // Misc
#  //
#  EFI_PTR32                     GetNextHighMonotonicCount;
#  EFI_PTR32                     ResetSystem;
# 
# #ifdef TIANO_EXTENSION_FLAG
#  //
#  // ////////////////////////////////////////////////////
#  // Extended EFI Services
#    //////////////////////////////////////////////////////
#  //
#  EFI_PTR32                     ReportStatusCode;
# #endif
# 
# } __attribute__((aligned(8))) EFI_RUNTIME_SERVICES_32;
# 
# typedef struct {
#  EFI_TABLE_HEADER              Hdr;
# 
#  //
#  // Time services
#  //
#  EFI_PTR64                     GetTime;
#  EFI_PTR64                     SetTime;
#  EFI_PTR64                     GetWakeupTime;
#  EFI_PTR64                     SetWakeupTime;
# 
#  //
#  // Virtual memory services
#  //
#  EFI_PTR64                     SetVirtualAddressMap;
#  EFI_PTR64                     ConvertPointer;
# 
#  //
#  // Variable services
#  //
#  EFI_PTR64                     GetVariable;
#  EFI_PTR64                     GetNextVariableName;
#  EFI_PTR64                     SetVariable;
# 
#  //
#  // Misc
#  //
#  EFI_PTR64                     GetNextHighMonotonicCount;
#  EFI_PTR64                     ResetSystem;
# 
# #ifdef TIANO_EXTENSION_FLAG
#  //
#  // ////////////////////////////////////////////////////
#  // Extended EFI Services
#    //////////////////////////////////////////////////////
#  //
#  EFI_PTR64                     ReportStatusCode;
# #endif
# 
# } __attribute__((aligned(8))) EFI_RUNTIME_SERVICES_64;
#===============================================================================
  
## 32bit, 64bit
DATA_EFI_RUNTIME_SERVICES = [
                         [68, '=8sIIIIIIIIIIIIIII'],
                         [112, '=8sIIIIQQQQQQQQQQQ']
                         ]    

class EFIRuntimeServices:
    def __init__(self, x86_mem_pae, arch, os_version, build, base_address):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.os_version = os_version
        self.build = build
        self.base_address = base_address
        
    def get_info(self, sym_addr):
        if not(self.x86_mem_pae.is_valid_address(sym_addr+self.base_address)):
            return 1
        
        if self.arch == 32:
            sym_addr_ptr = self.x86_mem_pae.read(sym_addr+self.base_address, 4)
            sym_addr = struct.unpack('=I', sym_addr_ptr)[0]
            
            EFI_RUNTIME_SERVICES = DATA_EFI_RUNTIME_SERVICES[0]
        elif self.arch == 64:
            sym_addr_ptr = self.x86_mem_pae.read(sym_addr+self.base_address, 8)
            sym_addr = struct.unpack('=Q', sym_addr_ptr)[0]
            
            EFI_RUNTIME_SERVICES = DATA_EFI_RUNTIME_SERVICES[1]
        
        if not(self.x86_mem_pae.is_valid_address(sym_addr)):
            print 'Invalid System Table Pointer'
            return 1
                   
        efi_runtime_services_info = self.x86_mem_pae.read(sym_addr, EFI_RUNTIME_SERVICES[0])
        efi_runtime_services = struct.unpack(EFI_RUNTIME_SERVICES[1], efi_runtime_services_info)
        
        return efi_runtime_services


def get_efi_runtime_services(x86_mem_pae, efi_runtime_ptr, arch, os_version, build, base_address):
    EFIRUNTIMECLASS = EFIRuntimeServices(x86_mem_pae, arch, os_version, build, base_address)
    efi_runtime_info = EFIRUNTIMECLASS.get_info(efi_runtime_ptr)
    
    return efi_runtime_info

def print_efi_runtime_services(efi_runtime, arch, os_version, build):
    print '[+] EFI Runtime Services'
    print ' [+] EFI Table Header'
    print '  [-] Signature: %s'%efi_runtime[0]
    print '  [-] revision: 0x%.8x'%efi_runtime[1]
    print '  [-] Header Size: %d'%efi_runtime[2]
    print '  [-] CRC32: 0x%.8x'%efi_runtime[3]
    print '  [-] Reserved: %d'%efi_runtime[4]
    print ''
    print ' [Time Services]'
    print ' [-] GetTime: 0x%.8x'%efi_runtime[5]
    print ' [-] SetTime: 0x%.8x'%efi_runtime[6]
    print ' [-] GetWakeupTime: 0x%.8x'%efi_runtime[7]
    print ' [-] SetWakeupTime: 0x%.8x'%efi_runtime[8]
    print ''
    print ' [Virtual Memory Services]'
    print ' [-] Set Virtual Address Map: 0x%.8x'%efi_runtime[9]
    print ' [-] ConvertPointer: 0x%.8x'%efi_runtime[10]
    print ''
    print ' [Variable Services]'
    print ' [-] Get Variable: 0x%.8x'%efi_runtime[11]
    print ' [-] Get Next Variable Name: 0x%.8x'%efi_runtime[12]
    print ' [-] Set Variable: 0x%.8x'%efi_runtime[13]
    print ''
    print ' [Misc]'
    print ' [-] Get Next High Monotonic Count: 0x%.8x'%efi_runtime[14]
    print ' [-] Reset System: 0x%.8x'%efi_runtime[15]

    
    
    
    
    
    