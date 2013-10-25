#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       Kyeongsik Lee
@license:      GNU General Public License 2.0 or later
@contact:      rapfer@gmail.com
"""

"""Module for dealing with IA-32 with PML4 Paging Mechnism stuff
 & based on x86.py (Volatility Framework)
"""
import struct
from addrspace import FileAddressSpace

#x86_native_types = { \
#    'int' : [4, 'l'], \
#    'long': [4, 'l'], \
#    'unsigned long' : [4, 'L'], \
#    'unsigned int' : [4, 'I'], \
#    'address' : [4, 'L'], \
#    'char' : [1, 'c'], \
#    'unsigned char' : [1, 'B'], \
#    'unsigned short' : [2, 'H'], \
#    'short' : [2, 'h'], \
#    'long long' : [8, 'q'], \
#    'unsigned long long' : [8, 'Q'], \
#    }

entry_size = 8
pointer_size = 8
page_shift = 12 # page offset
#ptrs_per_pte = 1024
#ptrs_per_pgd = 1024
ptrs_per_pae_pte = 512 ## 9 bits
ptrs_per_pae_pgd = 512 ## 9 bits
ptrs_per_pae_pml4 = 512 ## 9 bits
ptrs_per_pdpi = 512 ## 9bits
pgdir_shift = 22
pdpi_shift = 30
pdptb_shift = 5
pde_shift= 21
ptrs_per_pde = 512
ptrs_page = 2048

pml4_shift = 39 ####

class IA32PML4MemoryPae:
    def __init__(self, baseAddressSpace, pml4):
        self.base = baseAddressSpace
        self.pml4_vaddr = pml4 # 32 bit address
        #self.pgd_vaddr = pdbr
        self.pae = True

    def entry_present(self, entry):
        if (entry & (0x00000001)) == 0x00000001:
            return True
        return False

    def page_size_flag(self, entry):
        if (entry & (1 << 7)) == (1 << 7):
            return True
        return False    

    #def get_pdptb(self, pdpr):
    #    return pdpr & 0xFFFFFFE0

    def pgd_index(self, pgd):
        return (pgd >> pgdir_shift) & (ptrs_per_pgd - 1)

    ###
    def get_pdpib(self, pml4):
        return pml4 & 0xFFFFFFFE0

    def pml4_index(self, pml4):
        return ((pml4 & 0x0000FFFFFFFFFFFF) >> pml4_shift)

    ### PML4 Entry
    def get_pml4(self, vaddr):
        pdpi_entry = self.get_pdpib(self.pml4_vaddr) + self.pml4_index(vaddr) * entry_size
        return self.read_long_long_phys(pdpi_entry)
    
    ###
    def pdpa_base(self, pml4e):
        return pml4e & 0x0000FFFFFFFFF000

    def pdpi_index(self, pdpi):
        return ((pdpi & 0x0000007FFFFFFFFF) >> pdpi_shift)

    def get_pdpi(self, vaddr, pml4e):
        pdpi_entry = self.pdpa_base(pml4e) + self.pdpi_index(vaddr) * entry_size
        return self.read_long_long_phys(pdpi_entry)

    def pde_index(self, vaddr): 
        return (vaddr >> pde_shift) & (ptrs_per_pde - 1)

    def pdba_base(self, pdpe):
        return pdpe & 0xFFFFFFFFF000

    def get_pgd(self, vaddr, pdpe):
        pgd_entry = self.pdba_base(pdpe) + self.pde_index(vaddr) * entry_size
        return self.read_long_long_phys(pgd_entry)

    def pte_pfn(self, pte):
        return pte & 0xFFFFFFFFF000

    def pte_index(self, vaddr):
        return (vaddr >> page_shift) & (ptrs_per_pde - 1)

    ###
    def pml4_base(self, pml4):
        return pml4 & 0x0000FFFFFFFFF000

    def ptba_base(self, pde):
        return pde & 0xFFFFFFFFF000

    def get_pte(self, vaddr, pgd):
        pgd_val = self.ptba_base(pgd) + self.pte_index(vaddr) * entry_size
        return self.read_long_long_phys(pgd_val)

    def get_paddr(self, vaddr, pte):
        return self.pte_pfn(pte) | (vaddr & ((1 << page_shift) - 1))

    def get_large_paddr(self, vaddr, pgd_entry):
        return (pgd_entry & 0x0000FFFFFFE00000) | (vaddr & 0x00000000001FFFFF)

    def vtop(self, vaddr):
        retVal = None
        pdpi = self.get_pml4(vaddr) ###
        if not self.entry_present(pdpi): ###
            return retVal ###

        pdpe = self.get_pdpi(vaddr, pdpi)
        if not self.entry_present(pdpe):
            return retVal

        pgd = self.get_pgd(vaddr,pdpe)

        if self.entry_present(pgd):
            if self.page_size_flag(pgd):
                retVal = self.get_large_paddr(vaddr, pgd)
            else:
                pte = self.get_pte(vaddr, pgd)
                if self.entry_present(pte):
                    retVal =  self.get_paddr(vaddr, pte)
        return retVal

    def read(self, vaddr, length):
        first_block = 0x1000 - vaddr % 0x1000
        full_blocks = ((length + (vaddr % 0x1000)) / 0x1000) - 1
        left_over = (length + vaddr) % 0x1000
        
        paddr = self.vtop(vaddr)
        if paddr == None:
            return None
        
        if length < first_block:
            stuff_read = self.base.read(paddr, length)
            if stuff_read == None:
                return None
            return stuff_read

        stuff_read = self.base.read(paddr, first_block)
        if stuff_read == None:
            return None

        new_vaddr = vaddr + first_block
        for i in range(0,full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                return None
            new_stuff = self.base.read(paddr, 0x1000)
            if new_stuff == None:
                return None
            stuff_read = stuff_read + new_stuff
            new_vaddr = new_vaddr + 0x1000

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                return None
            new_stuff = self.base.read(paddr, left_over)
            if new_stuff == None:
                return None
            stuff_read = stuff_read + new_stuff
        return stuff_read

    def zread(self, vaddr, length):
        first_block = 0x1000 - vaddr % 0x1000
        full_blocks = ((length + (vaddr % 0x1000)) / 0x1000) - 1
        left_over = (length + vaddr) % 0x1000
        
        paddr = self.vtop(vaddr)

        if paddr == None:
            if length < first_block:
                return ('\0' * length)
            stuff_read = ('\0' * first_block)       
        else:
            if length < first_block:
                return self.base.zread(paddr, length)
            stuff_read = self.base.zread(paddr, first_block)

        new_vaddr = vaddr + first_block
        for i in range(0,full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                stuff_read = stuff_read + ('\0' * 0x1000)
            else:
                stuff_read = stuff_read + self.base.zread(paddr, 0x1000)

            new_vaddr = new_vaddr + 0x1000

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                stuff_read = stuff_read + ('\0' * left_over)
            else:
                stuff_read = stuff_read + self.base.zread(paddr, left_over)
        return stuff_read
        
    def read_long_phys(self, addr):
        string = self.base.read(addr, 4)
        if string == None:
            return None
        (longval, ) =  struct.unpack('=L', string)
        return longval

    def read_long_long_phys(self, addr):
        string = self.base.read(addr,8)
        if string == None:
            return None
        (longlongval, ) = struct.unpack('=Q', string)
        return longlongval

    def is_valid_address(self, addr):
        if addr == None:
            return False
        try:    
            phyaddr = self.vtop(addr)
        except:
            return False
        if phyaddr == None:
            return False
        if not self.base.is_valid_address(phyaddr):
            return False
        return True

#    def get_available_pages(self):
#        page_list = []
#       
#        pdpi_base = self.get_pdptb(self.pgd_vaddr)
#
#        for i in range(0,ptrs_per_pdpi): 
#
#	    start = (i * ptrs_per_pae_pgd * ptrs_per_pae_pgd * ptrs_per_pae_pte * 8)
#            pdpi_entry  = pdpi_base + i * entry_size        
#            pdpe = self.read_long_long_phys(pdpi_entry)
#
#            if not self.entry_present(pdpe):
#                continue
#          
#            pgd_curr = self.pdba_base(pdpe)          
#                  
#            for j in range(0,ptrs_per_pae_pgd):
#	      soffset = start + (j * ptrs_per_pae_pgd * ptrs_per_pae_pte * 8)
#              entry = self.read_long_long_phys(pgd_curr)
#              pgd_curr = pgd_curr + 8
#              if self.entry_present(entry) and self.page_size_flag(entry):
#		  page_list.append([soffset, 0x200000])
#              elif self.entry_present(entry):
#                  pte_curr = entry & ~((1 << page_shift)-1)                
#                  for k in range(0,ptrs_per_pae_pte):
#                        pte_entry = self.read_long_long_phys(pte_curr)
#                        pte_curr = pte_curr + 8
#                        if self.entry_present(pte_entry):
#			    page_list.append([soffset + k * 0x1000, 0x1000])
#        return page_list
