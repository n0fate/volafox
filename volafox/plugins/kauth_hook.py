# Copyright by n0fate
# License : GPLv2
# This plug-in will be used for finding AV Monster II
# AV Monster II use inline hooking method for hiding malicious code on Anti-Virus product.
#

import inline_hook_finder

def kauth_hook(x86_mem_pae, symbol_list, arch, os_version, base_address):
    kauth_fileop_ptr = symbol_list['_kauth_authorize_fileop']
    print '[+] Get an address of caller function : kauth_authorize_fileop, %8x'%kauth_fileop_ptr
    inline_hook_finder.inline_quick(x86_mem_pae, kauth_fileop_ptr, arch, os_version, base_address)