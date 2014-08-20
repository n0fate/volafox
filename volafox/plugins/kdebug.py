# Copyright by n0fate
# License : GPLv2
# This plug-in will be used for finding kdebug hook
#
#

import inline_hook_finder

def kdebug_hook(x86_mem_pae, symbol_list, arch, os_version, base_address):
    kernel_debug_ptr = symbol_list['_kernel_debug']
    print '[+] Get an address of caller function : kernel_debug, %8x'%kernel_debug_ptr
    print ''
    inline_hook_finder.inline_quick(x86_mem_pae, kernel_debug_ptr, arch, os_version, base_address)