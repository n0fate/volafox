# Copyright by n0fate
# License : GPLv2
# This plug-in will be used for finding OpenBSM hook
#
#

import inline_hook_finder


def find_auto_commit(x86_mem_pae, symbol_list, arch, os_version, base_address):
    caller_addr = symbol_list['_audit_syscall_exit']
    print '[+] Get an address of caller function : audit_syscall_exit, %8x'%caller_addr

    callee_addr = symbol_list['_audit_commit']
    print '[+] Get an address of callee function : audit_commit, %8x'%callee_addr

    ret, code = inline_hook_finder.find_function_in_code(x86_mem_pae, caller_addr, callee_addr, arch, os_version, base_address)

    if len(ret):
        print ''
        print '[+] Find "audit_commit" function :)'
        print '[+] OS X does not attacked by audit remover'
    else:
        print ''
        print '[+] The "audit_commit" function will be removed :(\nAssembly Code is as following:'
        print '[+] Function Name : audit_syscall_exit'
        for instruction in code:
            print '%8x  %s'%(instruction[0], instruction[2])