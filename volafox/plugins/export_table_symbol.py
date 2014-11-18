import json
__author__ = 'n0fate'

# This plugins is used to function matching with dumped KEXT in memory image
# Please checking a my github repo. (www.github.com/n0fate/idapython/makecommsyscallref.py)

def dump_symbollist(x86_mem_pae, arch, os_version, build, base_address, symbollist, filename):
    dict2 = {}
    for keys,values in symbollist.items():
        dict2[hex(base_address + values)] = keys

    json.dump(dict2, open(filename, 'w'))
    print '[+] Dump to symbol file : %s'%filename
