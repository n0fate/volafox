#!/usr/bin/env python # path


import sys
from volafox.binan.macho_an import *
import pickle

def usage():
    print 'overlay generator - n0fate(Chris Leat\'s Idea) '
    print 'Contact: rapfer@gmail.com or n0fate@live.com'
    print 'usage: python %s KERNELIMAGE OVERAY [32/64]\n'%sys.argv[0]

def main():
    try:
        if not(sys.argv[1]) or not(sys.argv[2]) or not(sys.argv[3]):
            usage()
            sys.exit()
    except IndexError:
        usage()
        sys.exit()

    is_universal_binary = 1
    
    macho = macho_an(sys.argv[1])
    arch_count = macho.load()

    if arch_count == -1:
        is_universal_binary = 0
        
    if int(sys.argv[3]) is not 32 and int(sys.argv[3]) is not 64:
        usage()
        sys.exit()
    elif int(sys.argv[3]) == 32:
        if not(is_universal_binary):
            symbol_list = macho.macho_getsymbol_x86(0, macho.getfilesize())
        else:
            header = macho.get_header(arch_count, ARCH_I386) # only support Intel x86
            symbol_list = macho.macho_getsymbol_x86(header[2], header[3])
    elif int(sys.argv[3]) == 64:
        if not(is_universal_binary):
            symbol_list = macho.macho_getsymbol_x64(0, macho.getfilesize())
        else:
            header = macho.get_header(arch_count, ARCH_X86_64) # only support Intel x86
            symbol_list = macho.macho_getsymbol_x64(header[2], header[3])
    ###### Added by CL
    f = open(sys.argv[2], 'wb')
    pickle.dump(symbol_list, f)
    f.close()

if __name__ == "__main__":
    main()
