import sys
from macho_an import *
import pickle

def usage():
    print 'overlay generator - n0fate(Chris Leat\'s Idea) '
    print 'Contact: rapfer@gmail.com or n0fate@live.com'
    print 'usage: python %s KERNELIMAGE OVERAY\n'%sys.argv[0]

def main():
    try:
        if not(sys.argv[1]) or not(sys.argv[2]):
            usage()
            sys.exit()
    except IndexError:
        usage()
        sys.exit()
        
    macho = macho_an(sys.argv[1])
    arch_count = macho.load()
    print arch_count
    header = macho.get_header(arch_count, ARCH_I386) # only support Intel x86
    symbol_list = macho.macho_getsymbol_x86(header[2], header[3])
    ###### Added by CL
    f = open(sys.argv[2], 'wb')
    pickle.dump(symbol_list, f)
    f.close()

if __name__ == "__main__":
    main()