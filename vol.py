#!/usr/bin/env python						# LSOF: new path
#!c:\python\python.exe
# -*- coding: utf-8 -*-
#  -*- mode: python; -*-

import getopt
import sys

from volafox.volafox import volafox

def usage():
    
    '''
    TODO
    1. Replace existing commands with their CLI equivalents (e.g. proc_info --> ps) - complete - 11/04/24 - n0fate
    2. Use more conventional usage format
    3. Make -m/x/p/v suboptions of their respective commands - working
    4. Print all tables using new lsof print function - complete
    5. kern_kext_info appears to be broken... - complete
    '''
    
    print ''
    print 'volafox: Mac OS X Memory Analysis Toolkit'
    print 'project: http://code.google.com/p/volafox'
    print 'support: 10.6-7; 32/64-bit kernel'
    print '  input: *.vmem (VMWare memory file), *.mmr (Mac Memory Reader, flattened x86, IA-32e)'
    print '  usage: python %s -i IMAGE [-o COMMAND [-vp PID][-fx PID][-x KEXT_ID]]\n' %sys.argv[0]
    
    print 'Options:'
    print '-o CMD     : Print kernel information for CMD (below)'
    print '-p PID     : List open files for PID (where CMD is "lsof")'
    print '-v         : Print all files, including unsupported types (where CMD is "lsof")'  
    print '-x PID/KID : Dump process/kernel extension address space for PID/KID (where CMD is "ps"/"kextstat")\n'
    #print '-f         : Full dump process address space for PID (where CMD is "ps" and -x PID) (experiment)\n'
    print 'COMMANDS:'
    print 'system_profiler : Kernel version, CPU, and memory spec, Boot/Sleep/Wakeup time'
    print 'mount           : Mounted filesystems'
    print 'kextstat        : KEXT (Kernel Extensions) listing'
    print 'kextscan        : Scanning KEXT (Kernel Extensions) (experiment)'
    print 'ps              : Process listing'
    print 'tasks           : Task listing (& Matching Process List) (experiment)'
    print 'systab          : Syscall table (Hooking Detection)'
    print 'mtt             : Mach trap table (Hooking Detection)'
    print 'netstat         : Network socket listing (Hash table)'
    print 'lsof            : Open files listing by process (research, osxmem@gmail.com)'	# LSOF: new lsof command
    print 'pestate         : Show Boot information (experiment)'
    print 'efiinfo         : EFI System Table, EFI Runtime Services(experiment)'
#    print 'net_info_test\t network information(plist), (experiment)'

def main():
    mempath = ''
    oflag = ''
    pflag = 0			# LSOF: new pid flag
    vflag = 0			# LSOF: show debugging output and experimental options for lsof
    dflag = 0
    mflag = 0   
    fflag = 0			# process full dump option  
    pid = -1			# LSOF: relocated this definition

    try:
    	# LSOF: added -p flag for pid specification with lsof, -v no longer needs arg
        #option, args = getopt.getopt(sys.argv[1:], 'o:i:x:v:m:')
        option, args = getopt.getopt(sys.argv[1:], 'o:i:x:vfp:')

    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit()

    debug = ""	# LSOF: debug string, print only with -v flag
    
    for op, p, in option:
        if op in '-o':  # data type
        
            # LSOF: add to debug string, no newline so -p can be added
            #print '[+] Information:', p
            debug += "[+] Command: %s" %p
            
            oflag = p
            
            # LSOF: new pid flag
	    suboption = option
            for i,x in enumerate(suboption):
            	if p == 'lsof' and x[0] == '-p':
		    pid = int(x[1], 10)
		    pflag = 1;
		    debug += " -p %d" %pid
		    break

		elif p == 'ps' and x[0] == '-x': # process dump
		    pid = int(x[1], 10)
		    debug += ' -x %d' %pid
		    dflag = 1
		    break
		
		elif p == 'kextstat' and x[0] == '-x': # kext dump
		    kext_num = int(x[1], 10)
		    debug += ' -x %d' %kext_num
		    mflag = 1
		    break
            del suboption
	    debug += "\n"	# LSOF: replacing newline

        elif op in '-i': # physical memory image file
        	
            # LSOF: add to debug string
            #print '[+] Memory Image:', p
            debug += '[+] Memory Image: %s\n' %p
            
            mempath = p

        # LSOF: reworked this, it appears to have been unused (now shows debug string)
        elif op == '-v': # verbose
            #print 'Verbose:', p
            vflag = 1
           
        else:
            #print '[+] Command error:', op	# LSOF: not printed, getopt catches this
            usage()
            sys.exit()
            
    # LSOF: all of this information now requires an explicit flag (or command error)
    if vflag:
    	print debug[:-1]

    if mempath == "" and ( oflag == "" or dflag == 0 or mflag == 0):
        usage()
        sys.exit()

    # Auto switching code for using overlays or original mach-o files.  We should autopickle
    # using the original file.
##    if is_universal_binary(file_image):
##        macho_file = macho_an.macho_an(file_image)
##        arch_count = macho_file.load()
##
##        ## 11.11.22 n0fate
##        if arch_num is not 32 and arch_num is not 64:
##            macho_file.close()
##            sys.exit()
##        elif arch_num is 32:
##            header = macho_file.get_header(arch_count, macho_file.ARCH_I386)
##            symbol_list = macho_file.macho_getsymbol_x86(header[2], header[3])
##            macho_file.close()
##        elif arch_num is 64:
##            header = macho_file.get_header(arch_count, macho_file.ARCH_X86_64)
##            symbol_list = macho_file.macho_getsymbol_x64(header[2], header[3])
##            macho_file.close()
##    else:
##        #Added by CL
##        f = open(file_image, 'rb')
##        symbol_list = pickle.load(f)
##        f.close()
##
    m_volafox = volafox(mempath)

    ## get kernel version, architecture ##
    
    # LSOF: pass the verbose flag so debugging information can be optionally printed
    overlay_path = m_volafox.get_kernel_version(vflag) # ret: true/false , overlay filepath
    if overlay_path == '':
        print '[+] WARNING: Can not found image information'
	sys.exit()

    ret_loader = m_volafox.overlay_loader(overlay_path, vflag)
    if ret_loader == 1:
        sys.exit()

    ## Setting Page Table Map
    nRet = m_volafox.init_vatopa_x86_pae(vflag)
    if nRet == 1:
        print "[+] WARNING: Memory Image Load Failed"
        sys.exit()

    if mflag == 1:
	m_volafox.kextdump(kext_num)
	sys.exit()
        
    if dflag == 1:
        m_volafox.proc_dump(pid, fflag)
        sys.exit()
	
    # test
    if oflag == 'get_phy':
	m_volafox.get_read_address(18446743521828375264)
	sys.exit()
	
    if oflag == 'system_profiler':
        m_volafox.get_system_profiler()
        sys.exit()

    elif oflag == 'kextstat':
        m_volafox.kextstat()
        sys.exit()

    elif oflag == 'mount':
        data_list = m_volafox.mount()
        sys.exit()

    elif oflag == 'ps':
        m_volafox.get_ps()
        sys.exit()
    
    elif oflag == 'tasks':
        m_volafox.get_tasks()
        sys.exit()
        
    # LSOF: lsof command branch
    elif oflag == 'lsof':
	if vflag:
    		print ""	# separate output from command specification
    	filelist = m_volafox.lsof(pid, vflag)
    	#if vflag:
    	#	print ""	# separate output from command specification
    	#printfilelist(filelist)
    	sys.exit()

    elif oflag == 'systab':
        m_volafox.systab()
        sys.exit()
    
    elif oflag == 'mtt':
        m_volafox.mtt()
        sys.exit()

    elif oflag == 'netstat':
        m_volafox.netstat()
        sys.exit()

    elif oflag == 'netstat_test':
        m_volafox.netstat_test()
        sys.exit()
    
    elif oflag == 'pestate':
        m_volafox.pe_state()
        sys.exit()

    elif oflag == 'efiinfo':
        m_volafox.efi_system_table()
        sys.exit()
    
    elif oflag == 'kextscan':
	m_volafox.kextscan()
	sys.exit()
        
    else:
        print '[+] WARNING: -o Argument Error\n'
        sys.exit()

if __name__ == "__main__":
    main()
