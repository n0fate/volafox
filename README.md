# volafox
## Introduction
volafox a.k.a 'Mac OS X Memory Analysis Toolkit' is developed on python 2.x

Lastest version : [http://volafox.tumblr.com/post/75481455662/volafox-0-9-release volafox-0.9]

*_please check out our repository for all of features included experiment_*

## License
GNU GPL v2

## System Environment
*Lang*: Python 2.x <br>
*Arch*: Intel 32/64 bit<br>
*OS*: Snow Leopard(10.6), Lion(10.7), Mountain Lion(10.8), Mavericks(10.9), *Yosemite(10.10)*<br>

### Requirement
* Kernel Symbol List
 * overlay data

* Memory Image
 * Linear File Format(OSXPMem, Firewire, VMware memory image)
 * Flatten Mac Memory Reader Format using flatten.py(32bit, 64bit)

## Information
    volafox: Mac OS X Memory Analysis Toolkit
    project: http://code.google.com/p/volafox
    support: 10.6-10(Snow Leopard ~ Yosemite); 32/64-bit kernel
      input: *.vmem (VMWare memory file), *.mmr (Mac Memory Reader, flattened x86, IA-32e)
      usage: python vol.py -i IMAGE [-o COMMAND [-vp PID][-x PID][-x KEXT_ID][-x TASKID][-x SYMFILENAME]]
    
    Options:
        -o CMD            : Print kernel information for CMD (below)
        -p PID            : List open files for PID (where CMD is "lsof" and dumpfile)
        -v                : Print all files, including unsupported types (where CMD is "lsof")
        -x PID/KID/TASKID/SYMBOLNAME/Virtual ADDRESS :
           Dump process/task/kernel extension address space for PID/KID/Task ID (where CMD is "ps"/"kextstat"/"tasks"/"machdump"/"dumpsym"/"dumpfile")
    
    COMMANDS:
    system_profiler : Kernel version, CPU, and memory spec, Boot/Sleep/Wakeup time
    mount           : Mounted filesystems
    kextstat        : KEXT (Kernel Extensions) listing
    kextscan        : Scanning KEXT (Kernel Extensions) (64bit OS only, experiment)
    ps              : Process listing
    tasks           : Task listing (Finding process hiding)
    machdump        : Dump macho binary (experiment)
    systab          : Syscall table (Hooking detection)
    mtt             : Mach trap table (Hooking detection)
    netstat         : Network socket listing (Hash table)
    lsof            : Open files listing by process (research, osxmem@gmail.com)
    dumpfile        : Dump a file on Memory (Required -p and -x option)
    pestate         : Show Boot information
    efiinfo         : EFI System Table, EFI Runtime Services
    keychaindump    : Dump master key candidates for decrypting keychain(Lion ~ Yosemite)
    dmesg           : Debug message at boot time
    uname           : Print a short for unix name(uname)
    hostname        : Print a hostname
    notifiers       : Detects I/O Kit function hooking (experiment)
    trustedbsd      : Show TrustedBSD MAC Framework
    bash_history    : Show history in bash process
    dumpsym         : Dump kernel symbol address considered of KASLR to file (for RE), experiment
    
    Kernel Rootkit Detection: (testing code by n0fate) - Required Library : distorm3
    kdebug_hook     : Examination of the KDebug function code for mal-code detection
    kauth_hook      : Examination of the KAUTH for mal-code hiding detection from Anti-virus
    bsm_hook        : Examination of auto_commit function on the OpenBSM
    fbt_syscall     : Examination of syscall table for hooking by DTrace FBT Provider



# volafox for BSD(experimental)
## Introduction
*FreeBSD Memory Analysis Toolkit*<br>
*Tested OS:* FreeBSD x86 7.x, 8.x<br>

### Requirement*
* Kernel Image(kernel)
* Memory Image

## Information*
* KLD list
* KLD dump
* System call hooking detection
* Process list(LIST, HASH) (0.2 beta2<=)
* *Process dump* (HASH)
* Network Information (IP, Port, flag) (0.2 beta2<=)
* Module list in KLD (0.2 beta1<=)<br>


<b>icon source</b> : www.kaishinlab.com
