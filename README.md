# volafox
## Introduction
volafox a.k.a 'Mac OS X Memory Analysis Toolkit' is developed on python 2.x

*_please check out our repository for all of features included experiment_*

## License
GNU GPL v2

## System Environment
*Language*: Python 2.x <br>
*Architecture*: Intel 32/64 bit<br>
*Officially supported os*: Snow Leopard(10.6), Lion(10.7), Mountain Lion(10.8), Mavericks(10.9), *Yosemite(10.10), El Capitan(10.11)*<br>

### Requirement
* Kernel Symbol List
 * overlay data(Included repo from Snow Leopard to El Capitan)

* Memory Image
 * Raw memory image(Firewire, VMware memory image)
 * Exported raw memory image using rekal developed by google
    * command : rekal aff4export -D . [AFF4 IMAGE] => output filename : Physical Memory
 * Flatten Mac Memory Reader Format using flatten.py(32bit, 64bit) => MMR doesn't support OS X Mountain Lion above now.

## Information
    volafox: Mac OS X Memory Analysis Toolkit
    project: https://github.com/n0fate/volafox
    support: 10.6-11(Snow Leopard ~ El Capitan); 32/64-bit kernel
      input: raw memory image (*.mem or exported raw memory image using rekal developed by google
      -> If you get a AFF4 format, you can export linear memory image as following cmd : rekal aff4export -D . [AFF4 MEMORY IMAGE]
    
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
    kextscan        : Scanning KEXT (Kernel Extensions) (64bit OS only)
    ps              : Process listing
    tasks           : Task listing (Finding process hiding)
    machdump        : Dump macho binary and relocation for analysis
    systab          : Syscall table (Hooking detection)
                      => Call Number 427 is bugged not hooked.
    mtt             : Mach trap table (Hooking detection)
    netstat         : Network socket listing (Hash table)
    lsof            : Open files listing by process (research, osxmem@gmail.com)
    dumpfile        : Dump a file on Memory (Required -p and -x option)
    pestate         : Show Boot information
    efiinfo         : EFI System Table, EFI Runtime Services
    keychaindump    : Dump master key candidates for decrypting keychain(Lion ~ El Capitan)
    dmesg           : Debug message at boot time
    uname           : Print a short for unix name(uname)
    hostname        : Print a hostname
    notifiers       : Detects I/O Kit function hooking
    trustedbsd      : Show TrustedBSD MAC Framework
    bash_history    : Show history in bash process
    sysctl          : show the result like sysctl command
    dumpsym         : Dump kernel symbol address considered of KASLR to file (for RCE)
    
    Kernel Rootkit Detection: (testing code by n0fate) - Required Library : distorm3
    kdebug_hook     : Examination of the KDebug function code for mal-code detection
    kauth_hook      : Examination of the KAUTH for mal-code hiding detection from Anti-virus
    bsm_hook        : Examination of auto_commit function on the OpenBSM
    fbt_syscall     : Examination of syscall table for hooking by DTrace FBT Provider


# volafox for BSD
* Experimental - I just keep it for researcher

# Introduction
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
