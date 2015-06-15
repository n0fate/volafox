# volafox
## Introduction
volafox a.k.a 'Mac OS X Memory Analysis Toolkit' is developed on python 2.x

Lastest version : [http://volafox.tumblr.com/post/75481455662/volafox-0-9-release volafox-0.9]

*_please check out our repository for all of features included experiment_*

## System Environment
*Lang*: Python 2.x <br>
*Arch*: Intel 32/64 bit<br>
*OS*: Snow Leopard(10.6), Lion(10.7), Mountain Lion(10.8), Mavericks(10.9), *Yosemite(10.10)*<br>
*Requirement*

  * Kernel Symbol List
    * overlay data

  * Memory Image
    * Linear File Format(OSXPMem, Firewire, VMware memory image)
    * Flatten Mac Memory Reader Format using flatten.py(32bit, 64bit)

## Information
  # Kernel version, CPU and memory spec, boot/sleep/wakeup time<br>
  # Mounted filesystems<br>
  # Process listing and dump address space<br>
  # KEXT(Kernel Extensions) listing<br>
  # System Call / Mach Trap Table (Hooking Detection)<br>
  # Network socket listing
  # Open files listing by process
  # PE State information ( Device Tree, Video Memory Area)
  # EFI information ( EFI System Table, EFI Configuration Table, EFI Runtime Services)
  # extract keychain master key candidates
  # TrustedBSD analysis
  # other command : uname, dmesg ... etc 



# volafox for BSD(experimental)
## Introduction
*FreeBSD Memory Analysis Toolkit*<br>
*Tested OS:* FreeBSD x86 7.x, 8.x<br>
*Requirement*
  * Kernel Image(kernel)
  * Memory Image
*Information*
  # KLD list
  # KLD dump
  # System call hooking detection
  # Process list(LIST, HASH) (0.2 beta2<=)
  # *Process dump* (HASH)
  # Network Information (IP, Port, flag) (0.2 beta2<=)
  # Module list in KLD (0.2 beta1<=)<br>


<b>icon source</b> : www.kaishinlab.com
