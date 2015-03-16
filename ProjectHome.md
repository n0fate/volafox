# volafox #
## Introduction ##
volafox a.k.a 'Mac OS X Memory Analysis Toolkit' is developed on python 2.x

Lastest version : [volafox-0.9](http://volafox.tumblr.com/post/75481455662/volafox-0-9-release)

**_please check out our repository for all of features included experiment_**

## System Environment ##
**Lang**: Python 2.x <br>
<b>Arch</b>: Intel 32/64 bit<br>
<b>OS</b>: Snow Leopard(10.6), Lion(10.7), Mountain Lion(10.8), Mavericks(10.9), <b>Yosemite(10.10)</b><br>
<b>Requirement</b>

<ul><li>Kernel Symbol List<br>
<ul><li>overlay data</li></ul></li></ul>

<ul><li>Memory Image<br>
<ul><li>Linear File Format(OSXPMem, Firewire, VMware memory image)<br>
</li><li>Flatten Mac Memory Reader Format using flatten.py(32bit, 64bit)</li></ul></li></ul>

<h2>Information</h2>
<ol><li>Kernel version, CPU and memory spec, boot/sleep/wakeup time<br>
</li><li>Mounted filesystems<br>
</li><li>Process listing and dump address space<br>
</li><li>KEXT(Kernel Extensions) listing<br>
</li><li>System Call / Mach Trap Table (Hooking Detection)<br>
</li><li>Network socket listing<br>
</li><li>Open files listing by process<br>
</li><li>PE State information ( Device Tree, Video Memory Area)<br>
</li><li>EFI information ( EFI System Table, EFI Configuration Table, EFI Runtime Services)<br>
</li><li>extract keychain master key candidates<br>
</li><li>TrustedBSD analysis<br>
</li><li>other command : uname, dmesg ... etc</li></ol>



<h1>volafox for BSD(experimental version)</h1>
<h2>Introduction</h2>
<b>FreeBSD Memory Analysis Toolkit</b><br>
<b>Tested OS:</b> FreeBSD x86 7.x, 8.x<br>
<b>Requirement</b>
<ul><li>Kernel Image(kernel)<br>
</li><li>Memory Image<br>
<b>Information</b>
</li></ul><ol><li>KLD list<br>
</li><li>KLD dump<br>
</li><li>System call hooking detection<br>
</li><li>Process list(LIST, HASH) (0.2 beta2<=)<br>
</li><li><b>Process dump</b> (HASH)<br>
</li><li>Network Information (IP, Port, flag) (0.2 beta2<=)<br>
</li><li>Module list in KLD (0.2 beta1<=)<br></li></ol>


<b>icon source</b> : www.kaishinlab.com