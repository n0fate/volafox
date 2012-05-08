#!/usr/bin/env python
#
# Copyright 2011 ATC-NY (http://www.cyber-marshal.com/)
#
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

# This program takes a mach-o image produced by the Mac Memory Reader and
# turns it into a flat file (an offset into the file is the physical memory
# address).  
#
# NOTE - Using this on the 64-bit kernels is probably a mistake and may be
#        buggy, because there are often large gaps in the mach-o image, which
#        will result in extremely large flat file images.

import sys
import mmap
import volafox.vatopa.machaddrspace

if len(sys.argv) != 3:
    print "Usage: %s <MAC MEMORY READER IMAGE> <FLAT IMAGE>."%sys.argv[0]
    exit(0)

fin     = open(sys.argv[1], 'rb')
    
ncmds   = volafox.vatopa.machaddrspace.getncmds(fin)
lcmds   = volafox.vatopa.machaddrspace.loadcommand(fin, ncmds)

fout    = open(sys.argv[2], 'w+b')

def copy(fin, fin_where, fout, fout_where, size):

    fin.seek(fin_where)
    fout.seek(fout_where)

    remaining = size
    while remaining > 0:
        if remaining > 4096*16:
            buffer = fin.read(4096*16)
            remaining = remaining - 4096*16
        else:
            buffer = fin.read(remaining)
            remaining = 0

        fout.write(buffer)


for cmd in lcmds:
    print("Copying: %s" % cmd)
    copy(fin, cmd.fileoff, fout, cmd.vmaddr, cmd.filesize)

fin.close
fout.close
