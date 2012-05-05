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

# This program prints the loader commands in the same format as the 
# showbootermemorymap kernel debug macro, which is also the same format
# as the /dev/pmap output in the Mac Memory Reader.

import sys
import mmap
import volafox.binan.macho

if len(sys.argv) != 2:
    print "Usage: showbootermemorymap <mach-o image>."
    exit(0)

fin     = open(sys.argv[1], 'rb')
map     = mmap.mmap(fin.fileno(), 4096*16, prot=mmap.PROT_READ)
ncmds   = macho.getncmds(map)
lcmds   = macho.loadcommand(map, ncmds)

print "Type       Physical Start   Number of Pages"
for cmd in lcmds:
    print cmd
