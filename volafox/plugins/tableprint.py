import sys

from sys import stderr

# print a string matrix as a formatted table of columns	
def columnprint(headerlist, contentlist, mszlist=[]):
	num_columns = len(headerlist)
	size_list   = []
	
	# start sizing by length of column titles
	for title in headerlist:
		size_list.append(len(title))
	
	# resize based on content
	for i in xrange(num_columns):
		for line in contentlist:
			if len(line) != len(headerlist):
				stderr.write("ERROR length of header list does not match content.\n")
				return -1
			if len(line[i]) > size_list[i]:
				size_list[i] = len(line[i])
	
	# check sizing against optional max size list		
	if len(mszlist) > 0:
		if len(mszlist) != len(headerlist):
			stderr.write("ERROR length of header list does not match max size list.\n")
			return -1
		for i in xrange(num_columns):
			if mszlist[i] < size_list[i] and mszlist[i] > 0:	# -1/0 for unrestricted sz
				if mszlist[i] < len(headerlist[i]):
					stderr.write("WARNING max size list and column header length mismatch.\n")
				size_list[i] = mszlist[i]
				
	# prepend header to content list
	contentlist = [headerlist] + contentlist
	
	# build comprehensive, justified, printstring
	printblock = ""
	for line in contentlist:
		printline = ""
		for i in xrange(num_columns):
			if i == 0:
				printline += line[i][:size_list[i]].ljust(size_list[i])
			elif i == (num_columns-1):
				printline += " " + line[i][:size_list[i]]
			else:
				printline += line[i][:size_list[i]].rjust(size_list[i]+1)
		printblock += printline + '\n'

	sys.stdout.write('%s' %printblock)
