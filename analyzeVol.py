from __future__ import print_function


def ssdt():
	outfile = open('interesting.txt', 'a')
	try:
		for line in open('ssdt.txt'):
			if ('Entry' in line):
				if ('ntoskrnl' not in line) and ('win32k' not in line):
					print('SSDT: {0}'.format(line))
					print('SSDT: {0}'.format(line), file=outfile)
	except:
		print("[-] Error, could not open ssdt.txt")
	outfile.close()

def svcscan():
	outfile = open('interesting.txt', 'a')
	try:
		a = open('svcscan.txt')
		for entry in a.read().split('\n\n'):
			fields = entry.split('\n')
			binPath = ' '.join(fields[-1].split(' ')[2:])
			if (':\windows\system32' not in binPath[:20].lower()):
				print('SvcScan: {0}'.format(entry))
				print('SvcScan: {0}'.format(entry), file=outfile)
	except:
		print("[-] Error, could not open svcscan.txt")
	outfile.close()

def apihooks():
	# do something with api hooks...no entries in current file to figure out format
	return 0

def idt():
	# do something with IDT...no entries in current file to figure out format
	return 0


	
