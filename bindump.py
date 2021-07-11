


def ppbits(binary):
	if(not isinstance(binary, bytes)):
		binary = bytes(binary, 'utf-8')
	for byte in binary:
		print("{0:#010b}".format(byte))
