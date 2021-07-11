

from crc import *
import binascii
import sys
import struct


def get_crc32_patch(cur_data, init_hash, goal_crc32, goal_length):
	crc32 = Crc32Provider()
	print "We take a message which has the hash {0}".format(init_hash)
	# Thanks to path:
	#   http://blog.w-nz.com/archives/2005/07/15/reversing-crc/#comments
	crc32._hash = crc32.xorOut ^ NumberFromHexadecimal(init_hash[2:])
	print "Required patch to make the hash {0}:".format(hex(goal_crc32))
	p = crc32.patch(NumberFromHexadecimal(hex(goal_crc32)[2:]))
	print "0x"+binascii.hexlify(p)
	print "Applying patch, resulting hash:"
	crc32.update(p)
	print NumberToHexadecimal(crc32.hash)
	print "It works ^_^"
	return p
    
    

def inject_trailer(cur_data, payload):
	if(len(payload)>8):
		print "Can not inject more than 8 bytes!"
		return
	payload_int = int((payload).encode("hex"), 16)
	print("payload_int")
	goal_crc32 = struct.unpack("<i", payload[:4])[0]#>>32
	goal_length = struct.unpack("<i", payload[4:])[0]#&0xffffffff
	init_hash = hex(binascii.crc32(cur_data)&0xffffffff)
	print("goal_length: {0}".format(str(goal_length)))
	print("goal_crc32: {0}".format(str(goal_crc32)))
	print("length cur data: {0}".format(str(len(cur_data))))
	if(goal_length < len(cur_data)):
		print "length of current data is already to large to inject {0}".format(str(payload))
		return
	if(len(cur_data)+4 != goal_length):
		print("Best results only when applying a patch of 4 bytes!")
		return
	for l in range(len(cur_data), goal_length): #TODO: try different values and recalculate init hash every time. But most likely the patch will always be 4 bytes
		print("trying length: {0}".format(str(l)))
	  	patch = get_crc32_patch(cur_data, init_hash, goal_crc32, goal_length)
		if(len(patch)+len(cur_data) != goal_length):
			print "Length Missmatch"
			continue
		return cur_data + patch
    	
    	
if(__name__ == "__main__"):
	payload = b"<?php ?>"
	goal_length = struct.unpack("<i", payload[4:8])[0]
	cur_data = b"B"*(goal_length-4)
	new_data = inject_trailer(cur_data, payload)
	if(new_data is None):
		print("Failed")
		sys.exit(0)
	crc32 = struct.pack("<i", binascii.crc32(new_data))
	len_ = struct.pack("<i", len(new_data))
	print("crc32: {0}".format(str(crc32)))
	print("length: {0}".format(str(len_)))

