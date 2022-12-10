#!/usr/bin/env python
# coding: utf-8

# In[6]:


LITERALS = 256
LENGTH_CODES = 29
_dist_code = [ 0,  1,  2,  3,  4,  4,  5,  5,  6,  6,  6,  6,  7,  7,  7,  7,  8,  8,  8,  8,
 8,  8,  8,  8,  9,  9,  9,  9,  9,  9,  9,  9, 10, 10, 10, 10, 10, 10, 10, 10,
10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13,
13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
13, 13, 13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15, 15, 15, 15,
15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,  0,  0, 16, 17,
18, 18, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 22, 22, 22, 22, 22, 22, 22, 22,
23, 23, 23, 23, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27,
27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
27, 27, 27, 27, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
28, 28, 28, 28, 28, 28, 28, 28, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29]
_length_code = [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  8,  9,  9, 10, 10, 11, 11, 12, 12, 12, 12,
13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16,
17, 17, 17, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 18, 18, 19, 19, 19, 19,
19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 22, 22, 22, 22,
22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23,
23, 23, 23, 23, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 26, 26, 26, 26, 26, 26, 26, 26,
26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 28]


# ### l_codes:
#     0..255   = literal bytes
#     256      = end of block
#     257..285 = length_codes
# ### dist:
#     1..32KiB

# In[4]:


def d_code(dist):
    if(dist<256):
        return _dist_code[dist]
    return _dist_code[256+((dist)>>7)]


# In[7]:


len(_length_code)


# In[18]:


bin(256+(285>>7))


# In[19]:


0b100000010


# In[22]:


_dist_code[256]


# In[26]:


def ppbits(b):
    for i in b:
        print("{0:#010b}".format(i))


# In[27]:


import gzip
ppbits(gzip.compress(b"A"))


# In[28]:


def parse_flags(flag_byte):
    if(flag_byte & 0x1):
        print("ASCII Flag set")
    if(flag_byte & 0x2):
        print("CRC-16 for header exists")
    if(flag_byte & 0x4):
        print("Extra Flag set")
    if(flag_byte & 0x8):
        print("Original Name exists")
    if(flag_byte & 0x10):
        print("Comment exists")


# In[67]:


import struct, datetime
def parse_timestamp(timestamp):
    recoverbinstamp = struct.unpack('<L', timestamp)[0]
    recovernow = datetime.datetime.fromtimestamp(recoverbinstamp)
    print("Last modification: {0}".format(str(recovernow)))


# In[30]:


def parse_extra_information(extra):
    if(extra & 0x2):
        print("Using maximal compression and slowest algorithm")
    if(extra & 0x4):
        print("Using fastest compression")


# In[33]:


def parse_os(byte):
    if(byte == 0x0):
        print("FAT")
    elif(byte==0x1):
        print("AmigaOS")
    elif(byte==0x2):
        print("OpenVMS")
    elif(byte==0x3):
        print("Unix")
    elif(byte==0x4):
        print("VM")
    elif(byte==0x5):
        print("Atari TOS")
    elif(byte==0x6):
        print("HPFS")
    elif(byte==0x7):
        print("Mac OS")
    elif(byte==0x8):
        print("Z-System")
    elif(byte==0x9):
        print("CP/M")
    elif(byte==0xa):
        print("TOPS-20")
    elif(byte==0xb):
        print("NTFS")
    elif(byte==0xc):
        print("QDOS")
    elif(byte==0xd):
        print("Acorn RISC OS")
    elif(byte==0xff):
        print("Unknown OS")
    else:
        print("Invalid OS")


# In[85]:


def parse_header(data):
    if(data[0:2] != b"\x1f\x8b"):
        print("invalid header")
        return
    print("-"*10 + "\nHeader:")
    print("Compression method: {0}".format(str(data[2])))
    parse_flags(data[3])
    parse_timestamp(data[4:8])
    parse_extra_information(data[8])
    parse_os(data[9])
    print("-"*10)


# In[110]:


def parse_trailer(data):
    print("-"*10 + "\nParse Trailer:")
    crc32 = data[:4]
    isize = data[4:]
    print("crc32 of uncompressed data: {0}".format(hex(int.from_bytes(crc32, "little"))))
    print("Size of uncompressed data: {0}".format(hex(int.from_bytes(isize, "little"))))
    print("-"*10)


# In[604]:


import bitstring
from numpy import *

class BitStreamWrapper(bitstring.BitStream):        
    def read(self, n, reverse=True):
        stream = super().read(n)
        if(reverse):
            stream.reverse()
        return stream
        
    @classmethod
    def from_reversed_bytes(cls, data):
        streams = list()
        for b in data:
            stream = cls(uint=b, length=8)
            stream.reverse()
            streams.append(stream)
        return cls().join(streams)


# In[636]:


def parse_no_compression(blocks):
    blocks.bytealign()
    len_ = blocks.read(16).uint
    nlen = blocks.read(16).uint
    print("*len = {0}".format(str(len_)))
    print("*nlen = {0}".format(str(nlen)))
    if(~len_ != nlen):
        print("Invalid len of uncompressed data!")
        return
    ppbits(blocks[blocks.pos:].bytes)
    data = blocks.read(len_*8)
    data.byteswap()
    print("uncompressed data: {0}".format(str(data.bytes)))


# In[638]:


fixed_codes = {7: {0: 256, 1: 257, 2: 258, 3: 259, 4: 260, 5: 261, 6: 262, 7: 263, 8: 264, 9: 265, 10: 266, 11: 267, 12: 268, 13: 269, 14: 270, 15: 271, 16: 272, 17: 273, 18: 274, 19: 275, 20: 276, 21: 277, 22: 278}, 8: {48: 0, 49: 1, 50: 2, 51: 3, 52: 4, 53: 5, 54: 6, 55: 7, 56: 8, 57: 9, 58: 10, 59: 11, 60: 12, 61: 13, 62: 14, 63: 15, 64: 16, 65: 17, 66: 18, 67: 19, 68: 20, 69: 21, 70: 22, 71: 23, 72: 24, 73: 25, 74: 26, 75: 27, 76: 28, 77: 29, 78: 30, 79: 31, 80: 32, 81: 33, 82: 34, 83: 35, 84: 36, 85: 37, 86: 38, 87: 39, 88: 40, 89: 41, 90: 42, 91: 43, 92: 44, 93: 45, 94: 46, 95: 47, 96: 48, 97: 49, 98: 50, 99: 51, 100: 52, 101: 53, 102: 54, 103: 55, 104: 56, 105: 57, 106: 58, 107: 59, 108: 60, 109: 61, 110: 62, 111: 63, 112: 64, 113: 65, 114: 66, 115: 67, 116: 68, 117: 69, 118: 70, 119: 71, 120: 72, 121: 73, 122: 74, 123: 75, 124: 76, 125: 77, 126: 78, 127: 79, 128: 80, 129: 81, 130: 82, 131: 83, 132: 84, 133: 85, 134: 86, 135: 87, 136: 88, 137: 89, 138: 90, 139: 91, 140: 92, 141: 93, 142: 94, 143: 95, 144: 96, 145: 97, 146: 98, 147: 99, 148: 100, 149: 101, 150: 102, 151: 103, 152: 104, 153: 105, 154: 106, 155: 107, 156: 108, 157: 109, 158: 110, 159: 111, 160: 112, 161: 113, 162: 114, 163: 115, 164: 116, 165: 117, 166: 118, 167: 119, 168: 120, 169: 121, 170: 122, 171: 123, 172: 124, 173: 125, 174: 126, 175: 127, 176: 128, 177: 129, 178: 130, 179: 131, 180: 132, 181: 133, 182: 134, 183: 135, 184: 136, 185: 137, 186: 138, 187: 139, 188: 140, 189: 141, 190: 142, 191: 143, 192: 280, 193: 281, 194: 282, 195: 283, 196: 284, 197: 285, 198: 286, 199: 287}, 9: {400: 144, 401: 145, 402: 146, 403: 147, 404: 148, 405: 149, 406: 150, 407: 151, 408: 152, 409: 153, 410: 154, 411: 155, 412: 156, 413: 157, 414: 158, 415: 159, 416: 160, 417: 161, 418: 162, 419: 163, 420: 164, 421: 165, 422: 166, 423: 167, 424: 168, 425: 169, 426: 170, 427: 171, 428: 172, 429: 173, 430: 174, 431: 175, 432: 176, 433: 177, 434: 178, 435: 179, 436: 180, 437: 181, 438: 182, 439: 183, 440: 184, 441: 185, 442: 186, 443: 187, 444: 188, 445: 189, 446: 190, 447: 191, 448: 192, 449: 193, 450: 194, 451: 195, 452: 196, 453: 197, 454: 198, 455: 199, 456: 200, 457: 201, 458: 202, 459: 203, 460: 204, 461: 205, 462: 206, 463: 207, 464: 208, 465: 209, 466: 210, 467: 211, 468: 212, 469: 213, 470: 214, 471: 215, 472: 216, 473: 217, 474: 218, 475: 219, 476: 220, 477: 221, 478: 222, 479: 223, 480: 224, 481: 225, 482: 226, 483: 227, 484: 228, 485: 229, 486: 230, 487: 231, 488: 232, 489: 233, 490: 234, 491: 235, 492: 236, 493: 237, 494: 238, 495: 239, 496: 240, 497: 241, 498: 242, 499: 243, 500: 244, 501: 245, 502: 246, 503: 247, 504: 248, 505: 249, 506: 250, 507: 251, 508: 252, 509: 253, 510: 254, 511: 255}}

def get_next_code(blocks):
    cur_pos = blocks.pos
    for bitlen in range(7,10):
        print("reading bitlen: {0}".format(str(bitlen)))
        blocks.pos = cur_pos
        print(str(blocks[blocks.pos:].bin))
        code = blocks.read(bitlen, reverse=False)
        print("trying code: {0}->{1}".format(str(code.bin), str(code.uint)))
        if(code.uint in fixed_codes[bitlen]):
            print("Found valid code: {0}->{1}".format(str(code.uint), str(fixed_codes[bitlen][code.uint])))
            return fixed_codes[bitlen][code.uint]
        


# In[584]:


length_codes = {257: [0, (3,)], 258: [0, (4,)], 259: [0, (5,)], 260: [0, (6,)], 261: [0, (7,)], 262: [0, (8,)], 263: [0, (9,)], 264: [0, (10,)], 265: [1, (11,12)], 266: [1, (13,14)], 267: [1, (15,16)], 268: [1, (17,18)], 269: [2, (19,22)], 270: [2, (23,26)], 271: [2, (27,30)], 272: [2, (31,34)], 273: [3, (35,42)], 274: [3, (43,50)], 275: [3, (51,58)], 276: [3, (59,66)], 277: [4, (67,82)], 278: [4, (83,98)], 279: [4, (99,114)], 280: [4, (115,130)], 281: [5, (131,162)], 282: [5, (163,194)], 283: [5, (195,226)], 284: [5, (227,257)], 285: [0, (258,)]}


def parse_code(code, blocks):
    if(code<256):
        literal = chr(code)
        print("Literal found: {0}".format(literal))
        return literal.encode("utf-8")
    if(code>256):
        extra_bits, length_range = length_codes[code]
        base_length = length_range[0]
        print("Length code found: \n\textra_bits: {0}\n\tbase_length: {1}".format(str(extra_bits), str(base_length)))
        distance_code = blocks.read(extra_bits)
        print("Distance code found: {0}".format(str(distance_code)))
        return b""
    return b""


# In[593]:


END_OF_BLOCK_CODE = 256

def parse_fixed_huffman_compression(blocks):
    data = b""
    next_code = get_next_code(blocks)
    while(next_code != END_OF_BLOCK_CODE):
        print("next_code: {0}".format(str(next_code)))
        data += parse_code(next_code, blocks)
        next_code = get_next_code(blocks)
    print("End of block!")


# In[586]:


def parse_block(blocks):
    btype = blocks.read(2).uint
    if(btype==0b00):
        print("*No compression")
        parse_no_compression(blocks)
    elif(btype==0b01):
        print("*Fixed Huffman encoding compression")
        parse_fixed_huffman_compression(blocks)
    elif(btype==0b10):
        print("*Dynamic Huffman encoding compression")
    elif(btype==0b11):
        print("*Unknown compression")
    else:
        print("!Invalid compression")


# In[587]:


import bitstring

def parse_blocks(blocks):
    blocks = BitStreamWrapper.from_reversed_bytes(blocks)
    last_block = False
    print("-"*10)
    while(not last_block):
        print("Parsing new Block...")
        if(blocks.read(1)):
            print("*Last Block")
            last_block = True
        parse_block(blocks)
        print("-"*10)


# In[588]:


def parse_gzip(data):
    parse_header(data[0:10])
    blocks = data[10:len(data)-8]
    print("All Blocks:")
    ppbits(blocks)
    parse_blocks(blocks)
    parse_trailer(data[-8:])


# In[754]:


parse_gzip(gzip.compress(b"\x90\x91\x92\x93\x94H", compresslevel=9))


# In[850]:


gzip.compress(b"\x90\x91\x92\x93\x94P\x10\x90p0` \x00\x80@X\x18x8h(\x08\x88HT\x14t4d$\x04\x84D\\\x1c|<l,\x0c\x8cLR\x12r2b\x02\x82BZ\x1az:j*\n\x8aJV\x16v6f&\x06\x86F^\x1e~>n.\x0e\x8eNQ\x11q1a!\x01\x81AY\x19y9i)\t\x89IU\x15u5e%\x05\x85E]\x1d}=m-\r\x8dMQ\x11q1a!\x01\x81AY\x19y9i)\t\x89IU\x15u5e%\x05\x85E]\x1d}=m-\r\x8dM", compresslevel=9)


# In[883]:


gzip.compress(b"\x90\x91\x92\x93\x94\x94\x14t4d$\x04\x84D\\\x1c|<l,\x0c\x8cLR\x12r")


# In[473]:


b = bitstring.BitStream(bin="0b10000010")
b.invert()
b.bin


# In[731]:


bin(0b00110000 +18)


# In[724]:


65-48


# In[694]:


chr(65)


# In[696]:


0b00100001


# In[729]:


ord("H")


# In[730]:


bin(72)


# In[894]:


import  bitstring

class InjectionBitValueRange():
    def __init__(self, minimum_injection_bit_value, maximum_injection_bit_value):
        self.minimum_injection_bit_value = minimum_injection_bit_value
        self.maximum_injection_bit_value = maximum_injection_bit_value
        
    def is_in_range(self, value):
        return bool(value>= self.minimum_injection_bit_value and value<=self.maximum_injection_bit_value)

class InjectionBitCountRange():
    def __init__(self, minimum_injection_bit_count, maximum_injection_bit_count):
        self.minimum_injection_bit_count = minimum_injection_bit_count # even if more bytes are written 
        self.maximum_injection_bit_count = maximum_injection_bit_count
        
    def is_in_range(self, value):
        return bool(value>= self.minimum_injection_bit_count and value<=self.maximum_injection_bit_count)
    

class InjectionTechnique():
    def __init__(self, injection_bit_count_range, injection_bit_value_range)
        self.injection_bit_count_range = injection_bit_count_range
        self.injection_bit_value_range = injection_bit_value_range
        
    def try_inject_match(self, bits_to_inject):
        #try to match parts or whole bits of data
        pass
    
class LowerLiteralsInjectionTechnique(InjectionTechnique):
    injection_bit_value_range = InjectionBitValueRange(48, 192)
    injection_bit_value_range = InjectionBitCountRange(8,8)
    def __init__(self):
            super().__init__(injection_bit_value_range, injection_bit_value_range)

class UpperLiteralsInjectionTechnique(InjectionTechnique):
    injection_bit_value_range = InjectionBitValueRange(48, 192)
    injection_bit_value_range = InjectionBitCountRange(9,9)
    
    def __init__(self):
            super().__init__(injection_bit_value_range, injection_bit_value_range)

class LowerLengthcodesInjectionTechnique(InjectionTechnique):
    injection_bit_value_range = InjectionBitValueRange(48, 192)
    injection_bit_value_range = InjectionBitCountRange(8,9)
    def __init__(self):
            super().__init__(injection_bit_value_range, injection_bit_value_range)

class UpperLengthcodesInjectionTechnique(InjectionTechnique):
    injection_bit_value_range = InjectionBitValueRange(48, 192)
    injection_bit_value_range = InjectionBitCountRange(8,8)
    def __init__(self):
            super().__init__(injection_bit_value_range, injection_bit_value_range)
        


class InjectionTechniqueManager():
    def __init__(self):
        self.injection_techniques = set()
        
    def register_injection_technique(self, injection_technique):
        if(not issubclass(injection_technique, InjectionTechnique)):
            return False
        self.injection_techniques.add(injection_technique)
        return True
    
    def get_injection_techniques(self):
        # techniques are preffered in order as they are registered
        yield from self.injection_techniques
    
    
class InjectionController():
    def __init__(self, data, injection_technique_manager):
        self.data = BitStreamWrapper.from_reversed_bytes(data)
        self.injection_technique_manager = injection_technique_manager
    
    def inject_bits(self):
        return self._inject_bits(self.data, b"")
    
    def _inject_bits(self, bits_to_inject, payload):
        print("Injecting {0}".format(str(data)))
        # we have 4 options:
        # (8bits)      1.with literals 0-143 we can achieve an code of 8bits 48-192!
        # (9bits)      2.with literals 144-255 we can achieve an code of 9bits 400-511 -> 8bits of 200-255! (then first bit of next byte is 0 or 1)
        #  ---------
        # ((11)29bits) 3.with lengthcodes 257-279 (->lengths of 3-114) we can achieve an code of 7bits 0-23 + 0-4extrabits
        # ((13)31bits) 4.with lengthcodes 280-287 (->lengths of 115-258) we can achieve an code of 8bits 192-199  + 4-5|0extrabits
        # (18bits)       + following distance codes: with distances 1-32768 we can achieve an code of 5bits 0-29 + 0-13extrabits
        # recursive algorithm
        # maybe graph theory!!!
        # we can go out of data bounds at the end cause that will not effect already injected data.
        # stop condition
        # for every possible injection type:
        #   try to match data sequence with injecting (yielding all possible injections with this given injection type)
        #   inject_bits(data[already_injected:], payload)
        for injection_technique in self.injection_technique_manager.get_injection_techniques():
            for injection_payload, injected_bit_count in injection_techique.try_inject_match(bits_to_inject):
                new_payload = payload+injection_payload
                if(injected_bit_count >= len(bits_to_inject)):
                    return new_payload
                new_bits_to_inject = bits_to_inject[injected_bit_count:]
                try:
                    return self._inject_bits(new_bits_to_inject, new_payload)
                except InjectionError:
                    pass
        raise InjectionError("Could not inject {0}".format(str(bits_to_inject)))


# In[889]:


import bitstring

def generate_code_combination_for_injection(byte):
    pass

def is_literal_eigth_bit_code_representable(byte):
    # with literals 0-143 we can achieve an code of 8bits 48-192!
    return bool(byte>=48 and byte<=192)

def is_literal_nine_bit_code_printable(byte):
    # with literals 144-255 we can achieve an code of 9bits 400-511!
    return bool(byte>=400 and byte<=511)

def is_literal_nine_seven_trick_acceptable(byte, next_byte):
    
    # with literals 144-255 we can achieve an code of 9bits 400-511 -> 8bits of 200-255! (then first byte of 7bitcode is 0 or 1)
    # with lengthcodes 257-279 (->lengths of 3-114) we can achieve an code of 7bits 0-23 + 0-4extrabits
    return bool(byte>=200 and byte<=255)


#with lengthcodes 257-279 (->lengths of 3-114) we can achieve an code of 7bits 0-23 + 0-4extrabits
#with lengthcodes 280-287 (->lengths of 115-258) we can achieve an code of 8bits 192-199  + 4-5|0extrabits
#  + following distance codes: with distances 1-32768 we can achieve an code of 5bits 0-29 + 0-13extrabits

def inject_fixed_huffman_only_literals(data):
    align_bytes = b"\x90\x91\x92\x93\x94" # (3bytes block header +) 9+9+9+9 = 48 bytes as codes -> 49th byte for us bytealligned
    payload = align_bytes
    for b in data:
        b = bitstring.BitArray(bytes=b, length=8)
        b.reverse()
        print("b: {0}".format(str(b.uint)))
        if(is_literal_eigth_bit_code_representable(b.uint)):
            #easy win simply store these 8bits! WE CAN ALSO SHIFT ALLIGNMENT WITH 9/7 CODES AND PRINT SO DIFFERENT CHARACTER!
            payload += int.to_bytes(b.uint-48, 1, "little")
        elif(b.uint>=193 and b.uint<=199): #literal value 280-287
            # we need length and distance codes . so we also need some literals at the beginning to refer to 
            payload += generate_code_combination_for_injection(b.uint)
        else:
            print("Cannot inject {0}".format(str(b.bytes)))
    return payload
        


# In[848]:


def inject_no_compression(data):
    return data


# In[880]:


acceptable_chars = [b'\x01', b'\x02', b'\x03', b'\x05', b'\x06', b'\t', b'\n', b'\x0c', b'\r', b'\x0e', b'\x11', b'\x12', b'\x15', b'\x16', b'\x19', b'\x1a', b'\x1c', b'\x1d', b'\x1e', b'!', b'"', b'%', b'&', b')', b'*', b',', b'-', b'.', b'1', b'2', b'5', b'6', b'9', b':', b'<', b'=', b'>', b'A', b'B', b'E', b'F', b'I', b'J', b'L', b'M', b'N', b'Q', b'R', b'U', b'V', b'Y', b'Z', b'\\', b']', b'^', b'a', b'b', b'e', b'f', b'i', b'j', b'l', b'm', b'n', b'q', b'r', b'u', b'v', b'y', b'z', b'|', b'}', b'~', b'\xc2\x81', b'\xc2\x82', b'\xc2\x85', b'\xc2\x86', b'\xc2\x89', b'\xc2\x8a', b'\xc2\x8c', b'\xc2\x8d', b'\xc2\x8e', b'\xc2\x91', b'\xc2\x92', b'\xc2\x95', b'\xc2\x96', b'\xc2\x99', b'\xc2\x9a', b'\xc2\x9c', b'\xc2\x9d', b'\xc2\x9e', b'\xc2\xa1', b'\xc2\xa2', b'\xc2\xa5', b'\xc2\xa6', b'\xc2\xa9', b'\xc2\xaa', b'\xc2\xac', b'\xc2\xad', b'\xc2\xae', b'\xc2\xb1', b'\xc2\xb2', b'\xc2\xb5', b'\xc2\xb6', b'\xc2\xb9', b'\xc2\xba', b'\xc2\xbc', b'\xc2\xbd', b'\xc2\xbe', b'\xc3\x81', b'\xc3\x82', b'\xc3\x85', b'\xc3\x86', b'\xc3\x89', b'\xc3\x8a', b'\xc3\x8c', b'\xc3\x8d', b'\xc3\x8e', b'\xc3\x91', b'\xc3\x92', b'\xc3\x95', b'\xc3\x96', b'\xc3\x99', b'\xc3\x9a', b'\xc3\x9c', b'\xc3\x9d', b'\xc3\x9e', b'\xc3\xa1', b'\xc3\xa2', b'\xc3\xa5', b'\xc3\xa6', b'\xc3\xa9', b'\xc3\xaa', b'\xc3\xac', b'\xc3\xad', b'\xc3\xae', b'\xc3\xb1', b'\xc3\xb2', b'\xc3\xb5', b'\xc3\xb6', b'\xc3\xb9', b'\xc3\xba', b'\xc3\xbc', b'\xc3\xbd', b'\xc3\xbe']
inject_fixed_huffman_only_literals(acceptable_chars[20:40])
#inject_fixed_huffman_only_literals([int.to_bytes(i, 1, "little") for i in b"<=>ytem"])
#inject_fixed_huffman_only_literals([b's', b'y', b's', b't', b'e', b'm'])


# In[ ]:




