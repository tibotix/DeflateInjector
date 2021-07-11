from pwn import *
import random as rand
import bitstring
from numpy import *
import enum
import zlib
import gzip
import time
import statistics
import collections
import logging
import multiprocessing
from scipy.stats import truncnorm
from multiprocessing.managers import BaseManager

context.log_level = logging.ERROR+1

class CompressionType(enum.Enum):
	STORED = 0b00
	FIXED = 0b01
	DYNAMIC = 0b10
	UNKNOWN = 0b11
	
class CompressedDetails():
	def __init__(self, lower_bound, upper_bound, length, n):
		self.lower_bound = lower_bound
		self.upper_bound = upper_bound
		self.length = length
		self.n = n

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

def parse_block(blocks):
	btype = blocks.read(2).uint
	return CompressionType(btype)

def parse_blocks(blocks):
	blocks = BitStreamWrapper.from_reversed_bytes(blocks)
	last_block = False
	while(not last_block):
		if(blocks.read(1)):
		    last_block = True
		yield parse_block(blocks)

def get_compression_type(data):
	blocks = data[10:len(data)-8]
	yield from parse_blocks(blocks)
    
    


# 1 - 143 -> 8 bits
# 144 - 255 -> 9 bits
def generate_alphabet(lower_bound, upper_bound):
	alphabet = [chr(i) for i in range(lower_bound,upper_bound)]
	rand.shuffle(alphabet)
	return ''.join(alphabet).encode("utf-8")


def fill_queue(q):
	while True:
		lower_bound = rand.randrange(1,180)
		upper_bound = rand.randrange(100,0xff)
		length = rand.randrange(10,500)
		for n in range(1,5):
			q.put(CompressedDetails(lower_bound, upper_bound, length, n))
	


def attack(stats, q):
	while(True):
		try:
			detail = q.get()
			alphabet = generate_alphabet(detail.lower_bound, detail.upper_bound)
			to_compress = cyclic(length=detail.length, alphabet=alphabet, n=detail.n)
			compressed = gzip.compress(to_compress)
			ctype = get_compression_type(compressed)
			for c in ctype:
				stats[c].append(detail)
		except Exception as e:
			#print("Error in attack: {0}".format(str(e)))
			continue


class StatsAnalyser():
	class Parameter():
		def __init__(self, l):
			self.mean = statistics.mean(l)
			self.median = statistics.median(l)
			self.mcommon = collections.Counter(l).most_common(5)
			self.max = max(l)
			self.min = min(l)
			self.pstdev = statistics.pstdev(l)
			
	class AnalyzeResult():
		def __init__(self, c, sample_count, n_para, l_para, u_para, lens_para):
			self.c = c
			self.sample_count = sample_count
			self.n_para = n_para
			self.l_para = l_para
			self.u_para = u_para
			self.lens_para = lens_para
			
		def print_report(self):
			print("\n"*5+"-"*20)
			print("Stats report for ctype: {0} - Samples: {1}".format(str(self.c), str(self.sample_count)))
			print("[Mean] N: {0}".format(str(self.n_para.mean)))
			print("[Median] N: {0}".format(str(self.n_para.median)))
			print("[Most Common] N: {0}".format(str(self.n_para.mcommon)))
			print("[Min] N: {0}".format(str(self.n_para.min)))
			print("[Max] N: {0}".format(str(self.n_para.max)))
			print("[Pstdev] N: {0}".format(str(self.n_para.pstdev)))
			print()
			print("[Mean] Length: {0}".format(str(self.lens_para.mean)))
			print("[Median] Length: {0}".format(str(self.lens_para.median)))
			print("[Most Common] Length: {0}".format(str(self.lens_para.mcommon)))
			print("[Min] Length: {0}".format(str(self.lens_para.min)))
			print("[Max] Length: {0}".format(str(self.lens_para.max)))
			print("[Pstdev] Length: {0}".format(str(self.lens_para.pstdev)))
			print()			
			print("[Mean] Upper: {0}".format(str(self.u_para.mean)))
			print("[Median] Upper: {0}".format(str(self.u_para.median)))
			print("[Most Common] Upper: {0}".format(str(self.u_para.mcommon)))
			print("[Min] Upper: {0}".format(str(self.u_para.min)))
			print("[Max] Upper: {0}".format(str(self.u_para.max)))
			print("[Pstdev] Upper: {0}".format(str(self.u_para.pstdev)))
			print()			
			print("[Mean] Lower: {0}".format(str(self.l_para.mean)))
			print("[Median] Lower: {0}".format(str(self.l_para.median)))
			print("[Most Common] Lower: {0}".format(str(self.l_para.mcommon)))
			print("[Min] Lower: {0}".format(str(self.l_para.min)))
			print("[Max] Lower: {0}".format(str(self.l_para.max)))
			print("[Pstdev] Lower: {0}".format(str(self.l_para.pstdev)))
			print("\n"+"-"*20)
			
	class InternalCTypeStats():
		def __init__(self, test_data, ctype):
			self.test_data = test_data
			self.ctype = ctype
			self.ns = list()
			self.ls = list()
			self.us = list()
			self.lens = list()
			
		def analyze_test_data(self):
			self._build_feature_lists()
			return StatsAnalyser.AnalyzeResult(self.ctype, len(self.test_data), StatsAnalyser.Parameter(self.ns), StatsAnalyser.Parameter(self.ls), StatsAnalyser.Parameter(self.us), StatsAnalyser.Parameter(self.lens))
			#return StatsAnalyser.AnalyzeResult(self.ctype, len(self.test_data), StatsAnalyser.Parameter(self.ns), StatsAnalyser.Parameter(zip(self.ls, self.us)), StatsAnalyser.Parameter(zip(self.ls, self.us, self.lens)), StatsAnalyser.Parameter(self.lens))
			
			
		def _build_feature_lists(self):
			for detail in self.test_data:
				self.ns.append(detail.n)
				self.ls.append(detail.lower_bound)
				self.us.append(detail.upper_bound)
				self.lens.append(detail.length)
		
	def __init__(self):
		pass
		
	def analyse_stats(self, stats):
		while True:
			try:
				time.sleep(60)
				self._analyse_stats(stats)
				self.report_stats()
			except Exception as e:
				print("EXCEPTION IN STATS: {0}".format(str(e)))
		
		
	def _analyse_stats(self, stats):
		self.stored_stats = StatsAnalyser.InternalCTypeStats(stats[CompressionType.STORED], CompressionType.STORED)
		self.fixed_stats = StatsAnalyser.InternalCTypeStats(stats[CompressionType.FIXED], CompressionType.FIXED)
		self.dynamic_stats = StatsAnalyser.InternalCTypeStats(stats[CompressionType.DYNAMIC], CompressionType.DYNAMIC)
	
	def report_stats(self):
		self.stored_stats.analyze_test_data().print_report()
		self.fixed_stats.analyze_test_data().print_report()
		self.dynamic_stats.analyze_test_data().print_report()
		



def get_truncated_normal(mean=0, sd=1, low=0, upp=10):
    return truncnorm((low - mean) / sd, (upp - mean) / sd, loc=mean, scale=sd)
    
class CompressionParameter():
	def __init__(self, mu, sigma, lower, upper):
		self.generator = get_truncated_normal(mean=mu, sd=sigma, low=lower, upp=upper)
		
	def get(self, n=1):
		return array(self.generator.rvs(n), dtype=int)
		
	
class CompressionTypeDetails():
	def generate_compression_details(self, n=1000):
		for n, length, upper, lower in zip(self.N.get(n=n), self.LENGTH.get(n=N), self.UPPER.get(n=n), self.LOWER.get(n=n))
			yield CompressedDetails(lower, upper, length, n)
		
class StoredCompressionTypeDetails(CompressionTypeDetails):
	N = CompressionParameter(1.0077252572995599, 0.1077581228016092, 1, 3)
	LENGTH = CompressionParameter(85.71846843708458, 49.58432233725107, 15, 274)
	UPPER = CompressionParameter(204.4208565225752, 29.17635337901767, 199, 254)
	LOWER = CompressionParameter(52.619344356409705, 42.75166349838119, 1, 179)

class FixedCompressionTypeDetails(CompressionTypeDetails):
	N = CompressionParameter(3.0890025724375816, 1.0386144168314502, 1, 4)
	LENGTH = CompressionParameter(64.7460645587065, 48.24575687229211, 10, 333)
	UPPER = CompressionParameter(193.81616091379195, 39.819761922457566, 100, 254)
	LOWER = CompressionParameter(76.5906455984828, 48.985898619446495, 1, 179)

class DynamicCompressionTypeDetails(CompressionTypeDetails):
	N = CompressionParameter(2.8482479182215124, 0.8902179168958725, 1, 4)
	LENGTH = CompressionParameter(284.20808589624664, 124.6263836070396, 16, 32767) # in reality this goes -> +32KB
	UPPER = CompressionParameter(184.04182696894338, 43.111347108645276, 100, 254)
	LOWER = CompressionParameter(81.53839605810447, 48.528270190687856, 1, 179)
					

def get_lit_bufsize(memlevel=9):
	return (1 << (memlevel + 6)) - 1


	
if __name__ == "__main__":
#	BaseManager.register("CompressedDetails", CompressedDetails)
	
	manager = multiprocessing.Manager()
#	manager.start()
	stats = manager.dict()
	stats[CompressionType.STORED] = manager.list()
	stats[CompressionType.FIXED] = manager.list()
	stats[CompressionType.DYNAMIC] = manager.list()
	
	q = multiprocessing.Queue(maxsize=10000)
	
	q_fill_task = multiprocessing.Process(target=fill_queue, args=(q,)) 
	q_fill_task.start()
	print("QueueFiller started!")
	time.sleep(5)
	
	
	stats_analyzer_task = multiprocessing.Process(target=StatsAnalyser().analyse_stats, args=(stats,)) 
	stats_analyzer_task.start()
	print("StatsAnaylzer started!")
	
	processes = [multiprocessing.Process(target=attack, args=(stats,q)) for x in range(6)]

	for p in processes:
		p.start()
	
		
	for p in processes:
		p.join()			
						

