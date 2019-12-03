from __future__ import division
from bitarray import bitarray
import mmh3
import os
import sys
import gc
import time
from math import log,ceil,exp

class BloomFilter:

	def __init__(self, size, hash_count):
		'''
			constructor of class BloomFilter. Arguments:
			- size: size of bloom filter in bits
			- hash_count: number of hash functions the filter uses
		'''
		self.size = size # the size of the bloom filter in bits
		self.hash_count = hash_count # the number of hash functions the filter uses
		self.bit_array = bitarray(size) # the bloom filter itself
		self.bit_array.setall(0) # initialize bloom filter with zeroes

	def add(self, string):
		'''
			A method to add an element in the Bloom filter
		'''
		for seed in xrange(self.hash_count):
			result = mmh3.hash(string, seed) % self.size # modulo the size of the filter to ensure
			self.bit_array[result] = 1 # the result is smaller than the size of the filter
		return None
	
	def query(self, string):
		'''
			A method to perform a Bloom filter query
		'''
		for seed in xrange(self.hash_count):
			result = mmh3.hash(string, seed) % self.size
			if self.bit_array[result] == 0:
                            return False
		return True

def create_bloom_filter(filter_size,hash_functions):
	'''
		A method to create the Bloom filter instance and initialize its parameters
	'''
	if filter_size == 0 or hash_functions == 0:
		bf = BloomFilter(5000,3) # some default values
	else:
		bf = BloomFilter(filter_size,hash_functions)

	return bf

def fill_bloom_filter(file_name,bloom_filter):
    '''
        A method that fills the Bloom filter with the elements of the given zone file
    '''
    file_to_open = open(file_name,"r")
    total_items = 0

    start_time = time.time()
    for line in file_to_open:
		name_to_add = line.rstrip() 
		bloom_filter.add(name_to_add)
		total_items = total_items + 1
    end_time = time.time()
    
    print("Bloom Filter filled in: ", end_time - start_time)

    return bloom_filter,total_items

def count_number_of_lines(file_name):
    '''
        A method that counts the number of elements in the zone file
    '''
    number_of_lines = sum(1 for line in open(file_name))
    gc.collect() # garbage collection
    return number_of_lines

def optimum_hash_functions_calculation(size_of_filter,number_of_elements):
	'''
		A method that calculates the optimum number of hash functions of the Bloom filter
		based on the number of elements stored in it and its size
	'''
	hash_functions_not_rounded = int(size_of_filter) / int(number_of_elements) * log(2)
	hash_functions = int(round(hash_functions_not_rounded))
	if hash_functions == 0:
		hash_functions = 1;
	print("Number of hash functions",hash_functions)
	return hash_functions

def convert_size_to_kb_mb(size_of_filter):
    '''
        A method to convert the size of the Bloom filter given in bits to KBs and MBs
    '''
    size_in_KB = (size_of_filter / 8) / 1024
    size_in_MB = size_in_KB / 1024
    return size_in_KB,size_in_MB

def set_filter_parameters(zone_file_name,size):
	'''
		A method that sets the parameters of the Bloom filter instance.
		The parameters of the Bloom filter are its size, the number of elements stored in it,
		and the number of hash functions used
	'''
	size_of_filter = size
	print("Size of filter is ",size_of_filter)
	size_in_KB,size_in_MB = convert_size_to_kb_mb(size_of_filter)
	number_of_elements = count_number_of_lines(zone_file_name)
	print("Number of elements stored in the filter ",number_of_elements)
	hash_functions = optimum_hash_functions_calculation(size_of_filter,number_of_elements)
	return size_of_filter,size_in_KB,size_in_MB,number_of_elements,hash_functions

def benchmark_bloom_filter(name,bf):
	start_time = time.time()
	is_contained = bf.query(name)
	end_time = time.time()
	time_required = end_time - start_time
	return time_required

def main():
	'''
		The main method of the python script
	'''

	print("Executing Python script",sys.argv[0])
	
    # enter zone file that you want to store in the filter
	zone_file_name = "/root/sftped/10m_test"
	
	try:
		size_of_filter,size_in_KB,size_in_MB,number_of_elements,hash_functions = set_filter_parameters(zone_file_name,int(sys.argv[1]))
	except:
		print("Size of filter not defined. Termination of Python script")
		sys.exit(1)

        hash_functions = 5

	# creation of the Bloom filter instance
	bf = create_bloom_filter(size_of_filter,hash_functions)	
	# store the contents of the zone file in the Bloom filter
	bf,total_items = fill_bloom_filter(zone_file_name,bf)

	query_name = "something_not_contained_in_the_filter"
	time_required = benchmark_bloom_filter(query_name,bf)
	print(time_required)

	return None

if __name__ == "__main__":
    main()
