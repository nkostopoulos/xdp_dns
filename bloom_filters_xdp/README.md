This folder contains code to produce the Bloom Filters used for experimentation or your own Bloom Filters.  
  
Note that separate calculations and double hashing lead to different Bloom Filters  
  
In case you want to create your own Bloom Filter:  
- Each folder corresponds to a particular method, i.e. separate calculations or double hashing to hash the names of the DNS zone. Both folders include subfolders that correspond to a different number of used hash functions. Currently, the supported number of hash functions is between 3 and 10. Pick a folder based on the method and the desired number of hash functions to use.  
- There is a converter.py Python script. Provide the names included in your DNS zone. Substitute file ntua names with your zone names. Execute the converter.py script. Please remember to change the size of the Bloom Filter based on your needs (https://hur.st/bloomfilter/) and remove the FQDN suffix ".example.com" from the converter.py script.  
- A C code file will be generated. Append this file to the murmurhash.c C program. Go at the end of the C program and append the commands "return 0;" and "}"  
- Compile and run the C program murmurhash.c. The Bloom Filter will be generated in the stdout. Save this output to a file that will hold your Bloom Filter.
- This Bloom Filter file will be provided to the XDP Control Plane Program. This program will fill an eBPF map with the Bloom Filter contents so that the XDP Data Plane Program can differentiate between valid and invalid names.  
- Bloom Filters of our demo zone are provided.  
