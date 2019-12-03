import socket
import time
import bloom_filter
import binascii

def handle_name(data):
    length = int(binascii.hexlify(data[12]),16)
    limit = 13 + length
    name = data[13:limit]
    name = name.decode('UTF-8')
    return name

if __name__ == "__main__":
    zone_file_name = "./ntua_names"
    size_of_filter = 119771
    hash_functions = 9
    bf = bloom_filter.create_bloom_filter(size_of_filter,hash_functions)
    bf,_ = bloom_filter.fill_bloom_filter(zone_file_name,bf)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    host = '192.168.1.1'
    port = 53
    size = 100
    s.bind((host, port))
    
    print("GO ON")
    
    while 1:
        data, addr = s.recvfrom(size)
        name = handle_name(data)
        decision = bf.query(name)
        if decision == True:
            s.sendto(data, ('192.168.1.2', 53))
