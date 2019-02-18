#!/usr/bin/python
#
# xdp_drop_count.py Drop incoming packets on XDP layer and count for which
#                   protocol type
#
# Copyright (c) 2016 PLUMgrid
# Copyright (c) 2016 Jan Ruth
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import pyroute2
import time
import sys

flags = 0
def usage():
    print("Usage: {0} [-S] <ifdev>".format(sys.argv[0]))
    print("       -S: use skb mode\n")
    print("e.g.: {0} eth0\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) < 2 or len(sys.argv) > 3:
    usage()

if len(sys.argv) == 2:
    device = sys.argv[1]

if len(sys.argv) == 3:
    if "-S" in sys.argv:
        # XDP_FLAGS_SKB_MODE
        flags |= 2 << 0

    if "-S" == sys.argv[1]:
        device = sys.argv[2]
    else:
        device = sys.argv[1]

mode = BPF.XDP
#mode = BPF.SCHED_CLS

if mode == BPF.XDP:
    ret = "XDP_DROP"
    ctxtype = "xdp_md"
else:
    ret = "TC_ACT_SHOT"
    ctxtype = "__sk_buff"

# load BPF program
b = BPF(text = """
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <uapi/linux/in.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/ptrace.h>


struct dns_hdr_t {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} BPF_PACKET_HEADER;


BPF_TABLE("percpu_array", uint32_t, long, dropcnt, 10000);

static inline int get_srcip(void *data, u64 nh_off, void *data_end) {

    struct iphdr *iph = data + nh_off;
    if ((void*)&iph[1] > data_end)
        return 0;
    return htonl(iph->saddr);
}

static inline int get_dstip(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end)
        return 0;
    return htonl(iph->daddr);
}

static inline int get_src_port(void *data, u64 nh_off, u64 udp_off, void *data_end) {
    struct udphdr *udph = data + nh_off + udp_off;

    if ((void*)&udph[1] > data_end)
        return 0;
    return ntohs(udph->source);
}

static inline int get_dst_port(void *data, u64 nh_off, u64 udp_off, void *data_end) {
    
    struct udphdr *udph = data + nh_off + udp_off;
    if ((void*)&udph[1] > data_end)
        return 0;
    return ntohs(udph->dest);
}

static inline int get_dns_id(void *data, u64 nh_off, u64 udp_off, u64 dns_off, void *data_end) {
    struct dns_hdr_t *dnsh = data + nh_off + udp_off + dns_off;
    if ((void*)&dnsh[1] > data_end)
	return 0;
    return ntohs(dnsh->id);
}

static inline char get_question_name(void *data, u64 nh_off, u64 udp_off, u64 dns_off, u64 payload_off, u64 position, void *data_end) {
    char *name = data + nh_off + udp_off + dns_off + payload_off;
    if ((void*)&name[position + 1] > data_end)
	return 0;
    return *(name + position);
}

int xdp_prog1(struct CTXTYPE *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;

    int rc = RETURNCODE; // let pass XDP_PASS or redirect to tx via XDP_TX
    long *value;
    uint16_t h_proto;
    uint8_t protocol;
    uint64_t nh_off = 0;
    uint64_t udp_off = 0;
    uint64_t dns_off = 0;
    uint64_t payload_off = 0;
    uint32_t src_ip;
    uint32_t dest_ip;
    uint64_t src_port;
    uint64_t dst_port;
    uint32_t index;
    uint64_t dns_id;

    // get the size of the ethernet header. Store it it nh_off
    nh_off = sizeof(*eth); 

    // test boundaries
    if (data + nh_off  > data_end)
        return rc;

    // ethernet header protocol
    h_proto = eth->h_proto;

    // check if the packet contains IP header
    if (h_proto == htons(ETH_P_IP))
    {
	  // get source ip and destination ip
	  src_ip = get_srcip(data, nh_off, data_end);
          dest_ip = get_dstip(data, nh_off, data_end);
	  
          // size of ip header
          struct iphdr *iph = data + nh_off;
          udp_off = sizeof(*iph);

          // test boundaries
	  if (data + nh_off + udp_off > data_end)
	      return rc;

          // what is the transport layer protocol?
	  protocol = iph->protocol;
	
          // check if the transport layer protocol is UDP
	  if (protocol == 17)
	  {
    		struct udphdr *udph = data + nh_off + udp_off;
                src_port = get_src_port(data, nh_off, udp_off, data_end);
	        dst_port = get_dst_port(data, nh_off, udp_off, data_end);

		dns_off = sizeof(*udph);
		if (data + nh_off + udp_off + dns_off > data_end)
		    return rc;
		
		if (dst_port == 53)
		{
			struct dns_hdr_t *dnsh = data + nh_off + udp_off + dns_off;
			payload_off = sizeof(*dnsh);
			if (data + nh_off + udp_off + dns_off + payload_off > data_end)
			    return rc;
	
			uint64_t position = 0;
			char letter = 0; 
			char word[30];
			uint32_t indicator = -1;

			word[0] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 0, data_end);
			indicator = word[0];
			

			if (indicator != 0)
			{
				index = 0;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[0];
				word[1] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 1, data_end);
				indicator = word[1];
			}
	
			if (indicator != 0)
			{
				index = 1;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[1];
				word[2] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 2, data_end);
				indicator = word[2];
			}

			if (indicator != 0)
			{
				index = 2;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[2];
				word[3] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 3, data_end);
				indicator = word[3];
			}
			

			if (indicator != 0)
			{
				index = 3;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[3];
				word[4] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 4, data_end);
				indicator = word[4];
			}

			if (indicator != 0)
			{
				index = 4;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[4];
				word[5] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 5, data_end);
				indicator = word[5];
			}

			if (indicator != 0)
			{
				index = 5;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[5];
				word[6] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 6, data_end);
				indicator = word[6];
			}

			if (indicator != 0)
			{
				index = 6;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[6];
				word[7] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 7, data_end);
				indicator = word[7];
			}


			if (indicator != 0)
			{
				index = 7;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[7];
				word[8] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 8, data_end);
				indicator = word[8];
			}

			if (indicator != 0)
			{
				index = 8;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[8];
				word[9] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 9, data_end);
				indicator = word[9];
			}

			if (indicator != 0)
			{
				index = 9;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[9];
				word[10] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 10, data_end);
				indicator = word[10];
			}

			if (indicator != 0)
			{
				index = 10;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[10];
				word[11] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 11, data_end);
				indicator = word[11];
			}


			if (indicator != 0)
			{
				index = 11;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[11];
				word[12] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 12, data_end);
				indicator = word[12];
			}


			if (indicator != 0)
			{
				index = 12;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[12];
				word[13] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 13, data_end);
				indicator = word[13];
			}


			if (indicator != 0)
			{
				index = 13;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[13];
				word[14] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 14, data_end);
				indicator = word[14];
			}


			if (indicator != 0)
			{
				index = 14;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[14];
				word[15] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 15, data_end);
				indicator = word[15];
			}


			if (indicator != 0)
			{
				index = 15;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[15];
				word[16] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 16, data_end);
				indicator = word[16];
			}
			if (indicator != 0)
			{
				index = 16;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[16];
				word[17] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 17, data_end);
				indicator = word[17];
			}


			if (indicator != 0)
			{
				index = 17;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[17];
				word[18] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 18, data_end);
				indicator = word[18];
			}

			if (indicator != 0)
			{
				index = 18;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[18];
				word[19] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 19, data_end);
				indicator = word[19];
			}

			if (indicator != 0)
			{
				index = 19;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[19];
				word[20] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 20, data_end);
				indicator = word[20];
			}

			if (indicator != 0)
			{
				index = 20;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[20];
				word[21] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 21, data_end);
				indicator = word[21];
			}

			if (indicator != 0)
			{
				index = 21;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[21];
				word[22] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 22, data_end);
				indicator = word[22];
			}

			if (indicator != 0)
			{
				index = 22;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[22];
				word[23] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 23, data_end);
				indicator = word[23];
			}

			if (indicator != 0)
			{
				index = 23;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[23];
				word[24] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 24, data_end);
				indicator = word[24];
			}

			if (indicator != 0)
			{
				index = 24;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[24];
				word[25] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 25, data_end);
				indicator = word[25];
			}

			if (indicator != 0)
			{
				index = 25;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[25];
				word[26] = get_question_name(data, nh_off, udp_off, dns_off, payload_off, 26, data_end);
				indicator = word[26];
			}

			if (indicator != 0)
			{
				index = 26;
				value = dropcnt.lookup(&index);
				if(value)
					*value = word[26];
			}

	  		//if (*value == dest_ip)
			//	return XDP_PASS;        

		}  
	}
    }
    
}
""", cflags=["-w", "-DRETURNCODE=%s" % ret, "-DCTXTYPE=%s" % ctxtype])

fn = b.load_func("xdp_prog1", mode)

if mode == BPF.XDP:
    b.attach_xdp(device, fn, flags)
else:
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    idx = ipdb.interfaces[device].index
    ip.tc("add", "clsact", idx)
    ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
          parent="ffff:fff2", classid=1, direct_action=True)

dropcnt = b.get_table("dropcnt")

prev = [0] * 256
print("Printing drops per IP protocol-number, hit CTRL+C to stop")
while 1:
    name = str()
    flag = True
    try:
        for k in dropcnt.keys():
	    if flag == True:
		flag = False
		continue
            val = dropcnt.sum(k).value
            i = k.value
	    if val:
            	if val > 30:
			name = name + chr(val)
		else:
			name = name + "."
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break;
    print(name)

if mode == BPF.XDP:
    b.remove_xdp(device, flags)
else:
    ip.tc("del", "clsact", idx)
    ipdb.release()
