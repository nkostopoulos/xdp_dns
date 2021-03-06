#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/dns.h>
#include "bpf_helpers.h"

#define bpf_printk(fmt, ...)                    \
({                              \
           char ____fmt[] = fmt;                \
           bpf_trace_printk(____fmt, sizeof(____fmt),   \
                ##__VA_ARGS__);         \
})

struct bpf_map_def SEC("maps") counter_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u64),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") bloom_filter_map = {
	.type	     = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u8),
	.max_entries = 15577, 
};

SEC("xdp_ip_filter")
int _xdp_ip_filter(struct xdp_md *ctx) {

  void *data_end = (void *)(long)ctx->data_end;
  void *data     = (void *)(long)ctx->data;
  struct ethhdr *eth = data;

  // check packet size
  if (eth + 1 > data_end) {
    return XDP_PASS;
  }

  // check if the packet is an IP packet
  if(ntohs(eth->h_proto) != ETH_P_IP) {
    return XDP_PASS;
  }

  // get the source address of the packet
  struct iphdr *iph = data + sizeof(struct ethhdr);
  if (iph + 1 > data_end) {
    return XDP_PASS;
  }

  // Get the protocol number from the IP header
  u8 ip_proto = iph->protocol;

  // UDP protocol number is 17
  // If the packet is not UDP, pass the packet to the TCP/IP Stack
  if (ip_proto != 17) {
     return XDP_PASS;
  }

  // Struct for UDP header
  struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  if (udph + 1 > data_end) {
	  return XDP_PASS;
  }

  // Get source and destination port of UDP segment
  //u16 source_port = udph->source;
  u16 destination_port = udph->dest;

  // If packet is not DNS request, pass the packet to the TCP/IP Stack
  // Notably, DNS destination port is logged in trace as 13568
  if (destination_port != 13568) {
	  return XDP_PASS;
  }

  // Struct for DNS header
  struct dnshdr *dnsh = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
  if (dnsh + 1 > data_end) {
	  return XDP_PASS;
  }

  // Reach the DNS Payload
  char* name = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) - 1;
  if (name + 1 > data_end) {
	  return XDP_PASS;
  }

  u32 i = 0;
  u32 byte = 0; // holds the last character in every iteration
  u32 prev_byte = 0; // holds the previous from the last character in the iteration
  u32 prev_prev_byte = 0; // holds the third character from the end
  u32 upper_16 = 0; // upper digit of the hexadecimal number
  u32 lower_16 = 0;  // lower digit of the hexadecimal number 
  u32 multiplier = 1; // although mmh3 works in chunks of 4, multiplier helps make it in steps of 1
  
  // variables that will hold the hashes of the string
  u32 h1 = 0;
  u32 h2 = 1;
  u32 h3 = 2;
  u32 h4 = 3;
  u32 h5 = 4;
  u32 h6 = 5;
  u32 h7 = 6;
  u32 k = 0;

  #pragma unroll
  for (i = 0; i < 46; i = i + 1) {
	if (name + i + 1 > data_end) {
	       	return XDP_PASS;
	}
	if (name[i] == 0) break;
	prev_prev_byte = prev_byte;
	prev_byte = byte;
	byte = name[i];
	upper_16 = byte / 16;
	lower_16 = byte % 16;
	k += lower_16 * multiplier;
	multiplier *= 16;
	k += upper_16 * multiplier;
	multiplier *= 16;
	// mmh3 works in chunks of 4
	if (i % 4 == 3) { 
		k *= 0xcc9e2d51;
		k = (k << 15) | (k >> 17);
		k *= 0x1b873593;
		h1 ^= k;
		h2 ^= k;
		h3 ^= k;
		h4 ^= k;
		h5 ^= k;
		h6 ^= k;
		h7 ^= k;
		h1 = (h1 << 13) | (h1 >> 19);
		h2 = (h2 << 13) | (h2 >> 19);
		h3 = (h3 << 13) | (h3 >> 19);
		h4 = (h4 << 13) | (h4 >> 19);
		h5 = (h5 << 13) | (h5 >> 19);
		h6 = (h6 << 13) | (h6 >> 19);
		h7 = (h7 << 13) | (h7 >> 19);
		h1 = h1 * 5 + 0xe6546b64;
		h2 = h2 * 5 + 0xe6546b64;
		h3 = h3 * 5 + 0xe6546b64;
		h4 = h4 * 5 + 0xe6546b64;
		h5 = h5 * 5 + 0xe6546b64;
		h6 = h6 * 5 + 0xe6546b64;
		h7 = h7 * 5 + 0xe6546b64;
		multiplier = 1;
		k = 0;
	}
  }

  // Deal with the remaining characters
  k = 0;
  u32 remains = i % 4;
  u8 tail0 = 0;
  u8 tail1 = 0;
  u8 tail2 = 0;

  if (remains == 1) {
	  tail0 = byte;
  } else if (remains == 2) {
	  tail1 = byte;
	  tail0 = prev_byte;
  } else if (remains == 3) {
	  tail2 = byte;
	  tail1 = prev_byte;
	  tail0 = prev_prev_byte;
  }

  if (remains == 3) {
	  k ^= (tail2 << 16);
	  remains = remains - 1;
  }
  if (remains == 2) {
	  k ^= (tail1 << 8);
	  remains = remains - 1;
  }
  if (remains == 1) {
	  k ^= tail0;
	  k *=0xcc9e2d51;
	  k = (k << 15) | (k >> 17);
	  k *= 0x1b873593;
	  h1 ^= k;
	  h2 ^= k;
	  h3 ^= k;
	  h4 ^= k;
	  h5 ^= k;
	  h6 ^= k;
	  h7 ^= k;
  }

  h1 ^= i;
  h1 ^= (h1 >> 16);
  h1 *= 0x85ebca6b;
  h1 ^= (h1 >> 13);
  h1 *= 0xc2b2ae35;
  h1 ^= (h1 >> 16);
  u32 hash1 = h1 % 124616;
  u32 index1 = hash1 / 8;
  u32 mod1 = (hash1 % 8) + 1;
  u8 *byte1 = bpf_map_lookup_elem(&bloom_filter_map, &index1);
  if (!byte1) return XDP_PASS;
  u8 char1 = *byte1;
  char1 >>= (8 - mod1);
  char1 &= 0x01;
  if (char1 == 0) return XDP_DROP;

  h2 ^= i;
  h2 ^= (h2 >> 16);
  h2 *= 0x85ebca6b;
  h2 ^= (h2 >> 13);
  h2 *= 0xc2b2ae35;
  h2 ^= (h2 >> 16);
  u32 hash2 = h2 % 124616;
  u32 index2 = hash2 / 8;
  u32 mod2 = (hash2 % 8) + 1;
  u8 *byte2 = bpf_map_lookup_elem(&bloom_filter_map, &index2);
  if (!byte2) return XDP_PASS;
  u8 char2 = *byte2;
  char2 >>= (8 - mod2);
  char2 &= 0x01;
  if (char2 == 0) return XDP_DROP;

  h3 ^= i;
  h3 ^= (h3 >> 16);
  h3 *= 0x85ebca6b;
  h3 ^= (h3 >> 13);
  h3 *= 0xc2b2ae35;
  h3 ^= (h3 >> 16);
  u32 hash3 = h3 % 124616;
  u32 index3 = hash3 / 8;
  u32 mod3 = (hash3 % 8) + 1;
  u8 *byte3 = bpf_map_lookup_elem(&bloom_filter_map, &index3);
  if (!byte3) return XDP_PASS;
  u8 char3 = *byte3;
  char3 >>= (8 - mod3);
  char3 &= 0x01;
  if (char3 == 0) return XDP_DROP;

  h4 ^= i;
  h4 ^= (h4 >> 16);
  h4 *= 0x85ebca6b;
  h4 ^= (h4 >> 13);
  h4 *= 0xc2b2ae35;
  h4 ^= (h4 >> 16);
  u32 hash4 = h4 % 124616;
  u32 index4 = hash4 / 8;
  u32 mod4 = (hash4 % 8) + 1;
  u8 *byte4 = bpf_map_lookup_elem(&bloom_filter_map, &index4);
  if (!byte4) return XDP_PASS;
  u8 char4 = *byte4;
  char4 >>= (8 - mod4);
  char4 &= 0x01;
  if (char4 == 0) return XDP_DROP;

  h5 ^= i;
  h5 ^= (h5 >> 16);
  h5 *= 0x85ebca6b;
  h5 ^= (h5 >> 13);
  h5 *= 0xc2b2ae35;
  h5 ^= (h5 >> 16);
  u32 hash5 = h5 % 124616;
  u32 index5 = hash5 / 8;
  u32 mod5 = (hash5 % 8) + 1;
  u8 *byte5 = bpf_map_lookup_elem(&bloom_filter_map, &index5);
  if (!byte5) return XDP_PASS;
  u8 char5 = *byte5;
  char5 >>= (8 - mod5);
  char5 &= 0x01;
  if (char5 == 0) return XDP_DROP;

  h6 ^= i;
  h6 ^= (h6 >> 16);
  h6 *= 0x85ebca6b;
  h6 ^= (h6 >> 13);
  h6 *= 0xc2b2ae35;
  h6 ^= (h6 >> 16);
  u32 hash6 = h6 % 124616;
  u32 index6 = hash6 / 8;
  u32 mod6 = (hash6 % 8) + 1;
  u8 *byte6 = bpf_map_lookup_elem(&bloom_filter_map, &index6);
  if (!byte6) return XDP_PASS;
  u8 char6 = *byte6;
  char6 >>= (8 - mod6);
  char6 &= 0x01;
  if (char6 == 0) return XDP_DROP;

  h7 ^= i;
  h7 ^= (h7 >> 16);
  h7 *= 0x85ebca6b;
  h7 ^= (h7 >> 13);
  h7 *= 0xc2b2ae35;
  h7 ^= (h7 >> 16);
  u32 hash7 = h7 % 124616;
  u32 index7 = hash7 / 8;
  u32 mod7 = (hash7 % 8) + 1;
  u8 *byte7 = bpf_map_lookup_elem(&bloom_filter_map, &index7);
  if (!byte7) return XDP_PASS;
  u8 char7 = *byte7;
  char7 >>= (8 - mod7);
  char7 &= 0x01;
  if (char7 == 0) return XDP_DROP;

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
