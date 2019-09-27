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

struct bpf_map_def SEC("maps") ip_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") counter_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u64),
	.max_entries = 1,
};


SEC("xdp_ip_filter")
int _xdp_ip_filter(struct xdp_md *ctx) {
  bpf_printk("Starting XDP Program\n");
  // key of the maps
  u32 key = 0;
  // the ip to filter
  u32 *ip;

  // get the ip to filter from the ip_filtered map
  ip = bpf_map_lookup_elem(&ip_map, &key);
  if (!ip){
    return XDP_PASS;
  }

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
  u32 ip_src = iph->saddr;
  u32 ip_dst = iph->daddr;


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
  u16 source_port = udph->source;
  u16 destination_port = udph->dest;
  bpf_printk("Destination port is: %u\n", destination_port);

  // If packet is not DNS request, pass the packet to the TCP/IP Stack
  // Notably, DNS destination port is logged in trace as 13568
  if (destination_port != 13568) {
	  return XDP_PASS;
  }
  // drop the packet if the ip source address is equal to ip
  /*
  if (ip_src == *ip) {
    u64 *filtered_count;
    u64 *counter;
    counter = bpf_map_lookup_elem(&counter_map, &key);
    if (counter) {
      *counter += 1;
    }
    return XDP_DROP;
  }
  return XDP_PASS;
  */

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
  u32 byte = 0; // holds the string characters in every iteration
  u32 upper_16 = 0; // upper digit of the hexadecimal number
  u32 lower_16 = 0;  // lower digit of the hexadecimal number 
  u32 multiplier = 1;
  
  // some variables for the mmh3
  u32 h = 0;
  u32 k = 0;

  #pragma unroll
  for (i = 0; i < 253; i = i + 1) {
	if (name + i + 1 > data_end) {
	       	return XDP_PASS;
	}
	if (name[i] == 0) break;
	byte = name[i];
	upper_16 = byte / 16;
	lower_16 = byte % 16;
	k += lower_16 * multiplier;
	multiplier *= 16;
	k += upper_16 * multiplier;
	multiplier *= 16;
	if (i % 4 == 3) {
		k *= 0xcc9e2d51;
		k = (k << 15) | (k >> 17);
		k *= 0x1b873593;
		h ^= k;
		h = (h << 13) | (h >> 19);
		h = h * 5 + 0xe6546b64;
		multiplier = 1;
		k = 0;
	}
  }

  bpf_printk("%u\n", h);



  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
