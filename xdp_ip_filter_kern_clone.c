#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
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
  // key of the maps
  u32 key = 0;
  // the ip to filter
  u32 *ip;

  bpf_printk("starting xdp ip filter\n");

  // get the ip to filter from the ip_filtered map
  ip = bpf_map_lookup_elem(&ip_map, &key);
  if (!ip){
    return XDP_PASS;
  }

  bpf_printk("the ip address to filter is %u\n", ip);

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
  bpf_printk("source ip address is %u\n", ip_src);

  // drop the packet if the ip source address is equal to ip
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
}

char _license[] SEC("license") = "GPL";
