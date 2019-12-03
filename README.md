# xdp_dns
This is the repository related to the following paper: "Leveraging on the XDP Framework for the Efficient Mitigation of Water Torture Attacks within Authoritative DNS Servers" submitted in IEEE NetSoft 2020, Ghent, Belgium.

Description:
In this paper we relied on the eXpress Data Path (XDP) framework to efficiently mitigate Water Torture attacks at the NIC driver level of Authoritative DNS Servers. Our Deep Packet Inspection approach may benefit DNS Administrators who wish to mitigate such attacks within their DNS infrastructure and avoid the latency overhead and additional costs of outsourcing mitigation to external cloud services. XDP does not depend on specialized hardware to work contrary to P4, DPDK, etc. and our approach does not blacklist entire domain suffices. We differentiate between valid and invalid DNS requests using Bloom Filters. Bloom Filters map DNS zone contents in memory efficient manner. These probabilistic data structures are free of false negatives and thus, all legitimate requests are forwarded for name resolution.

- Separate Calculations: We hash received DNS names using separate Mmh3 calculations
- Double Hashing: We hash received DNS names using Double Hashing for better performance. More information available in S. Tarkoma et al., "Theory and Practice of Bloom Filters for Distributed Systems", IEEE Communications Surveys & Tutorials, Volume 14, Issue 1, pp. 131-155, 1st Quarter 2012
- Traces: a Google Drive link to the Legitimate and Water Torture Traces that we used for experimentation.
- Bloom Filters XDP: Contains Bloom Filters used in our experimentation and guidelines on how to create your own. 
- User Space Filtering: a User Space utility introduced in our previous work "A Privacy-Preserving Schema for the Detection and Collaborative Mitigation of DNS Water Torture Attacks in Cloud Infrastructures" submitted and presented in IEEE CloudNet 2019. A link to the presentation is available from here: http://www.netmode.ntua.gr/Presentations/CloudNet_nkostopoulos.pptx

Useful Links:
https://mcorbin.fr/pages/xdp-introduction/: A very useful and well-written tutorial that provides installation instructions and a basic XDP program. We customized this code to build our programs.
https://github.com/jwerle/murmurhash.c/blob/master/murmurhash.c: Murmurhash3 implementation. Mmh3 hashes in chucks of 4-bytes. We customized this approach to hash DNS names as the FQDN is parsed. This is useful to reduce the number of loops that need to be unrolled in XDP.
https://github.com/matthewbentley/ebpf-flowradar: An implementation that uses XDP and Bloom Filters to handle Layer 2-4 packet header information. Our approach performs Deep Packet Inspection on DNS requests (Layer 7).
https://en.wikipedia.org/wiki/Bloom_filter: Bloom Filters, Wikipedia Article
