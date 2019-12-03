#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <time.h>
#include "bpf_load.h"
#include <bpf/bpf.h>
#include "bpf_util.h"

int convertBinaryToDecimal(int n);

//static int ifindex = 1; // localhost interface ifindex
static int ifindex = 3;
static __u32 xdp_flags = 0;

// unlink the xdp program and exit
static void int_exit(int sig) {
  printf("stopping\n");
  bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
  exit(0);
}

int main(int argc, char **argv) {
  char *filename="xdp_ip_filter_kern.o";

  // change limits
  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
  if (setrlimit(RLIMIT_MEMLOCK, &r)) {
    perror("setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY)");
    return 1;
  }

  // load the bpf kern file
  if (load_bpf_file(filename)) {
    printf("error %s", bpf_log_buf);
    return 1;
  }

  if (!prog_fd[0]) {
    printf("load_bpf_file: %s\n", strerror(errno));
    return 1;
  }

  // add sig handlers
  signal(SIGINT, int_exit);
  signal(SIGTERM, int_exit);

  __u32 result = 0;
  int i = 0;

  FILE *fptr;

  fptr = fopen("/root/bloom_filters_xdp/5_hashes_new/bloom_filter_5", "r");
  if (fptr == NULL) {
	  printf("Error! Exiting...\n");
	  exit(1);
  }

  int c;
  int index;
  __u8 bf_value;
  int number = 0;
  int decimal = 0;
  int processed_chars = 0;
  char myString[9];
  int times = 0;
  // set the first element of the first map to the ip passed as a parameter
  while ((c = getc(fptr)) != EOF)
  {
	index = processed_chars % 8;
	processed_chars++;
	myString[index] = (char)c;
	if (index == 7) {
		myString[8] = '\0';
		number = atoi(myString);
		decimal = convertBinaryToDecimal(number);
		bf_value = (__u8)decimal;
  		result = bpf_map_update_elem(map_fd[1], &times, &bf_value, BPF_ANY);
		times++;
  		if (result != 0) {
    			fprintf(stderr, "bpf_map_update_elem error %d %s \n", errno, strerror(errno));
    			return 1;
  		}	
	}
  }
  fclose(fptr);

  // link the xdp program to the interface
  if (bpf_set_link_xdp_fd(ifindex, prog_fd[0], xdp_flags) < 0) {
    printf("link set xdp fd failed\n");
    return 1;
  }

  // get the number of cpus
  unsigned int nr_cpus = bpf_num_possible_cpus();
  __u64 values[nr_cpus];
  int j = 0;
  __u32 key = 0;

  
  // "infinite" loop

  for (i=0; i< 1000; i++) {
    // get the values of the second map into values.
    assert(bpf_map_lookup_elem(map_fd[0], &key, values) == 0);
    printf("%d\n", i);
    __u32 sum = 0;
    for (j=0; j < nr_cpus; j++) {
      sum += values[j];
      printf("cpu %d, value = %llu\n", j, values[j]);
    }
    printf("Total is: %u\n", sum);
    printf("\n\n");
    sleep(1);
  }

  //for (;;){ sleep(5); }

  printf("end\n");
  // unlink the xdp program
  bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
  return 0;
}

int convertBinaryToDecimal(int n)
{
	int decimalNumber = 0, i = 0, remainder;
	while (n != 0)
	{
		remainder = n % 10;
		n /= 10;
		decimalNumber += remainder << i;
		++i;
	}
	return decimalNumber;
}
