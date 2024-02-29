// how to compile this program: gcc configure_map.c -o configure_map -lbpf -lelf

#include <stdio.h>
// include userspace API map helpers
#include <bpf/bpf.h>
// include close()
#include <unistd.h>
// add functions for network byte order conversions (htonl(), htons(), ntohl(), ntohs())
#include <netinet/in.h>

#define I_WANT_TO_FILTER 1
#define KEY_LOWER_IP_BOUDARY 1
#define KEY_UPPER_IP_BOUNDARY 2
#define KEY_CONFIG_NUMBER 3

int main()
{
  int map_file_descriptor;
  int ret;
  __u32 key;
  __u64 value;

  // open map
  map_file_descriptor = bpf_obj_get("/sys/fs/bpf/my_map");
  if (map_file_descriptor < 0)
  {
    perror("Failed to open BPF map");
    return 1;
  }

  if (I_WANT_TO_FILTER)
  {
    key = KEY_CONFIG_NUMBER;
    value = 1;
    ret = bpf_map_update_elem(map_file_descriptor, &key, &value, BPF_ANY);
    if (ret < 0)
    {
      perror("Failed to update BPF map");
      close(map_file_descriptor);
      return 1;
    }
  }

  key = KEY_LOWER_IP_BOUDARY;
  value = htonl(0xC0A8000A); // 192.168.0.10
  ret = bpf_map_update_elem(map_file_descriptor, &key, &value, BPF_ANY);
  if (ret < 0)
  {
    perror("Failed to update BPF map");
    close(map_file_descriptor);
    return 1;
  }

  key = KEY_UPPER_IP_BOUNDARY;
  value = htonl(0xC0A8000B); // 192.168.0.11
  ret = bpf_map_update_elem(map_file_descriptor, &key, &value, BPF_ANY);
  if (ret < 0)
  {
    perror("Failed to update BPF map");
    close(map_file_descriptor);
    return 1;
  }

  printf("OK\n");
  close(map_file_descriptor);
  return 0;
}
