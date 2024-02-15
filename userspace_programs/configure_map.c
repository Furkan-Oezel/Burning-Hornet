// how to compile this program: gcc configure_map.c -o configure_map -lbpf -lelf

#include <stdio.h>
// include userspace API map helpers
#include <bpf/bpf.h>
// include close()
#include <unistd.h>

int main() {
  int map_file_descriptor;
  int ret;
  __u32 key = 0;
  __u64 value;

  // open map
  map_file_descriptor = bpf_obj_get("/sys/fs/bpf/my_map");
  if (map_file_descriptor < 0) {
    perror("Failed to open BPF map");
    return 1;
  }

  // look at the map at index=key and write the value of that entry into the
  // variable value
  ret = bpf_map_lookup_elem(map_file_descriptor, &key, &value);
  if (ret < 0) {
    perror("Failed to read from BPF map");
    close(map_file_descriptor);
    return 1;
  }
  printf("value: %llu\n", value);

  value = 1;
  // update the map entry with the new value
  ret = bpf_map_update_elem(map_file_descriptor, &key, &value, BPF_ANY);
  if (ret < 0) {
    perror("Failed to update BPF map");
    close(map_file_descriptor);
    return 1;
  }
  printf("updated value: %llu\n", value);

  // close map
  close(map_file_descriptor);
  return 0;
}
