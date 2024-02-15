package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs firewallObjects
	if err := loadFirewallObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}

	// pin map
	mapPath := "/sys/fs/bpf/my_map"
	if err := objs.Map.Pin(mapPath); err != nil {
		log.Fatalf("Error pinning map: %s", err)
	}

	// unpin map when the program stops running
	defer func() {
		if err := os.Remove(mapPath); err != nil {
			log.Printf("Error unpinning map: %s", err)
		}
	}()
	defer objs.Close()

	// set the name of the network interface
	ifname := "wlp0s20f3"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach the "main function" (xdp_filter_ip_range()) of the bpf program to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFilterIpRange,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	log.Printf("Welcome to Furkan's Firewall!")
	log.Printf("Enjoy your stay and listen on the network interface %s!", ifname)

	// Periodically fetch from Map(bpf map),
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:

			var first_entry uint64
			var second_entry uint64
			var third_entry uint64

			err := objs.Map.Lookup(uint32(0), &first_entry)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}

			err = objs.Map.Lookup(uint32(1), &second_entry)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}

			err = objs.Map.Lookup(uint32(2), &third_entry)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}

			if third_entry == 1 {
				log.Printf("Filtering ip source address. Boundaries: 192.168.0.10 - 192.168.0.11")
				log.Printf("ip source address: %b", first_entry)
			} else {
				log.Printf("ip source address:      %b", first_entry)
				log.Printf("ip destination address: %b", second_entry)
			}

		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
