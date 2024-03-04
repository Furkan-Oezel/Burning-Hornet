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
	ifname := "eth0"
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

	log.Printf("<<<<--------------------------------------------------------->>>>")
	log.Printf("	              Welcome to Furkan's Firewall!")
	log.Printf("	Enjoy your stay and listen on the network interface %s!", ifname)
	log.Printf("<<<<--------------------------------------------------------->>>>")

	// Periodically fetch from Map(bpf map),
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:

			var ip_source_addres uint64
			var lower_ip_boundary uint64
			var upper_ip_boundary uint64
			var config_number uint64
			var crazy_counter uint64

			err := objs.Map.Lookup(uint32(0), &ip_source_addres)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}

			err = objs.Map.Lookup(uint32(1), &lower_ip_boundary)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}

			err = objs.Map.Lookup(uint32(2), &upper_ip_boundary)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}

			err = objs.Map.Lookup(uint32(3), &config_number)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}

			err = objs.Map.Lookup(uint32(4), &crazy_counter)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}

			if config_number == 1 {
				lower_ip := convert_little_to_big(lower_ip_boundary)
				upper_ip := convert_little_to_big(upper_ip_boundary)
				log.Printf("    _________________________________________________________")
				log.Printf("    ip range: %s <-> %s", lower_ip.String(), upper_ip.String())

				log.Printf("    _________________________________________________________")
				log.Printf("    number of accepted packets: %d", crazy_counter)

				source_ip := convert_little_to_big(ip_source_addres)
				log.Printf("    _________________________________________________________")
				log.Printf("    accepted ip : %s", source_ip.String())

				log.Printf("")
			} else {
				log.Printf("    waiting for configuration...")
			}

		case <-stop:
			log.Print("Received signal, exiting...")
			return
		}
	}
}
