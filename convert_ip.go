package main

import (
	"encoding/binary"
	"net"
)

// convert from host byte order to network byte order
func convert_little_to_big(ip uint64) net.IP {
	ip_ore := uint32(ip)

	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, ip_ore)

	converted_ip := binary.BigEndian.Uint32(bytes)

	bytes_ip := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes_ip, converted_ip)

	return net.IP(bytes_ip)
}
