package main

import (
	"log"
	"github.com/google/gopacket/pcap"
)

func main(){
	devices, _ := pcap.FindAllDevs()
	for _, device := range devices{
		log.Println(device)
	}
}
