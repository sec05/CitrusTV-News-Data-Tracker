package main

import (
	"log"
	"github.com/google/gopacket/pcap"
)

func main(){
	p, _:= pcap.FindAllDevs()
	log.Println(p)
	Parser()
}
