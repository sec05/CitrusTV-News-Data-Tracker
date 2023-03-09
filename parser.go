package main

import (
	"log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"strconv"
	"time"
)
func Parser()  *string{
	var (
		err      	error
		handle   	*pcap.Handle
		//InetAddr 	string
		SrcIP    	string
		DstIP    	string
		//eth layers.Ethernet
	 	ip4 layers.IPv4
	 	ip6 layers.IPv6
	 	//tcp layers.TCP
	 	//udp layers.UDP
	 	
		dns layers.DNS
	)
	type DnsMsg struct {
		Timestamp       string
		SourceIP        string
		DestinationIP   string
		DnsQuery        string
		DnsAnswer       []string
		DnsAnswerTTL    []string
		NumberOfAnswers string
		DnsResponseCode string
		DnsOpCode       string
	}
	var vlan10 pcap.Interface
	p, _:= pcap.FindAllDevs()
	for i := range p{
		address := p[i].Addresses
		for j := range p[i].Addresses{
			if address[j].IP.String() == "10.10.2.21"{
				vlan10 = p[i]
			}
		}
	}
	handle , err = pcap.OpenLive(vlan10.Name,22,true,pcap.BlockForever)
	log.Print("Listening to "+vlan10.Name+" on ")
	log.Println(handle)
	if err != nil{
		log.Fatalln("Parser recieved an error: "+err.Error())
	}
	defer handle.Close()
	decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &dns)
	decodedLayers := make([]gopacket.LayerType, 0,10)
	for {
		data, _, err := handle.ReadPacketData()
		if err != nil {
			log.Println("Error reading packet data: ", err)
			continue	
		}
	err = decoder.DecodeLayers(data, &decodedLayers)
	for _,t := range decodedLayers{
		switch t{
			case layers.LayerTypeIPv4:
				SrcIP = ip4.SrcIP.String()
				DstIP = ip4.DstIP.String()
			case layers.LayerTypeIPv6:
				SrcIP = ip6.SrcIP.String()
				DstIP = ip6.DstIP.String()
			case layers.LayerTypeDNS:
				dnsOpCode := int(dns.OpCode)
				dnsResponseCode := int(dns.ResponseCode)
				dnsANCount := int(dns.ANCount)
				if (dnsANCount == 0 && dnsResponseCode > 0) || (dnsANCount > 0) {

					log.Println("————————")
					log.Println("    DNS Record Detected")

					for _, dnsQuestion := range dns.Questions {

						t := time.Now()
						timestamp := t.Format(time.RFC3339)

						// Add a document to the index
						d := DnsMsg{Timestamp: timestamp, SourceIP: SrcIP,
							DestinationIP:   DstIP,
							DnsQuery:        string(dnsQuestion.Name),
							DnsOpCode:       strconv.Itoa(dnsOpCode),
							DnsResponseCode: strconv.Itoa(dnsResponseCode),
							NumberOfAnswers: strconv.Itoa(dnsANCount)}
							log.Println("    DNS OpCode: ", strconv.Itoa(int(dns.OpCode)))
							log.Println("    DNS ResponseCode: ", dns.ResponseCode.String())
							log.Println("    DNS # Answers: ", strconv.Itoa(dnsANCount))
							log.Println("    DNS Question: ", string(dnsQuestion.Name))
							log.Println("    DNS Endpoints: ", SrcIP, DstIP)

						if dnsANCount > 0 {

							for _, dnsAnswer := range dns.Answers {
								d.DnsAnswerTTL = append(d.DnsAnswerTTL,strconv.Itoa(int(dnsAnswer.TTL)))
								if dnsAnswer.IP.String() != "<nil>" {
									log.Println("    DNS Answer: ", dnsAnswer.IP.String())
									d.DnsAnswer = append(d.DnsAnswer, dnsAnswer.IP.String())
								}
							}

							}	}
		}
	}
}
	}
}