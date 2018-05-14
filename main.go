package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
	"github.com/zmap/zdns/modules/miekg"
)
import _ "net/http/pprof"
import "net/http"

type FlowIdentifier struct {
	net, transport gopacket.Flow
}

type manager struct {
	lock          sync.RWMutex
	connectionMap map[FlowIdentifier]*Connection
}

func handle_packets(streams *manager, handle *pcap.Handle, need_eth bool, packetSource *gopacket.PacketSource, closeHandler chan bool) {
	for {
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			//log.Println("PCAP Error:", err)
			if err.Error() == "Read Error" {
				closeHandler <- true
				return
			}
			select {
			case <-closeHandler:
				log.Printf("Exiting packet handler\n")
				return
			default:
				break
			}
			continue
		}
		//log.Printf("%s\n\n%s", packet.String(), packet.Dump())

		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
			// not what we want
			continue
		}

		tcp := packet.TransportLayer().(*layers.TCP)
		netFlow := packet.NetworkLayer().NetworkFlow()
		tcpFlow := packet.TransportLayer().TransportFlow()
		k := FlowIdentifier{netFlow, tcpFlow}
		//log.Printf("Got packet for flow %s, %s", k.net.String(), k.transport.String())
		// do we have anything for this connection???
		streams.lock.RLock()
		conn := streams.connectionMap[k]

		if conn == nil {
			streams.lock.RUnlock()
			// reset it
			outputBuffer := gopacket.NewSerializeBuffer()
			serializeOptions := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}

			var eth layers.Ethernet
			if need_eth {
				incoming_eth := packet.LinkLayer().(*layers.Ethernet)
				eth = layers.Ethernet{SrcMAC: incoming_eth.DstMAC, DstMAC: incoming_eth.SrcMAC, EthernetType: layers.EthernetTypeIPv4}
			}
			incoming_ipv4 := packet.NetworkLayer().(*layers.IPv4)
			ip := layers.IPv4{
				SrcIP:    incoming_ipv4.DstIP,
				DstIP:    incoming_ipv4.SrcIP,
				TTL:      64,
				Version:  4,
				Protocol: layers.IPProtocolTCP,
			}
			outgoing_tcp := layers.TCP{
				SrcPort: tcp.DstPort,
				DstPort: tcp.SrcPort,
				Seq:     tcp.Ack,
				ACK:     false,
				RST:     true,
				Window:  0,
			}
			tcp.SetNetworkLayerForChecksum(&ip)
			if need_eth {
				gopacket.SerializeLayers(outputBuffer, serializeOptions, &eth, &ip, &outgoing_tcp)
			} else {
				gopacket.SerializeLayers(outputBuffer, serializeOptions, &ip, &outgoing_tcp)
			}

			handle.WritePacketData(outputBuffer.Bytes())
		} else {
			// notfiy conn of packet
			if len(conn.PacketChannel) < MAX_PACKETS {
				conn.PacketChannel <- tcp
			}
			streams.lock.RUnlock()
		}
	}
}

type Result struct {
	Error string       `json:"error"`
	Dns   miekg.Result `json:"dns"`
	Conn  *Connection  `json:"connection"`
}

func resolve_dns(host string, source_ip net.IP, timeout time.Duration, dnsserver []string) (*miekg.Result, error) {

	c := dns.Client{Timeout: timeout, Dialer: &net.Dialer{LocalAddr: &net.UDPAddr{IP: source_ip, Port: 0}}}
	// let it look like a dig query
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true
	choice := rand.Intn(len(dnsserver))
	m.AuthenticatedData = true
	m.SetEdns0(4096, false)
	r, _, err := c.Exchange(&m, dnsserver[choice])
	if err != nil {
		return nil, err
	}

	res := miekg.Result{}

	res.Flags.Response = r.Response
	res.Flags.Opcode = r.Opcode
	res.Flags.Authoritative = r.Authoritative
	res.Flags.Truncated = r.Truncated
	res.Flags.RecursionDesired = r.RecursionDesired
	res.Flags.RecursionAvailable = r.RecursionAvailable
	res.Flags.Authenticated = r.AuthenticatedData
	res.Flags.CheckingDisabled = r.CheckingDisabled
	res.Flags.ErrorCode = r.Rcode

	for _, ans := range r.Answer {
		inner := miekg.ParseAnswer(ans)
		if inner != nil {
			res.Answers = append(res.Answers, inner)
		}
	}
	for _, ans := range r.Extra {
		inner := miekg.ParseAnswer(ans)
		if inner != nil {
			res.Additional = append(res.Additional, inner)
		}
	}
	for _, ans := range r.Ns {
		inner := miekg.ParseAnswer(ans)
		if inner != nil {
			res.Authorities = append(res.Authorities, inner)
		}
	}
	return &res, nil
}

func measure_iw(streams *manager, handle chan []byte, src_ip net.IP, dst_port uint16, use_vpn bool, dev string, gateway string, src_mac string, timeout int, inline map[string]interface{}, result_chan chan map[string]interface{}) {

	res := Result{}

	// check if there is some DNS in an already existing results data
	if inline["result"] != nil {
		blob, err := json.Marshal(inline["result"])
		if err != nil {
			res.Error = "Existing result cannot be marshalled"
			inline["result"] = res
			result_chan <- inline
			return
		}
		err = json.Unmarshal(blob, &res)
		if err != nil {
			res.Error = "Existing result cannot be unmarshalled to proper result"
			inline["result"] = res
			result_chan <- inline
			return
		}
		res.Error = ""
		res.Conn = nil
	}
	query_url, err := url.Parse(inline["url"].(string))
	if err != nil {
		res.Error = err.Error()
		inline["result"] = res
		result_chan <- inline
		return
	}
	mss := uint16(inline["mss"].(float64))
	dst_ip_str := ""
	// try to get an ip from existing result data
	for _, ans := range res.Dns.Answers {
		if ans.(map[string]interface{})["type"] == "A" {
			dst_ip_str = ans.(map[string]interface{})["answer"].(string)
			break
		}

	}

	// if this did not yield anything resolve again
	if dst_ip_str == "" {
		log.Printf("Resolving %s\n", query_url.Hostname())
		var dns_answer *miekg.Result
		var err error
		for i := 0; i < 5; i++ {
			dns_answer, err = resolve_dns(query_url.Hostname(), src_ip, time.Duration(5)*time.Second, []string{"8.8.8.8:53", "8.8.4.4:53"})
			if err == nil {
				break
			}

		}
		if err != nil {
			if strings.Contains(err.Error(), "i/o timeout") {
				res.Error = "DNS timeout"
			} else {
				res.Error = err.Error()
			}
			inline["result"] = res
			result_chan <- inline
			return
		}
		res.Dns = *dns_answer

		for _, ans := range dns_answer.Answers {
			if ans.(miekg.Answer).Type == "A" {
				dst_ip_str = ans.(miekg.Answer).Answer
				break
			}
		}
	}
	if dst_ip_str == "" {
		res.Error = "No A record found"
		inline["result"] = res
		result_chan <- inline
		return
	}
	dst_ip := net.ParseIP(dst_ip_str)
	if dst_ip == nil {
		res.Error = "Invalid IP in A record"
		inline["result"] = res
		result_chan <- inline
		return
	}
	// todo this should be unique per dst_ip
	src_port := rand.Intn(65535-1024) + 1024
	var conn *Connection
	if !use_vpn {
		conn, err = PrepareLocalConnection(handle, dst_ip, src_ip, uint16(src_port), uint16(dst_port), src_mac, gateway, mss, time.Duration(timeout)*time.Second)
	} else {
		conn, err = PrepareVPNConnection(handle, dst_ip, src_ip, uint16(src_port), uint16(dst_port), mss, time.Duration(timeout)*time.Second)
	}
	if err != nil {
		res.Error = err.Error()
		inline["result"] = res
		result_chan <- inline
		return
	}
	res.Conn = conn
	// append conn to dict
	streams.lock.Lock()
	streams.connectionMap[conn.Flow] = conn
	streams.lock.Unlock()

	defer func() {
		streams.lock.Lock()
		delete(streams.connectionMap, conn.Flow)
		close(conn.PacketChannel)
		streams.lock.Unlock()
	}()

	go conn.receivePacket()
	err = conn.Connect()
	if err != nil {
		res.Error = err.Error()
		inline["result"] = res
		result_chan <- inline
		return
	}
	var http_req string
	if inline["referer"] != nil {
		http_req = fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36\r\nConnection: close\r\nReferer: %s\r\n\r\n", query_url.RequestURI(), query_url.Hostname(), inline["referer"].(string))
	} else {
		http_req = fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36\r\nConnection: close\r\n\r\n", query_url.RequestURI(), query_url.Hostname())
	}
	err = conn.sendData([]byte(http_req))
	if err != nil {
		res.Error = err.Error()
		inline["result"] = res
		result_chan <- inline
		conn.kill()
		return
	}
	err = conn.consumeAndLogUntilRetransmission()
	if err != nil {
		res.Error = err.Error()
		inline["result"] = res
		result_chan <- inline
		conn.kill()
		return
	}
	conn.acknowledgeData()
	err = conn.waitForNewData()
	if err != nil {
		res.Error = err.Error()
		inline["result"] = res
		result_chan <- inline
		conn.kill()
		return
	}
	conn.kill()
	inline["result"] = res
	result_chan <- inline
	return
}

func line_from_stdin(stdin_chan chan<- string, running_chan chan<- bool) {
	fscanner := bufio.NewScanner(os.Stdin)
	maxsize := 64 * 1024 * 1024
	inbuff := make([]byte, maxsize, maxsize)
	fscanner.Buffer(inbuff, maxsize)
	for fscanner.Scan() {
		running_chan <- true
		stdin_chan <- fscanner.Text()
	}
	close(stdin_chan)
}

func send_pkts(send_handle *pcap.Handle, send_chan <-chan []byte) {
	time_to_sleep := 1.0 / float64(*pktrate) * 1000 * 1000 * 1000
	for {

		time.Sleep(time.Duration(time_to_sleep) * time.Nanosecond)
		pkt, ok := <-send_chan
		if !ok {
			return
		}
		send_handle.WritePacketData(pkt)
	}
}

var src_ip = flag.String("source-ip", "", "Set the source IP")
var dev = flag.String("dev", "", "The device to use")
var use_vpn = flag.Bool("vpn", false, "Should this use a VPN (no L2 created)")
var gw = flag.String("gw", "", "The gateway to use, if not VPN")
var src_mac = flag.String("src-mac", "", "The source mac  if not VPN")
var conn_timeout = flag.Int("conn-timeout", 10, "Timeout in seconds for each connection")
var dst_port = flag.Int("dst_port", 80, "Destination port")
var num_concurrent = flag.Int("parallel", 10, "Number of parallel pacing estimations")
var profile = flag.String("profile", "", "Should open pprof on port 6060 on this ip")
var pktrate = flag.Int("pktrate", 100, "How many packets should we allow per second? [default shared to roughly 1 Mbit]")

func main() {
	rand.Seed(time.Now().Unix())
	log.Println("Startup")
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Parse()
	source_ip := net.ParseIP(*src_ip)
	if source_ip == nil {
		panic("Source IP is invalid")
	}

	enc := json.NewEncoder(os.Stdout)
	os.Stdout.Sync()
	enc.SetEscapeHTML(false)

	if *profile != "" {
		log.Println("Starting profiler")
		go func() {
			log.Println(http.ListenAndServe(*profile+":6060", nil))
		}()
	}

	var handle *pcap.Handle

	// this is where all the magic is stored
	streams := &manager{connectionMap: make(map[FlowIdentifier]*Connection), lock: sync.RWMutex{}}

	// setting up the pcap sniffing
	log.Printf("Using %s with %s to sniff\n", *dev, *src_ip)
	inactive, err := pcap.NewInactiveHandle(*dev)
	defer inactive.CleanUp()
	if err != nil {
		panic(err)
	}
	// this is the largest IW that we are assuming
	err = inactive.SetBufferSize(65535 * 8)
	if err != nil {
		log.Printf("Failed setting large buffer")
	}

	inactive.SetTimeout(time.Second)
	inactive.SetImmediateMode(true)
	if handle, err = inactive.Activate(); err != nil {
		panic("PCAP Activate error:")
	}

	log.Printf("Using filter %s", fmt.Sprintf("tcp src port %d", *dst_port))
	err = handle.SetBPFFilter(fmt.Sprintf("tcp src port %d", *dst_port))
	if err != nil {
		panic(err)
	}
	linktype := layers.LinkTypeRaw // is this a OS X only thingy?
	if !*use_vpn {
		linktype = handle.LinkType()
	}
	log.Printf("handling link type %d", linktype)

	packetSource := gopacket.NewPacketSource(handle, linktype)
	closePacketHandler := make(chan bool, 1)
	send_chan := make(chan []byte, *pktrate)

	go send_pkts(handle, send_chan)
	go handle_packets(streams, handle, !*use_vpn, packetSource, closePacketHandler)

	result_chan := make(chan map[string]interface{})
	running_chan := make(chan bool, *num_concurrent)

	stdin_chan := make(chan string, 1)
	running := true

	go line_from_stdin(stdin_chan, running_chan)

	// we use running_chan to count currently actives,
	for len(running_chan) > 0 || running {
		select {
		case line, ok := <-stdin_chan:
			if ok {
				//log.Printf("Scheduled %s\n", line)
				var inline map[string]interface{}
				if err := json.Unmarshal([]byte(line), &inline); err != nil {
					log.Printf("Error parsing json: %s (%s)\n", err.Error(), line)
					break
				}
				//results := strings.Split(fscanner.Text(), ",")
				go measure_iw(streams, send_chan, source_ip, uint16(*dst_port), *use_vpn, *dev, *gw, *src_mac, *conn_timeout, inline, result_chan)

			} else {
				//log.Printf("Done with reading stdin, waiting for outstanding answers from %d hosts\n", current)
				running = false

			}
		case <-closePacketHandler:
			return // the pcap crashed
		case result := <-result_chan:
			enc.Encode(result)
			<-running_chan
		case <-closePacketHandler:
			return // the pcap crashed

		}
	}
	close(send_chan)
	closePacketHandler <- true
	log.Println("Shutdown")
}
