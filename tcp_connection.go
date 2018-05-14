package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	//"log"
	"net"
	"sort"
	"time"
	//	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

type ReceivedSegment struct {
	Seq_num tcpassembly.Sequence `json:"seq_num"`
	Length  uint32               `json:"len"`
}

type Connection struct {
	Flow              FlowIdentifier       `json:"-"`
	Source            net.IP               `json:"-"`
	SourceString      string               `json:"source"`
	Destination       net.IP               `json:"-"`
	DestinationString string               `json:"destination"`
	Gateway           net.HardwareAddr     `json:"-"`
	GatewayString     string               `json:"gateway,omitempty"`
	SrcMAC            net.HardwareAddr     `json:"-"`
	SrcMACString      string               `json:"src_mac,omitempty"`
	AnnouncedMSS      uint16               `json:"announced_mss"`
	SrcPort           layers.TCPPort       `json:"src_port"`
	DstPort           layers.TCPPort       `json:"dst_port"`
	hasLayerTwo       bool                 `json:"-"`
	LastSeqSent       tcpassembly.Sequence `json:"-"`
	HighestSeqRcv     tcpassembly.Sequence `json:"-"`
	LenHighestSeqRcv  uint32               `json:"-"`
	SndNxt            tcpassembly.Sequence `json:"-"`
	RcvNxt            tcpassembly.Sequence `json:"-"`
	SendHandle        chan ([]byte)        `json:"-"`
	Timeout           time.Duration        `json:"-"`
	Irtt              time.Duration        `json:"-"`
	State             int                  `json:"-"`
	PacketChannel     chan (*layers.TCP)   `json:"-"`
	SynAckChan        chan (*layers.TCP)   `json:"-"`
	EstablishedChan   chan (*layers.TCP)   `json:"-"`
	Data              struct {
		Start_of_data   tcpassembly.Sequence `json:"start_of_data"`
		End_of_data     tcpassembly.Sequence `json:"end_of_data"`
		Largest_segment uint32               `json:"observed_mss"`
		Received_segs   []ReceivedSegment    `json:"segments"`
	} `json:"data"`
}

const ( // iota is reset to 0
	CLOSED = iota // c0 == 0
	SYN_SENT
	ESTABLISHED
	TIMEOUT
)

const MAX_PACKETS = 1000

func prepareConnection(handle chan ([]byte), destination net.IP, source net.IP, srcPort uint16, dstPort uint16, announcedMSS uint16, timeout time.Duration) (*Connection, error) {
	conn := &Connection{}
	conn.SendHandle = handle
	conn.Destination = destination
	if conn.Destination == nil {
		return nil, fmt.Errorf("Invalid destination IP")
	}
	conn.DestinationString = destination.String()
	conn.Source = source
	if conn.Source == nil {
		return nil, fmt.Errorf("Invalid source IP")
	}
	conn.SourceString = source.String()
	conn.PacketChannel = make(chan *layers.TCP, MAX_PACKETS)
	conn.EstablishedChan = make(chan *layers.TCP, MAX_PACKETS)
	conn.SynAckChan = make(chan *layers.TCP, 1)
	conn.Timeout = timeout
	conn.SrcPort = layers.TCPPort(srcPort)
	conn.DstPort = layers.TCPPort(dstPort)
	conn.State = CLOSED
	conn.HighestSeqRcv = 0
	conn.SndNxt = 1
	conn.AnnouncedMSS = announcedMSS

	// this allow matching this conn on new input
	conn.Flow.net = gopacket.NewFlow(layers.EndpointIPv4, layers.NewIPEndpoint(destination).Raw(), layers.NewIPEndpoint(source).Raw())
	conn.Flow.transport = gopacket.NewFlow(layers.EndpointTCPPort, layers.NewTCPPortEndpoint(conn.DstPort).Raw(), layers.NewTCPPortEndpoint(conn.SrcPort).Raw())
	return conn, nil
}

func PrepareLocalConnection(handle chan ([]byte), destination net.IP, source net.IP, srcPort uint16, dstPort uint16, src_mac string, gateway string, announcedMSS uint16, timeout time.Duration) (*Connection, error) {
	conn, err := prepareConnection(handle, destination, source, srcPort, dstPort, announcedMSS, timeout)
	if conn == nil {
		return nil, err
	}
	conn.SrcMAC, err = net.ParseMAC(src_mac)
	if err != nil {
		return nil, err
	}
	conn.SrcMACString = src_mac
	conn.Gateway, err = net.ParseMAC(gateway)
	if err != nil {
		return nil, err
	}
	conn.GatewayString = gateway
	conn.hasLayerTwo = true

	return conn, nil
}

func PrepareVPNConnection(handle chan ([]byte), destination net.IP, source net.IP, srcPort uint16, dstPort uint16, announcedMSS uint16, timeout time.Duration) (*Connection, error) {
	conn, err := prepareConnection(handle, destination, source, srcPort, dstPort, announcedMSS, timeout)
	if conn == nil {
		return nil, err
	}
	conn.hasLayerTwo = false

	return conn, nil
}

func (c *Connection) make_eth() layers.Ethernet {
	eth := layers.Ethernet{
		SrcMAC:       c.SrcMAC,
		DstMAC:       c.Gateway,
		EthernetType: layers.EthernetTypeIPv4,
	}
	return eth
}

func (c *Connection) make_ip() layers.IPv4 {
	ip := layers.IPv4{
		SrcIP:    c.Source,
		DstIP:    c.Destination,
		TTL:      64,
		Version:  4,
		Protocol: layers.IPProtocolTCP,
	}
	return ip
}

func (c *Connection) make_syn(seq_num uint32) layers.TCP {

	optionData := make([]byte, 2)
	binary.BigEndian.PutUint16(optionData, c.AnnouncedMSS)
	mssOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 2,
		OptionData:   optionData,
	}
	winScaleOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindWindowScale,
		OptionLength: 1,
		OptionData:   []byte{3},
	}
	tcpOptions := []layers.TCPOption{mssOption, winScaleOption}
	tcp := layers.TCP{
		SrcPort: c.SrcPort,
		DstPort: c.DstPort,
		Seq:     seq_num,
		ACK:     false,
		SYN:     true,
		Window:  0xFFFF,
		Options: tcpOptions,
	}
	return tcp
}

func (c *Connection) make_ack(seq_num uint32, ack_num uint32) layers.TCP {

	tcp := layers.TCP{
		SrcPort: c.SrcPort,
		DstPort: c.DstPort,
		Seq:     seq_num,
		ACK:     true,
		Ack:     ack_num,
		Window:  0xFFFF,
	}
	return tcp
}

func (c *Connection) make_rst(seq_num uint32) layers.TCP {

	tcp := layers.TCP{
		SrcPort: c.SrcPort,
		DstPort: c.DstPort,
		Seq:     seq_num,
		ACK:     false,
		RST:     true,
		Window:  0,
	}
	return tcp
}

func (c *Connection) Connect() error {

	outputBuffer := gopacket.NewSerializeBuffer()
	serializeOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	var err error
	var eth layers.Ethernet
	if c.hasLayerTwo {
		eth = c.make_eth()
	}
	ip := c.make_ip()

	c.SndNxt = tcpassembly.Sequence(rand.Intn(0xFFFF))
	c.LastSeqSent = c.SndNxt
	tcp := c.make_syn(uint32(c.SndNxt & 0xFFFFFFFF))
	c.SndNxt = c.LastSeqSent + 1
	tcp.SetNetworkLayerForChecksum(&ip)
	if c.hasLayerTwo {
		err = gopacket.SerializeLayers(outputBuffer, serializeOptions, &eth, &ip, &tcp)
		if err != nil {
			return err
		}
	} else {
		err = gopacket.SerializeLayers(outputBuffer, serializeOptions, &ip, &tcp)
		if err != nil {
			return err
		}
	}
	c.State = SYN_SENT
	tsynsent := time.Now()
	c.SendHandle <- outputBuffer.Bytes()

	// wait for SYN/ACK
	globaltimeout := time.After(c.Timeout)
loop:
	for {
		select {
		case syn_ack := <-c.SynAckChan:
			if syn_ack.RST {
				return fmt.Errorf("RST on SYN, port closed")
			}
			rcv_ack := tcpassembly.Sequence(syn_ack.Ack)
			rcv_seq := tcpassembly.Sequence(syn_ack.Seq)
			//log.Printf("SYN FLAG %t ACK FLAG %t SEQ NUM %d ACK NUM %d", syn_ack.SYN, syn_ack.ACK, syn_ack.Seq, syn_ack.Ack)
			if syn_ack.SYN && syn_ack.ACK && rcv_ack == c.SndNxt {
				// this is really a SYN/ACK to our SYN
				//log.Println("Got SYN/ACK For SYN")
				c.HighestSeqRcv = rcv_seq
				c.RcvNxt = rcv_seq.Add(1)
				//c.RcvNxt = syn_ack.Seq + 1
				c.Data.Start_of_data = c.RcvNxt
				c.Data.End_of_data = c.RcvNxt
				break loop
			}
		case <-time.After(3 * time.Second):
			// do a retransmission of the syn
			tsynsent = time.Now()
			c.SendHandle <- outputBuffer.Bytes()

			break
		case <-globaltimeout:
			c.State = TIMEOUT
			return fmt.Errorf("Timeout in conn establishment")
		}
	}
	c.Irtt = time.Now().Sub(tsynsent)
	c.State = ESTABLISHED
	outputBuffer.Clear()
	tcp = c.make_ack(uint32(c.SndNxt&0xFFFFFFFF), uint32(c.RcvNxt&0xFFFFFFFF))
	tcp.SetNetworkLayerForChecksum(&ip)
	c.LastSeqSent = c.SndNxt
	c.SndNxt = c.LastSeqSent
	if c.hasLayerTwo {
		err = gopacket.SerializeLayers(outputBuffer, serializeOptions, &eth, &ip, &tcp)
		if err != nil {
			return err
		}
	} else {
		err = gopacket.SerializeLayers(outputBuffer, serializeOptions, &ip, &tcp)
		if err != nil {
			return err
		}
	}
	/// AAAACHHHTUNNG RTT vorgaukeln
	//<-time.After(time.Millisecond * 50)
	c.SendHandle <- outputBuffer.Bytes()

	return nil
}

func (c *Connection) sendData(data []byte) error {
	outputBuffer := gopacket.NewSerializeBuffer()
	serializeOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	payload := gopacket.Payload(data)
	var eth layers.Ethernet
	if c.hasLayerTwo {
		eth = c.make_eth()
	}
	ip := c.make_ip()
	c.LastSeqSent = c.SndNxt
	tcp := c.make_ack(uint32(c.SndNxt&0xFFFFFFFF), uint32(c.RcvNxt&0xFFFFFFFF))
	tcp.SetNetworkLayerForChecksum(&ip)
	//c.SndNxt = c.SndNxt.Add(len(data))

	if c.hasLayerTwo {
		gopacket.SerializeLayers(outputBuffer, serializeOptions, &eth, &ip, &tcp, payload)
	} else {
		gopacket.SerializeLayers(outputBuffer, serializeOptions, &ip, &tcp, payload)
	}
	c.SendHandle <- outputBuffer.Bytes()

	//todo wait here for an ACK and do retransmissions if necessary
	// but make sure to log so refactor log below
	globaltimeout := time.After(c.Timeout)
	for {
		select {
		case pkt := <-c.EstablishedChan:
			finished, err := consume_and_log_packet(c, pkt)
			if err != nil {
				return err
			}
			if !finished {
				if c.LastSeqSent.Add(len(data)).Difference(c.SndNxt) >= 0 {
					return nil
				}
			}
			if finished {
				return fmt.Errorf("retransmission on request")
			}
		case <-time.After(time.Second):
			// retransmit
			c.SendHandle <- outputBuffer.Bytes()
		case <-globaltimeout:
			return fmt.Errorf("timeout sending data")
		}
	}
}

func max_seq(a tcpassembly.Sequence, b tcpassembly.Sequence) tcpassembly.Sequence {
	if b.Difference(a) > 0 {
		return a
	}
	return b
}

func max_int(a uint32, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func consume_and_log_packet(c *Connection, pkt *layers.TCP) (bool, error) {
	// log this until we find a retransmission
	if pkt.RST {
		return false, fmt.Errorf("RST while waiting for data")
	}
	if pkt.FIN {
		return false, fmt.Errorf("FIN while waiting for data")
	}
	if pkt.ACK {
		c.SndNxt = tcpassembly.Sequence(pkt.Ack)
	}

	seq_rcv := tcpassembly.Sequence(pkt.Seq)
	if c.RcvNxt.Difference(seq_rcv) >= 0 {
		// if this has no data ignore it
		if len(pkt.Payload) == 0 {
			return false, nil
		}
		if c.HighestSeqRcv < seq_rcv {
			c.HighestSeqRcv = seq_rcv
			c.LenHighestSeqRcv = uint32(len(pkt.Payload))
		}
		seg := ReceivedSegment{Seq_num: seq_rcv,
			Length: uint32(len(pkt.Payload))}
		if len(c.Data.Received_segs) > MAX_PACKETS {
			return false, fmt.Errorf("Too many packets while waiting for data")
		}
		c.Data.Received_segs = append(c.Data.Received_segs, seg)

		sort.Slice(c.Data.Received_segs, func(i, j int) bool {
			return c.Data.Received_segs[i].Seq_num.Difference(c.Data.Received_segs[j].Seq_num) > 0
		})
		for _, segment := range c.Data.Received_segs {
			c.Data.End_of_data = max_seq(c.Data.End_of_data, segment.Seq_num.Add(int(segment.Length)))
			c.Data.Largest_segment = max_int(c.Data.Largest_segment, segment.Length)
			// what to expect next?
			if segment.Seq_num == c.RcvNxt {
				c.RcvNxt = segment.Seq_num.Add(int(segment.Length))
			}
		}
	} else {
		if seq_rcv >= c.Data.Start_of_data {
			// this is a retransmission
			return true, nil
		} else {
			// this could be a retrans of syn/ack...
			return false, nil
		}
	}
	return false, nil
}

func (c *Connection) consumeAndLogUntilRetransmission() error {
	for {
		select {
		case pkt := <-c.EstablishedChan:
			finished, err := consume_and_log_packet(c, pkt)
			if err != nil {
				return err
			}
			if finished {
				return nil
			}
		case <-time.After(c.Timeout):
			c.State = TIMEOUT
			return fmt.Errorf("Timeout while waiting for data")
		}
	}
}

func (c *Connection) acknowledgeData() {
	outputBuffer := gopacket.NewSerializeBuffer()
	serializeOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	var eth layers.Ethernet
	if c.hasLayerTwo {
		eth = c.make_eth()
	}
	ip := c.make_ip()
	c.LastSeqSent = c.SndNxt
	tcp := c.make_ack(uint32(c.SndNxt&0xFFFFFFFF), uint32(c.HighestSeqRcv.Add(int(c.LenHighestSeqRcv))&0xFFFFFFFF))
	tcp.SetNetworkLayerForChecksum(&ip)
	tcp.Window = c.AnnouncedMSS // this is anyway scaled by four due to window scaling
	if c.hasLayerTwo {
		gopacket.SerializeLayers(outputBuffer, serializeOptions, &eth, &ip, &tcp)
	} else {
		gopacket.SerializeLayers(outputBuffer, serializeOptions, &ip, &tcp)
	}
	for i := 0; i < 3; i++ {
		c.SendHandle <- outputBuffer.Bytes()
		<-time.After(50 * time.Microsecond)
	}
}

func (c *Connection) waitForNewData() error {
	for {
		select {
		case pkt := <-c.EstablishedChan:
			// log this until we find a retransmission

			if pkt.RST {
				return fmt.Errorf("RST while waiting for data")
			}
			if pkt.FIN {
				return fmt.Errorf("FIN while waiting for data")
			}
			if pkt.ACK {
				c.SndNxt = tcpassembly.Sequence(pkt.Ack)
			}
			if tcpassembly.Sequence(pkt.Seq) >= c.RcvNxt {
				return nil
			}
		case <-time.After(c.Timeout):
			c.State = TIMEOUT
			return fmt.Errorf("Timeout while waiting for data after retransmission")
		}
	}
}

func (c *Connection) kill() {
	outputBuffer := gopacket.NewSerializeBuffer()
	serializeOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	var eth layers.Ethernet
	if c.hasLayerTwo {
		eth = c.make_eth()
	}
	ip := c.make_ip()
	c.LastSeqSent = c.SndNxt
	tcp := c.make_rst(uint32(c.SndNxt & 0xFFFFFFFF))
	tcp.SetNetworkLayerForChecksum(&ip)
	if c.hasLayerTwo {
		gopacket.SerializeLayers(outputBuffer, serializeOptions, &eth, &ip, &tcp)
	} else {
		gopacket.SerializeLayers(outputBuffer, serializeOptions, &ip, &tcp)
	}
	c.State = CLOSED
	for i := 0; i < 3; i++ {
		c.SendHandle <- outputBuffer.Bytes()
		<-time.After(50 * time.Microsecond)
	}

}

func (c *Connection) receivePacket() {

	for {
		select {
		case tcp, ok := <-c.PacketChannel:
			if !ok {
				return
			}

			if c.State == SYN_SENT {

				c.SynAckChan <- tcp

			}
			if c.State == ESTABLISHED {
				c.EstablishedChan <- tcp
			}
			if c.State == TIMEOUT || c.State == CLOSED {
				// build a RST from the data that we got
				if tcp.RST {
					break
				}
				outputBuffer := gopacket.NewSerializeBuffer()
				serializeOptions := gopacket.SerializeOptions{
					FixLengths:       true,
					ComputeChecksums: true,
				}

				var eth layers.Ethernet
				if c.hasLayerTwo {
					eth = c.make_eth()
				}
				ip := c.make_ip()
				c.LastSeqSent = c.SndNxt
				var tcpout layers.TCP
				if tcp.ACK {
					tcpout = c.make_rst(tcp.Ack)
				} else {
					tcpout = c.make_rst(uint32(c.SndNxt & 0xFFFFFFFF))
				}
				tcpout.SetNetworkLayerForChecksum(&ip)
				if c.hasLayerTwo {
					gopacket.SerializeLayers(outputBuffer, serializeOptions, &eth, &ip, &tcpout)
				} else {
					gopacket.SerializeLayers(outputBuffer, serializeOptions, &ip, &tcpout)
				}
				c.SendHandle <- outputBuffer.Bytes()
			}
		}
	}
}
