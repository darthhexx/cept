package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/darthhexx/cept/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kung-foo/freki/netfilter"
)

// Setup in the firewall
// iptables -A OUTPUT -p tcp --dport 3306:3330 -j NFQUEUE --queue-num 0
// iptables -A OUTPUT -p tcp --dport 11211:11220 -j NFQUEUE --queue-num 1

const CONFIG_FILE_PATH = "/usr/local/cept/config/cept.json"

const (
	MAX_QUEUE_SIZE = 100

	MYSQL_QUEUE_INDEX       = 0
	MYSQL_HEADER_LENGTH     = 4
	MYSQL_MAX_PACKET_LENGTH = 1448

	MEMCACHED_QUEUE_INDEX  = 1
	MEMCACHED_ERR_FORMAT   = -1
	MEMCACHED_ERROR_FLAGS  = -2
	MEMCACHED_ERROR_TTL    = -3
	MEMCACHED_ERROR_LENGTH = -4
)

type Transaction struct {
	Data    []byte
	DataLen uint32
	Packets []*netfilter.RawPacket
}

type SqlCommand Transaction
type MemcachedCommand Transaction
type connectionKey [2]uint64

var gMySqlPacketsProcessed uint64
var gMemcachedPacketsProcessed uint64
var ethHdr = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x08, 0x00,
}

var l *utils.LogFile
var conf *utils.Config

func connectionHash(clientAddress gopacket.Endpoint, clientPort gopacket.Endpoint) (*connectionKey, error) {
	if clientAddress.EndpointType() != layers.EndpointIPv4 {
		return &connectionKey{}, errors.New("client address must be of type layers.EndpointIPv4")
	}

	if clientPort.EndpointType() != layers.EndpointTCPPort {
		return &connectionKey{}, errors.New("client port must be of type layers.EndpointTCPPort")
	}

	return &connectionKey{clientAddress.FastHash(), clientPort.FastHash()}, nil
}

func handleMySQLTraffic() {
	var gSQLCommands = make(map[connectionKey]*SqlCommand, 0)
	var err error

	nfq, err := netfilter.New(MYSQL_QUEUE_INDEX, MAX_QUEUE_SIZE, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		l.Println(err)
		os.Exit(1)
	}
	defer nfq.Close()
	go nfq.Run()
	packets := nfq.Packets()

PacketLoop:
	for {
		select {
		case p := <-packets:

			atomic.AddUint64(&gMySqlPacketsProcessed, 1)

			buffer := append(ethHdr, p.Data...)

			packet := gopacket.NewPacket(
				buffer,
				layers.LayerTypeEthernet,
				gopacket.DecodeOptions{Lazy: false, NoCopy: true},
			)

			var (
				eth  layers.Ethernet
				ip   layers.IPv4
				tcp  layers.TCP
				udp  layers.UDP
				icmp layers.ICMPv4
				body gopacket.Payload
			)

			parser := gopacket.NewDecodingLayerParser(
				layers.LayerTypeEthernet,
				&eth,
				&ip,
				&tcp,
				&udp,
				&icmp,
				&body)

			var foundLayerTypes []gopacket.LayerType
			err = parser.DecodeLayers(packet.Data(), &foundLayerTypes)

			if err != nil {
				l.Printf("%v %v\n", err, foundLayerTypes)
				nfq.SetVerdict(p, netfilter.NF_ACCEPT)
				continue
			}

			for _, layer := range foundLayerTypes {

				switch layer.String() {
				case "TCP":
					srcIP := ip.NetworkFlow().Src()
					srcPort := tcp.TransportFlow().Src()

					ck, err := connectionHash(srcIP, srcPort)
					if nil != err {
						l.Printf("Failed to get the Connection Key: %v\n", err.Error())
						continue
					}

					if tcp.SYN && !tcp.ACK {
						l.Printf("new connection %s:%s -> %d\n", srcIP.String(), srcPort.String(), tcp.DstPort)
					} else if tcp.RST {
						l.Printf("RST on connection %s:%s->%d", srcIP.String(), srcPort.String(), tcp.DstPort)
						gSQLCommands[*ck].Data = make([]byte, 0)
						gSQLCommands[*ck].DataLen = 0
						gSQLCommands[*ck].Packets = make([]*netfilter.RawPacket, 0)
					} else if tcp.FIN {
						l.Printf("FIN on connection %s:%s->%d", srcIP.String(), srcPort.String(), tcp.DstPort)
						delete(gSQLCommands, *ck)
					}

				case "Payload":
					srcIP := ip.NetworkFlow().Src()
					srcPort := tcp.TransportFlow().Src()
					l.Printf("data on connection %s:%s -> %d\n", srcIP.String(), srcPort.String(), tcp.DstPort)

					ck, err := connectionHash(srcIP, srcPort)
					if nil != err {
						l.Printf("Failed to get the Connection Key: %v\n", err.Error())
						continue
					}

					sqlCmd, found := gSQLCommands[*ck]
					if !found {
						sqlCmd = &SqlCommand{Data: []byte{}, DataLen: 0}
						gSQLCommands[*ck] = sqlCmd
					}

					data := packet.ApplicationLayer().Payload()

					if 0 == len(sqlCmd.Packets) {
						sqlCmd.DataLen = uint32(data[2])
						sqlCmd.DataLen <<= 8
						sqlCmd.DataLen |= uint32(data[1])
						sqlCmd.DataLen <<= 8
						sqlCmd.DataLen |= uint32(data[0])

						if 0 == sqlCmd.DataLen {
							nfq.SetVerdict(p, netfilter.NF_ACCEPT)
							continue
						}
						sqlCmd.Data = data[MYSQL_HEADER_LENGTH:]
						sqlCmd.Packets = make([]*netfilter.RawPacket, 1)
						sqlCmd.Packets[0] = p
					} else {
						gSQLCommands[*ck].Data = append(sqlCmd.Data, data...)
						sqlCmd.Packets = append(sqlCmd.Packets, p)
					}

					l.Printf("%s : seq ID %d : payload len %d : pending %d\n",
						time.Now().Format(time.RFC3339),
						int32(data[3]),
						gSQLCommands[*ck].DataLen,
						gSQLCommands[*ck].DataLen-uint32(len(gSQLCommands[*ck].Data)))

					if uint32(len(gSQLCommands[*ck].Data)) == gSQLCommands[*ck].DataLen {
						l.Println("Finished processing MySQL packet: ", string(gSQLCommands[*ck].Data[1:]))
						l.Println("sending ACCEPT for all packets")

						for _, pp := range gSQLCommands[*ck].Packets {
							nfq.SetVerdict(pp, netfilter.NF_ACCEPT)
						}

						gSQLCommands[*ck].Packets = make([]*netfilter.RawPacket, 0)
					}
					continue PacketLoop
				}
			}

			nfq.SetVerdict(p, netfilter.NF_ACCEPT)
		}

	}
}

func parseMemcachedRequestLength(commandArray []string) int {
	if len(commandArray) != 5 {
		return MEMCACHED_ERR_FORMAT
	}

	_, err := strconv.ParseUint(strings.TrimSpace(commandArray[2]), 10, 32)
	if err != nil {
		l.Printf("Error parsing flags: %s\n", err.Error())
		return MEMCACHED_ERROR_FLAGS
	}

	_, err = strconv.ParseUint(strings.TrimSpace(commandArray[3]), 10, 32)
	if err != nil {
		l.Printf("Error parsing ttl: %s\n", err.Error())
		return MEMCACHED_ERROR_TTL
	}

	length, err := strconv.ParseUint(strings.TrimSpace(commandArray[4]), 10, 32)
	if err != nil {
		l.Printf("Error parsing length: %s\n", err.Error())
		return MEMCACHED_ERROR_LENGTH
	}

	return int(length)
}

func handleMemcachedTraffic() {
	var gMemcachedCommands = make(map[connectionKey]*MemcachedCommand, 0)
	var err error

	nfq, err := netfilter.New(MEMCACHED_QUEUE_INDEX, MAX_QUEUE_SIZE, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		l.Println(err)
		os.Exit(1)
	}
	defer nfq.Close()
	go nfq.Run()
	packets := nfq.Packets()

PacketLoop:
	for {
		select {
		case p := <-packets:
			atomic.AddUint64(&gMemcachedPacketsProcessed, 1)
			buffer := append(ethHdr, p.Data...)
			packet := gopacket.NewPacket(
				buffer,
				layers.LayerTypeEthernet,
				gopacket.DecodeOptions{Lazy: false, NoCopy: true},
			)

			var (
				eth  layers.Ethernet
				ip   layers.IPv4
				tcp  layers.TCP
				udp  layers.UDP
				icmp layers.ICMPv4
				body gopacket.Payload
			)

			parser := gopacket.NewDecodingLayerParser(
				layers.LayerTypeEthernet,
				&eth,
				&ip,
				&tcp,
				&udp,
				&icmp,
				&body)

			var foundLayerTypes []gopacket.LayerType
			err = parser.DecodeLayers(packet.Data(), &foundLayerTypes)

			if err != nil {
				l.Printf("%v %v\n", err, foundLayerTypes)
				nfq.SetVerdict(p, netfilter.NF_ACCEPT)
				continue
			}

			for _, layer := range foundLayerTypes {

				switch layer.String() {
				case "TCP":

					srcIP := ip.NetworkFlow().Src()
					srcPort := tcp.TransportFlow().Src()

					ck, err := connectionHash(srcIP, srcPort)
					if nil != err {
						l.Printf("Failed to get the Connection Key: %v\n", err.Error())
						continue
					}

					if tcp.SYN && !tcp.ACK {
						l.Printf("new connection %s:%s -> %d\n", srcIP.String(), srcPort.String(), tcp.DstPort)

						// TODO:
						// Change the Destination IP/Port of the connection to localhost when in read only mode
						// using the nfq.SetVerdictModifed() method.

					} else if tcp.RST {

						l.Printf("RST on connection %s:%s -> %d\n", srcIP.String(), srcPort.String(), tcp.DstPort)
						gMemcachedCommands[*ck].Data = make([]byte, 0)
						gMemcachedCommands[*ck].DataLen = 0
						gMemcachedCommands[*ck].Packets = make([]*netfilter.RawPacket, 0)

					} else if tcp.FIN {

						l.Printf("FIN on connection %s:%s -> %d\n", srcIP.String(), srcPort.String(), tcp.DstPort)
						delete(gMemcachedCommands, *ck)
					}

				case "Payload":
					srcIP := ip.NetworkFlow().Src()
					srcPort := tcp.TransportFlow().Src()
					l.Printf("data on connection %s:%s -> %d\n", srcIP.String(), srcPort.String(), tcp.DstPort)

					ck, err := connectionHash(srcIP, srcPort)
					if nil != err {
						l.Printf("Failed to get the Connection Key: %v\n", err.Error())
						continue
					}

					memCmd, found := gMemcachedCommands[*ck]
					if !found {
						memCmd = &MemcachedCommand{Data: []byte{}, DataLen: 0}
						gMemcachedCommands[*ck] = memCmd
					}

					if 0 == len(memCmd.Packets) {
						commandArray := strings.Split(strings.TrimSpace(string(body)), " ")

						switch commandArray[0] {
						case "set", "add", "replace", "append", "prepend":
							datalen := parseMemcachedRequestLength(commandArray)
							switch datalen {
							case MEMCACHED_ERR_FORMAT:
								fallthrough
							case MEMCACHED_ERROR_FLAGS:
								fallthrough
							case MEMCACHED_ERROR_TTL:
								fallthrough
							case MEMCACHED_ERROR_LENGTH:
								continue
							}
							memCmd.DataLen = uint32(datalen)

						case "get", "delete", "touch", "noop", "quit", "version":
							memCmd.DataLen = 0

						default:
							l.Printf("Unknown command: %s\n", commandArray[0])
							continue
						}

						if 0 == memCmd.DataLen {
							continue
						}
						memCmd.Data = body
						memCmd.Packets = make([]*netfilter.RawPacket, 1)
						memCmd.Packets[0] = p
					} else {
						memCmd.Data = append(memCmd.Data, body...)
						memCmd.Packets = append(memCmd.Packets, p)
					}

					l.Printf("%s : seq ID %d : payload len %d : pending %d\n",
						time.Now().Format(time.RFC3339),
						int32(data[3]),
						gMemcachedCommands[*ck].DataLen,
						gMemcachedCommands[*ck].DataLen-uint32(len(gMemcachedCommands[*ck].Data)))

					if uint32(len(gMemcachedCommands[*ck].Data)) == gMemcachedCommands[*ck].DataLen {
						l.Println("Finished processing Memcached packet: ", string(gMemcachedCommands[*ck].Data[1:]))
						l.Println("sending ACCEPT for all packets")
						for _, pp := range gMemcachedCommands[*ck].Packets {
							nfq.SetVerdict(pp, netfilter.NF_ACCEPT)
						}

						gMemcachedCommands[*ck].Packets = make([]*netfilter.RawPacket, 0)
					}
					continue PacketLoop
				}
			}

			nfq.SetVerdict(p, netfilter.NF_ACCEPT)
		}
	}
}

func main() {
	conf = &utils.Config{}
	conf.Load(CONFIG_FILE_PATH)

	l = &utils.LogFile{Conf: conf}
	if err := l.Init(true); nil != err {
		fmt.Println("Error initializing log file: ", err.Error())
		os.Exit(1)
	}
	l.Println("initializing cept")

	go handleMySQLTraffic()
	go handleMemcachedTraffic()

	// Setup the stats ticker
	statsTick := time.Tick(time.Duration(30 * time.Second.Nanoseconds()))

	for {
		select {
		case <-statsTick:
			l.Printf("OK:\tMySQL Packets: %d\tMemcached Packets: %d\n",
				atomic.LoadUint64(&gMySqlPacketsProcessed),
				atomic.LoadUint64(&gMemcachedPacketsProcessed))
		}
	}
}
