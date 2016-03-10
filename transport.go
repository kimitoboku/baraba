package baraba

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func BinaryContent(packet gopacket.Packet, match []byte) bool {
	return bytes.Contains(packet.Data(), match)
}

func StringContent(packet gopacket.Packet, match string) bool {
	return strings.Contains(string(packet.Data()), match)
}

func SrcPortMatch(packet gopacket.Packet, match int) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return strings.Compare(tcp.SrcPort.String(), strconv.Itoa(match)) == 0
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return strings.Compare(udp.SrcPort.String(), strconv.Itoa(match)) == 0
	}
	return false
}

func DstPortMatch(packet gopacket.Packet, match int) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return strings.Compare(tcp.DstPort.String(), strconv.Itoa(match)) == 0
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return strings.Compare(udp.DstPort.String(), strconv.Itoa(match)) == 0
	}
	return false
}

func TcpSYNFlag(packet gopacket.Packet) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.SYN
	}
	return false
}

func TcpFINFlag(packet gopacket.Packet) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.FIN
	}
	return false
}

func TcpRSTFlag(packet gopacket.Packet) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.RST
	}
	return false
}

func TcpPSHFlag(packet gopacket.Packet) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.PSH
	}
	return false
}

func TcpACKFlag(packet gopacket.Packet) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.ACK
	}
	return false
}

func TcpURGFlag(packet gopacket.Packet) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.URG
	}
	return false
}

func TcpECEFlag(packet gopacket.Packet) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.ECE
	}
	return false
}

func TcpCWRFlag(packet gopacket.Packet) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.CWR
	}
	return false
}

func TcpNSFlag(packet gopacket.Packet) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.NS
	}
	return false
}

func TcpChecksumMatch(packet gopacket.Packet, match uint16) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.Checksum == match
	}
	return false
}

func UdpChecksumMatch(packet gopacket.Packet, match uint16) bool {
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return udp.Checksum == match
	}
	return false
}
