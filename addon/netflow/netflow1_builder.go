package netflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/datasapiens/cachier"
	tcpipheader "github.com/google/netstack/tcpip/header"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	nf1 "github.com/tehmaze/netflow/netflow1"
)

type netflow1PacketBuilder struct {
	baseNetflowPacketBuilder
} // end type

func NewNetflow1PacketBuilder(cache *cachier.Cache[any]) *netflow1PacketBuilder {
	baseBuilder := initBaseNetflowPacketBuilder(cache, nil)
	return &netflow1PacketBuilder{baseNetflowPacketBuilder: baseBuilder}
} // end NewNetflow1PacketBuilder()

func (*netflow1PacketBuilder) buildV1Header(flowCount uint16) ([]byte, error) {
	b := make([]byte, 16)
	binary.BigEndian.PutUint16(b[0:2], nf1.Version)
	binary.BigEndian.PutUint16(b[2:4], flowCount)
	uptime, errUT := helper.SysUpTime()
	if errUT != nil {
		return nil, errUT
	} // end if
	binary.BigEndian.PutUint32(b[4:8], uint32(uptime.Milliseconds()))
	sec, nsec := now_sec_nsec()
	binary.BigEndian.PutUint32(b[8:12], uint32(sec))
	binary.BigEndian.PutUint32(b[12:16], uint32(nsec))
	return b, nil
} // end buildV1Header()

func (builder *netflow1PacketBuilder) buildV1Record(srcIp net.IP, SrcPort int, dstIp net.IP, DstPort int, dur time.Duration, payload []byte) []byte {
	b := make([]byte, 48)
	copy(b[0:4], srcIp) // srcaddr
	copy(b[4:8], dstIp) // dstaddr
	if gwIp := builder.NextHop(); gwIp != nil {
		gwIp = gwIp.To4()
		copy(b[8:12], gwIp) // nexthop
	} // end if
	if ifIndexIn, errIfIdxIn := builder.getLocalInterfaceSnmpIndexForPeer(srcIp); errIfIdxIn == nil && ifIndexIn > 0 {
		binary.BigEndian.PutUint16(b[12:14], uint16(ifIndexIn)) // input
	} // end if
	if ifIndexOut, errIfIdxOut := builder.getLocalInterfaceSnmpIndexForPeer(dstIp); errIfIdxOut == nil && ifIndexOut > 0 {
		binary.BigEndian.PutUint16(b[14:16], uint16(ifIndexOut)) // output
	} // end if
	binary.BigEndian.PutUint32(b[16:20], uint32(packetCount(payload)))              // dPkts
	binary.BigEndian.PutUint32(b[20:24], uint32(len(payload)))                      // dOctets
	binary.BigEndian.PutUint32(b[28:32], uint32(dur.Milliseconds()))                // last
	binary.BigEndian.PutUint16(b[32:34], uint16(SrcPort))                           // srcport
	binary.BigEndian.PutUint16(b[34:36], uint16(DstPort))                           // dstport
	b[38] = byte(tcpipheader.TCPProtocolNumber)                                     // prot
	b[40] = byte(getTCPFlags(false, false, false, true, true, false, false, false)) // flags
	return b
} // end buildV1Record()

func (builder *netflow1PacketBuilder) Build(srcAddr, dstAddr net.Addr, rawReqBytes []byte, firstSwitched time.Duration, rawRepBytes []byte, lastSwitched time.Duration) ([]byte, error) {
	srcIp, SrcPort, errIpSrc := helper.NetAddr2IpAndPort(srcAddr)
	if errIpSrc != nil {
		return nil, errIpSrc
	} // end if
	srcIp = srcIp.To4()
	if srcIp == nil {
		return nil, fmt.Errorf("unsupported address family")
	} // end if
	dstIp, DstPort, errIpDst := helper.NetAddr2IpAndPort(dstAddr)
	if errIpDst != nil {
		return nil, errIpDst
	} // end if
	dstIp = dstIp.To4()
	if dstIp == nil {
		return nil, fmt.Errorf("unsupported address family")
	} // end if
	var flowCount uint16 = 0
	var dataRecords bytes.Buffer
	if len(rawReqBytes) > 0 {
		flowCount++
		dataRecords.Write(builder.buildV1Record(srcIp, SrcPort, dstIp, DstPort, firstSwitched, rawReqBytes))
	} // end if
	if len(rawRepBytes) > 0 {
		flowCount++
		dataRecords.Write(builder.buildV1Record(dstIp, DstPort, srcIp, SrcPort, firstSwitched, rawRepBytes))
	} // end if
	if flowCount <= 0 {
		return nil, nil
	} // end if
	dataHeader, errPackHeader := builder.buildV1Header(flowCount)
	if errPackHeader != nil {
		return nil, errPackHeader
	} // end if
	var buf bytes.Buffer
	buf.Write(dataHeader)
	buf.Write(dataRecords.Bytes())
	return buf.Bytes(), nil
} // end Build()

/*
References:
https://www.ibm.com/docs/nl/npi/1.3.1?topic=versions-netflow-v1-formats
*/
