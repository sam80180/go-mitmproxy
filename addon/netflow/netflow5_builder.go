package netflow

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/datasapiens/cachier"
	tcpipheader "github.com/google/netstack/tcpip/header"
	"github.com/gravwell/gravwell/v3/netflow"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	nf5 "github.com/tehmaze/netflow/netflow5"
)

const (
	SamplingModeNone          = 0b00 // no sampling
	SamplingModeDeterministic = 0b01 // every Nth packet
	SamplingModeRandom        = 0b10 // probabilistic 1/N
	SamplingModeReserved      = 0b11
)

type netflow5PacketBuilder struct {
	baseNetflowPacketBuilder
} // end type

func NewNetflow5PacketBuilder(cache *cachier.Cache[any]) *netflow5PacketBuilder {
	baseBuilder := initBaseNetflowPacketBuilder(cache, nil)
	return &netflow5PacketBuilder{baseNetflowPacketBuilder: baseBuilder}
} // end NewNetflow5PacketBuilder()

func (builder *netflow5PacketBuilder) buildV5Record(srcIp net.IP, SrcPort int, dstIp net.IP, DstPort int, dur time.Duration, payload []byte) netflow.NFv5Record {
	record := netflow.NFv5Record{
		Bytes:      uint32(len(payload)),
		Dst:        dstIp,
		DstAs:      uint16(builder.Ip2Asn(dstIp)),
		DstMask:    32,
		DstPort:    uint16(DstPort),
		Flags:      byte(getTCPFlags(false, false, false, true, true, false, false, false)),
		Src:        srcIp,
		SrcAs:      uint16(builder.Ip2Asn(srcIp)),
		SrcMask:    32,
		SrcPort:    uint16(SrcPort),
		Pkts:       uint32(packetCount(payload)),
		Protocol:   byte(tcpipheader.TCPProtocolNumber),
		UptimeLast: uint32(dur.Milliseconds()),
	}
	if ifIndexIn, errIfIdxIn := builder.getLocalInterfaceSnmpIndexForPeer(srcIp); errIfIdxIn == nil && ifIndexIn > 0 {
		record.Input = uint16(ifIndexIn)
	} // end if
	if ifIndexOut, errIfIdxOut := builder.getLocalInterfaceSnmpIndexForPeer(dstIp); errIfIdxOut == nil && ifIndexOut > 0 {
		record.Output = uint16(ifIndexOut)
	} // end if
	return record
} // end buildV5Record()

func (builder *netflow5PacketBuilder) Build(srcAddr, dstAddr net.Addr, rawReqBytes []byte, firstSwitched time.Duration, rawRepBytes []byte, lastSwitched time.Duration) ([]byte, error) {
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
	uptime, errUT := helper.SysUpTime()
	if errUT != nil {
		return nil, errUT
	} // end if
	sec, nsec := now_sec_nsec()
	h := netflow.NFv5Header{
		Nsec:           uint32(nsec),
		Sec:            uint32(sec),
		Uptime:         uint32(uptime.Milliseconds()),
		Version:        nf5.Version,
		SampleMode:     SamplingModeDeterministic,
		SampleInterval: 1,
	}
	nf := netflow.NFv5{}
	offset := 0
	gwIp := builder.NextHop()
	if gwIp != nil {
		gwIp = gwIp.To4()
	} // end if
	if len(rawReqBytes) > 0 {
		h.Count++
		record := builder.buildV5Record(srcIp, SrcPort, dstIp, DstPort, firstSwitched, rawReqBytes)
		record.Next = gwIp
		nf.Recs[offset] = record
		offset++
	} // end if
	if len(rawRepBytes) > 0 {
		h.Count++
		record := builder.buildV5Record(dstIp, DstPort, srcIp, SrcPort, lastSwitched, rawRepBytes)
		record.Next = gwIp
		nf.Recs[offset] = record
		offset++
	} // end if
	if h.Count <= 0 {
		return nil, nil
	} // end if
	nf.NFv5Header = h
	b, e := nf.Encode()
	if e != nil {
		return nil, e
	} // end if
	binary.BigEndian.PutUint16(b[22:24], (uint16(h.SampleMode)<<14)|uint16(h.SampleInterval)) // the above `Encode()` method doesn't work, so write it myself
	return b, nil
} // end Build()
