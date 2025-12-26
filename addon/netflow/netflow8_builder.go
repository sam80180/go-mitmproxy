package netflow

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/datasapiens/cachier"
	tcpipheader "github.com/google/netstack/tcpip/header"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	"github.com/lunixbochs/struc"
	"github.com/sirupsen/logrus"
)

const (
	NETFLOW8_AGGREGATION_SCHEME_AS byte = iota + 1
	NETFLOW8_AGGREGATION_SCHEME_PROTOPORT
	NETFLOW8_AGGREGATION_SCHEME_SRCPREFIX
	NETFLOW8_AGGREGATION_SCHEME_DSTPREFIX
	NETFLOW8_AGGREGATION_SCHEME_PREFIX
	NETFLOW8_AGGREGATION_SCHEME_DST
	NETFLOW8_AGGREGATION_SCHEME_SRCDST
	NETFLOW8_AGGREGATION_SCHEME_FULLFLOW
	NETFLOW8_AGGREGATION_SCHEME_ASTOS
	NETFLOW8_AGGREGATION_SCHEME_PROTOPORTTOS
	NETFLOW8_AGGREGATION_SCHEME_SRCPREFIXTOS
	NETFLOW8_AGGREGATION_SCHEME_DSTPREFIXTOS
	NETFLOW8_AGGREGATION_SCHEME_PREFIXTOS
	NETFLOW8_AGGREGATION_SCHEME_PREFIXPORT

	Version8 uint16 = 0x0008
)

type V8PacketHeader struct {
	Version            uint16
	Count              uint16
	Uptime             uint32
	Sec                uint32
	Nsec               uint32
	Sequence           uint32
	EngineType         byte
	EngineID           byte
	Aggregation        byte
	AggregationVersion byte
	Reserved           []byte `struc:"pad,[4]byte"`
} // end type

type V8AggregationRecord1 struct { // AS
	Flows           uint32
	Packets         uint32
	Bytes           uint32
	FirstSwitched   uint32
	LastSwitched    uint32
	SrcAS           uint16
	DstAS           uint16
	InputSNMPIndex  uint16
	OutputSNMPIndex uint16
} // end type

type V8AggregationRecord2 struct { // Protocol-Port
	Flows         uint32
	Packets       uint32
	Bytes         uint32
	FirstSwitched uint32
	LastSwitched  uint32
	Protocol      byte
	Pad           byte   `struc:"pad"`
	Reserved      []byte `struc:"pad,[2]byte"`
	SrcPort       uint16
	DstPort       uint16
} // end type

type V8AggregationRecord3 struct { // Source-Prefix
	Flows          uint32
	Packets        uint32
	Bytes          uint32
	FirstSwitched  uint32
	LastSwitched   uint32
	SrcPrefix      net.IP `struc:"[4]byte"`
	SrcMask        byte
	Pad            byte `struc:"pad"`
	SrcAS          uint16
	InputSNMPIndex uint16
	Reserved       []byte `struc:"pad,[2]byte"`
} // end type

type V8AggregationRecord4 struct { // Destination-Prefix
	Flows           uint32
	Packets         uint32
	Bytes           uint32
	FirstSwitched   uint32
	LastSwitched    uint32
	DstPrefix       net.IP `struc:"[4]byte"`
	DstMask         byte
	Pad             byte `struc:"pad"`
	DstAS           uint16
	OutputSNMPIndex uint16
	Reserved        []byte `struc:"pad,[2]byte"`
} // end type

type V8AggregationRecord5 struct { // Prefix
	Flows           uint32
	Packets         uint32
	Bytes           uint32
	FirstSwitched   uint32
	LastSwitched    uint32
	SrcPrefix       net.IP `struc:"[4]byte"`
	DstPrefix       net.IP `struc:"[4]byte"`
	DstMask         byte
	SrcMask         byte
	Reserved        []byte `struc:"pad,[2]byte"`
	SrcAS           uint16
	DstAS           uint16
	InputSNMPIndex  uint16
	OutputSNMPIndex uint16
} // end type

type V8AggregationRecord6 struct { // Destination
	DstAddr         net.IP `struc:"[4]byte"`
	Packets         uint32
	Bytes           uint32
	FirstSwitched   uint32
	LastSwitched    uint32
	OutputSNMPIndex uint16
	ToS             byte
	MarkedToS       byte
	ExtraPackets    uint32
	RouterSC        net.IP `struc:"[4]byte"`
} // end type

type V8AggregationRecord7 struct { // Source-Destination
	DstAddr         net.IP `struc:"[4]byte"`
	SrcAddr         net.IP `struc:"[4]byte"`
	Packets         uint32
	Bytes           uint32
	FirstSwitched   uint32
	LastSwitched    uint32
	OutputSNMPIndex uint16
	InputSNMPIndex  uint16
	ToS             byte
	MarkedToS       byte
	Reserved        []byte `struc:"pad,[2]byte"`
	ExtraPackets    uint32
	RouterSC        net.IP `struc:"[4]byte"`
} // end type

type V8AggregationRecord8 struct { // Full-Flow
	DstAddr         net.IP `struc:"[4]byte"`
	SrcAddr         net.IP `struc:"[4]byte"`
	DstPort         uint16
	SrcPort         uint16
	Packets         uint32
	Bytes           uint32
	FirstSwitched   uint32
	LastSwitched    uint32
	OutputSNMPIndex uint16
	InputSNMPIndex  uint16
	ToS             byte
	Protocol        byte
	MarkedToS       byte
	Pad             byte `struc:"pad"`
	ExtraPackets    uint32
	RouterSC        net.IP `struc:"[4]byte"`
} // end type

type V8AggregationRecord9 struct { // AS-TOS
	Flows           uint32
	Packets         uint32
	Bytes           uint32
	FirstSwitched   uint32
	LastSwitched    uint32
	SrcAS           uint16
	DstAS           uint16
	InputSNMPIndex  uint16
	OutputSNMPIndex uint16
	ToS             byte
	Pad             byte   `struc:"pad"`
	Reserved        []byte `struc:"pad,[2]byte"`
} // end type

type V8AggregationRecord10 struct { // Protocol-Port-TOS
	Flows           uint32
	Packets         uint32
	Bytes           uint32
	FirstSwitched   uint32
	LastSwitched    uint32
	Protocol        byte
	ToS             byte
	Reserved        []byte `struc:"pad,[2]byte"`
	SrcPort         uint16
	DstPort         uint16
	InputSNMPIndex  uint16
	OutputSNMPIndex uint16
} // end type

type V8AggregationRecord11 struct { // Source-Prefix-TOS
	Flows          uint32
	Packets        uint32
	Bytes          uint32
	FirstSwitched  uint32
	LastSwitched   uint32
	SrcPrefix      net.IP `struc:"[4]byte"`
	SrcMask        byte
	ToS            byte
	SrcAS          uint16
	InputSNMPIndex uint16
	Reserved       []byte `struc:"pad,[2]byte"`
} // end type

type V8AggregationRecord12 struct { // Destination-Prefix-TOS
	Flows           uint32
	Packets         uint32
	Bytes           uint32
	FirstSwitched   uint32
	LastSwitched    uint32
	DstPrefix       net.IP `struc:"[4]byte"`
	DstMask         byte
	ToS             byte
	DstAS           uint16
	OutputSNMPIndex uint16
	Reserved        []byte `struc:"pad,[2]byte"`
} // end type

type V8AggregationRecord13 struct { // Prefix-TOS
	Flows           uint32
	Packets         uint32
	Bytes           uint32
	FirstSwitched   uint32
	LastSwitched    uint32
	SrcPrefix       net.IP `struc:"[4]byte"`
	DstPrefix       net.IP `struc:"[4]byte"`
	DstMask         byte
	SrcMask         byte
	ToS             byte
	Pad             byte `struc:"pad"`
	SrcAS           uint16
	DstAS           uint16
	InputSNMPIndex  uint16
	OutputSNMPIndex uint16
} // end type

type V8AggregationRecord14 struct { // Prefix-Port
	Flows           uint32
	Packets         uint32
	Bytes           uint32
	FirstSwitched   uint32
	LastSwitched    uint32
	SrcPrefix       net.IP `struc:"[4]byte"`
	DstPrefix       net.IP `struc:"[4]byte"`
	DstMask         byte
	SrcMask         byte
	ToS             byte
	Protocol        byte
	SrcPort         uint16
	DstPort         uint16
	InputSNMPIndex  uint16
	OutputSNMPIndex uint16
} // end type

type netflow8PacketBuilder struct {
	baseNetflowPacketBuilder
	router_sc net.IP
} // end type

func NewNetflow8PacketBuilder(cache *cachier.Cache[any], addr string, options NetflowExporterOptions) *netflow8PacketBuilder {
	baseBuilder := initBaseNetflowPacketBuilder(cache, &options)
	addon := &netflow8PacketBuilder{baseNetflowPacketBuilder: baseBuilder}
	if sc, _ := getRouterSC(addr); sc != nil {
		sc = sc.To4()
		if sc != nil {
			addon.router_sc = sc
		} // end if
	} // end if
	return addon
} // end NewNetflow8PacketBuilder()

func (builder *netflow8PacketBuilder) buildV8ASRecord(srcIp net.IP, _ int, dstIp net.IP, _ int, dur time.Duration, payload []byte) ([]byte, error) {
	record := V8AggregationRecord1{
		Bytes:        uint32(len(payload)),
		DstAS:        uint16(builder.Ip2Asn(dstIp)),
		Flows:        1,
		LastSwitched: uint32(dur.Milliseconds()),
		Packets:      uint32(packetCount(payload)),
		SrcAS:        uint16(builder.Ip2Asn(srcIp)),
	}
	if ifIndexIn, errIfIdxIn := builder.getLocalInterfaceSnmpIndexForPeer(srcIp); errIfIdxIn == nil && ifIndexIn > 0 {
		record.InputSNMPIndex = uint16(ifIndexIn)
	} // end if
	if ifIndexOut, errIfIdxOut := builder.getLocalInterfaceSnmpIndexForPeer(dstIp); errIfIdxOut == nil && ifIndexOut > 0 {
		record.OutputSNMPIndex = uint16(ifIndexOut)
	} // end if
	var buf bytes.Buffer
	if errPack := struc.Pack(&buf, &record); errPack != nil {
		return nil, errPack
	} // end if
	return buf.Bytes(), nil
} // end buildV8ASRecord()

func (builder *netflow8PacketBuilder) buildV8ProtoPortRecord(_ net.IP, SrcPort int, _ net.IP, DstPort int, dur time.Duration, payload []byte) ([]byte, error) {
	record := V8AggregationRecord2{
		Bytes:        uint32(len(payload)),
		DstPort:      uint16(DstPort),
		Flows:        1,
		LastSwitched: uint32(dur.Milliseconds()),
		Packets:      uint32(packetCount(payload)),
		Protocol:     byte(tcpipheader.TCPProtocolNumber),
		SrcPort:      uint16(SrcPort),
	}
	var buf bytes.Buffer
	if errPack := struc.Pack(&buf, &record); errPack != nil {
		return nil, errPack
	} // end if
	return buf.Bytes(), nil
} // end buildV8ProtoPortRecord()

func (builder *netflow8PacketBuilder) buildV8SrcPrefixRecord(srcIp net.IP, _ int, _ net.IP, _ int, dur time.Duration, payload []byte) ([]byte, error) {
	record := V8AggregationRecord3{
		Bytes:        uint32(len(payload)),
		Flows:        1,
		LastSwitched: uint32(dur.Milliseconds()),
		Packets:      uint32(packetCount(payload)),
		SrcAS:        uint16(builder.Ip2Asn(srcIp)),
		SrcPrefix:    srcIp,
		SrcMask:      32,
	}
	if ifIndexIn, errIfIdxIn := builder.getLocalInterfaceSnmpIndexForPeer(srcIp); errIfIdxIn == nil && ifIndexIn > 0 {
		record.InputSNMPIndex = uint16(ifIndexIn)
	} // end if
	var buf bytes.Buffer
	if errPack := struc.Pack(&buf, &record); errPack != nil {
		return nil, errPack
	} // end if
	return buf.Bytes(), nil
} // end buildV8SrcPrefixRecord()

func (builder *netflow8PacketBuilder) buildV8DstPrefixRecord(_ net.IP, _ int, dstIp net.IP, _ int, dur time.Duration, payload []byte) ([]byte, error) {
	record := V8AggregationRecord4{
		Bytes:        uint32(len(payload)),
		DstAS:        uint16(builder.Ip2Asn(dstIp)),
		DstPrefix:    dstIp,
		DstMask:      32,
		Flows:        1,
		LastSwitched: uint32(dur.Milliseconds()),
		Packets:      uint32(packetCount(payload)),
	}
	if ifIndexOut, errIfIdxOut := builder.getLocalInterfaceSnmpIndexForPeer(dstIp); errIfIdxOut == nil && ifIndexOut > 0 {
		record.OutputSNMPIndex = uint16(ifIndexOut)
	} // end if
	var buf bytes.Buffer
	if errPack := struc.Pack(&buf, &record); errPack != nil {
		return nil, errPack
	} // end if
	return buf.Bytes(), nil
} // end buildV8DstPrefixRecord()

func (builder *netflow8PacketBuilder) buildV8PrefixRecord(srcIp net.IP, _ int, dstIp net.IP, _ int, dur time.Duration, payload []byte) ([]byte, error) {
	record := V8AggregationRecord5{
		Bytes:        uint32(len(payload)),
		DstAS:        uint16(builder.Ip2Asn(dstIp)),
		DstPrefix:    dstIp,
		DstMask:      32,
		Flows:        1,
		LastSwitched: uint32(dur.Milliseconds()),
		Packets:      uint32(packetCount(payload)),
		SrcAS:        uint16(builder.Ip2Asn(srcIp)),
		SrcPrefix:    srcIp,
		SrcMask:      32,
	}
	if ifIndexIn, errIfIdxIn := builder.getLocalInterfaceSnmpIndexForPeer(srcIp); errIfIdxIn == nil && ifIndexIn > 0 {
		record.InputSNMPIndex = uint16(ifIndexIn)
	} // end if
	if ifIndexOut, errIfIdxOut := builder.getLocalInterfaceSnmpIndexForPeer(dstIp); errIfIdxOut == nil && ifIndexOut > 0 {
		record.OutputSNMPIndex = uint16(ifIndexOut)
	} // end if
	var buf bytes.Buffer
	if errPack := struc.Pack(&buf, &record); errPack != nil {
		return nil, errPack
	} // end if
	return buf.Bytes(), nil
} // end buildV8PrefixRecord()

func (builder *netflow8PacketBuilder) buildV8DstRecord(_ net.IP, _ int, dstIp net.IP, _ int, dur time.Duration, payload []byte) ([]byte, error) {
	record := V8AggregationRecord6{
		Bytes:        uint32(len(payload)),
		DstAddr:      dstIp,
		LastSwitched: uint32(dur.Milliseconds()),
		Packets:      uint32(packetCount(payload)),
		RouterSC:     builder.router_sc,
	}
	if ifIndexOut, errIfIdxOut := builder.getLocalInterfaceSnmpIndexForPeer(dstIp); errIfIdxOut == nil && ifIndexOut > 0 {
		record.OutputSNMPIndex = uint16(ifIndexOut)
	} // end if
	var buf bytes.Buffer
	if errPack := struc.Pack(&buf, &record); errPack != nil {
		return nil, errPack
	} // end if
	return buf.Bytes(), nil
} // end buildV8DstRecord()

func (builder *netflow8PacketBuilder) buildV8SrcDstRecord(srcIp net.IP, _ int, dstIp net.IP, _ int, dur time.Duration, payload []byte) ([]byte, error) {
	record := V8AggregationRecord7{
		Bytes:        uint32(len(payload)),
		DstAddr:      dstIp,
		LastSwitched: uint32(dur.Milliseconds()),
		Packets:      uint32(packetCount(payload)),
		RouterSC:     builder.router_sc,
		SrcAddr:      srcIp,
	}
	if ifIndexIn, errIfIdxIn := builder.getLocalInterfaceSnmpIndexForPeer(srcIp); errIfIdxIn == nil && ifIndexIn > 0 {
		record.InputSNMPIndex = uint16(ifIndexIn)
	} // end if
	if ifIndexOut, errIfIdxOut := builder.getLocalInterfaceSnmpIndexForPeer(dstIp); errIfIdxOut == nil && ifIndexOut > 0 {
		record.OutputSNMPIndex = uint16(ifIndexOut)
	} // end if
	var buf bytes.Buffer
	if errPack := struc.Pack(&buf, &record); errPack != nil {
		return nil, errPack
	} // end if
	return buf.Bytes(), nil
} // end buildV8SrcDstRecord()

func (builder *netflow8PacketBuilder) buildV8FullFlowRecord(srcIp net.IP, SrcPort int, dstIp net.IP, DstPort int, dur time.Duration, payload []byte) ([]byte, error) {
	record := V8AggregationRecord8{
		Bytes:        uint32(len(payload)),
		DstAddr:      dstIp,
		DstPort:      uint16(DstPort),
		LastSwitched: uint32(dur.Milliseconds()),
		Packets:      uint32(packetCount(payload)),
		Protocol:     byte(tcpipheader.TCPProtocolNumber),
		RouterSC:     builder.router_sc,
		SrcAddr:      srcIp,
		SrcPort:      uint16(SrcPort),
	}
	if ifIndexIn, errIfIdxIn := builder.getLocalInterfaceSnmpIndexForPeer(srcIp); errIfIdxIn == nil && ifIndexIn > 0 {
		record.InputSNMPIndex = uint16(ifIndexIn)
	} // end if
	if ifIndexOut, errIfIdxOut := builder.getLocalInterfaceSnmpIndexForPeer(dstIp); errIfIdxOut == nil && ifIndexOut > 0 {
		record.OutputSNMPIndex = uint16(ifIndexOut)
	} // end if
	var buf bytes.Buffer
	if errPack := struc.Pack(&buf, &record); errPack != nil {
		return nil, errPack
	} // end if
	return buf.Bytes(), nil
} // end buildV8FullFlowRecord()

func (builder *netflow8PacketBuilder) buildV8ASToSRecord(srcIp net.IP, _ int, dstIp net.IP, _ int, dur time.Duration, payload []byte) ([]byte, error) {
	record := V8AggregationRecord9{
		Bytes:        uint32(len(payload)),
		DstAS:        uint16(builder.Ip2Asn(dstIp)),
		Flows:        1,
		LastSwitched: uint32(dur.Milliseconds()),
		Packets:      uint32(packetCount(payload)),
		SrcAS:        uint16(builder.Ip2Asn(srcIp)),
	}
	if ifIndexIn, errIfIdxIn := builder.getLocalInterfaceSnmpIndexForPeer(srcIp); errIfIdxIn == nil && ifIndexIn > 0 {
		record.InputSNMPIndex = uint16(ifIndexIn)
	} // end if
	if ifIndexOut, errIfIdxOut := builder.getLocalInterfaceSnmpIndexForPeer(dstIp); errIfIdxOut == nil && ifIndexOut > 0 {
		record.OutputSNMPIndex = uint16(ifIndexOut)
	} // end if
	var buf bytes.Buffer
	if errPack := struc.Pack(&buf, &record); errPack != nil {
		return nil, errPack
	} // end if
	return buf.Bytes(), nil
} // end buildV8ASToSRecord()

func (builder *netflow8PacketBuilder) buildV8ProtoPortToSRecord(srcIp net.IP, SrcPort int, dstIp net.IP, DstPort int, dur time.Duration, payload []byte) ([]byte, error) {
	record := V8AggregationRecord10{
		Bytes:        uint32(len(payload)),
		DstPort:      uint16(DstPort),
		Flows:        1,
		LastSwitched: uint32(dur.Milliseconds()),
		Packets:      uint32(packetCount(payload)),
		Protocol:     byte(tcpipheader.TCPProtocolNumber),
		SrcPort:      uint16(SrcPort),
	}
	if ifIndexIn, errIfIdxIn := builder.getLocalInterfaceSnmpIndexForPeer(srcIp); errIfIdxIn == nil && ifIndexIn > 0 {
		record.InputSNMPIndex = uint16(ifIndexIn)
	} // end if
	if ifIndexOut, errIfIdxOut := builder.getLocalInterfaceSnmpIndexForPeer(dstIp); errIfIdxOut == nil && ifIndexOut > 0 {
		record.OutputSNMPIndex = uint16(ifIndexOut)
	} // end if
	var buf bytes.Buffer
	if errPack := struc.Pack(&buf, &record); errPack != nil {
		return nil, errPack
	} // end if
	return buf.Bytes(), nil
} // end buildV8ProtoPortToSRecord()

func (builder *netflow8PacketBuilder) buildV8SrcPrefixToSRecord(srcIp net.IP, _ int, _ net.IP, _ int, dur time.Duration, payload []byte) ([]byte, error) {
	record := V8AggregationRecord11{
		Bytes:        uint32(len(payload)),
		Flows:        1,
		LastSwitched: uint32(dur.Milliseconds()),
		Packets:      uint32(packetCount(payload)),
		SrcAS:        uint16(builder.Ip2Asn(srcIp)),
		SrcPrefix:    srcIp,
		SrcMask:      32,
	}
	if ifIndexIn, errIfIdxIn := builder.getLocalInterfaceSnmpIndexForPeer(srcIp); errIfIdxIn == nil && ifIndexIn > 0 {
		record.InputSNMPIndex = uint16(ifIndexIn)
	} // end if
	var buf bytes.Buffer
	if errPack := struc.Pack(&buf, &record); errPack != nil {
		return nil, errPack
	} // end if
	return buf.Bytes(), nil
} // end buildV8SrcPrefixToSRecord()

func (builder *netflow8PacketBuilder) buildV8DstPrefixToSRecord(_ net.IP, _ int, dstIp net.IP, _ int, dur time.Duration, payload []byte) ([]byte, error) {
	record := V8AggregationRecord12{
		Bytes:        uint32(len(payload)),
		DstAS:        uint16(builder.Ip2Asn(dstIp)),
		DstMask:      32,
		DstPrefix:    dstIp,
		Flows:        1,
		LastSwitched: uint32(dur.Milliseconds()),
		Packets:      uint32(packetCount(payload)),
	}
	if ifIndexOut, errIfIdxOut := builder.getLocalInterfaceSnmpIndexForPeer(dstIp); errIfIdxOut == nil && ifIndexOut > 0 {
		record.OutputSNMPIndex = uint16(ifIndexOut)
	} // end if
	var buf bytes.Buffer
	if errPack := struc.Pack(&buf, &record); errPack != nil {
		return nil, errPack
	} // end if
	return buf.Bytes(), nil
} // end buildV8DstPrefixToSRecord()

func (builder *netflow8PacketBuilder) buildV8PrefixToSRecord(srcIp net.IP, _ int, dstIp net.IP, _ int, dur time.Duration, payload []byte) ([]byte, error) {
	record := V8AggregationRecord13{
		Bytes:        uint32(len(payload)),
		DstAS:        uint16(builder.Ip2Asn(dstIp)),
		DstMask:      32,
		DstPrefix:    dstIp,
		Flows:        1,
		LastSwitched: uint32(dur.Milliseconds()),
		Packets:      uint32(packetCount(payload)),
		SrcAS:        uint16(builder.Ip2Asn(srcIp)),
		SrcMask:      32,
		SrcPrefix:    srcIp,
	}
	if ifIndexIn, errIfIdxIn := builder.getLocalInterfaceSnmpIndexForPeer(srcIp); errIfIdxIn == nil && ifIndexIn > 0 {
		record.InputSNMPIndex = uint16(ifIndexIn)
	} // end if
	if ifIndexOut, errIfIdxOut := builder.getLocalInterfaceSnmpIndexForPeer(dstIp); errIfIdxOut == nil && ifIndexOut > 0 {
		record.OutputSNMPIndex = uint16(ifIndexOut)
	} // end if
	var buf bytes.Buffer
	if errPack := struc.Pack(&buf, &record); errPack != nil {
		return nil, errPack
	} // end if
	return buf.Bytes(), nil
} // end buildV8PrefixToSRecord()

func (builder *netflow8PacketBuilder) buildV8PrefixPortRecord(srcIp net.IP, SrcPort int, dstIp net.IP, DstPort int, dur time.Duration, payload []byte) ([]byte, error) {
	record := V8AggregationRecord14{
		Bytes:        uint32(len(payload)),
		DstMask:      32,
		DstPort:      uint16(DstPort),
		DstPrefix:    dstIp,
		Flows:        1,
		LastSwitched: uint32(dur.Milliseconds()),
		Packets:      uint32(packetCount(payload)),
		Protocol:     byte(tcpipheader.TCPProtocolNumber),
		SrcMask:      32,
		SrcPort:      uint16(SrcPort),
		SrcPrefix:    srcIp,
	}
	if ifIndexIn, errIfIdxIn := builder.getLocalInterfaceSnmpIndexForPeer(srcIp); errIfIdxIn == nil && ifIndexIn > 0 {
		record.InputSNMPIndex = uint16(ifIndexIn)
	} // end if
	if ifIndexOut, errIfIdxOut := builder.getLocalInterfaceSnmpIndexForPeer(dstIp); errIfIdxOut == nil && ifIndexOut > 0 {
		record.OutputSNMPIndex = uint16(ifIndexOut)
	} // end if
	var buf bytes.Buffer
	if errPack := struc.Pack(&buf, &record); errPack != nil {
		return nil, errPack
	} // end if
	return buf.Bytes(), nil
} // end buildV8PrefixPortRecord()

func (builder *netflow8PacketBuilder) buildV8Header(flowCount uint16) ([]byte, error) {
	uptime, errUT := helper.SysUpTime()
	if errUT != nil {
		return nil, errUT
	} // end if
	sec, nsec := now_sec_nsec()
	header := V8PacketHeader{
		Version:     Version8,
		Count:       flowCount,
		Uptime:      uint32(uptime.Milliseconds()),
		Sec:         uint32(sec),
		Nsec:        uint32(nsec),
		Aggregation: NETFLOW8_AGGREGATION_SCHEME_FULLFLOW,
	}
	var bufHeader bytes.Buffer
	if errPackHer := struc.Pack(&bufHeader, &header); errPackHer != nil {
		return nil, errPackHer
	} // end if
	return bufHeader.Bytes(), nil
} // end buildV8Header()

func (builder *netflow8PacketBuilder) buildV8Record(srcIp net.IP, SrcPort int, dstIp net.IP, DstPort int, dur time.Duration, payload []byte) ([]byte, error) {
	switch builder.options.V8Aggregation {
	case NETFLOW8_AGGREGATION_SCHEME_AS:
		return builder.buildV8ASRecord(srcIp, SrcPort, dstIp, DstPort, dur, payload)
	case NETFLOW8_AGGREGATION_SCHEME_PROTOPORT:
		return builder.buildV8ProtoPortRecord(srcIp, SrcPort, dstIp, DstPort, dur, payload)
	case NETFLOW8_AGGREGATION_SCHEME_SRCPREFIX:
		return builder.buildV8SrcPrefixRecord(srcIp, SrcPort, dstIp, DstPort, dur, payload)
	case NETFLOW8_AGGREGATION_SCHEME_DSTPREFIX:
		return builder.buildV8DstPrefixRecord(srcIp, SrcPort, dstIp, DstPort, dur, payload)
	case NETFLOW8_AGGREGATION_SCHEME_PREFIX:
		return builder.buildV8PrefixRecord(srcIp, SrcPort, dstIp, DstPort, dur, payload)
	case NETFLOW8_AGGREGATION_SCHEME_DST:
		return builder.buildV8DstRecord(srcIp, SrcPort, dstIp, DstPort, dur, payload)
	case NETFLOW8_AGGREGATION_SCHEME_SRCDST:
		return builder.buildV8SrcDstRecord(srcIp, SrcPort, dstIp, DstPort, dur, payload)
	case NETFLOW8_AGGREGATION_SCHEME_FULLFLOW:
		return builder.buildV8FullFlowRecord(srcIp, SrcPort, dstIp, DstPort, dur, payload)
	case NETFLOW8_AGGREGATION_SCHEME_ASTOS:
		return builder.buildV8ASToSRecord(srcIp, SrcPort, dstIp, DstPort, dur, payload)
	case NETFLOW8_AGGREGATION_SCHEME_PROTOPORTTOS:
		return builder.buildV8ProtoPortToSRecord(srcIp, SrcPort, dstIp, DstPort, dur, payload)
	case NETFLOW8_AGGREGATION_SCHEME_SRCPREFIXTOS:
		return builder.buildV8SrcPrefixToSRecord(srcIp, SrcPort, dstIp, DstPort, dur, payload)
	case NETFLOW8_AGGREGATION_SCHEME_DSTPREFIXTOS:
		return builder.buildV8DstPrefixToSRecord(srcIp, SrcPort, dstIp, DstPort, dur, payload)
	case NETFLOW8_AGGREGATION_SCHEME_PREFIXTOS:
		return builder.buildV8PrefixToSRecord(srcIp, SrcPort, dstIp, DstPort, dur, payload)
	case NETFLOW8_AGGREGATION_SCHEME_PREFIXPORT:
		return builder.buildV8PrefixPortRecord(srcIp, SrcPort, dstIp, DstPort, dur, payload)
	} // end switch
	return builder.buildV8FullFlowRecord(srcIp, SrcPort, dstIp, DstPort, dur, payload)
} // end buildV8Record()

func (builder *netflow8PacketBuilder) Build(srcAddr, dstAddr net.Addr, rawReqBytes []byte, firstSwitched time.Duration, rawRepBytes []byte, lastSwitched time.Duration) ([]byte, error) {
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
	var dataRecords, buf bytes.Buffer
	if len(rawReqBytes) > 0 {
		if bb, errRec := builder.buildV8Record(srcIp, SrcPort, dstIp, DstPort, firstSwitched, rawReqBytes); errRec != nil {
			logrus.Warnf("%+v", errRec)
		} else {
			dataRecords.Write(bb)
			flowCount++
		} // end if
	} // end if
	if len(rawRepBytes) > 0 {
		if bb, errRec := builder.buildV8Record(dstIp, DstPort, srcIp, SrcPort, lastSwitched, rawRepBytes); errRec != nil {
			logrus.Warnf("%+v", errRec)
		} else {
			dataRecords.Write(bb)
			flowCount++
		} // end if
	} // end if
	if flowCount <= 0 {
		return nil, nil
	} // end if
	bufHeader, errPackHer := builder.buildV8Header(flowCount)
	if errPackHer != nil {
		return nil, errPackHer
	} // end if
	buf.Write(bufHeader)
	buf.Write(dataRecords.Bytes())
	return buf.Bytes(), nil
} // end Build()

/*
References:
https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/5-0-3/user/guide/format.html#wp1040741
*/
