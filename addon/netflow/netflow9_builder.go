package netflow

import (
	"bytes"
	"encoding/binary"
	"net"
	"reflect"
	"time"
	_ "unsafe" // required for go:linkname

	"github.com/datasapiens/cachier"
	tcpipheader "github.com/google/netstack/tcpip/header"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	"github.com/lunixbochs/struc"
	"github.com/sirupsen/logrus"
	nf9 "github.com/tehmaze/netflow/netflow9"
	"github.com/vmware/go-ipfix/pkg/registry"
)

//go:linkname struc_parseFields github.com/lunixbochs/struc.parseFields
func struc_parseFields(reflect.Value) (struc.Fields, error)

type MyIPFlowInfoRecord struct { // mimic NetFlow V5 format
	Src         net.IP `ipfix:"sourceIPv6Address" struc:"[16]byte"`
	Dst         net.IP `ipfix:"destinationIPv6Address" struc:"[16]byte"`
	Next        net.IP `ipfix:"ipNextHopIPv6Address" struc:"[16]byte"`
	Input       uint32 `ipfix:"ingressInterface"`
	Output      uint32 `ipfix:"egressInterface"`
	Pkts        uint64 `ipfix:"packetDeltaCount"`
	Bytes       uint64 `ipfix:"octetDeltaCount"`
	UptimeFirst uint32 `ipfix:"flowStartSysUpTime"`
	UptimeLast  uint32 `ipfix:"flowEndSysUpTime"`
	SrcPort     uint16 `ipfix:"tcpSourcePort"`
	DstPort     uint16 `ipfix:"tcpDestinationPort"`
	Pad         byte   `ipfix:"paddingOctets" struc:"pad"`
	Flags       uint16 `ipfix:"tcpControlBits"`
	Protocol    byte   `ipfix:"protocolIdentifier"`
	ToS         byte   `ipfix:"ipClassOfService"`
	SrcAs       uint32 `ipfix:"bgpSourceAsNumber"`
	DstAs       uint32 `ipfix:"bgpDestinationAsNumber"`
	SrcMask     byte   `ipfix:"sourceIPv6PrefixLength"`
	DstMask     byte   `ipfix:"destinationIPv6PrefixLength"`
	Pad2        byte   `ipfix:"paddingOctets" struc:"pad"`
} // end type

func getStrucFieldLengths(o any) (struc.Fields, error) {
	strucVal := reflect.ValueOf(o)
	strucElem := strucVal.Elem()
	strucOpts := struc.Options{}
	strucFields, errSF := struc_parseFields(strucVal)
	if errSF != nil {
		return nil, errSF
	} // end if
	for i, strucField := range strucFields {
		strucField.Len = strucField.Size(strucElem.Field(i), &strucOpts) // https://github.com/lunixbochs/struc/blob/8d528fa2c5439b5d03f50858890a98d6336607f7/fields.go#L38
	} // end for
	return strucFields, nil
} // end getStrucFieldLengths()

func (record *MyIPFlowInfoRecord) getV9TemplateFields() nf9.FieldSpecifiers {
	// get field lengths
	strucFields, errSF := getStrucFieldLengths(record)
	if errSF != nil {
		return nil
	} // end if

	// get field types by tag
	t := reflect.TypeOf(record).Elem()
	ipv4tpl := nf9.FieldSpecifiers{}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.Anonymous {
			continue
		} // end if
		tagVal, bHasTag := field.Tag.Lookup("ipfix")
		if !bHasTag || tagVal == "" || tagVal == "-" {
			continue
		} // end if
		var fieldLength uint16 = 0
		for _, strucField := range strucFields {
			if strucField.Name == field.Name {
				fieldLength = uint16(strucField.Len)
				break
			} // end if
		} // end for
		if fieldLength <= 0 {
			continue
		} // end if
		ie, errIE := registry.GetInfoElement(tagVal, registry.IANAEnterpriseID)
		if errIE != nil {
			logrus.Warnf("Failed to get InfoElement for %s", tagVal)
			continue
		} // end if
		ipv4tpl = append(ipv4tpl, nf9.FieldSpecifier{Type: ie.ElementId, Length: fieldLength})
	} // end for
	return ipv4tpl
} // end getV9TemplateFields()

func (record *MyIPFlowInfoRecord) getTemplateId() uint16 {
	return 2460
} // end getTemplateId()

func (record *MyIPFlowInfoRecord) getTemplateIdFunc(f func() uint16) uint16 {
	var id uint16 = 0
	if f != nil {
		id = f()
	} // end
	if id <= 0 {
		id = record.getTemplateId()
	} // end if
	return id
} // end getTemplateIdFunc()

func (record *MyIPFlowInfoRecord) marshalTemplateFlowSetRecord(funcGetTemplateId func() uint16) []byte {
	ipv4tpl := record.getV9TemplateFields()
	fieldCount := len(ipv4tpl)
	length := 4 + fieldCount*4
	b := make([]byte, length)
	offset := 4
	for _, entry := range ipv4tpl {
		binary.BigEndian.PutUint16(b[offset:offset+2], entry.Type)
		binary.BigEndian.PutUint16(b[offset+2:offset+4], entry.Length)
		offset += 4
	} // end for
	binary.BigEndian.PutUint16(b[0:2], record.getTemplateIdFunc(funcGetTemplateId)) // template ID
	binary.BigEndian.PutUint16(b[2:4], uint16(fieldCount))
	return b
} // end marshalTemplateFlowSetRecord()

func (record *MyIPFlowInfoRecord) MarshalTemplateFlowSet(funcGetTemplateId func() uint16) []byte {
	recordBytes := record.marshalTemplateFlowSetRecord(funcGetTemplateId)
	header := nf9.FlowSetHeader{ID: 0}
	paddedLength := header.Len() + len(recordBytes)
	if paddedLength%4 != 0 {
		paddedLength = ((paddedLength / 4) + 1) * 4
	} // end if
	header.Length = uint16(paddedLength)
	b := make([]byte, paddedLength)
	var bufHeader bytes.Buffer
	struc.Pack(&bufHeader, &header)
	copy(b[0:], bufHeader.Bytes())
	copy(b[header.Len():], recordBytes)
	return b
} // end MarshalTemplateFlowSet()

func (record *MyIPFlowInfoRecord) marshalDataFlowSetRecord() []byte {
	var buf bytes.Buffer
	struc.Pack(&buf, record)
	return buf.Bytes()
} // end marshalDataFlowSetRecord()

func (record *MyIPFlowInfoRecord) MarshalDataFlowSet(records []MyIPFlowInfoRecord) []byte {
	header := nf9.FlowSetHeader{ID: record.getTemplateId()}
	length := header.Len()
	var bufRecords bytes.Buffer
	for _, record := range records {
		bb := record.marshalDataFlowSetRecord()
		bufRecords.Write(bb)
		length += len(bb)
	} // end for
	if length%4 != 0 {
		length = ((length / 4) + 1) * 4
	} // end if
	header.Length = uint16(length)
	var bufHeader bytes.Buffer
	struc.Pack(&bufHeader, &header)
	b := make([]byte, length)
	copy(b[0:], bufHeader.Bytes())
	copy(b[header.Len():], bufRecords.Bytes())
	return b
} // end MarshalDataFlowSet()

type netflow9PacketBuilder struct {
	baseNetflowPacketBuilder
} // end type

func NewNetflow9PacketBuilder(cache *cachier.Cache[any], options NetflowExporterOptions) *netflow9PacketBuilder {
	registry.LoadRegistry()
	baseBuilder := initBaseNetflowPacketBuilder(cache, &options)
	return &netflow9PacketBuilder{baseNetflowPacketBuilder: baseBuilder}
} // end NewNetflow9PacketBuilder()

func (*netflow9PacketBuilder) buildV9Header(len uint16) ([]byte, error) {
	uptime, errUT := helper.SysUpTime()
	if errUT != nil {
		return nil, errUT
	} // end if
	sec, _ := now_sec_nsec()
	header := nf9.PacketHeader{
		Version:   nf9.Version,
		Count:     len,
		SysUpTime: uint32(uptime.Milliseconds()),
		UnixSecs:  uint32(sec),
	}
	var bufHeader bytes.Buffer
	if errPack := struc.Pack(&bufHeader, &header); errPack != nil {
		return nil, errPack
	} // end if
	return bufHeader.Bytes(), nil
} // end buildV9Header()

func (builder *netflow9PacketBuilder) buildV9DataRecord(srcIp net.IP, SrcPort int, dstIp net.IP, DstPort int, dur time.Duration, payload []byte) MyIPFlowInfoRecord {
	record := MyIPFlowInfoRecord{
		Bytes:      uint64(len(payload)),
		Dst:        dstIp,
		DstAs:      builder.Ip2Asn(dstIp),
		DstMask:    128,
		DstPort:    uint16(DstPort),
		Flags:      getTCPFlags(false, false, false, true, true, false, false, false),
		Pkts:       packetCount(payload),
		Protocol:   byte(tcpipheader.TCPProtocolNumber),
		Src:        srcIp,
		SrcAs:      builder.Ip2Asn(srcIp),
		SrcMask:    128,
		SrcPort:    uint16(SrcPort),
		UptimeLast: uint32(dur.Milliseconds()),
	}
	if ifIndexIn, errIfIdxIn := builder.getLocalInterfaceSnmpIndexForPeer(srcIp); errIfIdxIn == nil && ifIndexIn > 0 {
		record.Input = ifIndexIn
	} // end if
	if ifIndexOut, errIfIdxOut := builder.getLocalInterfaceSnmpIndexForPeer(dstIp); errIfIdxOut == nil && ifIndexOut > 0 {
		record.Output = ifIndexOut
	} // end if
	return record
} // end buildV9DataRecord()

func (builder *netflow9PacketBuilder) Build(srcAddr, dstAddr net.Addr, rawReqBytes []byte, firstSwitched time.Duration, rawRepBytes []byte, lastSwitched time.Duration) ([]byte, error) {
	srcIp, SrcPort, errIpSrc := helper.NetAddr2IpAndPort(srcAddr)
	if errIpSrc != nil {
		return nil, errIpSrc
	} // end if
	srcIp = srcIp.To16()
	dstIp, DstPort, errIpDst := helper.NetAddr2IpAndPort(dstAddr)
	if errIpDst != nil {
		return nil, errIpDst
	} // end if
	dstIp = dstIp.To16()
	var buf bytes.Buffer
	records := []MyIPFlowInfoRecord{}
	gwIp := builder.NextHop()
	if gwIp != nil {
		gwIp = gwIp.To16()
	} // end if
	if len(rawReqBytes) > 0 {
		record := builder.buildV9DataRecord(srcIp, SrcPort, dstIp, DstPort, firstSwitched, rawReqBytes)
		record.Next = gwIp
		records = append(records, record)
	} // end if
	if len(rawRepBytes) > 0 {
		record := builder.buildV9DataRecord(dstIp, DstPort, srcIp, SrcPort, lastSwitched, rawRepBytes)
		record.Next = gwIp
		records = append(records, record)
	} // end if
	if len(records) <= 0 {
		return nil, nil
	} // end if
	bufHeader, errPackHdr := builder.buildV9Header(uint16(1 + len(records)))
	if errPackHdr != nil {
		return nil, errPackHdr
	} // end if
	buf.Write(bufHeader)
	dummy := MyIPFlowInfoRecord{}
	buf.Write(dummy.MarshalTemplateFlowSet(func() uint16 { return builder.options.TemplateID }))
	buf.Write(dummy.MarshalDataFlowSet(records))
	return buf.Bytes(), nil
} // end Build()

/*
References:
https://www.ibm.com/docs/en/npi/1.3.0?topic=versions-netflow-v5-formats
https://github.com/tehmaze/netflow/blob/master/translate/rfc5102.go
*/
