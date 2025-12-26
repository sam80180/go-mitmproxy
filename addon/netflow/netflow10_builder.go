package netflow

import (
	"bytes"
	"encoding/binary"
	"net"
	"reflect"
	"time"

	"github.com/datasapiens/cachier"
	tcpipheader "github.com/google/netstack/tcpip/header"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	"github.com/sirupsen/logrus"
	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
)

const (
	Version10    uint16 = 10
	VersionIPFIX uint16 = Version10
)

func (record *MyIPFlowInfoRecord) getV10TemplateFields() ([]*entities.InfoElement, error) {
	// get field lengths
	strucFields, errSF := getStrucFieldLengths(record)
	if errSF != nil {
		return nil, errSF
	} // end if

	// get by tag
	elems := []*entities.InfoElement{}
	t := reflect.TypeOf(record).Elem()
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
		if ie.Len != fieldLength { // DO NOT modify original (shared) entity
			ie_copied := entities.InfoElement(*ie)
			ie_copied.Len = fieldLength
			ie = &ie_copied
		} // end if
		elems = append(elems, ie)
	} // end for
	return elems, nil
} // end getV10TemplateFields()

type netflow10PacketBuilder struct {
	baseNetflowPacketBuilder
} // end type

func NewNetflow10PacketBuilder(cache *cachier.Cache[any], options NetflowExporterOptions) *netflow10PacketBuilder {
	registry.LoadRegistry()
	baseBuilder := initBaseNetflowPacketBuilder(cache, &options)
	return &netflow10PacketBuilder{baseNetflowPacketBuilder: baseBuilder}
} // end NewNetflow10PacketBuilder()

func (*netflow10PacketBuilder) buildV10Header(len uint16) ([]byte, error) {
	b := make([]byte, entities.MsgHeaderLength)
	binary.BigEndian.PutUint16(b[0:2], Version10)
	binary.BigEndian.PutUint16(b[2:4], len)
	binary.BigEndian.PutUint32(b[4:8], uint32(time.Now().Unix()))
	return b, nil
} // end buildV10Header()

func (builder *netflow10PacketBuilder) buildV10DataRecord(srcIp net.IP, SrcPort int, dstIp net.IP, DstPort int, dur time.Duration, payload []byte) MyIPFlowInfoRecord {
	record := MyIPFlowInfoRecord{
		Bytes:      uint64(len(payload)),
		Dst:        dstIp,
		DstAs:      builder.Ip2Asn(dstIp),
		DstMask:    128,
		DstPort:    uint16(SrcPort),
		Flags:      getTCPFlags(false, false, false, true, true, false, false, false),
		Pkts:       packetCount(payload),
		Protocol:   byte(tcpipheader.TCPProtocolNumber),
		Src:        srcIp,
		SrcAs:      builder.Ip2Asn(srcIp),
		SrcMask:    128,
		SrcPort:    uint16(DstPort),
		UptimeLast: uint32(dur.Milliseconds()),
	}
	if ifIndexIn, errIfIdxIn := builder.getLocalInterfaceSnmpIndexForPeer(srcIp); errIfIdxIn == nil && ifIndexIn > 0 {
		record.Input = ifIndexIn
	} // end if
	if ifIndexOut, errIfIdxOut := builder.getLocalInterfaceSnmpIndexForPeer(dstIp); errIfIdxOut == nil && ifIndexOut > 0 {
		record.Output = ifIndexOut
	} // end if
	return record
} // end buildV10DataRecord()

func (builder *netflow10PacketBuilder) buildV10TemplateFlowSetRecord() ([]byte, error) {
	dummy := MyIPFlowInfoRecord{}
	fields, errFlds := dummy.getV10TemplateFields()
	if errFlds != nil {
		return nil, errFlds
	} // end if
	var bufRecord bytes.Buffer
	recordLength := entities.TemplateRecordHeaderLength
	for _, field := range fields {
		fieldDefLength := 4
		var E uint16 = 0
		if field.EnterpriseId != registry.IANAEnterpriseID {
			fieldDefLength += 4
			E = 1
		} // end if
		recordLength += fieldDefLength
		bufFieldSpec := make([]byte, fieldDefLength)
		var ieId uint16 = (E << 15) | field.ElementId
		binary.BigEndian.PutUint16(bufFieldSpec[0:2], ieId)      // information element ID
		binary.BigEndian.PutUint16(bufFieldSpec[2:4], field.Len) // field length
		if field.EnterpriseId != registry.IANAEnterpriseID {
			binary.BigEndian.PutUint32(bufFieldSpec[4:8], field.EnterpriseId) // enterprise number
		} // end if
		bufRecord.Write(bufFieldSpec)
	} // end for
	b := make([]byte, recordLength)
	binary.BigEndian.PutUint16(b[0:2], dummy.getTemplateIdFunc(func() uint16 { return builder.options.TemplateID })) // template ID
	binary.BigEndian.PutUint16(b[2:4], uint16(len(fields)))                                                          // field count
	copy(b[4:], bufRecord.Bytes())
	return b, nil
} // end buildV10TemplateFlowSetRecord()

func (builder *netflow10PacketBuilder) buildV10TemplateFlowSet() ([]byte, error) {
	bufRecord, errRec := builder.buildV10TemplateFlowSetRecord()
	if errRec != nil {
		return nil, errRec
	} // end if
	paddedLength := len(bufRecord) + entities.SetHeaderLen
	if paddedLength%4 != 0 {
		paddedLength = ((paddedLength / 4) + 1) * 4
	} // end if
	bufSet := make([]byte, paddedLength)
	binary.BigEndian.PutUint16(bufSet[0:2], entities.TemplateSetID) // set ID
	binary.BigEndian.PutUint16(bufSet[2:4], uint16(paddedLength))   // set length
	copy(bufSet[4:], bufRecord)
	return bufSet, nil
} // end buildV10TemplateFlowSet()

func (builder *netflow10PacketBuilder) Build(srcAddr, dstAddr net.Addr, rawReqBytes []byte, firstSwitched time.Duration, rawRepBytes []byte, lastSwitched time.Duration) ([]byte, error) {
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

	// data set
	var bufDataRecords bytes.Buffer
	gwIp := builder.NextHop()
	if gwIp != nil {
		gwIp = gwIp.To16()
	} // end if
	if len(rawReqBytes) > 0 {
		record := builder.buildV10DataRecord(srcIp, SrcPort, dstIp, DstPort, firstSwitched, rawReqBytes)
		record.Next = gwIp
		bufDataRecords.Write(record.marshalDataFlowSetRecord())
	} // end if
	if len(rawRepBytes) > 0 {
		record := builder.buildV10DataRecord(dstIp, DstPort, srcIp, SrcPort, lastSwitched, rawRepBytes)
		record.Next = gwIp
		bufDataRecords.Write(record.marshalDataFlowSetRecord())
	} // end if
	if bufDataRecords.Len() <= 0 {
		return nil, nil
	} // end if
	var paddedLength uint16 = 4 + uint16(bufDataRecords.Len())
	if paddedLength%4 != 0 {
		paddedLength = ((paddedLength / 4) + 1) * 4
	} // end if
	bufData := make([]byte, paddedLength)
	dummy := MyIPFlowInfoRecord{}
	binary.BigEndian.PutUint16(bufData[0:2], dummy.getTemplateIdFunc(func() uint16 { return builder.options.TemplateID })) // template ID
	binary.BigEndian.PutUint16(bufData[2:4], paddedLength)
	copy(bufData[4:], bufDataRecords.Bytes())

	// template set
	bufTpl, errHeader := builder.buildV10TemplateFlowSet()
	if errHeader != nil {
		return nil, errHeader
	} // end if

	// header
	bufHeader, errHdr := builder.buildV10Header(uint16(entities.MsgHeaderLength + len(bufTpl) + len(bufData)))
	if errHdr != nil {
		return nil, errHdr
	} // end if

	var buf bytes.Buffer
	buf.Write(bufHeader)
	buf.Write(bufTpl)
	buf.Write(bufData)
	return buf.Bytes(), nil
} // end Build()

/*
References:
https://info.support.huawei.com/hedex/api/pages/EDOC1100277644/AEM10221/03/resources/vrp/feature_netstream_4.html
*/
