package sflow

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/datasapiens/cachier"
	"github.com/fstelzer/sflow"
	sflow_record "github.com/fstelzer/sflow/records"
	"github.com/google/gopacket/layers"
	tcpipheader "github.com/google/netstack/tcpip/header"
	"github.com/gosnmp/gosnmp"
	addon_pd "github.com/lqqyt2423/go-mitmproxy/addon/packet_dumper"
	mycache "github.com/lqqyt2423/go-mitmproxy/cache"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/lqqyt2423/go-mitmproxy/udpclient"
	"github.com/sirupsen/logrus"
)

const (
	SFLOW_COLLECTOR_DEFAULT_PORT int    = 6343
	SFLOW_DEFAULT_EXPORTER_HOST  string = "localhost"
)

type SFlow5Exporter struct {
	mitmproxy.BaseAddon
	udpClient    *udpclient.UdpClient
	outgoingIntf net.IP
	cache        *cachier.Cache[any]
} // end type

func NewSFlow5Exporter(p *mitmproxy.Proxy, addr string) (mitmproxy.Addon, error) {
	posQ := strings.Index(addr, "?")
	addrWithoutQuery := addr
	if posQ >= 0 {
		addrWithoutQuery = addr[0:posQ]
	} // end if
	hostResult, errClassify := helper.ClassifyHost(addrWithoutQuery)
	if errClassify != nil {
		return nil, errClassify
	} // end if
	exporterHost := hostResult.Addr.String()
	if !hostResult.Addr.IsValid() { // FQDN
		exporterHost = helper.StripPortIfPresent(addrWithoutQuery)
	} // end if
	if exporterHost == "" {
		exporterHost = SFLOW_DEFAULT_EXPORTER_HOST
	} // end if
	var exporterPort int = SFLOW_COLLECTOR_DEFAULT_PORT
	posColon := strings.LastIndex(addrWithoutQuery, ":")
	if posColon >= 0 {
		if v := addrWithoutQuery[posColon+1:]; helper.IsValidPortStr(v) {
			exporterPort, _ = strconv.Atoi(v)
		} // end if
	} // end if
	addrWithoutQuery = fmt.Sprintf("%s:%d", exporterHost, exporterPort)
	exporter := SFlow5Exporter{}
	udpClient, errClient := udpclient.NewUdpClient(
		addrWithoutQuery,
		udpclient.WithBackoff(200*time.Millisecond, 5*time.Second),
		udpclient.WithQueueSize(256),
		udpclient.WithOnConnect(func(*net.UDPConn) {
			//logrus.WithField("collector_addr", addrWithoutQuery).Infof("sFlow exporter started")
		}),
		udpclient.WithOnDisconnect(func(e error) {
			logrus.WithField("collector_addr", addrWithoutQuery).Infof("sFlow collector disconnected")
		}),
	)
	if errClient != nil {
		return nil, errClient
	} // end if
	udpClient.Start()
	exporter.udpClient = udpClient
	if host, _, bMatched := helper.ParseHostAndPort(addrWithoutQuery); bMatched {
		if hostResult, _ := helper.ClassifyHost(host); hostResult != nil {
			if !hostResult.Addr.IsValid() { // probably a FQDN
				if ip, _ := helper.LookupAddr(host); ip != nil {
					host = ip.String()
				} // end if
			} // end if
		} // end if
		if sc, errIp := helper.LocalIPForPeer(net.ParseIP(host)); errIp == nil && sc != nil {
			if scv4 := sc.To4(); scv4 != nil {
				sc = scv4
			} // end if
			exporter.outgoingIntf = sc
		} // end if
	} // end if
	if exporter.outgoingIntf == nil {
		exporter.outgoingIntf = net.ParseIP("127.0.0.1").To4()
	} // end if
	exporter.cache = p.Cache()
	logrus.WithField("collector_addr", addrWithoutQuery).Info("sFlow exporter initialized")
	return &exporter, nil
} // end NewSFlow5Exporter()

func (that *SFlow5Exporter) Request(flow *mitmproxy.Flow) {
	go (func() {
		<-flow.Done()
		dur := flow.ElapsedTime()
		if b, _ := that.generate_sflow_datagram(flow, dur); len(b) > 0 {
			that.udpClient.Send(b)
		} // end if
	})()
} // end Request()

func sflowHttpRequestMethodNum(s string) uint32 {
	switch s {
	case http.MethodOptions:
		return sflow_record.HTTPOptions
	case http.MethodGet:
		return sflow_record.HTTPGet
	case http.MethodHead:
		return sflow_record.HTTPHead
	case http.MethodPost:
		return sflow_record.HTTPPost
	case http.MethodPut:
		return sflow_record.HTTPPut
	case http.MethodDelete:
		return sflow_record.HTTPDelete
	case http.MethodTrace:
		return sflow_record.HTTPTrace
	case http.MethodConnect:
		return sflow_record.HTTPConnect
	} // end switch
	return sflow_record.HTTPOther
} // end sflowHttpRequestMethodNum()

func mitmproxyFlow2HTTPRequestSFlow(flow *mitmproxy.Flow, dur time.Duration) sflow_record.Record {
	req_uri := flow.Request.URL.String()
	strReferer := flow.Request.Raw().Referer()
	strUA := flow.Request.Raw().UserAgent()
	strRespMime := flow.Response.Header.Get("Content-Type")
	strXFF := flow.Request.Header.Get("X-Forwarded-For")
	record := sflow_record.HTTPRequestFlow{
		Duration:     uint32(dur.Microseconds()),
		Host:         []byte(flow.Request.URL.Host),
		HostLen:      uint32(len(flow.Request.URL.Host)),
		Method:       sflowHttpRequestMethodNum(flow.Request.Method),
		MimeType:     []byte(strRespMime),
		MimeTypeLen:  uint32(len(strRespMime)),
		Referer:      []byte(strReferer),
		RefererLen:   uint32(len(strReferer)),
		ReqBytes:     uint64(flow.Request.Raw().ContentLength),
		RespBytes:    uint64(flow.Response.Raw().ContentLength),
		Status:       uint32(flow.Response.StatusCode),
		URI:          []byte(req_uri),
		URILen:       uint32(len(req_uri)),
		UserAgent:    []byte(strUA),
		UserAgentLen: uint32(len(strUA)),
		XFF:          []byte(strXFF),
		XFFLen:       uint32(len(strXFF)),
	}
	reHttpProto := regexp.MustCompile(`^HTTP/(?P<ver>[0-9]+(?:\.[0-9]+)?)`)
	matchHttpProto := reHttpProto.FindStringSubmatch(flow.Request.Proto)
	if matchHttpProto != nil {
		strProtoVer := matchHttpProto[reHttpProto.SubexpIndex("ver")]
		verParts := strings.Split(strProtoVer, ".")
		var protoVer uint32 = 0
		verMaj, _ := strconv.Atoi(verParts[0])
		protoVer = uint32(verMaj * 1000)
		if len(verParts) >= 2 {
			verMin, _ := strconv.Atoi(verParts[1])
			protoVer += uint32(verMin)
		} // end if
		record.Protocol = protoVer
	} // end if
	return newMyHTTPRequestFlowRecord(record)
} // end mitmproxyFlow2HTTPRequestSFlow()

func packetCount(payload []byte) uint64 {
	return uint64(math.Ceil(float64(len(payload)) / float64(addon_pd.PACKET_PAYLOAD_SEGMENT_SIZE)))
} // end packetCount()

func (exporter *SFlow5Exporter) generate_sflow_datagram(flow *mitmproxy.Flow, dur time.Duration) ([]byte, error) {
	srcAddr := flow.ConnContext.ClientConn.Conn.RemoteAddr()
	srcIp, SrcPort, errIpSrc := helper.NetAddr2IpAndPort(srcAddr)
	if errIpSrc != nil {
		return nil, errIpSrc
	} // end if
	dstAddr := flow.ConnContext.ServerConn.Conn.RemoteAddr()
	dstIp, DstPort, errIpDst := helper.NetAddr2IpAndPort(dstAddr)
	if errIpDst != nil {
		return nil, errIpDst
	} // end if
	inputIdx, _ := exporter.getLocalInterfaceSnmpIndexForPeer(srcIp)
	outputIdx, _ := exporter.getLocalInterfaceSnmpIndexForPeer(dstIp)
	expIdx, _ := exporter.getLocalInterfaceSnmpIndexForPeer(exporter.outgoingIntf)
	packetCount := uint32(packetCount(flow.Request.Body) + packetCount(flow.Response.Body))
	flowSample := &sflow.FlowSample{
		SourceIdType:     byte(layers.SFlowTypeSingleInterface),
		SourceIdIndexVal: expIdx,
		SamplingRate:     packetCount,
		SamplePool:       packetCount,
		Input:            inputIdx,
		Output:           outputIdx, //0x3FFFFFFF,
		Records:          []sflow_record.Record{mitmproxyFlow2HTTPRequestSFlow(flow, dur)},
	}
	if srcIp.To4() != nil {
		srcIp = srcIp.To4()
		dstIp = dstIp.To4()
		flowSample.Records = append(flowSample.Records, newMyExtendedSocketIPv4Flow(sflow_record.ExtendedSocketIPv4Flow{
			LocalIP:    srcIp,
			LocalPort:  uint32(SrcPort),
			Protocol:   uint32(tcpipheader.TCPProtocolNumber),
			RemoteIP:   dstIp,
			RemotePort: uint32(DstPort),
		}))
	} else {
		srcIp = srcIp.To16()
		dstIp = dstIp.To16()
		flowSample.Records = append(flowSample.Records, newMyExtendedSocketIPv6Flow(sflow_record.ExtendedSocketIPv6Flow{
			LocalIP:    srcIp,
			LocalPort:  uint32(SrcPort),
			Protocol:   uint32(tcpipheader.TCPProtocolNumber),
			RemoteIP:   dstIp,
			RemotePort: uint32(DstPort),
		}))
	} // end if
	enc := sflow.NewEncoder(exporter.outgoingIntf, 0, 0)
	var buf bytes.Buffer
	if uptime, errUt := helper.SysUpTime(); errUt == nil {
		enc.Uptime = uint32(uptime.Milliseconds())
	} // end if
	if errEnc := enc.Encode(&buf, []sflow.Sample{flowSample}); errEnc != nil {
		return nil, errEnc
	} // end if
	return buf.Bytes(), nil
} // end generate_sflow_datagram()

func (exporter *SFlow5Exporter) ifNameForIP(ip net.IP) (ifName string, errIfname error) {
	getter := func() (string, error) {
		localIP, e := helper.LocalIPForPeer(ip)
		if e != nil {
			return "", e
		} // end if
		ifi, ee := helper.IfaceByLocalIP(localIP)
		if ee != nil {
			return "", ee
		} // end if
		return ifi.Name, nil
	}
	if exporter.cache != nil {
		var result *string
		var bHit bool
		if result, bHit, errIfname = mycache.GetOrComputeValueWithTTL[string](exporter.cache, fmt.Sprintf("ifName:%s", ip.To16().String()), func() (*any, error) {
			var p any
			var e error
			p, e = getter()
			return &p, e
		}, 24*time.Hour); result != nil {
			ifName = *result
			if bHit {
				logrus.Debugf("Interface name for IP cache hit: %s -> %s", ip.String(), ifName)
			} // end if
		} // end if
	} else {
		ifName, errIfname = getter()
	} // end if
	return
} // end ifNameForIP()

func (exporter *SFlow5Exporter) ifIndex(ifName string) (ifIndex uint32, errIfindex error) {
	getter := func() (uint32, error) {
		g := &gosnmp.GoSNMP{
			// TODO: configure these values from CLI
			// TODO: configure these values from CLI
			// TODO: configure these values from CLI
			// TODO: configure these values from CLI
			// TODO: configure these values from CLI
			Target:    "localhost",
			Port:      161,
			Community: "public",
			Version:   gosnmp.Version2c,
			Timeout:   3 * time.Second,
			Retries:   1,
		}
		if errConn := g.Connect(); errConn != nil {
			return 0, errConn
		} // end if
		defer g.Conn.Close()
		if idx, errIdx := helper.GetSNMPIfIndex(g, ifName); errIdx != nil {
			return 0, errIdx
		} else {
			return idx, nil
		} // end if
	}
	if exporter.cache != nil {
		var result *uint32
		var bHit bool
		if result, bHit, errIfindex = mycache.GetOrComputeValueWithTTL[uint32](exporter.cache, fmt.Sprintf("ifIndex:%s", ifName), func() (*any, error) {
			var ptr any
			var err error
			ptr, err = getter()
			return &ptr, err
		}, 24*time.Hour); result != nil {
			ifIndex = *result
			if bHit {
				logrus.Debugf("Interface index cache hit: %s -> %d", ifName, ifIndex)
			} // end if
		} // end if
	} else {
		ifIndex, errIfindex = getter()
	} // end if
	return
} // end ifIndex()

func (exporter *SFlow5Exporter) getLocalInterfaceSnmpIndexForPeer(ip net.IP) (uint32, error) {
	ifName, errIfname := exporter.ifNameForIP(ip)
	if errIfname != nil {
		return 0, errIfname
	} // end if
	if ifName == "" {
		return 0, fmt.Errorf("empty ifName")
	} // end if
	return exporter.ifIndex(ifName)
} // end getLocalInterfaceSnmpIndexForPeer()

/*
References:
https://github.com/google/gopacket/blob/master/layers/sflow.go
*/
