package netflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strconv"
	"strings"
	"time"

	tcp_consts "github.com/cilium/cilium/pkg/option"
	"github.com/datasapiens/cachier"
	validator "github.com/go-playground/validator/v10"
	"github.com/gosnmp/gosnmp"
	"github.com/hetiansu5/urlquery"
	"github.com/ipinfo/go/v2/ipinfo"
	"github.com/jamesog/iptoasn"
	addon_pd "github.com/lqqyt2423/go-mitmproxy/addon/packet_dumper"
	mycache "github.com/lqqyt2423/go-mitmproxy/cache"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/lqqyt2423/go-mitmproxy/udpclient"
	gateway "github.com/net-byte/go-gateway"
	"github.com/rivo/tview"
	"github.com/sirupsen/logrus"
	nf1 "github.com/tehmaze/netflow/netflow1"
	nf5 "github.com/tehmaze/netflow/netflow5"
	nf6 "github.com/tehmaze/netflow/netflow6"
	nf7 "github.com/tehmaze/netflow/netflow7"
	nf9 "github.com/tehmaze/netflow/netflow9"
)

const (
	NETFLOW_COLLECTOR_DEFAULT_PORT        = 2055
	NETFLOW_DEFAULT_VERSION        uint16 = nf9.Version
	NETFLOW_DEFAULT_EXPORTER_HOST         = "localhost"
)

type netflowPacketBuilderImpl interface {
	Build(srcAddr, dstAddr net.Addr, rawReqBytes []byte, firstSwitched time.Duration, rawRepBytes []byte, lastSwitched time.Duration) ([]byte, error)
} // end type

type baseNetflowPacketBuilder struct {
	options *NetflowExporterOptions
	cache   *cachier.Cache[any]
} // end type

func (*baseNetflowPacketBuilder) Build(_, _ net.Addr, _ []byte, _ time.Duration, _ []byte, _ time.Duration) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
} // end Build()

func (builder *baseNetflowPacketBuilder) Ip2Asn(ip net.IP) uint32 {
	if ip.IsPrivate() {
		return 0
	} // end if
	getter := func() (uint32, error) {
		asn, e := iptoasn.LookupIP(ip.String())
		if e == nil {
			return asn.ASNum, e
		} // end if

		// try another method
		var ipinfoCore ipinfo.Core
		statusCode, _, errHttp := helper.HttpGetRequest("https://ipinfo.io", fmt.Sprintf("/%s/json", ip.String()), nil, nil, &ipinfoCore)
		if errHttp != nil {
			return 0, errHttp
		} // end if
		if statusCode != http.StatusOK {
			return 0, nil
		} // end if
		reOrg := regexp.MustCompile(`AS(?P<asn>[0-9]+) .+`)
		match := reOrg.FindStringSubmatch(ipinfoCore.Org)
		if match != nil {
			idxAsn := reOrg.SubexpIndex("asn")
			if intAsn, errConv := strconv.Atoi(match[idxAsn]); errConv != nil {
				return 0, errConv
			} else {
				return uint32(intAsn), nil
			} // end if
		} // end if
		return 0, nil
	}
	var asn uint32
	if builder.cache != nil {
		if ptrAsn, bHit, _ := mycache.GetOrComputeValueWithTTL[uint32](builder.cache, fmt.Sprintf("asn:%s", ip.String()), func() (*any, error) {
			var ptr any
			var err error
			ptr, err = getter()
			return &ptr, err
		}, 24*time.Hour); ptrAsn != nil {
			asn = *ptrAsn
			if bHit {
				logrus.Debugf("ASN cache hit: %s -> %d", ip.String(), asn)
			} // end if
		} // end if
	} else {
		asn, _ = getter()
	} // end if
	return asn
} // end Ip2Asn()

func (builder *baseNetflowPacketBuilder) NextHop() net.IP {
	getter := func() (net.IP, error) {
		gwIp, _ := gateway.DiscoverGatewayIPv4()
		if gwIp != nil {
			return gwIp.To4(), nil
		} // end if
		return gateway.DiscoverGatewayIPv6()
	}
	var gwIp net.IP
	if builder.cache != nil {
		if result, bHit, _ := mycache.GetOrComputeValueWithTTL[net.IP](builder.cache, "nexthop", func() (*any, error) {
			var ptr any
			var err error
			ptr, err = getter()
			return &ptr, err
		}, 24*time.Hour); result != nil {
			gwIp = *result
			if bHit {
				logrus.Debugf("Next hop cache hit: %s", gwIp.String())
			} // end if
		} // end if
	} else {
		gwIp, _ = getter()
	} // end if
	return gwIp
} // end NextHop()

func (builder *baseNetflowPacketBuilder) ifNameForIP(ip net.IP) (ifName string, err error) {
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
	if builder.cache != nil {
		var result *string
		var bHit bool
		if result, bHit, err = mycache.GetOrComputeValueWithTTL[string](builder.cache, fmt.Sprintf("ifName:%s", ip.To16().String()), func() (*any, error) {
			var ptr any
			var err error
			ptr, err = getter()
			return &ptr, err
		}, 24*time.Hour); result != nil {
			ifName = *result
			if bHit {
				logrus.Debugf("Interface name for IP cache hit: %s -> %s", ip.String(), ifName)
			} // end if
		} // end if
	} else {
		ifName, err = getter()
	} // end if
	return
} // end ifNameForIP()

func (builder *baseNetflowPacketBuilder) ifIndex(ifName string) (ifIndex uint32, err error) {
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
		return helper.GetSNMPIfIndex(g, ifName)
	}
	if builder.cache != nil {
		var result *uint32
		var bHit bool
		if result, bHit, err = mycache.GetOrComputeValueWithTTL[uint32](builder.cache, fmt.Sprintf("ifIndex:%s", ifName), func() (*any, error) {
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
		ifIndex, err = getter()
	} // end if
	return
} // end ifIndex()

func (builder *baseNetflowPacketBuilder) getLocalInterfaceSnmpIndexForPeer(ip net.IP) (uint32, error) {
	ifName, errIfname := builder.ifNameForIP(ip)
	if errIfname != nil {
		return 0, errIfname
	} // end if
	if ifName == "" {
		return 0, fmt.Errorf("empty ifName")
	} // end if
	return builder.ifIndex(ifName)
} // end getLocalInterfaceSnmpIndexForPeer()

func initBaseNetflowPacketBuilder(cache *cachier.Cache[any], options *NetflowExporterOptions) baseNetflowPacketBuilder {
	return baseNetflowPacketBuilder{options: options, cache: cache}
} // end initBaseNetflowPacketBuilder()

type netflowExporterImpl interface {
	DoExport(b any) error
} // end type

type NetflowExporterOptions struct {
	Version       uint16 `query:"version" validate:"required,oneof=1 5 6 7 8 9 10"`
	TemplateID    uint16 `query:"templateId" validate:"omitempty,min=1"`
	V8Aggregation byte   `query:"v8Aggregation" validate:"omitempty,min=1,max=14"`
} // end type

func (opts *NetflowExporterOptions) QueryEncode() []byte {
	b1, _ := urlquery.Marshal(opts)
	return b1
} // end QueryEncode()

func DefaultNetflowExporterOptions() NetflowExporterOptions {
	return NetflowExporterOptions{
		Version:       NETFLOW_DEFAULT_VERSION,
		TemplateID:    (&MyIPFlowInfoRecord{}).getTemplateId(),
		V8Aggregation: 8,
	}
} // end DefaultNetflowExporterOptions()

func TviewFormItems(form *tview.Form, results map[string]any) []tview.FormItem {
	// set default values
	defaultNetflowOpts := DefaultNetflowExporterOptions()
	b, _ := helper.JSONCustomTagMarshal(defaultNetflowOpts, "query", "")
	json.Unmarshal(b, &results)

	// setup form items
	v8_agg_methods := []string{
		" 1. AS",
		" 2. Protocol-Port",
		" 3. Source-Prefix",
		" 4. Destination-Prefix",
		" 5. Prefix",
		" 6. Destination",
		" 7. Source-Destination",
		" 8. Full-Flow",
		" 9. AS-TOS",
		"10. Protocol-Port-TOS",
		"11. Source-Prefix-TOS",
		"12. Destination-Prefix-TOS",
		"13. Prefix-TOS",
		"14. Prefix-Port",
	}
	dropdownNf8AggMthd := tview.NewDropDown().
		SetLabel("Aggregation Method: ").
		SetOptions(v8_agg_methods, func(_ string, index int) {
			results["v8Aggregation"] = index + 1
		})
	inputNfTplId := tview.NewInputField().
		SetLabel("Template ID: ").
		SetChangedFunc(func(s string) {
			if s == "" {
				s = fmt.Sprintf("%+v", defaultNetflowOpts.TemplateID)
			} // end if
			results["templateId"] = s
		}).
		SetPlaceholder(fmt.Sprintf("%+v", defaultNetflowOpts.TemplateID)).
		SetAcceptanceFunc(func(s string, _ rune) bool {
			_, e := strconv.Atoi(s)
			return e == nil
		})
	nf_versions := []string{"1", "5", "6", "7", "8", "9", "10"}
	dropdownNfVer := tview.NewDropDown().
		SetLabel("Version: ").
		SetOptions(nf_versions, func(txt string, _ int) {
			results["version"] = txt
			helper.TviewRemoveTrailingFormItems(form)
			switch txt {
			case "8":
				form.AddFormItem(dropdownNf8AggMthd)
			case "9", "10":
				form.AddFormItem(inputNfTplId)
			} // end switch
		})
	return []tview.FormItem{dropdownNfVer}
} // end TviewFormItems()

type NetflowExporter struct {
	mitmproxy.BaseAddon
	options  NetflowExporterOptions
	exporter netflowExporterImpl
	builder  netflowPacketBuilderImpl
} // end type

type udpExporter struct {
	udpClient *udpclient.UdpClient
} // end type

func (exporter *udpExporter) DoExport(b any) error {
	return exporter.udpClient.Send(b.([]byte))
} // end DoExport()

func (nf *NetflowExporter) initUdpExporter(addr string) error {
	exporter, errClient := udpclient.NewUdpClient(
		addr,
		udpclient.WithBackoff(200*time.Millisecond, 5*time.Second),
		udpclient.WithQueueSize(256),
		udpclient.WithOnConnect(func(*net.UDPConn) {

		}),
		udpclient.WithOnDisconnect(func(e error) {
			logrus.WithField("collector_addr", addr).Infof("Netflow collector disconnected")
		}),
	)
	if errClient != nil {
		return errClient
	} // end if
	exporter.Start()
	nf.exporter = &udpExporter{udpClient: exporter}
	return nil
} // end initUdpExporter()

func NewNetflowExporter(p *mitmproxy.Proxy, addr string) (mitmproxy.Addon, error) {
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
		exporterHost = NETFLOW_DEFAULT_EXPORTER_HOST
	} // end if
	var exporterPort int = NETFLOW_COLLECTOR_DEFAULT_PORT
	posColon := strings.LastIndex(addrWithoutQuery, ":")
	if posColon >= 0 {
		if v := addrWithoutQuery[posColon+1:]; helper.IsValidPortStr(v) {
			exporterPort, _ = strconv.Atoi(v)
		} // end if
	} // end if
	addrWithoutQuery = fmt.Sprintf("%s:%d", exporterHost, exporterPort)
	options := DefaultNetflowExporterOptions()
	urlquery.Unmarshal([]byte(addr[int(math.Max(0, float64(posQ+1))):]), &options)
	validate := validator.New(validator.WithRequiredStructEnabled())
	if errValidat := validate.Struct(options); errValidat != nil {
		var validateErrs validator.ValidationErrors
		if errors.As(errValidat, &validateErrs) {
			for _, validateErr := range validateErrs {
				/*
					if validateErr.ActualTag() == "oneof" {
						panic(fmt.Sprintf("%s has invalid value, must be: %+v", validateErr.Namespace(), validateErr.Param()))
					} // end if
				*/
				panic(fmt.Errorf("%+v: param= %+v", validateErr, validateErr.Param()))
			} // end if
		} // end if
	} // end if
	var builder netflowPacketBuilderImpl
	cache := p.Cache()
	switch options.Version {
	case nf1.Version:
		builder = NewNetflow1PacketBuilder(cache)
	case nf5.Version:
		builder = NewNetflow5PacketBuilder(cache)
	case nf6.Version:
		builder = NewNetflow6PacketBuilder(cache)
	case nf7.Version:
		builder = NewNetflow7PacketBuilder(cache, addrWithoutQuery)
	case Version8:
		builder = NewNetflow8PacketBuilder(cache, addrWithoutQuery, options)
	case nf9.Version:
		builder = NewNetflow9PacketBuilder(cache, options)
	case Version10:
		builder = NewNetflow10PacketBuilder(cache, options)
	default:
		panic(fmt.Sprintf("unsupported NetFlow version ‘%+v’", options.Version))
	} // end switch
	nfExporter := &NetflowExporter{options: options, builder: builder}
	errExptr := nfExporter.initUdpExporter(addrWithoutQuery)
	if errExptr != nil {
		return nil, errExptr
	} // end if
	logrus.WithField("options", string(options.QueryEncode())).WithField("collector_addr", addrWithoutQuery).Info("Netflow exporter initialized")
	return nfExporter, nil
} // end NewNetflowExporter()

func (that *NetflowExporter) Request(flow *mitmproxy.Flow) {
	firstSwitched, errT0 := helper.SysUpTime()
	if errT0 != nil {
		logrus.Warnf("Failed to get system uptime: %+v", errT0)
		return
	} // end if
	go (func() {
		<-flow.Done()
		lastSwitched, errT1 := helper.SysUpTime()
		if errT1 != nil {
			logrus.Warnf("Failed to get system uptime: %+v", errT1)
			return
		} // end if
		httpReq := flow.Request.Raw()
		rawReqBytes, errRawReq := httputil.DumpRequest(httpReq, true)
		if errRawReq != nil {
			logrus.Warnf("Failed to dump request: %+v", errRawReq)
		} // end if
		res := flow.Response.Reconstruct()
		rawResBytes, errDump := httputil.DumpResponse(res, true)
		if errDump != nil {
			logrus.Warnf("Failed to dump response: %+v", errDump)
		} // end if
		b, errBuild := that.builder.Build(flow.ConnContext.ClientConn.Conn.RemoteAddr(), flow.ConnContext.ServerConn.Conn.RemoteAddr(), rawReqBytes, firstSwitched, rawResBytes, lastSwitched)
		if errBuild != nil {
			logrus.Warnf("Failed to build NetFlow packet: %+v", errBuild)
			return
		} // end if
		if len(b) > 0 {
			that.exporter.DoExport(b)
		} // end if
	})()
} // end Request()

func getRouterSC(addr string) (net.IP, error) {
	if host, _, bMatched := helper.ParseHostAndPort(addr); bMatched {
		if hostResult, _ := helper.ClassifyHost(host); hostResult != nil {
			if !hostResult.Addr.IsValid() { // probably a FQDN
				if ip, _ := helper.LookupAddr(host); ip != nil {
					host = ip.String()
				} // end if
			} // end if
		} // end if
		if sc, errIp := helper.LocalIPForPeer(net.ParseIP(host)); errIp == nil && sc != nil {
			return sc, nil
		} // end if
	} // end if
	return nil, nil
} // end getRouterSC()

func getTCPFlags(CWR, ECE, URG, ACK, PSH, RST, SYN, FIN bool) uint16 {
	var flags uint16 = 0
	if FIN {
		flags = flags | tcp_consts.TCP_FIN
	} // end if
	if SYN {
		flags = flags | tcp_consts.TCP_SYN
	} // end if
	if RST {
		flags = flags | tcp_consts.TCP_RST
	} // end if
	if PSH {
		flags = flags | tcp_consts.TCP_PSH
	} // end if
	if ACK {
		flags = flags | tcp_consts.TCP_ACK
	} // end if
	if URG {
		flags = flags | tcp_consts.TCP_URG
	} // end if
	if ECE {
		flags = flags | tcp_consts.TCP_ECE
	} // end if
	if CWR {
		flags = flags | tcp_consts.TCP_CWR
	} // end if
	return flags
} // end getTCPFlags()

func packetCount(payload []byte) uint64 {
	return uint64(math.Ceil(float64(len(payload)) / float64(addon_pd.PACKET_PAYLOAD_SEGMENT_SIZE)))
} // end packetCount()

func now_sec_nsec() (int64, int64) {
	t := time.Now().UnixNano()
	sec := t / int64(time.Second)
	nsec := t - sec*int64(time.Second)
	return sec, nsec
} // end now_sec_nsec()
