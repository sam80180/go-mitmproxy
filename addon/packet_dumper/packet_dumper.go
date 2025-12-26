package packet_dumper

/*
#cgo LDFLAGS: -lpcap
#cgo windows CFLAGS: -I${SRCDIR}/npcsdk/Include
#cgo windows LDFLAGS: -L${SRCDIR}/npcsdk/Lib/x64 -lwpcap
#include <pcap/pcap.h>
#include <stdlib.h>
*/
import "C"

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/ThreeDotsLabs/watermill"
	watermillmsg "github.com/ThreeDotsLabs/watermill/message"
	"github.com/UnwrittenFun/pluralise"
	"github.com/datasapiens/cachier"
	"github.com/go-zeromq/zmq4"
	zmq "github.com/go-zeromq/zmq4" // just want some of the enums, nothing else 😜
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
	"github.com/hetiansu5/urlquery"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/lestrrat-go/strftime"
	mycache "github.com/lqqyt2423/go-mitmproxy/cache"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	myipc "github.com/lqqyt2423/go-mitmproxy/ipc"
	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	mypubsub "github.com/lqqyt2423/go-mitmproxy/pubsub"
	maurice2k_tcpserver "github.com/maurice2k/tcpserver"
	gateway "github.com/net-byte/go-gateway"
	"github.com/rivo/tview"
	"github.com/samber/do/v2"
	"github.com/sirupsen/logrus"
	"github.com/tiendc/gofn"
)

const (
	PACKET_PAYLOAD_SEGMENT_SIZE int = 1400
	DEFAULT_DUMPER_PORT             = 12345
)

const (
	PACKET_DUMP_TYPE_FILE int = iota
	PACKET_DUMP_TYPE_TCP
)

var _PACKET_DUMPER_WORKER_TOPIC string = uuid.New().String()
var _PACKET_DUMPER_SUBSCRIPTION_TOPIC string = uuid.New().String()

type PacketDumperOptions struct {
	Type    string `query:"type" validate:"required,oneof=tcp file"`
	Address string `query:"-"`
	Filter  string `query:"filter"`

	// file output
	FileRotationSize int64  `query:"rotationSize"`
	FileRotationTime string `query:"rotationTime"`
	FileMaxAge       string `query:"maxAge"`
	Path             string `query:"path"`
} // end type

func (opts *PacketDumperOptions) QueryEncode() []byte {
	var b0 []byte
	if opts.Type == "tcp" && opts.Address != "" {
		b0 = []byte(opts.Address)
	} // end if
	var sep []byte = nil
	b1, _ := urlquery.Marshal(opts)
	if len(b1) > 0 && len(b0) > 0 {
		sep = []byte("?")
	} // end if
	return gofn.Concat(b0, sep, b1)
} // end QueryEncode()

func (opts *PacketDumperOptions) String() string {
	return string(opts.QueryEncode())
} // end String()

func (opts *PacketDumperOptions) Set(s string) error {
	return urlquery.Unmarshal([]byte(s), opts)
} // end Set()

func (opts *PacketDumperOptions) UnmarshalJSON(data []byte) error {
	var s any
	if e := json.Unmarshal(data, &s); e != nil {
		return e
	} // end if
	switch reflect.TypeOf(s).Kind() {
	case reflect.String:
		opts.Set(s.(string))
	case reflect.Map:
		if v, ok := s.(map[string]any); ok {
			return helper.JSONCustomTagUnmarshal(v, "query", nil, opts)
		} // end if
	} // end switch
	return nil
} // end UnmarshalJSON()

func (opts *PacketDumperOptions) ToMap() map[string]any {
	b, _ := helper.JSONCustomTagMarshal(opts, "query", "")
	m := map[string]any{}
	json.Unmarshal(b, &m)
	if host, port, okay := helper.ParseHostAndPort(opts.Address); okay {
		m["host"] = host
		m["port"] = port
	} // end if
	return m
} // end ToMap()

func ParsePacketDumperOptions(s string) *PacketDumperOptions {
	opts := DefaultPacketDumperOptions()
	posQ := strings.Index(s, "?")
	urlquery.Unmarshal([]byte(s[int(math.Max(0, float64(posQ+1))):]), &opts)
	switch opts.Type {
	case "file":
		opts = DefaultFilePacketDumperOptions()
	case "tcp":
		opts = DefaultTcpPacketDumperOptions()
	} // end switch
	urlquery.Unmarshal([]byte(s[int(math.Max(0, float64(posQ+1))):]), &opts)
	addrWithoutQuery := s
	if posQ >= 0 {
		addrWithoutQuery = s[0:posQ]
	} // end if
	if host, port, okay := helper.ParseHostAndPort(addrWithoutQuery); okay {
		opts.Address = fmt.Sprintf("%s:%d", host, port)
	} // end if
	return &opts
} // end ParsePacketDumperOptions()

func DefaultFilePacketDumperOptions() PacketDumperOptions {
	return PacketDumperOptions{
		Type: "file",
		Path: "packets-%Y%m%d-%H%M%S.pcap",
		//FileRotationSize: 100 * 1024 * 1024, // 100M
		//FileRotationTime: "24h",             // daily
		//FileMaxAge:       "168h",            // 1 week
	}
} // end DefaultFilePacketDumperOptions()

func DefaultTcpPacketDumperOptions() PacketDumperOptions {
	return PacketDumperOptions{
		Type:    "tcp",
		Address: fmt.Sprintf(":%d", DEFAULT_DUMPER_PORT),
	}
} // end DefaultTcpPacketDumperOptions()

func DefaultPacketDumperOptions() PacketDumperOptions {
	return DefaultTcpPacketDumperOptions()
} // end DefaultPacketDumperOptions()

func TviewForm() map[string]any {
	results := map[string]any{}
	b, _ := helper.JSONCustomTagMarshal(DefaultPacketDumperOptions(), "query", "")
	json.Unmarshal(b, &results)
	app := helper.NewMyTviewFormApplication(helper.MyDefaultTviewAppCustomizer, true, func(form *tview.Form) *tview.Form {
		helper.MyDefaultTviewFormCustomizer(form).SetTitle("Packet Dumper Configuration")
		return form
	})
	form := app.Form
	inputBind := tview.NewInputField().
		SetLabel("Bind IP: ").
		SetFieldWidth(0).
		SetChangedFunc(func(str string) {
			if str != "" {
				if ip := net.ParseIP(str); ip == nil {
					str = ""
				} // end if
			} // end if
			results["host"] = str
		})
	inputPort := tview.NewInputField().
		SetFieldWidth(6).
		SetLabel("Bind Port: ").
		SetAcceptanceFunc(func(s string, _ rune) bool {
			return helper.IsValidPortStr(s)
		}).
		SetChangedFunc(func(s string) {
			results["port"] = s
		})
	fnAddTcpItems := func() {
		app.AddInputFieldWithStatusIcon(inputBind, func(s string, _ rune) bool {
			if s == "" {
				return true
			} // end if
			ip := net.ParseIP(s)
			return (ip != nil)
		}, true)
		app.AddFormItem(inputPort)
	}
	inputPeriod := tview.NewInputField().
		SetLabel("Rotation time: ").
		SetFieldWidth(10).
		SetChangedFunc(func(str string) {
			results["rotationTime"] = str
		})
	inputMaxAge := tview.NewInputField().
		SetLabel("Retention: ").
		SetFieldWidth(10).
		SetChangedFunc(func(str string) {
			results["maxAge"] = str
		})
	inputPath := tview.NewInputField().
		SetLabel("Path: ").
		SetFieldWidth(0).
		SetChangedFunc(func(str string) {
			results["path"] = str
		})
	inputFileSize := tview.NewInputField().
		SetLabel("Split size: ").
		SetFieldWidth(20).
		SetAcceptanceFunc(func(s string, _ rune) bool {
			_, e := strconv.Atoi(s)
			return (e == nil)
		}).
		SetChangedFunc(func(s string) {
			results["rotationSize"] = s
		})
	fnAddFileItems := func() {
		app.AddInputFieldWithStatusIcon(inputPath, func(s string, _ rune) bool {
			_, err := strftime.New(s)
			return (err == nil)
		}, true)
		form.AddFormItem(inputFileSize)
		app.AddInputFieldWithStatusIcon(inputPeriod, func(s string, _ rune) bool {
			_, e := time.ParseDuration(s)
			return (e == nil)
		}, true)
		app.AddInputFieldWithStatusIcon(inputMaxAge, func(s string, _ rune) bool {
			_, e := time.ParseDuration(s)
			return (e == nil)
		}, true)
	}
	handle := C.pcap_open_dead(C.int(layers.LinkTypeEthernet), 65535)
	if handle != nil {
		defer C.pcap_close(handle)
	} // end if
	inputFilter := tview.NewInputField().
		SetLabel("Filter: ").
		SetFieldWidth(0).
		SetChangedFunc(func(str string) {
			results["filter"] = str
		})
	fnAddFilter := func() {
		app.AddInputFieldWithStatusIcon(inputFilter, func(s string, _ rune) bool {
			if s == "" || handle == nil {
				return true
			} // end if
			cExpr := C.CString(s)
			defer C.free(unsafe.Pointer(cExpr))
			var bpf C.struct_bpf_program
			if C.pcap_compile(handle, &bpf, cExpr, 1, 0) < 0 {
				return false
			} // end if
			defer C.pcap_freecode(&bpf)
			return true
		}, true)
	}
	dropdownDumpType := tview.NewDropDown().
		SetLabel("Flow Type: ").
		SetOptions([]string{"File", "TCP"}, func(txt string, index int) {
			results["type"] = strings.ToLower(txt)
			helper.TviewRemoveTrailingFormItems(form)
			switch index {
			case PACKET_DUMP_TYPE_FILE:
				fnAddFileItems()
			case PACKET_DUMP_TYPE_TCP:
				fnAddTcpItems()
			} // end switch
			fnAddFilter()
		})
	form.AddFormItem(dropdownDumpType)
	fnAddFilter()
	form.AddButton("OK", func() {
		app.Stop()
	})
	app.Run()
	return results
} // end TviewForm()

type PacketDumper struct {
	mitmproxy.BaseAddon
	options   PacketDumperOptions
	cache     *cachier.Cache[any]
	isnSecret []byte
	tcpserver *maurice2k_tcpserver.Server
	rotator   io.Writer
	bpf       C.struct_bpf_program // BPF filter

	// for rebuilding packets
	publisherFromAddon      watermillmsg.Publisher
	subscriberRebuildWorker watermillmsg.Subscriber

	// for disseminating to clients
	publisherTcpServer watermillmsg.Publisher
} // end type

// ¡¡¡ DO NOT use 'inproc:' here, as it requires subscribers to be created before publishers !!!
func getOutboundMqEndpoint(opts PacketDumperOptions) (string, error) {
	la, errResolv := net.ResolveTCPAddr("tcp", opts.Address)
	if errResolv != nil {
		return "", errResolv
	} // end if
	ex, errExe := os.Executable()
	if errExe != nil {
		return "", errExe
	} // end if
	exeDir := filepath.Dir(ex)
	socketDir := filepath.Join(exeDir, "tmp")
	if !helper.PathExists(socketDir) {
		os.MkdirAll(socketDir, 0644)
	} // end if
	return fmt.Sprintf("ipc://%s.%d", filepath.Join(socketDir, "PacketDumper"), la.Port), nil
} // end getOutboundMqEndpoint()

func NewPacketDumper(p *mitmproxy.Proxy, opts PacketDumperOptions) (*PacketDumper, error) {
	addon := PacketDumper{
		options:   opts,
		isnSecret: newISNSecret(),
		cache:     p.Cache(),
	}
	pubSub := mypubsub.NewGoChannelPubSub()
	addon.publisherFromAddon = pubSub
	addon.subscriberRebuildWorker = pubSub
	if opts.Filter != "" {
		if errF := addon.updateFilter(opts.Filter); errF != nil {
			return nil, errF
		} // end if
	} // end if
	switch opts.Type {
	case "tcp": // packet dump server
		ep, errEp := getOutboundMqEndpoint(opts)
		if errEp != nil {
			return nil, errEp
		} // end if
		if pubTcpSvr, err := mypubsub.NewZmqPub(mypubsub.ZmqPubSubOptions{Address: ep}); err != nil {
			return nil, err
		} else {
			addon.publisherTcpServer = pubTcpSvr
		} // end if
		server, errSvr := maurice2k_tcpserver.NewServer(opts.Address)
		if errSvr != nil {
			return nil, errSvr
		} // end if
		addon.tcpserver = server
		go (func() {
			server.SetRequestHandler(func(conn maurice2k_tcpserver.Connection) {
				addon.handleConnection(conn)
			})
			server.Listen()
			server.Serve()
		})()
	case "file":
		period, _ := time.ParseDuration(opts.FileRotationTime)
		maxAge, _ := time.ParseDuration(opts.FileMaxAge)
		if maxAge <= 0 {
			maxAge = math.MaxInt64 // https://github.com/lestrrat-go/file-rotatelogs/blob/fa6221d6e82aacf5291bc60a62928c451fd4f1b1/rotatelogs.go#L82-L84
		} // end if
		writer, err := NewRotaPrefixWriter(
			opts.Path,
			rotatelogs.WithRotationSize(opts.FileRotationSize),
			rotatelogs.WithRotationTime(period),
			rotatelogs.WithMaxAge(maxAge),
		)
		if err != nil {
			return nil, err
		} // end if
		writer.(*RotaPrefixWriter).SetHeaderProvider(func(string) []byte {
			fileHeader, _ := pcap_header()
			return fileHeader
		})
		addon.rotator = writer
	default:
		return nil, fmt.Errorf("unsupported packet dumper type ‘%s’", opts.Type)
	} // end switch
	go (func(that *PacketDumper, pub watermillmsg.Publisher, sub watermillmsg.Subscriber) { // worker (rebuild packets)
		sub1, err := sub.Subscribe(context.Background(), _PACKET_DUMPER_WORKER_TOPIC)
		if err != nil {
			log.Fatal(err)
			return
		} // end if
		chIPC := make(chan zmq4.Msg)
		var socketIPC zmq4.Socket
		sockId := zmq4.SocketIdentity("packet_dumper")
		if p.Opts.IPCOptions != nil {
			ipc := do.MustInvoke[*myipc.IPC](p.DI())
			socketIPC = zmq4.NewDealer(context.Background(), zmq4.WithID(sockId))
			if err := socketIPC.Dial(ipc.EndpointBack); err != nil {
				logrus.Errorf("Failed to connect IPC proxy: %+v", err)
				return
			} // end if
			go (func() {
				for {
					if msg, err := socketIPC.Recv(); err != nil {
						logrus.Warnf("Error receiving IPC message: %+v", err)
						continue
					} else {
						chIPC <- msg
					} // end if
				} // end for
			})()
		} // end if
		for {
			select {
			case msg, ok := <-chIPC:
				if !ok {
					logrus.Info("IPC channel closed")
					break
				} // end if
				logrus.WithField("id", sockId.String()).WithField("msg", msg.String()).Info("Process IPC message")
				ipcResp := map[string]any{}
				if len(msg.Frames) >= 1 {
					newOpts := ParsePacketDumperOptions(string(msg.Frames[0]))
					ipcResp["data"] = map[string]any{"old": that.options.Filter, "new": newOpts.Filter}
					if that.options.Filter == newOpts.Filter {
						ipcResp["status"] = http.StatusNotModified
						logrus.WithField("old", that.options.Filter).Debug("BPF filter not changed")
					} else {
						if errF := addon.updateFilter(newOpts.Filter); errF != nil {
							ipcResp["status"] = http.StatusBadRequest
							ipcResp["error"] = errF.Error()
							logrus.WithField("new", newOpts.Filter).Warnf("Failed to update BPF filter: %+v", errF)
						} else {
							ipcResp["status"] = http.StatusOK
							logrus.WithField("old", that.options.Filter).WithField("new", newOpts.Filter).Infof("Update BPF filter")
						} // end if
					} // end if
				} else {
					ipcResp["status"] = http.StatusNotAcceptable
				} // end if
				b, _ := json.Marshal(ipcResp)
				msgResp := zmq4.NewMsg(b)
				logrus.WithField("id", sockId.String()).WithField("msg", msgResp.String()).Info("IPC results")
				socketIPC.Send(msgResp)
			case msg, ok := <-sub1:
				if !ok {
					logrus.Info("Worker channel closed")
					break
				} // end if
				msg.Ack()
				if addon.options.Type == "tcp" && addon.tcpserver.GetActiveConnections() <= 0 {
					continue
				} // end if
				srcAddr, errSrc := net.ResolveTCPAddr("tcp", msg.Metadata["src"])
				if errSrc != nil {
					logrus.WithField("src", msg.Metadata["src"]).Warnf("Failed to parse src address: %+v", errSrc)
					continue
				} // end if
				var dstAddr net.Addr
				if msg.Metadata["dst"] != "" {
					var errDst error
					dstAddr, errDst = net.ResolveTCPAddr("tcp", msg.Metadata["dst"])
					if errDst != nil {
						logrus.WithField("src", msg.Metadata["dst"]).Warnf("Failed to parse dst address: %+v", errDst)
						continue
					} // end if
				} // end if
				stype := msg.Metadata["type"]
				rawPackets, errRebuild := that.rebuildPackets(srcAddr, dstAddr, zmq.SocketType(stype), msg.Payload)
				if errRebuild != nil {
					logrus.Warnf("Failed to rebuild packets: %+v", errRebuild)
					continue
				} // end if
				if that.options.Filter != "" {
					var filtered [][]byte
					for _, pkt := range rawPackets {
						if len(pkt) == 0 {
							continue
						} // end if
						var hdr C.struct_pcap_pkthdr
						hdr.caplen = C.bpf_u_int32(len(pkt))
						hdr.len = C.bpf_u_int32(len(pkt))
						match := C.pcap_offline_filter(&that.bpf, &hdr, (*C.u_char)(unsafe.Pointer(&pkt[0])))
						if match != 0 {
							filtered = append(filtered, pkt)
						} // end if
					} // end for
					numRawPackets := len(rawPackets)
					numFilteredPackets := len(filtered)
					if numRawPackets != numFilteredPackets {
						logrus.Debugf("%d out of %d %s omitted by filter", numRawPackets-numFilteredPackets, numRawPackets, pluralise.WithCountInclusive("packet", numRawPackets))
						rawPackets = filtered
					} // end if
				} // end if
				duration, _ := time.ParseDuration(msg.Metadata["duration"])
				interval := int64(0)
				if numPakcets := len(rawPackets); numPakcets > 1 {
					interval = duration.Nanoseconds() / int64(numPakcets-1)
				} // end if
				for i, rawPacket := range rawPackets {
					if i > 0 {
						time.Sleep(time.Duration(interval) * time.Nanosecond)
					} // end if
					switch opts.Type {
					case "tcp":
						msg := watermillmsg.NewMessage(watermill.NewUUID(), rawPacket)
						if errPub := pub.Publish(_PACKET_DUMPER_SUBSCRIPTION_TOPIC, msg); errPub != nil {
							logrus.Warnf("Error publishing message: %+v", errPub)
						} // end if
					case "file":
						that.rotator.Write(rawPacket)
					} // end switch
				} // end for
			} // end select
		} // end for
	})(&addon, addon.publisherTcpServer, addon.subscriberRebuildWorker)
	logrus.WithField("options", string(opts.QueryEncode())).Info("Packet dumper started")
	return &addon, nil
} // end NewPacketDumper()

// create a 256-bit secret once per process.
func newISNSecret() []byte {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}
	return secret
} // end newISNSecret()

func (that *PacketDumper) updateFilter(s string) error {
	if s == "" {
		s = "greater 0" // a dummy filter that effectively matches all packets
	} // end if
	handle := C.pcap_open_dead(C.int(layers.LinkTypeEthernet), 65535)
	if handle == nil {
		return fmt.Errorf("pcap_open_dead failed")
	} // end if
	//defer C.pcap_close(handle)
	cExpr := C.CString(s)
	//defer C.free(unsafe.Pointer(cExpr))
	if C.pcap_compile(handle, &that.bpf, cExpr, 1, 0) < 0 {
		C.pcap_close(handle)
		C.free(unsafe.Pointer(cExpr))
		return fmt.Errorf("invalid BPF filter")
	} // end if
	//defer C.pcap_freecode(&addon.bpf)
	that.options.Filter = s
	return nil
} // end updateFilter()

// returns a 32-bit Initial Sequence Number per RFC 6528:
// ISN = G(t) + F(K, src, sport, dst, dport)  (mod 2^32)
// G(t) increases by 1 every 4 microseconds. F is a PRF (HMAC-SHA256 here).
func (that *PacketDumper) pickISN(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, secret []byte, now time.Time) uint32 {
	// Normalize IPs to 16 bytes (mapped IPv4 becomes ::ffff:w.x.y.z)
	s := srcIP.To16()
	d := dstIP.To16()
	if s == nil || d == nil {
		panic("invalid IP")
	} // end if

	// Build tuple bytes: srcIP(16) | srcPort(2) | dstIP(16) | dstPort(2)
	var tuple [36]byte
	copy(tuple[0:16], s)
	binary.BigEndian.PutUint16(tuple[16:18], uint16(srcPort))
	copy(tuple[18:34], d)
	binary.BigEndian.PutUint16(tuple[34:36], uint16(dstPort))

	// F = HMAC-SHA256(secret, tuple)
	mac := hmac.New(sha256.New, secret)
	mac.Write(tuple[:])
	sum := mac.Sum(nil)

	// Take the first 32 bits of F
	f := binary.BigEndian.Uint32(sum[0:4])

	// G(t): 32-bit time counter, +1 every 4 microseconds
	// time.Duration is in nanoseconds; 4µs == 4000ns
	g := uint32(uint64(now.UnixNano()/4000) & 0xffffffff)

	return g + f
} // end pickISN()

func (that *PacketDumper) buildL2(srcIp, dstIp net.IP) (gopacket.LinkLayer, error) {
	getter := func(ip net.IP) (map[string]any, error) {
		var ifname string
		var errL2 error
		var myMAC, clientMAC net.HardwareAddr
		myMAC, clientMAC, ifname, errL2 = helper.ResolveMACs(ip)
		if errL2 != nil {
			logrus.Warn(errL2)
		} // end if
		if myMAC == nil {
			myMAC = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		} // end if
		if clientMAC == nil {
			var gwIp net.IP
			if ip.To4() != nil {
				gwIp, _ = gateway.DiscoverGatewayIPv4()
			} else {
				gwIp, _ = gateway.DiscoverGatewayIPv6()
			} // end if
			if gwIp != nil {
				_, clientMAC, _, _ = helper.ResolveMACs(gwIp)
			} // end if
			if clientMAC == nil {
				clientMAC = net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
			} // end if
		} // end if
		return map[string]any{"myMAC": myMAC, "clientMAC": clientMAC, "ifname": ifname}, nil
	}
	var dstArpCache map[string]any
	if that.cache != nil {
		var result *map[string]any
		var bHit bool
		const ttl = 30 * time.Minute
		if result, bHit, _ = mycache.GetOrComputeValueWithTTL[map[string]any](that.cache, fmt.Sprintf("arp:%s-%s", srcIp.String(), dstIp.String()), func() (*any, error) {
			var ptr any
			var err error
			ptr, err = getter(dstIp)
			return &ptr, err
		}, ttl); result != nil {
			dstArpCache = *result
			if bHit {
				logrus.Debugf("ARP cache hit: %s-%s => %+v", srcIp.String(), dstIp.String(), dstArpCache)
			} else {
				mycache.GetOrComputeValueWithTTL[map[string]any](that.cache, fmt.Sprintf("arp:%s-%s", dstIp.String(), srcIp.String()), func() (*any, error) {
					myMAC, _ := helper.ToType[net.HardwareAddr](dstArpCache["clientMAC"])
					clientMAC, _ := helper.ToType[net.HardwareAddr](dstArpCache["myMAC"])
					ifName, _ := helper.ToType[string](dstArpCache["ifname"])
					var ptr any = map[string]any{"myMAC": myMAC, "clientMAC": clientMAC, "ifname": ifName}
					return &ptr, nil
				}, ttl)
			} // end if
		} // end if
	} else {
		dstArpCache, _ = getter(dstIp)
	} // end if
	var myMAC, clientMAC net.HardwareAddr
	if dstArpCache != nil {
		myMAC, _ = helper.ToType[net.HardwareAddr](dstArpCache["myMAC"])
		clientMAC, _ = helper.ToType[net.HardwareAddr](dstArpCache["clientMAC"])
	} // end if
	ethType := layers.EthernetTypeIPv4
	if dstIp.To4() == nil {
		ethType = layers.EthernetTypeIPv6
	} // end if
	return &layers.Ethernet{
		SrcMAC:       myMAC,
		DstMAC:       clientMAC,
		EthernetType: ethType,
	}, nil
} // end buildL2()

func (that *PacketDumper) buildL3(srcIP, dstIP net.IP, proto layers.IPProtocol) (gopacket.NetworkLayer, error) {
	if srcIP.To4() != nil && dstIP.To4() != nil {
		return &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: proto,
			SrcIP:    srcIP,
			DstIP:    dstIP,
		}, nil
	} // end if
	if srcIP.To16() != nil && dstIP.To16() != nil {
		return &layers.IPv6{
			Version:    6,
			HopLimit:   64,
			NextHeader: proto,
			SrcIP:      srcIP,
			DstIP:      dstIP,
		}, nil
	} // end if
	return nil, fmt.Errorf("address family mismatch: src=%v dst=%v", srcIP, dstIP)
} // end buildL3()

func (that *PacketDumper) calcWindow(payloadLen int) uint16 {
	const mss = 1460
	segs := (payloadLen + mss - 1) / mss
	return uint16(segs * mss)
} // end calcWindow()

func (that *PacketDumper) buildL4(SrcPort, DstPort int, ethLayer gopacket.NetworkLayer, payloadLen int, seq uint32, ack uint32) (gopacket.TransportLayer, error) {
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(SrcPort),
		DstPort: layers.TCPPort(DstPort),
		Seq:     seq,
		SYN:     false,
		ACK:     true,
		Ack:     ack,
		PSH:     true,
		Window:  that.calcWindow(payloadLen),
	}
	errChk := tcp.SetNetworkLayerForChecksum(ethLayer)
	return tcp, errChk
} // end buildL4()
/*
//go:linkname getProxyUpstreamConn github.com/lqqyt2423/go-mitmproxy/proxy.(*Proxy).getUpstreamConn
func getProxyUpstreamConn(*mitmproxy.Proxy, context.Context, *http.Request) (net.Conn, error)
*/
func (that *PacketDumper) rebuildPackets(srcAddr, dstAddr net.Addr, stype zmq.SocketType, rawBytes []byte) ([][]byte, error) {
	srcIp, errIpSrc := helper.NetAddrToIP(srcAddr)
	if errIpSrc != nil {
		return nil, errIpSrc
	} // end if
	if stype == zmq.Req {
		if dstAddr == nil {
			req, errReq := helper.BytesToRequest(rawBytes)
			if errReq != nil {
				return nil, errReq
			} // end if
			hostResult, errClassify := helper.ClassifyHost(req.Host)
			if errClassify != nil {
				return nil, errClassify
			} // end if
			if !hostResult.Addr.IsValid() { // probably a FQDN
				reqHost := helper.StripPortIfPresent(req.Host)
				cacheKey := fmt.Sprintf("dns:%s", reqHost)
				getter := func() (string, error) {
					/*
						// https://github.com/lqqyt2423/go-mitmproxy/blob/v1.8.5/proxy/attacker.go#L160
						// https://github.com/lqqyt2423/go-mitmproxy/blob/v1.8.5/proxy/proxy.go#L127
						conn, errDial := getProxyUpstreamConn(that.p, context.Background(), req) //(&net.Dialer{}).DialContext(context.Background(), "tcp", req.Host)
						if errDial != nil {
							return "", fmt.Errorf("failed to dial %s: %+v", req.Host, errDial)
						} // end if
						dstAddr = conn.RemoteAddr()
						dstIp, errIp := helper.NetAddrToIP(dstAddr)
						if errIp != nil {
							return "", errIp
						} // end if
						return dstIp.String(), nil
					*/
					if dstIp, errLookup := helper.LookupAddr(reqHost); errLookup != nil {
						return "", errLookup
					} else {
						return dstIp.String(), nil
					} // end if
				}
				var targetIp string
				if that.cache != nil {
					var result *string
					var bHit bool
					if result, bHit, _ = mycache.GetOrComputeValueWithTTL[string](that.cache, cacheKey, func() (*any, error) {
						var ptr any
						var err error
						ptr, err = getter()
						return &ptr, err
					}, 10*time.Minute); result != nil {
						targetIp = *result
						if bHit {
							logrus.Debugf("DNS cache hit: %s => %s", reqHost, targetIp)
						} // end if
					} // end if
				} else {
					targetIp, _ = getter()
				} // end if
				if targetIp != "" {
					reqPort := 0
					strPort := req.URL.Port()
					if strPort == "" {
						switch req.URL.Scheme {
						case "http":
							reqPort = 80
						case "https":
							reqPort = 443
						} // end switch
					} else {
						reqPort, _ = strconv.Atoi(strPort)
					} // end if
					nip := net.ParseIP(targetIp)
					strZone := ""
					if nip.To4() == nil {
						if a, errParse := netip.ParseAddr(targetIp); errParse == nil {
							strZone = a.Zone()
						} // end if
					} // end if
					dstAddr = &net.TCPAddr{IP: nip, Port: reqPort, Zone: strZone}
				} // end if
			} else {
				tcpAddr, errResolve := net.ResolveTCPAddr("tcp", req.Host)
				if errResolve != nil {
					return nil, fmt.Errorf("failed to resolve address %s: %+v", req.Host, errResolve)
				} // end if
				dstAddr = tcpAddr
			} // end if
		} // end if
	} // end if
	dstIp, errIpDst := helper.NetAddrToIP(dstAddr)
	if errIpDst != nil {
		return nil, errIpDst
	} // end if
	layer2, errL2 := that.buildL2(srcIp, dstIp)
	if errL2 != nil {
		return nil, errL2
	} // end if
	layer3, errL3 := that.buildL3(srcIp, dstIp, layers.IPProtocolTCP)
	if errL3 != nil {
		return nil, errL3
	} // end if
	SrcPort, eSrcPrt := helper.GetPortFromNetAddr(srcAddr)
	if eSrcPrt != nil {
		return nil, eSrcPrt
	} // end if
	DstPort, eDsrPrt := helper.GetPortFromNetAddr(dstAddr)
	if eDsrPrt != nil {
		return nil, eDsrPrt
	} // end if
	layer2Ser, _ := layer2.(gopacket.SerializableLayer)
	layer3Ser, _ := layer3.(gopacket.SerializableLayer)
	isn := that.pickISN(srcIp, SrcPort, dstIp, DstPort, that.isnSecret, time.Now())
	ack := uint32(0)
	if stype == zmq.Req {
		strIsnCacheKey := fmt.Sprintf("tcp_isn:%s:%s", dstAddr, srcAddr)
		ack = that.pickISN(dstIp, DstPort, srcIp, SrcPort, that.isnSecret, time.Now())
		var ptrACK any = ack
		that.cache.Set(strIsnCacheKey, &ptrACK)
	} else {
		strIsnCacheKey := fmt.Sprintf("tcp_isn:%s:%s", srcAddr, dstAddr)
		if _isn, _ := that.cache.Get(strIsnCacheKey); _isn != nil {
			isn, _ = (*_isn).(uint32)
			that.cache.Delete(strIsnCacheKey)
		} // end if
		strAckCacheKey := fmt.Sprintf("tcp_ack:%s:%s", dstAddr, srcAddr)
		if _ack, _ := that.cache.Get(strAckCacheKey); _ack != nil {
			ack, _ = (*_ack).(uint32)
			that.cache.Delete(strAckCacheKey)
		} // end if
	} // end if
	offset := 0
	N := len(rawBytes)
	output := [][]byte{}
	for {
		if offset >= N { // no more
			break
		} // end if
		endIndex := int(math.Min(float64(offset+PACKET_PAYLOAD_SEGMENT_SIZE), float64(N)))
		segment := rawBytes[offset:endIndex]
		offset += PACKET_PAYLOAD_SEGMENT_SIZE
		layer4, errL4 := that.buildL4(SrcPort, DstPort, layer3, len(segment), isn, ack)
		if errL4 != nil {
			return nil, errL4
		} // end if
		packet_buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}
		layer4Ser, _ := layer4.(gopacket.SerializableLayer)
		gopacket.SerializeLayers(packet_buf, opts, layer2Ser, layer3Ser, layer4Ser, gopacket.Payload(segment))
		data := packet_buf.Bytes()
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(data),
			Length:        len(data),
		}
		var buf bytes.Buffer
		bw := bufio.NewWriter(&buf)
		w := pcapgo.NewWriter(bw)
		if errWrite := w.WritePacket(ci, data); errWrite != nil {
			return nil, fmt.Errorf("pcap write failed: %+v", errWrite)
		} // end if
		if errFlush := bw.Flush(); errFlush != nil {
			return nil, fmt.Errorf("buffer flush failed: %+v", errFlush)
		} // end if
		output = append(output, buf.Bytes())
		isn += uint32(len(segment))
		if len(segment) < PACKET_PAYLOAD_SEGMENT_SIZE { // last segment
			break
		} // end if
	} // end for
	if stype == zmq.Req {
		strAckCacheKey := fmt.Sprintf("tcp_ack:%s:%s", srcAddr, dstAddr)
		var ptrISN any = isn
		that.cache.Set(strAckCacheKey, &ptrISN)
	} // end if
	return output, nil
} // end rebuildPackets()

func (that *PacketDumper) Request(flow *mitmproxy.Flow) {
	go (func() {
		dur := flow.ElapsedTime()

		// dump request
		if that.options.Type != "tcp" || that.tcpserver.GetActiveConnections() > 0 {
			httpReq := flow.Request.Raw()
			rawReqBytes, errRawReq := httputil.DumpRequest(httpReq, true)
			if errRawReq != nil {
				logrus.Warnf("Failed to dump request: %+v", errRawReq)
			} else {
				var strDstAddr string
				if flow.ConnContext.ServerConn != nil && flow.ConnContext.ServerConn.Conn != nil {
					strDstAddr = flow.ConnContext.ServerConn.Conn.RemoteAddr().String()
				} // end if
				that.publisherFromAddon.Publish(_PACKET_DUMPER_WORKER_TOPIC, &watermillmsg.Message{
					Metadata: map[string]string{
						"src":      flow.ConnContext.ClientConn.Conn.RemoteAddr().String(),
						"dst":      strDstAddr,
						"type":     string(zmq.Req),
						"duration": dur.String(),
					},
					Payload: rawReqBytes,
				})
			} // end if
		} // end if

		// dump response
		<-flow.Done()
		dur = flow.ElapsedTime()
		if (that.options.Type == "tcp" && that.tcpserver.GetActiveConnections() <= 0) || flow.Response == nil {
			return
		} // end if
		res := flow.Response.Reconstruct()
		rawResBytes, errDump := httputil.DumpResponse(res, true)
		if errDump != nil {
			logrus.Warnf("Failed to dump response: %+v", errDump)
			return
		} // end if
		that.publisherFromAddon.Publish(_PACKET_DUMPER_WORKER_TOPIC, &watermillmsg.Message{
			Metadata: map[string]string{
				"src":      flow.ConnContext.ServerConn.Conn.RemoteAddr().String(),
				"dst":      flow.ConnContext.ClientConn.Conn.RemoteAddr().String(),
				"type":     string(zmq.Rep),
				"duration": dur.String(),
			},
			Payload: rawResBytes,
		})
	})()
} // end Request()

func pcap_header() ([]byte, error) {
	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return nil, err
	} // end if
	return buf.Bytes(), nil
} // end pcap_header()

func (addon *PacketDumper) handleConnection(c net.Conn) error {
	logrus.WithField("client", c.RemoteAddr()).Infof("Packet dumper client connected")
	ep, errEp := getOutboundMqEndpoint(addon.options)
	if errEp != nil {
		return errEp
	} // end if
	sub, errSub := mypubsub.NewZmqSub(mypubsub.ZmqPubSubOptions{Address: ep})
	if errSub != nil {
		return errSub
	} // end if

	// write pcap header
	header, errHdr := pcap_header()
	if errHdr != nil {
		return errHdr
	} // end if
	c.Write(header)

	// send request/response packets
	ctx, fnCancel := context.WithCancel(context.Background())
	defer fnCancel()
	sub1, err := sub.Subscribe(ctx, _PACKET_DUMPER_SUBSCRIPTION_TOPIC)
	if err != nil {
		return err
	} // end if
	go (func(conn net.Conn, cancel context.CancelFunc) { // watch connection
		buf := make([]byte, 1)
		for {
			_, err := conn.Read(buf)
			if err != nil {
				cancel()
				return
			} // end if
			time.Sleep(100 * time.Millisecond)
		} // end for
	})(c, fnCancel)
	for {
		select {
		case <-ctx.Done():
			logrus.WithField("client", c.RemoteAddr()).Infof("Packet dumper client disconnected")
			return nil
		case msg, ok := <-sub1:
			if !ok {
				logrus.WithField("client", c.RemoteAddr()).Infof("Channel closed")
				break
			} // end if
			msg.Ack()
			c.Write(msg.Payload)
		} // end select
	} // end for
	return nil
} // end handleConnection()
