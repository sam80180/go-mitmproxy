package main

import (
	"flag"
	"fmt"
	rawLog "log"
	"math"
	"net/http"
	"os"
	"strings"

	"github.com/hetiansu5/urlquery"
	"github.com/lqqyt2423/go-mitmproxy/addon"
	addon_b "github.com/lqqyt2423/go-mitmproxy/addon/beat"
	addon_nf "github.com/lqqyt2423/go-mitmproxy/addon/netflow"
	addon_pd "github.com/lqqyt2423/go-mitmproxy/addon/packet_dumper"
	addon_sf "github.com/lqqyt2423/go-mitmproxy/addon/sflow"
	mybeater "github.com/lqqyt2423/go-mitmproxy/beater"
	mycache "github.com/lqqyt2423/go-mitmproxy/cache"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	myipc "github.com/lqqyt2423/go-mitmproxy/ipc"
	mymetrics "github.com/lqqyt2423/go-mitmproxy/metrics"
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	mysyslog "github.com/lqqyt2423/go-mitmproxy/syslog"
	mytracing "github.com/lqqyt2423/go-mitmproxy/tracing"
	"github.com/lqqyt2423/go-mitmproxy/web"
	"github.com/phayes/freeport"
	do "github.com/samber/do/v2"
	log "github.com/sirupsen/logrus"
	"github.com/tiendc/gofn"
)

const (
	DEFAULT_PROXY_PORT = 9080
)

type Config struct {
	version bool // show go-mitmproxy version

	Addr            string         // proxy listen addr
	WebAddr         string         // web interface listen addr
	PacketDumper    string         // packet dumper listen address & options
	FlowCollector   string         // flow collector address & options
	MetricsExporter string         // metrics exporter options
	Tracer          string         // trace requests
	Syslog          optionalString // syslog
	Beat            string         // beat config
	IPC             string         // for live update, etc
	SslInsecure     bool           // not verify upstream server SSL/TLS certificates.
	IgnoreHosts     []string       // a list of ignore hosts
	AllowHosts      []string       // a list of allow hosts
	CertPath        string         // path of generate cert files
	Debug           int            // debug mode: 1 - print debug log, 2 - show debug from
	Dump            string         // dump filename
	DumpLevel       int            // dump level: 0 - header, 1 - header + body
	Upstream        string         // upstream proxy
	UpstreamCert    bool           // Connect to upstream server to look up certificate details. Default: True
	MapRemote       string         // map remote config filename
	MapLocal        string         // map local config filename

	filename string // read config from the filename

	ProxyAuth string // Require proxy authentication

}

func capture_beat_flags(di do.Injector) {
	oldName := flag.CommandLine.Name()
	oldErrHandling := flag.CommandLine.ErrorHandling()
	oldOutput := flag.CommandLine.Output()
	tmpFlagSet := flag.NewFlagSet(oldName, oldErrHandling)
	tmpFlagSet.SetOutput(oldOutput)
	flag.CommandLine.VisitAll(func(pf *flag.Flag) { // clone each flag
		tmpFlagSet.Var(pf.Value, pf.Name, pf.Usage)
	})
	do.Provide(di, func(do.Injector) (*flag.FlagSet, error) {
		return tmpFlagSet, nil
	})
	flag.CommandLine = flag.NewFlagSet(oldName, oldErrHandling) // remove all beat's flags
	flag.CommandLine.SetOutput(oldOutput)
} // end capture_beat_flags()

func main() {
	injector := do.New()
	capture_beat_flags(injector)
	config := loadConfig()
	mask_proc_title()

	beatHandlers := []*mybeater.EventHandler{}
	if config.Syslog.IsSet() {
		if config.Syslog.String() == "!" {
			q := mysyslog.TviewForm()
			b, _ := urlquery.Marshal(q)
			config.Syslog.value = string(b)
		} // end if
		if syslogBeatHandler, errSyslog := mysyslog.Setup(config.Syslog.value); errSyslog != nil {
			log.Warn(errSyslog)
		} else if syslogBeatHandler != nil {
			beatHandlers = append(beatHandlers, syslogBeatHandler)
		} // end if
	} // end if
	if config.PacketDumper == "!" {
		q := addon_pd.TviewForm()
		dumperHost := gofn.MapPop(q, "host", "")
		dumperPort := gofn.MapPop(q, "port", addon_pd.DEFAULT_DUMPER_PORT)
		b, _ := urlquery.Marshal(q)
		config.PacketDumper = fmt.Sprintf("%s:%+v?%s", dumperHost, dumperPort, string(b))
	} // end if
	if config.FlowCollector == "!" {
		q := addon.TviewForm()
		flowHost := gofn.MapPop(q, "host", addon_nf.NETFLOW_DEFAULT_EXPORTER_HOST)
		flowPort := gofn.MapPop(q, "port", addon_nf.NETFLOW_COLLECTOR_DEFAULT_PORT)
		b, _ := urlquery.Marshal(q)
		config.FlowCollector = fmt.Sprintf("%s:%+v?%s", flowHost, flowPort, string(b))
	} // end if
	if config.MetricsExporter == "!" {
		q := mymetrics.TviewForm()
		exporterHost := gofn.MapPop(q, "host", "")
		exporterPort := gofn.MapPop(q, "port", mymetrics.DEFAULT_EXPORTER_PORT)
		b, _ := urlquery.Marshal(q)
		config.MetricsExporter = fmt.Sprintf("%s:%+v?%s", exporterHost, exporterPort, string(b))
	} // end if
	if config.Tracer == "!" {
		q := mytracing.TviewForm()
		b, _ := urlquery.Marshal(q)
		config.Tracer = string(b)
	} // end if
	if config.IPC == "!" {
		q := myipc.TviewForm()
		ep := gofn.MapPop(q, "endpoint", "")
		b, _ := urlquery.Marshal(q)
		config.IPC = fmt.Sprintf("%s?%s", ep, string(b))
	} // end if
	if config.Debug > 0 {
		rawLog.SetFlags(rawLog.LstdFlags | rawLog.Lshortfile)
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	if config.Debug == 2 {
		log.SetReportCaller(true)
	}
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	if config.Addr != "" {
		proxyHost, proxyPort, _ := helper.ParseHostAndPort(config.Addr)
		if !helper.IsValidPort(proxyPort) {
			proxyPort, _ = freeport.GetFreePort()
			if helper.IsValidPort(proxyPort) {
				config.Addr = fmt.Sprintf("%s:%d", proxyHost, proxyPort)
			} // end if
		} // end if
	} // end if
	opts := &proxy.Options{
		Debug:             config.Debug,
		Addr:              config.Addr,
		StreamLargeBodies: 1024 * 1024 * 5,
		SslInsecure:       config.SslInsecure,
		CaRootPath:        config.CertPath,
		Upstream:          config.Upstream,
	}
	if config.MetricsExporter != "" {
		opts.MetricsOptions = mymetrics.ParseMetricsOptions(config.MetricsExporter)
	} // end if
	if config.Tracer != "" {
		opts.TracingOptions = mytracing.ParseTracingOptions(config.Tracer)
	} // end if
	if config.IPC != "" {
		opts.IPCOptions = myipc.ParseIPCOptions(config.IPC)
	} // end if

	p, err := proxy.NewProxyWithDI(opts, injector)
	if err != nil {
		log.Fatal(err)
	}
	cacheEngine, errCache := mycache.NewRistrettoCache(1e7)
	if errCache != nil {
		log.Fatal(errCache)
	} // end if
	p.InitCache(cacheEngine)

	if config.version {
		fmt.Println("go-mitmproxy: " + p.Version)
		os.Exit(0)
	}

	log.Infof("go-mitmproxy version %v\n", p.Version)

	if len(config.IgnoreHosts) > 0 {
		p.SetShouldInterceptRule(func(req *http.Request) bool {
			return !helper.MatchHost(req.Host, config.IgnoreHosts)
		})
	}
	if len(config.AllowHosts) > 0 {
		p.SetShouldInterceptRule(func(req *http.Request) bool {
			return helper.MatchHost(req.Host, config.AllowHosts)
		})
	}

	if !config.UpstreamCert {
		p.AddAddon(proxy.NewUpstreamCertAddon(false))
		log.Infoln("UpstreamCert config false")
	}

	if config.ProxyAuth != "" && strings.ToLower(config.ProxyAuth) != "any" {
		log.Infoln("Enable entry authentication")
		auth := NewDefaultBasicAuth(config.ProxyAuth)
		p.SetAuthProxy(auth.EntryAuth)
	}

	p.AddAddon(&proxy.LogAddon{})
	if config.WebAddr != "" {
		_, proxyPort, _ := helper.ParseHostAndPort(config.Addr)
		webHost, webPort, _ := helper.ParseHostAndPort(config.WebAddr)
		if webPort <= 0 {
			if helper.IsValidPort(proxyPort) && helper.IsValidPort(proxyPort+1) {
				config.WebAddr = fmt.Sprintf("%s:%d", webHost, proxyPort+1)
			} // end if
		} // end if
		config.WebAddr = fmt.Sprintf("%s:%d", webHost, webPort)
		p.AddAddon(web.NewWebAddon(config.WebAddr))
	} // end if
	if config.PacketDumper != "" {
		optsPktDump := addon_pd.ParsePacketDumperOptions(config.PacketDumper)
		if addonPktDump, errAddon2 := addon_pd.NewPacketDumper(p, *optsPktDump); errAddon2 != nil {
			log.Errorf("Failed to initialize Packet Dumper addon: %+v", errAddon2)
		} else {
			p.AddAddon(addonPktDump)
		} // end if
	} // end if
	if config.FlowCollector != "" {
		posQ := strings.Index(config.FlowCollector, "?")
		flowExporterOptions := addon.FlowExporterOptions{Type: "netflow"}
		urlquery.Unmarshal([]byte(config.FlowCollector[int(math.Max(0, float64(posQ+1))):]), &flowExporterOptions)
		var flowExp proxy.Addon = nil
		switch flowExporterOptions.Type {
		case "netflow":
			if addonNfExp, errAddon3 := addon_nf.NewNetflowExporter(p, config.FlowCollector); errAddon3 != nil {
				log.Errorf("Failed to initialize NetFlow exporter addon: %+v", errAddon3)
			} else {
				flowExp = addonNfExp
			} // end if
		case "sflow":
			if addonSfExp, errAddon3 := addon_sf.NewSFlow5Exporter(p, config.FlowCollector); errAddon3 != nil {
				log.Errorf("Failed to initialize sFlow exporter addon: %+v", errAddon3)
			} else {
				flowExp = addonSfExp
			} // end if
		case "beat":
			beatAddon := addon_b.NewBeatAddon(config.FlowCollector)
			beatHandlers = append(beatHandlers, beatAddon.BeatHandler)
			flowExp = beatAddon
		default:
			panic(fmt.Sprintf("unsupported flow exporter type ‘%+v’", flowExporterOptions.Type))
		} // end switch
		if flowExp != nil {
			p.AddAddon(flowExp)
		} // end if
	} // end if

	if config.MapRemote != "" {
		mapRemote, err := addon.NewMapRemoteFromFile(config.MapRemote)
		if err != nil {
			log.Warnf("load map remote error: %v", err)
		} else {
			p.AddAddon(mapRemote)
		}
	}

	if config.MapLocal != "" {
		mapLocal, err := addon.NewMapLocalFromFile(config.MapLocal)
		if err != nil {
			log.Warnf("load map local error: %v", err)
		} else {
			p.AddAddon(mapLocal)
		}
	}

	if config.Dump != "" {
		dumper := addon.NewDumperWithFilename(config.Dump, config.DumpLevel)
		p.AddAddon(dumper)
	}
	if len(beatHandlers) > 0 {
		go (func() { // can only have 1 beater
			opts := mybeater.ParseBeatOptions(config.Beat)
			mybeater.Launch(injector, *opts, beatHandlers)
		})()
	} // end if
	log.Fatal(p.Start())
}
