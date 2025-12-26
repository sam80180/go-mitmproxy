package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"

	"github.com/lqqyt2423/go-mitmproxy/addon"
	addon_pd "github.com/lqqyt2423/go-mitmproxy/addon/packet_dumper"
	mybeater "github.com/lqqyt2423/go-mitmproxy/beater"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	myipc "github.com/lqqyt2423/go-mitmproxy/ipc"
	mymetrics "github.com/lqqyt2423/go-mitmproxy/metrics"
	mysyslog "github.com/lqqyt2423/go-mitmproxy/syslog"
	mytracing "github.com/lqqyt2423/go-mitmproxy/tracing"
	log "github.com/sirupsen/logrus"
)

func loadConfigFromFile(filename string) (*Config, error) {
	var config Config
	if err := helper.NewStructFromFile(filename, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

type optionalString struct {
	Name  string
	set   bool
	value string
} // end type

func (o *optionalString) String() string { return o.value } // end String()

func (o *optionalString) IsSet() bool { return o.set } // end IsSet()

func (o *optionalString) Set(s string) error {
	o.set = true
	bLastVal := ""
	reNoVal := regexp.MustCompile(fmt.Sprintf(`^[-]{1,2}%s$`, o.Name))
	reExpVal := regexp.MustCompile(fmt.Sprintf(`^[-]{1,2}%s=.*`, o.Name))
	for i := 1; i < len(os.Args); i++ {
		argv := os.Args[i]
		if reNoVal.MatchString(argv) { // no value
			bLastVal = ""
		} else if reExpVal.MatchString(argv) { // explicit value
			bLastVal = s
		} // end if
	} // end for
	o.value = bLastVal
	return nil
} // end Set()

func (o *optionalString) IsBoolFlag() bool {
	return true // This lets `-mode` work without an explicit value
} // end IsBoolFlag()

func (o *optionalString) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	} // end if
	return o.Set(s)
} // end UnmarshalJSON()

func loadConfigFromCli() *Config {
	config := Config{Syslog: optionalString{Name: "syslog"}}

	flag.BoolVar(&config.version, "version", false, "show go-mitmproxy version")
	flag.StringVar(&config.Addr, "addr", fmt.Sprintf(":%d", DEFAULT_PROXY_PORT), "proxy listen addr")
	flag.StringVar(&config.WebAddr, "web_addr", "", "web interface listen addr")

	defaultPktDumpOpts := addon_pd.DefaultPacketDumperOptions()
	flag.StringVar(&config.PacketDumper, "packet_dumper", "", fmt.Sprintf("start packet dumper server (default: %s)", string(defaultPktDumpOpts.QueryEncode())))

	defaultFlowOptions := addon.DefaultFlowExporterOptions()
	flag.StringVar(&config.FlowCollector, "flow_exporter", "", fmt.Sprintf("start flow exporter (default: %s)", string(defaultFlowOptions.QueryEncode())))

	defaultMetricsOptions := mymetrics.DefaultPormetheusMetricsOptions()
	flag.StringVar(&config.MetricsExporter, "metrics_exporter", "", fmt.Sprintf("start metrics exporter (default: %s)", string(defaultMetricsOptions.QueryEncode())))

	defaultTracingOptions := mytracing.DefaultTracingOptions()
	flag.StringVar(&config.Tracer, "tracing", "", fmt.Sprintf("trace requests (default: %s)", string(defaultTracingOptions.QueryEncode())))

	defaultSyslogOptions := mysyslog.DefaultSyslogOptions()
	flag.Var(&config.Syslog, config.Syslog.Name, fmt.Sprintf("enable syslog (default: %s)", defaultSyslogOptions.QueryEncode()))

	defaultBeatOptions := mybeater.DefaultBeatOptions()
	flag.StringVar(&config.Beat, "beat", "", fmt.Sprintf("beat config [needed when type of '-syslog' or '-flow_exporter' is \"beat\"] (default: %s)", string(defaultBeatOptions.QueryEncode())))

	defaultIpcOptions := myipc.DefaultIPCOptions()
	flag.StringVar(&config.IPC, "ipc", "", fmt.Sprintf("enable IPC (default: %s)", string(defaultIpcOptions.QueryEncode())))

	flag.BoolVar(&config.SslInsecure, "ssl_insecure", false, "not verify upstream server SSL/TLS certificates.")
	flag.Var((*arrayValue)(&config.IgnoreHosts), "ignore_hosts", "a list of ignore hosts")
	flag.Var((*arrayValue)(&config.AllowHosts), "allow_hosts", "a list of allow hosts")
	flag.StringVar(&config.CertPath, "cert_path", "", "path of generate cert files")
	flag.IntVar(&config.Debug, "debug", 0, "debug mode: 1 - print debug log, 2 - show debug from")
	flag.StringVar(&config.Dump, "dump", "", "dump filename")
	flag.IntVar(&config.DumpLevel, "dump_level", 0, "dump level: 0 - header, 1 - header + body")
	flag.StringVar(&config.Upstream, "upstream", "", "upstream proxy")
	flag.BoolVar(&config.UpstreamCert, "upstream_cert", true, "connect to upstream server to look up certificate details")
	flag.StringVar(&config.MapRemote, "map_remote", "", "map remote config filename")
	flag.StringVar(&config.MapLocal, "map_local", "", "map local config filename")
	flag.StringVar(&config.filename, "f", "", "read config from the filename")

	flag.StringVar(&config.ProxyAuth, "proxyauth", "", `enable proxy authentication. Format: "username:pass", "user1:pass1|user2:pass2","any" to accept any user/pass combination`)
	flag.Parse()

	return &config
}

func mergeConfigs(fileConfig, cliConfig *Config) *Config {
	config := new(Config)
	*config = *fileConfig
	if cliConfig.Addr != "" {
		config.Addr = cliConfig.Addr
	}
	if cliConfig.WebAddr != "" {
		config.WebAddr = cliConfig.WebAddr
	}
	if cliConfig.PacketDumper != "" {
		config.PacketDumper = cliConfig.PacketDumper
	} // end if
	if cliConfig.FlowCollector != "" {
		config.FlowCollector = cliConfig.FlowCollector
	} // end if
	if cliConfig.MetricsExporter != "" {
		config.MetricsExporter = cliConfig.MetricsExporter
	} // end if
	if cliConfig.Tracer != "" {
		config.Tracer = cliConfig.Tracer
	} // end if
	if cliConfig.Syslog.IsSet() {
		config.Syslog = cliConfig.Syslog
	} // end if
	if cliConfig.Beat != "" {
		config.Beat = cliConfig.Beat
	} // end if
	if cliConfig.IPC != "" {
		config.IPC = cliConfig.IPC
	} // end if
	if cliConfig.SslInsecure {
		config.SslInsecure = cliConfig.SslInsecure
	}
	if len(cliConfig.IgnoreHosts) > 0 {
		config.IgnoreHosts = cliConfig.IgnoreHosts
	}
	if len(cliConfig.AllowHosts) > 0 {
		config.AllowHosts = cliConfig.AllowHosts
	}
	if cliConfig.CertPath != "" {
		config.CertPath = cliConfig.CertPath
	}
	if cliConfig.Debug != 0 {
		config.Debug = cliConfig.Debug
	}
	if cliConfig.Dump != "" {
		config.Dump = cliConfig.Dump
	}
	if cliConfig.DumpLevel != 0 {
		config.DumpLevel = cliConfig.DumpLevel
	}
	if cliConfig.Upstream != "" {
		config.Upstream = cliConfig.Upstream
	}
	if !cliConfig.UpstreamCert {
		config.UpstreamCert = cliConfig.UpstreamCert
	}
	if cliConfig.MapRemote != "" {
		config.MapRemote = cliConfig.MapRemote
	}
	if cliConfig.MapLocal != "" {
		config.MapLocal = cliConfig.MapLocal
	}
	return config
}

func loadConfig() *Config {
	cliConfig := loadConfigFromCli()
	if cliConfig.version {
		return cliConfig
	}
	if cliConfig.filename == "" {
		return cliConfig
	}

	fileConfig, err := loadConfigFromFile(cliConfig.filename)
	if err != nil {
		log.Warnf("read config from %v error %v", cliConfig.filename, err)
		return cliConfig
	}
	return mergeConfigs(fileConfig, cliConfig)
}

// arrayValue 实现了 flag.Value 接口
type arrayValue []string

func (a *arrayValue) String() string {
	return fmt.Sprint(*a)
}

func (a *arrayValue) Set(value string) error {
	*a = append(*a, value)
	return nil
}
