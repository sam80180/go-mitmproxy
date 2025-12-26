package metrics

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"reflect"
	"strings"

	zmq "github.com/go-zeromq/zmq4" // just want some of the enums, nothing else 😜
	"github.com/hetiansu5/urlquery"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	mysnmp "github.com/lqqyt2423/go-mitmproxy/snmp"
	"github.com/phayes/freeport"
	"github.com/rivo/tview"
	"github.com/tiendc/gofn"
)

const (
	METRIC_TYPE_PROM int = iota
	METRIC_TYPE_SNMP
	METRIC_TYPE_DD

	DEFAULT_EXPORTER_PORT = 9100
	DEFAULT_METRICS_PATH  = "/metrics"
)

type MetricsOptions struct {
	Addr            string `query:"-"`
	Type            string `query:"type" validate:"required,oneof=prometheus snmp datadog"`
	Mode            string `query:"mode"`
	RefreshInterval string `query:"snmp_refresh_interval"`

	// Prometheus
	MetricsPath string `query:"metrics_path"`

	// SNMP
	SNMPCommunity string `query:"snmp_community" mask:"zero"`
} // end type

func (opts *MetricsOptions) QueryEncode() []byte {
	var b0 []byte
	if opts.Addr != "" {
		b0 = []byte(opts.Addr)
	} // end if
	var sep []byte = nil
	b1, _ := urlquery.Marshal(opts)
	if len(b1) > 0 && len(b0) > 0 {
		sep = []byte("?")
	} // end if
	return gofn.Concat(b0, sep, b1)
} // end QueryEncode()

func (opts *MetricsOptions) String() string {
	return string(opts.QueryEncode())
} // end String()

func (opts *MetricsOptions) Set(s string) error {
	return urlquery.Unmarshal([]byte(s), opts)
} // end Set()

func (opts *MetricsOptions) UnmarshalJSON(data []byte) error {
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

func DefaultPormetheusMetricsOptions() MetricsOptions {
	return MetricsOptions{
		Addr:        fmt.Sprintf(":%d", DEFAULT_EXPORTER_PORT),
		Type:        "prometheus",
		Mode:        string(zmq.Pull),
		MetricsPath: DEFAULT_METRICS_PATH,
	}
} // end DefaultPormetheusMetricsOptions()

func DefaultSnmpMetricsOptions() MetricsOptions {
	return MetricsOptions{
		Addr:            fmt.Sprintf(":%d", mysnmp.SNMPD_DEFAULT_PORT),
		Type:            "snmp",
		Mode:            string(zmq.Pull),
		SNMPCommunity:   mysnmp.SNMPD_DEFAULT_COMMUNITY,
		RefreshInterval: mysnmp.SNMPD_DEFAULT_REFRESH_INTERVAL,
	}
} // end DefaultSnmpMetricsOptions()

func DefaultDatadogMetricsOptions() MetricsOptions {
	return MetricsOptions{
		Addr:            "http://localhost:4317",
		Type:            "datadog",
		Mode:            string(zmq.Push),
		RefreshInterval: "60s",
	}
} // end DefaultDatadogMetricsOptions()

func DefaultMetricsOptions() MetricsOptions {
	return DefaultPormetheusMetricsOptions()
} // end DefaultMetricsOptions()

func PromTviewFormItems(form *tview.Form, results map[string]any) []tview.FormItem {
	inputPath := tview.NewInputField().
		SetLabel("Metrics Path: ").
		SetChangedFunc(func(s string) {
			if s == "" {
				s = DEFAULT_METRICS_PATH
			} // end if
			results["metrics_path"] = s
		}).
		SetPlaceholder(DEFAULT_METRICS_PATH)
	dropdownMode := tview.NewDropDown().
		SetLabel("Mode: ").
		SetOptions([]string{"Pull", "Push"}, func(txt string, _ int) {
			results["mode"] = strings.ToUpper(txt)
			helper.TviewRemoveTrailingFormItems(form)
			switch results["mode"] {
			case string(zmq.Pull):
				form.AddFormItem(inputPath)
			} // end switch
		})
	return []tview.FormItem{dropdownMode}
} // end PromTviewFormItems()

func TviewForm() map[string]any {
	b, _ := helper.JSONCustomTagMarshal(DefaultMetricsOptions(), "query", "")
	results := map[string]any{"port": DEFAULT_EXPORTER_PORT}
	json.Unmarshal(b, &results)
	app := tview.NewApplication()
	form := tview.NewForm()
	formItemsSnmp := SnmpTviewFormItems(form, results)
	formItemsProm := PromTviewFormItems(form, results)
	dropdownMetricsType := tview.NewDropDown().
		SetLabel("Type: ").
		SetOptions([]string{"Prometheus", "SNMP", "Datadog"}, func(txt string, index int) {
			results["type"] = strings.ToLower(txt)
			helper.TviewRemoveTrailingFormItems(form)
			switch index {
			case METRIC_TYPE_PROM:
				for _, item := range formItemsProm {
					form.AddFormItem(item)
				} // end for
			case METRIC_TYPE_SNMP:
				for _, item := range formItemsSnmp {
					form.AddFormItem(item)
				} // end for
			} // end switch
		})
	form.AddInputField("Bind IP: ", "", 0, nil, func(str string) {
		if str != "" {
			if ip := net.ParseIP(str); ip == nil {
				str = ""
			} // end if
		} // end if
		results["host"] = str
	})
	form.AddInputField("Bind Port: ", "", 6, func(s string, _ rune) bool {
		return helper.IsValidPortStr(s)
	}, func(s string) {
		var p any = s
		if strType, bHas := results["type"]; s == "" && bHas {
			switch strType {
			case "prometheus":
				p = DEFAULT_EXPORTER_PORT
			case "snmp":
				p = mysnmp.SNMPD_DEFAULT_PORT
			} // end switch
		} // end if
		results["port"] = p
	})
	form.AddFormItem(dropdownMetricsType).
		AddButton("OK", func() {
			app.Stop()
		})
	form.SetBorder(true).SetTitle("Metrics Exporter Configuration").SetTitleAlign(tview.AlignLeft)
	app.SetRoot(form, true).EnableMouse(true).EnablePaste(true).Run()
	return results
} // end TviewForm()

func ParseMetricsOptions(s string) *MetricsOptions {
	posQ := strings.Index(s, "?")
	addrWithoutQuery := s
	if posQ >= 0 {
		addrWithoutQuery = s[0:posQ]
	} // end if
	metricsOptions := DefaultMetricsOptions()
	urlquery.Unmarshal([]byte(s[int(math.Max(0, float64(posQ+1))):]), &metricsOptions)
	metricsOptions.Mode = strings.ToUpper(metricsOptions.Mode)
	metricsExptrHost, metricsExptrPort, _ := helper.ParseHostAndPort(addrWithoutQuery)
	if !helper.IsValidPort(metricsExptrPort) {
		if !helper.IsValidPort(metricsExptrPort) {
			switch metricsOptions.Type {
			case "prometheus":
				metricsExptrPort = DEFAULT_EXPORTER_PORT
			case "snmp":
				metricsExptrPort = mysnmp.SNMPD_DEFAULT_PORT
			default:
				metricsExptrPort, _ = freeport.GetFreePort()
			} // end switch
		} // end if
	} // end if
	metricsOptions.Addr = fmt.Sprintf("%s:%d", metricsExptrHost, metricsExptrPort)
	if metricsOptions.MetricsPath == "" {
		metricsOptions.MetricsPath = DEFAULT_METRICS_PATH
	} // end if
	if !strings.HasPrefix(metricsOptions.MetricsPath, "/") {
		metricsOptions.MetricsPath = fmt.Sprintf("/%s", metricsOptions.MetricsPath)
	} // end if
	return &metricsOptions
} // end ParseMetricsOptions()
