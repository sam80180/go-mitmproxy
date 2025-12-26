package syslog

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RackSec/srslog"
	"github.com/hetiansu5/urlquery"
	gosyslog "github.com/leodido/go-syslog/v4/common"
	mybeater "github.com/lqqyt2423/go-mitmproxy/beater"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	"github.com/rivo/tview"
	"github.com/sirupsen/logrus"
	"github.com/tiendc/gofn"
	"golang.org/x/exp/constraints"
)

const (
	SYSLOG_TYPE_HOST int = iota
	SYSLOG_TYPE_REMOTE
	SYSLOG_TYPE_BEAT
)

const (
	DEFAULT_RSYSLOG_HOST    = "localhost"
	DEFAULT_RSYSLOG_PORT    = 514
	DEFAULT_SYSLOG_FACILITY = uint8(srslog.LOG_LOCAL0 >> 3)
)

var DEFAULT_SYSLOG_FACILITY_LABEL string = gosyslog.FacilityKeywords[DEFAULT_SYSLOG_FACILITY]

type SyslogOptions struct {
	Type         string `query:"type" validate:"required,oneof=host remote beat"`
	URI          string `query:"uri"`
	Facility     string `query:"facility"`
	FacilityCode uint8  `query:"-"`

	// beat
	BeatOptions *mybeater.BeatOptions `query:"-"`
} // end type

func (opts *SyslogOptions) QueryEncode() []byte {
	b1, _ := helper.JSONCustomTagMarshal(opts, "query", "")
	m := map[string]any{}
	json.Unmarshal(b1, &m)
	if opts.BeatOptions != nil {
		b2, _ := helper.JSONCustomTagMarshal(opts.BeatOptions, "query", "")
		json.Unmarshal(b2, &m)
	} // end if
	bb, _ := urlquery.Marshal(m)
	return bb
} // end QueryEncode()

func (opts *SyslogOptions) String() string {
	return string(opts.QueryEncode())
} // end String()

func (opts *SyslogOptions) Set(s string) error {
	return urlquery.Unmarshal([]byte(s), opts)
} // end Set()

func (opts *SyslogOptions) UnmarshalJSON(data []byte) error {
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

func DefaultHostSyslogOptions() SyslogOptions {
	return SyslogOptions{
		Type:         "host",
		Facility:     DEFAULT_SYSLOG_FACILITY_LABEL,
		FacilityCode: DEFAULT_SYSLOG_FACILITY,
	}
} // end DefaultHostSyslogOptions()

func DefaultRemoteSyslogOptions() SyslogOptions {
	return SyslogOptions{
		Type:         "remote",
		URI:          fmt.Sprintf("udp://%s:%d", DEFAULT_RSYSLOG_HOST, DEFAULT_RSYSLOG_PORT),
		Facility:     DEFAULT_SYSLOG_FACILITY_LABEL,
		FacilityCode: DEFAULT_SYSLOG_FACILITY,
	}
} // end DefaultRemoteSyslogOptions()

func DefaultBeatSyslogOptions() SyslogOptions {
	return SyslogOptions{
		Type:         "beat",
		Facility:     DEFAULT_SYSLOG_FACILITY_LABEL,
		FacilityCode: DEFAULT_SYSLOG_FACILITY,
	}
} // end DefaultBeatSyslogOptions()

func DefaultSyslogOptions() SyslogOptions {
	return DefaultHostSyslogOptions()
} // end DefaultSyslogOptions()

func parseSyslogOptions(s string) SyslogOptions {
	opts := DefaultSyslogOptions()
	urlquery.Unmarshal([]byte(s), &opts)
	if helper.IsAllDigits(opts.Facility) {
		if c, e := strconv.Atoi(opts.Facility); e == nil {
			uc := uint8(c)
			if v, b := gosyslog.FacilityKeywords[uc]; b {
				opts.Facility = v
				opts.FacilityCode = uc
			} // end if
		} // end if
	} else {
		for c, f := range gosyslog.FacilityKeywords {
			if f == opts.Facility {
				opts.FacilityCode = c
				break
			} // end if
		} // end for
	} // end if
	return opts
} // end parseSyslogOptions()

func TviewForm() map[string]any {
	results := map[string]any{}
	defaultSyslogOpts := DefaultSyslogOptions()
	b, _ := helper.JSONCustomTagMarshal(defaultSyslogOpts, "query", "")
	json.Unmarshal(b, &results)
	app := helper.NewMyTviewFormApplication(helper.MyDefaultTviewAppCustomizer, true, func(form *tview.Form) *tview.Form {
		helper.MyDefaultTviewFormCustomizer(form).SetTitle("Syslog Configuration")
		return form
	})
	itemsBeat := mybeater.TviewFormItems(app.Form, results)
	fnAddBeatItems := func() {
		// config file
		app.AddInputFieldWithStatusIcon(itemsBeat[0].(*tview.InputField), func(s string, _ rune) bool {
			if s == "" {
				return true
			} // end if
			stat, bExists, err := helper.PathExistsOrStat(s)
			return (err == nil && bExists && stat.Mode().IsRegular())
		}, true)

		// drain timeout
		app.AddInputFieldWithStatusIcon(itemsBeat[1].(*tview.InputField), func(s string, _ rune) bool {
			_, e := time.ParseDuration(s)
			return (e == nil)
		}, true)
	}
	dropdownProto := tview.NewDropDown().
		SetLabel("Protocol: ").
		SetOptions([]string{"UDP", "TCP"}, func(txt string, _ int) {
			results["scheme"] = strings.ToLower(txt)
		})
	inputHost := tview.NewInputField().
		SetLabel("Host: ").
		SetChangedFunc(func(s string) {
			if s == "" {
				s = DEFAULT_RSYSLOG_HOST
			} // end if
			results["host"] = s
		})
	inputPort := tview.NewInputField().
		SetLabel("Port: ").
		SetFieldWidth(6).
		SetAcceptanceFunc(func(s string, _ rune) bool {
			return helper.IsValidPortStr(s)
		}).
		SetChangedFunc(func(s string) {
			p := s
			if s == "" {
				p = strconv.Itoa(DEFAULT_RSYSLOG_PORT)
			} // end if
			results["port"] = p
		})
	arrFacilityCodes := gofn.MapKeys(gosyslog.FacilityKeywords)
	sort.Slice(arrFacilityCodes, func(i, j int) bool {
		return arrFacilityCodes[i] < arrFacilityCodes[j]
	})
	lstFacilities := []string{}
	for _, c := range arrFacilityCodes {
		lstFacilities = append(lstFacilities, gosyslog.FacilityKeywords[c])
	} // end for
	dropdownFacility := tview.NewDropDown().
		SetLabel("Facility: ").
		SetOptions(lstFacilities, func(txt string, _ int) {
			if txt == "" {
				txt = DEFAULT_SYSLOG_FACILITY_LABEL
			} // end if
			results["facility"] = txt
		})
	fnAddRemoteItems := func() {
		app.AddFormItem(dropdownProto)
		app.AddFormItem(inputHost)
		app.AddFormItem(inputPort)
	}
	dropdownSyslogType := tview.NewDropDown().
		SetLabel("Type: ").
		SetOptions([]string{"Host", "Remote", "Beat"}, func(txt string, index int) {
			results["type"] = strings.ToLower(txt)
			helper.TviewRemoveTrailingFormItems(app.Form)
			switch index {
			case SYSLOG_TYPE_REMOTE:
				fnAddRemoteItems()
			case SYSLOG_TYPE_BEAT:
				fnAddBeatItems()
			} // end switch
			app.AddFormItem(dropdownFacility)
		})
	app.AddFormItem(dropdownSyslogType).
		AddButton("OK", func() {
			app.Stop()
		})
	app.Run()
	if v, _ := results["type"]; v == "remote" {
		collectorHost := gofn.MapPop(results, "host", DEFAULT_RSYSLOG_HOST)
		if collectorHost == "" {
			collectorHost = DEFAULT_RSYSLOG_HOST
		} // end if
		collectorPort := gofn.MapPop(results, "port", DEFAULT_RSYSLOG_PORT)
		if collectorPort == "" {
			collectorPort = strconv.Itoa(DEFAULT_RSYSLOG_PORT)
		} // end if
		collectorProto := gofn.MapPop(results, "scheme", "udp")
		results["uri"] = fmt.Sprintf("%s://%s:%+v", collectorProto, collectorHost, collectorPort)
	} // end if
	return results
} // end TviewForm()

func parseRemoteSyslogURI(s string) (string, string, error) {
	proto := ""
	sock := ""
	if s != "" {
		u, errUri := url.Parse(s)
		if errUri != nil {
			return "", "", errUri
		} // end if
		if u.Scheme != "tcp" && u.Scheme != "udp" {
			return "", "", fmt.Errorf("unsupported scheme")
		} // end if
		proto = u.Scheme
		collectorPort := u.Port()
		if collectorPort == "" {
			collectorPort = strconv.Itoa(DEFAULT_RSYSLOG_PORT)
		} // end if
		collectorHostname := u.Hostname()
		if collectorHostname == "" {
			collectorHostname = DEFAULT_RSYSLOG_HOST
		} // end if
		sock = fmt.Sprintf("%s:%+v", collectorHostname, collectorPort)
	} // end if
	return proto, sock, nil
} // end parseRemoteSyslogURI()

func toPriority[T constraints.Integer](facility, level T) T {
	return (level | (facility << 3))
} // end toPriority()

func Setup(q string) (*mybeater.EventHandler, error) {
	opts := parseSyslogOptions(q)
	logrus.WithField("options", string(opts.QueryEncode())).Info("Enable syslog")
	switch opts.Type {
	case "beat":
		opts.BeatOptions = mybeater.ParseBeatOptions(q)
		return initBeat(&opts), nil
	} // end switch
	return nil, initSyslog(&opts)
} // end Setup()
