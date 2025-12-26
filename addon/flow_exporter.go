package addon

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/hetiansu5/urlquery"
	addon_b "github.com/lqqyt2423/go-mitmproxy/addon/beat"
	addon_nf "github.com/lqqyt2423/go-mitmproxy/addon/netflow"
	addon_sf "github.com/lqqyt2423/go-mitmproxy/addon/sflow"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	"github.com/rivo/tview"
	"github.com/tiendc/gofn"
)

const (
	FLOWEXP_TYPE_NETFLOW int = iota
	FLOWEXP_TYPE_SFLOW
	FLOWEXP_TYPE_BEAT

	DEFAULT_FLOW_EXPORTER_HOST string = "localhost"
)

type FlowExporterOptions struct {
	Addr                   string                           `query:"-"`
	Type                   string                           `query:"type" validate:"required,oneof=netflow sflow beat"`
	NetflowExporterOptions *addon_nf.NetflowExporterOptions `query:"-"`
	BeatOptions            *addon_b.BeatOptions             `query:"-"`
} // end type

func (opts *FlowExporterOptions) QueryEncode() []byte {
	var b0 []byte
	if opts.Addr != "" {
		b0 = []byte(opts.Addr)
	} // end if
	var sep []byte = nil
	b1, _ := helper.JSONCustomTagMarshal(opts, "query", "")
	m := map[string]any{}
	json.Unmarshal(b1, &m)
	if opts.NetflowExporterOptions != nil {
		b2, _ := helper.JSONCustomTagMarshal(opts.NetflowExporterOptions, "query", "")
		json.Unmarshal(b2, &m)
	} // end if
	if opts.BeatOptions != nil {
		b2, _ := helper.JSONCustomTagMarshal(opts.BeatOptions, "query", "")
		json.Unmarshal(b2, &m)
	} // end if
	bb, _ := urlquery.Marshal(m)
	if len(bb) > 0 && len(b0) > 0 {
		sep = []byte("?")
	} // end if
	return gofn.Concat(b0, sep, bb)
} // end QueryEncode()

func (opts *FlowExporterOptions) String() string {
	return string(opts.QueryEncode())
} // end String()

func (opts *FlowExporterOptions) Set(s string) error {
	return urlquery.Unmarshal([]byte(s), opts)
} // end Set()

func (opts *FlowExporterOptions) UnmarshalJSON(data []byte) error {
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

func DefaultFlowExporterOptions() FlowExporterOptions {
	nfOpts := addon_nf.DefaultNetflowExporterOptions()
	return FlowExporterOptions{
		Addr:                   fmt.Sprintf("%s:%d", DEFAULT_FLOW_EXPORTER_HOST, addon_nf.NETFLOW_COLLECTOR_DEFAULT_PORT),
		Type:                   "netflow",
		NetflowExporterOptions: &nfOpts,
	}
} // end DefaultFlowExporterOptions()

func TviewForm() map[string]any {
	results := map[string]any{"type": "netflow", "host": DEFAULT_FLOW_EXPORTER_HOST, "port": addon_nf.NETFLOW_COLLECTOR_DEFAULT_PORT}
	app := tview.NewApplication()
	form := tview.NewForm()
	formItemsNf := addon_nf.TviewFormItems(form, results)
	formItemsBeat := addon_b.TviewFormItems(form, results)
	inputHost := tview.NewInputField().
		SetLabel("Collector Host: ").
		SetFieldWidth(0).
		SetChangedFunc(func(s string) {
			if s == "" {
				s = DEFAULT_FLOW_EXPORTER_HOST
			} // end if
			results["host"] = s
		})
	inputPort := tview.NewInputField().
		SetLabel("Collector Port: ").
		SetFieldWidth(6).
		SetAcceptanceFunc(func(s string, _ rune) bool {
			return helper.IsValidPortStr(s)
		}).
		SetChangedFunc(func(s string) {
			var p any = s
			if strFlowType, bHas := results["type"]; s == "" && bHas {
				switch strFlowType {
				case "netflow":
					p = addon_nf.NETFLOW_COLLECTOR_DEFAULT_PORT
				case "sflow":
					p = addon_sf.SFLOW_COLLECTOR_DEFAULT_PORT
				} // end switch
			} // end if
			results["port"] = p
		})
	fnAddCollector := func() {
		form.AddFormItem(inputHost)
		form.AddFormItem(inputPort)
	}
	dropdownFlowType := tview.NewDropDown().
		SetLabel("Flow Type: ").
		SetOptions([]string{"NetFlow", "sFlow", "Beat"}, func(txt string, index int) {
			results["type"] = strings.ToLower(txt)
			helper.TviewRemoveTrailingFormItems(form)
			switch index {
			case FLOWEXP_TYPE_NETFLOW:
				fnAddCollector()
				for _, item := range formItemsNf {
					form.AddFormItem(item)
				} // end for
			case FLOWEXP_TYPE_SFLOW:
				fnAddCollector()
			case FLOWEXP_TYPE_BEAT:
				for _, item := range formItemsBeat {
					form.AddFormItem(item)
				} // end for
			} // end switch
		})
	form.AddFormItem(dropdownFlowType).
		AddButton("OK", func() {
			app.Stop()
		})
	form.SetBorder(true).SetTitle("Flow Exporter Configuration").SetTitleAlign(tview.AlignLeft)
	app.SetRoot(form, true).EnableMouse(true).EnablePaste(true).Run()
	return results
} // end TviewForm()
