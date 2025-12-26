package tracing

import (
	"encoding/json"
	"reflect"
	"strings"

	"github.com/hetiansu5/urlquery"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	"github.com/rivo/tview"
)

type TracingOptions struct {
	Type string `query:"type" validate:"required,oneof=zipkin jaeger datadog"`
	URL  string `query:"url" validate:"required"`
} // end type

func (opts *TracingOptions) QueryEncode() []byte {
	b, _ := urlquery.Marshal(opts)
	return b
} // end QueryEncode()

func (opts *TracingOptions) String() string {
	return string(opts.QueryEncode())
} // end String()

func (opts *TracingOptions) Set(s string) error {
	return urlquery.Unmarshal([]byte(s), opts)
} // end Set()

func (opts *TracingOptions) UnmarshalJSON(data []byte) error {
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

func DefaultZipkinTracingOptions() TracingOptions {
	return TracingOptions{
		Type: "zipkin",
		URL:  "http://localhost:9411/api/v2/spans",
	}
} // end DefaultZipkinTracingOptions()

func DefaultJaegerTracingOptions() TracingOptions {
	return TracingOptions{
		Type: "jaeger",
		URL:  "http://localhost:14268/api/traces",
	}
} // end DefaultJaegerTracingOptions()

func DefaultDatadogTracingOptions() TracingOptions {
	return TracingOptions{
		Type: "jaeger",
		URL:  "http://localhost:8126/api/v2/otlp",
	}
} // end DefaultDatadogTracingOptions()

func DefaultTracingOptions() TracingOptions {
	return DefaultZipkinTracingOptions()
} // end DefaultTracingOptions()

func TviewForm() map[string]any {
	results := map[string]any{}
	b, _ := helper.JSONCustomTagMarshal(DefaultTracingOptions(), "query", "")
	json.Unmarshal(b, &results)
	app := tview.NewApplication()
	form := tview.NewForm()
	dropdownTracingType := tview.NewDropDown().
		SetLabel("Type: ").
		SetOptions([]string{"Zipkin", "Jaeger", "Datadog"}, func(txt string, index int) {
			results["type"] = strings.ToLower(txt)
		})
	form.AddFormItem(dropdownTracingType).
		AddInputField("Endpoint: ", "", 0, func(s string, _ rune) bool {
			return len(s) > 0
		}, func(s string) {
			results["url"] = strings.ToLower(s)
		}).
		AddButton("OK", func() {
			app.Stop()
		})
	form.SetBorder(true).SetTitle("Tracing Configuration").SetTitleAlign(tview.AlignLeft)
	app.SetRoot(form, true).EnableMouse(true).EnablePaste(true).Run()
	return results
} // end TviewForm()

func ParseTracingOptions(s string) *TracingOptions {
	tracerOptions := DefaultTracingOptions()
	tracerOptions.Set(s)
	return &tracerOptions
} // end ParseTracingOptions()
