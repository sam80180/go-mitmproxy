package metrics

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	mysnmp "github.com/lqqyt2423/go-mitmproxy/snmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	prom_testutil "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rivo/tview"
	"github.com/slayercat/GoSNMPServer"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type SNMPRecorder struct {
	interval time.Duration
	onTick   func(*metricdata.ResourceMetrics)

	httpStatusCounter   *prometheus.CounterVec
	totalRequestKbytes  *prometheus.CounterVec
	totalResponseKbytes *prometheus.CounterVec

	serverRequestsPerSec   *prometheus.GaugeVec // the average rate of all requests per second
	serverKBytesPerSec     *prometheus.GaugeVec // the average rate of kilobytes served per second
	serverKBytesPerRequest *prometheus.GaugeVec // the average number of bytes per request
} // end type

func (r *SNMPRecorder) OnTick(rm *metricdata.ResourceMetrics) {
	seconds := r.interval.Seconds()
	for _, sm := range rm.ScopeMetrics { // walk through the resource metrics → scope metrics → data points
		for _, m := range sm.Metrics {
			switch m.Name {
			case "http.server.request.body.size", "http.server.response.body.size":

			default:
				continue
			} // end switch
			var valKbytes float64
			valHits := map[int]uint64{}
			switch data := m.Data.(type) {
			case metricdata.Histogram[int64]:
				for _, dp := range data.DataPoints {
					valKbytes += float64(dp.Sum / 1024.0)
					if m.Name == "http.server.response.body.size" {
						statusCode := http.StatusTeapot
						if attrStatusCode, bOk := dp.Attributes.Value(attribute.Key("http.response.status_code")); bOk {
							statusCode = int(attrStatusCode.AsInt64())
						} // end if
						if _, bOk := valHits[statusCode]; !bOk {
							valHits[statusCode] = 0
						} // end if
						valHits[statusCode] += dp.Count
					} // end if
				} // end for
			default:
				continue
			} // end switch
			var totalHits float64 = 0
			for statusCode, hits := range valHits {
				label := strconv.Itoa(statusCode)
				if prevCount, errHits := helper.GetCounterValue(r.httpStatusCounter, label); errHits == nil {
					deltaHits := float64(hits) - prevCount
					totalHits += deltaHits
					r.httpStatusCounter.WithLabelValues(label).Add(deltaHits)
				} // end if
			} // end for
			r.serverRequestsPerSec.WithLabelValues().Set(totalHits / seconds)
			switch m.Name {
			case "http.server.request.body.size":
				r.serverKBytesPerRequest.Reset()
				detalVal := float64(0)
				if prevVal, errVal := helper.GetCounterValue(r.totalRequestKbytes); errVal == nil {
					detalVal = valKbytes - prevVal
				} // end if
				r.totalRequestKbytes.WithLabelValues().Add(detalVal)
				if totalHits > 0 {
					r.serverKBytesPerRequest.WithLabelValues().Add(detalVal / totalHits)
				} else {
					r.serverKBytesPerRequest.WithLabelValues().Add(0)
				} // end if
			case "http.server.response.body.size":
				r.serverKBytesPerSec.Reset()
				detalVal := float64(0)
				if prevVal, errVal := helper.GetCounterValue(r.totalResponseKbytes); errVal == nil {
					detalVal = valKbytes - prevVal
				} // end if
				r.serverKBytesPerSec.WithLabelValues().Add(detalVal / seconds)
				r.totalResponseKbytes.WithLabelValues().Add(detalVal)
			} // end switch
		} // end for
	} // end for
} // end OnTick()

func NewSnmpRecorder(interval time.Duration) SNMPRecorder {
	r := SNMPRecorder{
		interval: interval,
		httpStatusCounter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "request_count",
		}, []string{"status"}),
		totalRequestKbytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "request_size_kbytes",
		}, nil),
		totalResponseKbytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "response_size_kbytes",
		}, nil),
		serverRequestsPerSec: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "serverRequestsPerSec",
		}, nil),
		serverKBytesPerSec: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "serverKBytesPerSec",
		}, nil),
		serverKBytesPerRequest: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "serverKBytesPerRequest",
		}, nil),
	}
	r.serverRequestsPerSec.WithLabelValues().Set(0)
	r.serverKBytesPerSec.WithLabelValues().Set(0)
	r.serverKBytesPerRequest.WithLabelValues().Set(0)
	return r
} // end NewSnmpRecorder()

func (r *SNMPRecorder) OIDs() []*GoSNMPServer.PDUValueControlItem {
	items := []*GoSNMPServer.PDUValueControlItem{
		{ // the total number of kilobytes this server has served
			Document: "totalTraffic",
			OID:      fmt.Sprintf("%s.2.1.0", mysnmp.APACHE2_MIB_OID_PREFIX),
			OnGet: func() (value any, err error) {
				return int(helper.SumCounterVec(r.totalResponseKbytes)), nil
			},
			Type: gosnmp.Integer,
		},
		{
			Document: "totalAccess",
			OID:      fmt.Sprintf("%s.2.2.0", mysnmp.APACHE2_MIB_OID_PREFIX),
			OnGet: func() (value any, err error) {
				return uint32(helper.SumCounterVec(r.httpStatusCounter)), nil
			},
			Type: gosnmp.Counter32,
		},
		{
			Document: "serverRequestsPerSec",
			OID:      fmt.Sprintf("%s.2.8.0", mysnmp.APACHE2_MIB_OID_PREFIX),
			OnGet: func() (value any, err error) {
				return fmt.Sprintf("%e", testutil.ToFloat64(r.serverRequestsPerSec)), nil
			},
			Type: gosnmp.OctetString,
		},
		{
			Document: "serverKBytesPerSec",
			OID:      fmt.Sprintf("%s.2.9.0", mysnmp.APACHE2_MIB_OID_PREFIX),
			OnGet: func() (value any, err error) {
				return fmt.Sprintf("%e", testutil.ToFloat64(r.serverKBytesPerSec)), nil
			},
			Type: gosnmp.OctetString,
		},
		{
			Document: "serverKBytesPerRequest",
			OID:      fmt.Sprintf("%s.2.10.0", mysnmp.APACHE2_MIB_OID_PREFIX),
			OnGet: func() (value any, err error) {
				return fmt.Sprintf("%e", testutil.ToFloat64(r.serverKBytesPerRequest)), nil
			},
			Type: gosnmp.OctetString,
		},
	}
	for _, statusCode := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusInternalServerError, http.StatusNotImplemented, http.StatusHTTPVersionNotSupported} {
		items = append(items, &GoSNMPServer.PDUValueControlItem{
			Document: fmt.Sprintf("httpError%d", statusCode),
			OID:      fmt.Sprintf("%s.5.%d.0", mysnmp.APACHE2_MIB_OID_PREFIX, statusCode),
			OnGet: func() (value any, err error) {
				v := r.httpStatusCounter.WithLabelValues(fmt.Sprintf("%d", statusCode))
				return uint32(prom_testutil.ToFloat64(v)), nil
			},
			Type: gosnmp.Counter32,
		})
	} // end for
	return items
} // end OIDs()

func SnmpTviewFormItems(form *tview.Form, results map[string]any) []tview.FormItem {
	// set default values
	defaults := DefaultSnmpMetricsOptions()
	b, _ := helper.JSONCustomTagMarshal(defaults, "query", "")
	json.Unmarshal(b, &results)

	// setup form items
	inputCommunity := tview.NewInputField().
		SetLabel("SNMP Community: ").
		SetChangedFunc(func(s string) {
			if s == "" {
				s = defaults.SNMPCommunity
			} // end if
			results["snmp_community"] = s
		}).
		SetPlaceholder(defaults.SNMPCommunity)
	inputInterval := tview.NewInputField().
		SetLabel("Refresh interval: ").
		SetChangedFunc(func(s string) {
			if d, e := time.ParseDuration(s); e != nil || d == 0 {
				s = defaults.RefreshInterval
			} // end if
			results["interval"] = s
		}).
		SetPlaceholder(defaults.RefreshInterval)
	return []tview.FormItem{inputCommunity, inputInterval}
} // end SnmpTviewFormItems()

/*
References:
https://github.com/eplx/mod_apache_snmp/blob/master/mib/APACHE2-MIB.TXT
https://mod-apache-snmp.sourceforge.net/english/APACHE2-MIB.TXT
https://documentation.solarwinds.com/en/success_center/sam/content/sam-apache-sw4137.htm
*/
