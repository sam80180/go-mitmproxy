package beat

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"strings"
	"time"
	_ "unsafe" // required for go:linkname

	watermillmsg "github.com/ThreeDotsLabs/watermill/message"
	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/packetbeat/pb"
	pbhttp "github.com/elastic/beats/v7/packetbeat/protos/http"
	"github.com/elastic/ecs/code/go/ecs"
	zmq "github.com/go-zeromq/zmq4" // just want some of the enums, nothing else ??
	"github.com/google/uuid"
	"github.com/hetiansu5/urlquery"
	mybeater "github.com/lqqyt2423/go-mitmproxy/beater"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	mypubsub "github.com/lqqyt2423/go-mitmproxy/pubsub"
	"github.com/rivo/tview"
	"github.com/sirupsen/logrus"
)

var _PACKETBEAT_SUBSCRIPTION_TOPIC string = uuid.New().String()

type BeatOptions struct {
	SendBody            bool `query:"sendBody"`
	RedactAuthorization bool `query:"redactAuthorization"`
} // end type

func DefaultBeatOptions() BeatOptions {
	return BeatOptions{
		SendBody: true,
	}
} // end DefaultBeatOptions()

func (opts *BeatOptions) QueryEncode() []byte {
	b1, _ := urlquery.Marshal(opts)
	return b1
} // end QueryEncode()

func ParseBeatOptions(s string) *BeatOptions {
	opts := DefaultBeatOptions()
	urlquery.Unmarshal([]byte(s), &opts)
	return &opts
} // end ParseBeatOptions()

type BeatAddon struct {
	mitmproxy.BaseAddon
	options     BeatOptions
	publisher   watermillmsg.Publisher
	BeatHandler *mybeater.EventHandler
} // end type

func NewBeatAddon(a string) *BeatAddon {
	options := ParseBeatOptions(a)
	pubsub := mypubsub.NewGoChannelPubSub()
	return &BeatAddon{
		options: *options,
		BeatHandler: &mybeater.EventHandler{
			Sub: pubsub,
			Handler: func(msg *watermillmsg.Message) (*beat.Event, error) {
				var ev beat.Event
				err := json.Unmarshal(msg.Payload, &ev)
				return &ev, err
			},
			Topic: _PACKETBEAT_SUBSCRIPTION_TOPIC,
		},
		publisher: pubsub,
	}
} // end NewBeatAddon()

func (that *BeatAddon) Request(flow *mitmproxy.Flow) {
	go (func() {
		<-flow.Done()
		if evt, err := that.newTransaction(flow, that.options); err != nil {
			logrus.Warnf("%+v", err)
		} else {
			b, _ := json.Marshal(evt)
			that.publisher.Publish(_PACKETBEAT_SUBSCRIPTION_TOPIC, &watermillmsg.Message{Payload: b})
		} // end if
	})()
} // end Request()

func (that *BeatAddon) newTransaction(flow *mitmproxy.Flow, opts BeatOptions) (*beat.Event, error) {
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
	status := common.OK_STATUS
	resp := flow.Response.Raw()
	requ := flow.Request.Raw()
	if resp == nil {
		status = common.ERROR_STATUS
	} else if resp.StatusCode >= http.StatusBadRequest {
		status = common.ERROR_STATUS
	} // end if
	if requ == nil {
		status = common.ERROR_STATUS
	} // end if
	ts := time.Now()
	evt, pbf := pb.NewBeatEvent(ts)
	pbf.SetSource(&common.Endpoint{
		IP:   srcIp.String(),
		Port: uint16(SrcPort),
	})
	pbf.SetDestination(&common.Endpoint{
		IP:   dstIp.String(),
		Port: uint16(DstPort),
	})
	pbf.AddIP(srcIp.String())
	pbf.AddIP(dstIp.String())
	pbf.Network.Transport = "tcp"
	pbf.Network.Protocol = "http"
	fields := evt.Fields
	fields["type"] = pbf.Network.Protocol
	fields["status"] = status
	var httpFields pbhttp.ProtocolFields
	estRequSize := helper.EstimateHttpRequestSize(requ)
	pbf.Source.Bytes = int64(estRequSize)
	hostResult, errClassify := helper.ClassifyHost(requ.Host)
	if errClassify != nil {
		return nil, errClassify
	} // end if
	if !hostResult.Addr.IsValid() { // probably a FQDN
		host := helper.StripPortIfPresent(requ.Host)
		pbf.Destination.Domain = host
		pbf.AddHost(host)
	} else {
		pbf.AddIP(dstIp.String())
	} // end if
	pbf.Event.Start = flow.StartTime
	pbf.Network.ForwardedIP = srcIp.String()
	pbf.AddIP(srcIp.String())
	httpFields.Version = requ.Proto
	httpFields.RequestBytes = int64(estRequSize)
	httpFields.RequestBodyBytes = requ.ContentLength
	httpFields.RequestMethod = common.NetString(requ.Method)
	httpFields.RequestReferrer = common.NetString(requ.Referer())
	pbf.AddHost(requ.Referer())
	rawRequBytes, errDumpRequ := httputil.DumpRequest(requ, opts.SendBody)
	if errDumpRequ != nil {
		return nil, errDumpRequ
	} // end if
	fields["request"] = rawRequBytes
	if opts.SendBody {
		httpFields.RequestBytes = int64(len(rawRequBytes))
		httpFields.RequestBodyContent = common.NetString(flow.Request.Body)
	} // end if
	httpFields.RequestHeaders = that.collectHeaders(requ.Header, zmq.Req, opts)
	pb.MarshalStruct(evt.Fields, "url", requ.URL)
	userAgent := ecs.UserAgent{Original: requ.UserAgent()}
	pb.MarshalStruct(evt.Fields, "user_agent", userAgent)
	fields["method"] = httpFields.RequestMethod
	fields["query"] = requ.URL.RawQuery
	if username := requ.URL.User.Username(); !opts.RedactAuthorization && username != "" {
		fields["user.name"] = username
		pbf.AddUser(username)
	} // end if
	reres := flow.Response.Reconstruct()
	rawResBytes, errDumpRep := httputil.DumpResponse(reres, opts.SendBody)
	if errDumpRep != nil {
		return nil, errDumpRep
	} // end if
	defer reres.Body.Close()
	estRespSize := helper.EstimateHttpResponseSize(resp)
	pbf.Destination.Bytes = int64(estRespSize)
	pbf.Event.End = flow.StartTime.Add(flow.ElapsedTime())
	httpFields.ResponseStatusCode = int64(resp.StatusCode)
	httpFields.ResponseStatusPhrase = common.NetString(strings.ToLower(resp.Status[4:]))
	httpFields.ResponseBytes = int64(estRespSize)
	httpFields.ResponseBodyBytes = resp.ContentLength
	fields["response"] = rawResBytes
	if opts.SendBody {
		if res_body, err := io.ReadAll(reres.Body); err != nil {
			return nil, err
		} else {
			httpFields.ResponseBodyContent = res_body
		} // end if
		httpFields.ResponseBytes = int64(len(rawResBytes))
	} // end if
	httpFields.ResponseHeaders = that.collectHeaders(resp.Header, zmq.Rep, opts)
	pb.MarshalStruct(evt.Fields, "http", httpFields)
	return &evt, nil
} // end newTransaction()

//go:linkname packetbeat_http_splitCookiesHeader github.com/elastic/beats/v7/packetbeat/protos/http.splitCookiesHeader
func packetbeat_http_splitCookiesHeader(string) map[string]string

func (that *BeatAddon) collectHeaders(headers http.Header, stype zmq.SocketType, opts BeatOptions) common.MapStr {
	hdrs := common.MapStr{}
	cookie := "cookie"
	if stype != zmq.Req {
		cookie = "set-cookie"
	} // end if
	for k, vv := range headers {
		switch k {
		case textproto.CanonicalMIMEHeaderKey("authorization"):
			if opts.RedactAuthorization {
				for j, _ := range vv {
					vv[j] = "*"
				} // end for
			} // end if
			hdrs[k] = vv
		case textproto.CanonicalMIMEHeaderKey(cookie):
			hdrs[k] = packetbeat_http_splitCookiesHeader(vv[0])
		default:
			hdrs[k] = vv
		} // end switch
	} // end for
	return hdrs
} // end collectHeaders()

func TviewFormItems(form *tview.Form, results map[string]any) []tview.FormItem {
	defaults := DefaultBeatOptions()
	b, _ := helper.JSONCustomTagMarshal(defaults, "query", "")
	json.Unmarshal(b, &results)
	redactAuthorization := tview.NewCheckbox().
		SetLabel("Redact authorization: ").
		SetChecked(defaults.RedactAuthorization).
		SetChangedFunc(func(checked bool) {
			results["redactAuthorization"] = checked
		})
	sendBody := tview.NewCheckbox().
		SetLabel("Send body: ").
		SetChecked(defaults.SendBody).
		SetChangedFunc(func(checked bool) {
			results["sendBody"] = checked
		})
	return []tview.FormItem{redactAuthorization, sendBody}
} // end TviewFormItems()

/*
References:
https://github.com/elastic/beats/blob/e1c8a0af983d821b4cebc32352c01cf916c21fef/packetbeat/protos/http/http.go#L507
*/
