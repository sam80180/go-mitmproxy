package syslog

import (
	"encoding/json"
	"net"
	"os"
	"strconv"
	"time"

	watermillmsg "github.com/ThreeDotsLabs/watermill/message"
	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/google/uuid"
	"github.com/jinzhu/copier"
	gosyslog "github.com/leodido/go-syslog/v4/common"
	mybeater "github.com/lqqyt2423/go-mitmproxy/beater"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	mypubsub "github.com/lqqyt2423/go-mitmproxy/pubsub"
	gateway "github.com/net-byte/go-gateway"
	"github.com/sirupsen/logrus"
)

var _SYSLOGBEAT_SUBSCRIPTION_TOPIC string = uuid.New().String()

type logrusBeatHook struct {
	opts      *SyslogOptions
	logSource net.IP
	formatter logrus.TextFormatter
	publisher watermillmsg.Publisher
} // end type

func (btr *logrusBeatHook) createBeatEvent(msg *watermillmsg.Message) (*beat.Event, error) {
	f := common.MapStr{"message": string(msg.Payload)}
	syslog := common.MapStr{}
	event := common.MapStr{}
	process := common.MapStr{}
	if hostname, err := os.Hostname(); err != nil {
		return nil, err
	} else {
		f["hostname"] = hostname
	} // end if
	process["pid"] = os.Getpid()
	if exeBin, errBin := os.Executable(); errBin != nil {
		return nil, errBin
	} else {
		process["program"] = exeBin
	} // end if
	if lv, errLv := strconv.Atoi(msg.Metadata["level"]); errLv != nil {
		return nil, errLv
	} else {
		syslog["priority"] = toPriority(int(btr.opts.FacilityCode), lv)
		strSeverity := gosyslog.SeverityLevels[6]
		switch logrus.Level(lv) {
		case logrus.PanicLevel:
			strSeverity = gosyslog.SeverityLevels[0]
		case logrus.FatalLevel:
			strSeverity = gosyslog.SeverityLevels[2]
		case logrus.ErrorLevel:
			strSeverity = gosyslog.SeverityLevels[3]
		case logrus.WarnLevel:
			strSeverity = gosyslog.SeverityLevels[4]
		case logrus.DebugLevel, logrus.TraceLevel:
			strSeverity = gosyslog.SeverityLevels[7]
		} // end switch
		event["severity"] = lv
		syslog["severity_label"] = strSeverity
	} // end if
	syslog["facility"] = btr.opts.FacilityCode
	if v, ok := gosyslog.FacilityKeywords[btr.opts.FacilityCode]; ok {
		syslog["facility_label"] = v
	} // end if
	//process["name"] =
	//process["entity_id"] =
	syslog["msgid"] = msg.UUID
	//syslog["version"] =
	evData := logrus.Fields{}
	json.Unmarshal([]byte(msg.Metadata["data"]), &evData)
	syslog["data"] = evData
	f["syslog"] = syslog
	f["event"] = event
	if len(process) > 0 {
		f["process"] = process
	} // end if
	//f["event.sequence"] =
	timestamp := time.Now()
	timestamp.UnmarshalText([]byte(msg.Metadata["time"]))
	return btr.newBeatEvent(timestamp, f), nil
} // end createBeatEvent()

func (btr *logrusBeatHook) newBeatEvent(timestamp time.Time, fields common.MapStr) *beat.Event {
	event := beat.Event{
		Timestamp: timestamp,
		Fields:    fields,
	}
	if btr.logSource != nil {
		event.Fields.Put("log.source.address", btr.logSource.String())
	} // end if
	return &event
} // end newBeatEvent()

func newLogrusBeatHook(opts *SyslogOptions, publisher watermillmsg.Publisher) *logrusBeatHook {
	btr := logrusBeatHook{opts: opts, publisher: publisher}
	gwIp, _ := gateway.DiscoverGatewayIPv4()
	if gwIp == nil {
		gwIp, _ = gateway.DiscoverGatewayIPv6()
	} // end if
	if gwIp != nil {
		btr.logSource, _ = helper.LocalIPForPeer(gwIp)
	} // end if
	if stdFormatter := logrus.StandardLogger().Formatter; stdFormatter != nil {
		if tf, ok := stdFormatter.(*logrus.TextFormatter); ok {
			copier.Copy(&btr.formatter, tf)
		} // end if
	} // end if
	btr.formatter.DisableColors = true
	return &btr
} // end newLogrusBeatHook()

func (h *logrusBeatHook) Levels() []logrus.Level { return logrus.AllLevels } // end Levels()

func (h *logrusBeatHook) Fire(e *logrus.Entry) error {
	bLine, err := h.formatter.Format(e)
	if err != nil {
		return err
	} // end if
	line := string(bLine)
	bT, _ := e.Time.MarshalText()
	bData, _ := json.Marshal(e.Data)
	msg := watermillmsg.Message{
		Metadata: watermillmsg.Metadata{
			"level": strconv.Itoa(int(e.Level)),
			"time":  string(bT),
			"data":  string(bData),
		},
		Payload: []byte(line),
	}
	h.publisher.Publish(_SYSLOGBEAT_SUBSCRIPTION_TOPIC, &msg)
	return nil
} // end Fire()

func initBeat(opts *SyslogOptions) *mybeater.EventHandler {
	pubsub := mypubsub.NewGoChannelPubSub()
	h := newLogrusBeatHook(opts, pubsub)
	logrus.AddHook(h)
	return &mybeater.EventHandler{
		Handler: h.createBeatEvent,
		Sub:     pubsub,
		Topic:   _SYSLOGBEAT_SUBSCRIPTION_TOPIC,
	}
} // end initBeat()

/*
References:
https://github.com/elastic/beats/blob/main/filebeat/input/syslog/input.go#L214
*/
