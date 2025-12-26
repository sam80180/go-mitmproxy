//go:build windows
// +build windows

package syslog

import (
	"crypto/tls"

	"github.com/RackSec/srslog"
	"github.com/freman/eventloghook"
	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc/eventlog"
)

type SyslogHookForWindows struct {
	w *srslog.Writer
} // end type

func NewSyslogHookForWindows(proto, raddr, tag string, facility srslog.Priority, tlsCfg *tls.Config) (*SyslogHookForWindows, error) {
	var w *srslog.Writer
	var err error
	if proto == "tcp" && tlsCfg != nil {
		w, err = srslog.DialWithTLSConfig(proto, raddr, facility, tag, tlsCfg) // RFC5425 (syslog over TLS), commonly port 6514
	} else {
		w, err = srslog.Dial(proto, raddr, facility, tag) // UDP 514 or TCP 514 (no TLS)
	} // end if
	if err != nil {
		return nil, err
	} // end if
	w.SetFormatter(srslog.RFC5424Formatter) // RFC5424 formatter is widely accepted (better than legacy RFC3164)
	return &SyslogHookForWindows{w: w}, nil
} // end NewSyslogHookForWindows()

func (h *SyslogHookForWindows) Levels() []logrus.Level { return logrus.AllLevels } // end Levels()

func (h *SyslogHookForWindows) Fire(e *logrus.Entry) error {
	line, _ := e.String()
	switch e.Level {
	case logrus.PanicLevel:
		return h.w.Emerg(line)
	case logrus.FatalLevel:
		return h.w.Crit(line)
	case logrus.ErrorLevel:
		return h.w.Err(line)
	case logrus.WarnLevel:
		return h.w.Warning(line)
	/*
		case logrus.InfoLevel:
			return h.w.Info(line)
	*/
	case logrus.DebugLevel, logrus.TraceLevel:
		return h.w.Debug(line)
	} // end switch
	return h.w.Info(line)
} // end Fire()

func initSyslog(opts *SyslogOptions) error {
	if opts.URI == "" { // write to Windows event log
		elog, err := eventlog.Open(mitmproxy.SERVICE_NAME)
		if err == nil {
			logrus.AddHook(eventloghook.NewHook(elog))
		} // end if
		return err
	} // end if
	proto, sock, errParse := parseRemoteSyslogURI(opts.URI)
	if errParse != nil {
		return errParse
	} // end if
	syslogHook, errHook := NewSyslogHookForWindows(proto, sock, mitmproxy.SERVICE_NAME, toPriority(srslog.Priority(opts.FacilityCode), srslog.LOG_INFO), nil)
	if errHook != nil {
		return errHook
	} // end if
	logrus.AddHook(syslogHook)
	return nil
} // end initSyslog()
