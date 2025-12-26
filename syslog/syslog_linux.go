//go:build linux
// +build linux

package syslog

import (
	"log/syslog"

	"github.com/jinzhu/copier"
	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/sirupsen/logrus"
	lSyslog "github.com/sirupsen/logrus/hooks/syslog"
)

type noColorLinuxSyslogHook struct {
	hook      *lSyslog.SyslogHook
	formatter *logrus.TextFormatter
} // end type

func (h *noColorLinuxSyslogHook) Levels() []logrus.Level {
	return logrus.AllLevels
} // end Levels()

func (h *noColorLinuxSyslogHook) Fire(entry *logrus.Entry) error {
	// Format entry without colors
	data, err := h.formatter.Format(entry)
	if err != nil {
		return err
	}
	// Send plain text to syslog
	line := string(data)
	switch entry.Level {
	case logrus.PanicLevel:
		return h.hook.Writer.Emerg(line)
	case logrus.FatalLevel:
		return h.hook.Writer.Crit(line)
	case logrus.ErrorLevel:
		return h.hook.Writer.Err(line)
	case logrus.WarnLevel:
		return h.hook.Writer.Warning(line)
	/*
		case logrus.InfoLevel:
			return h.hook.Writer.Info(line)
	*/
	case logrus.DebugLevel, logrus.TraceLevel:
		return h.hook.Writer.Debug(line)
	} // end switch
	return h.hook.Writer.Info(line)
} // end Fire()

func initSyslog(opts *SyslogOptions) error {
	proto, sock, errParse := parseRemoteSyslogURI(opts.URI)
	if errParse != nil {
		return errParse
	} // end if
	hook, errHook := lSyslog.NewSyslogHook(proto, sock, toPriority(syslog.Priority(opts.FacilityCode), syslog.LOG_INFO), mitmproxy.SERVICE_NAME)
	if errHook == nil {
		stdFormatter := logrus.StandardLogger().Formatter
		if stdFormatter != nil {
			if tf, ok := stdFormatter.(*logrus.TextFormatter); ok {
				copiedTf := logrus.TextFormatter{}
				copier.Copy(&copiedTf, tf)
				copiedTf.DisableColors = true
				colorlessHook := noColorLinuxSyslogHook{hook: hook, formatter: &copiedTf}
				logrus.AddHook(&colorlessHook)
			} else {
				logrus.AddHook(hook)
			} // end if
		} else {
			logrus.AddHook(hook)
		} // end if
	} // end if
	return errHook
} // end initSyslog()
