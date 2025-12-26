package beater

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"reflect"
	"regexp"
	"syscall"
	"time"
	_ "unsafe" // required for go:linkname

	watermillmsg "github.com/ThreeDotsLabs/watermill/message"
	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/cmd"
	"github.com/elastic/beats/v7/libbeat/cmd/instance"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/hetiansu5/urlquery"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	mitmproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/rivo/tview"
	"github.com/samber/do/v2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type BeatOptions struct {
	ConfigFile   string `query:"config"`
	DrainTimeout string `query:"drainTimeout"`
} // end type

func (opts *BeatOptions) QueryEncode() []byte {
	b, _ := urlquery.Marshal(opts)
	return b
} // end QueryEncode()

func (opts *BeatOptions) String() string {
	return string(opts.QueryEncode())
} // end String()

func (opts *BeatOptions) Set(s string) error {
	return urlquery.Unmarshal([]byte(s), opts)
} // end Set()

func (opts *BeatOptions) UnmarshalJSON(data []byte) error {
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

func DefaultBeatOptions() BeatOptions {
	return BeatOptions{ConfigFile: "beat.yml", DrainTimeout: "5s"}
} // end DefaultBeatOptions()

func ParseBeatOptions(s string) *BeatOptions {
	btOptions := DefaultBeatOptions()
	btOptions.Set(s)
	return &btOptions
} // end ParseBeatOptions()

type beater struct {
	opts     BeatOptions
	cancel   context.CancelFunc
	handlers []*EventHandler
} // end type

type EventHandler struct {
	Topic   string
	Sub     watermillmsg.Subscriber
	Handler func(*watermillmsg.Message) (*beat.Event, error)
} // end type

type eventSubscription struct {
	Topic        string
	Handler      func(*watermillmsg.Message) (*beat.Event, error)
	Subscription <-chan *watermillmsg.Message
} // end type

func newBeater(opts BeatOptions, handlers []*EventHandler) *beater {
	return &beater{handlers: handlers, opts: opts}
} // end newBeater()

func (btr *beater) Run(*beat.Beat) error { return nil } // end Run()

func (btr *beater) _run(b *beat.Beat) error {
	client, errConn := b.Publisher.Connect()
	if errConn != nil {
		return errConn
	} // end if
	defer client.Close()
	ctx, fnCancel := context.WithCancel(context.Background())
	btr.cancel = fnCancel
	subscriptions := []eventSubscription{}
	chans := []<-chan *watermillmsg.Message{}
	for _, handler := range btr.handlers {
		if subscription, errSub := handler.Sub.Subscribe(ctx, handler.Topic); errSub != nil {
			logrus.Warn(errSub)
		} else {
			subscriptions = append(subscriptions, eventSubscription{Topic: handler.Topic, Handler: handler.Handler, Subscription: subscription})
			chans = append(chans, subscription)
		} // end if
	} // end for
	drain_timeout := 5 * time.Second
	if btr.opts.DrainTimeout != "" {
		if to, errTo := time.ParseDuration(btr.opts.DrainTimeout); errTo == nil {
			drain_timeout = to
		} // end if
	} // end if
	helper.DrainChannelsWithTimeout(ctx, chans, drain_timeout, func(msg *watermillmsg.Message, i int) {
		if subscriptions[i].Handler != nil {
			if evt, errEv := subscriptions[i].Handler(msg); errEv != nil {
				logrus.Warn(errEv)
			} else {
				client.Publish(*evt)
			} // end if
		} // end if
	}, func(i int) {
		/******** ¡ 此處用logrus且syslog type=beat會造成 infinite loop！ ************/
	}, func(i int) {
		logrus.Warnf("Topic ‘%s’ closed", subscriptions[i].Topic)
	}, func(i int) {
		logrus.Debugf("Timeout reading from topic ‘%s’", subscriptions[i].Topic)
	}, func() {
		logrus.Warnf("Draining cancelled.")
	})
	return nil
} // end _run()

func (b *beater) Stop() {
	if b.cancel != nil {
		b.cancel()
	} // end if
} // end Stop()

//go:linkname beat_configfiles github.com/elastic/beats/v7/libbeat/cfgfile.configfiles
var beat_configfiles *common.StringsFlag

type shellFlagReadonlyValue struct {
	OriginalValue flag.Value
	ROValue       any
} // end type

func (v *shellFlagReadonlyValue) Set(s string) error {
	return v.OriginalValue.Set(v.String())
} // end Set()

func (v *shellFlagReadonlyValue) String() string {
	return fmt.Sprintf("%+v", v.ROValue)
} // end String()

func Launch(di do.Injector, opts BeatOptions, handlers []*EventHandler) {
	settings := instance.Settings{
		Name:           mitmproxy.SERVICE_NAME,
		Version:        mitmproxy.APP_VERSION,
		HasDashboards:  false,
		InputQueueSize: 400,
	}
	btr := newBeater(opts, handlers)
	var _beat *beat.Beat
	creator := func(b *beat.Beat, c *common.Config) (beat.Beater, error) {
		_beat = b
		return btr, nil
	}
	oldBeatFlagSet := do.MustInvoke[*flag.FlagSet](di) // get beat's FlagSet
	tmpFlagSet := flag.NewFlagSet("", flag.ContinueOnError)
	tmpFlagSet.Usage = func() {}
	tmpFlagSet.SetOutput(io.Discard)              // hide output
	oldBeatFlagSet.VisitAll(func(pf *flag.Flag) { // freeze / override flags
		vv := shellFlagReadonlyValue{OriginalValue: pf.Value}
		switch pf.Name {
		case "c":
			vv.ROValue = opts.ConfigFile
		} // end switch
		tmpFlagSet.Var(&vv, pf.Name, "")
	})
	originalFlagSet := flag.CommandLine
	flag.CommandLine = tmpFlagSet // temporarily replace
	rootCmd := cmd.GenRootCmdWithSettings(creator, settings)
	flag.CommandLine = originalFlagSet // restore
	rootCmd.DisableFlagParsing = true
	rootCmd.DisableFlagsInUseLine = true
	rootCmd.DisableSuggestions = true
	rootCmd.SilenceUsage = true
	originalFnRun := rootCmd.Run
	rootCmd.Run = func(cmd *cobra.Command, args []string) {
		logrus.WithField("options", string(opts.QueryEncode())).Info("Beating...")
		go (func() { // `beat` intercepts Ctrl+C (don't know why), so capture signal ourself
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
			c := syscall.Signal(0)
			switch sg := <-sigCh; sg {
			case os.Interrupt, syscall.SIGINT:
				c = syscall.SIGINT
			case syscall.SIGTERM:
				c = syscall.SIGTERM
			case syscall.SIGKILL:
				c = syscall.SIGKILL
			default:
				return
			} // end switch
			btr.Stop()
			os.Exit(128 + int(c)) // https://itsfoss.com/linux-exit-codes/#code-143-or-sigterm
		})()
		flag.CommandLine = tmpFlagSet
		originalFnRun(cmd, args)
		flag.CommandLine = originalFlagSet
		btr._run(_beat)
	}
	beat_configfiles.SetDefault(opts.ConfigFile)
	beat_configfiles.Set(opts.ConfigFile)
	rootCmd.ResetCommands() // remove all subcommands
	rootCmd.ResetFlags()    // remove all flags
	rootCmd.RunCmd.FParseErrWhitelist.UnknownFlags = true
	rootCmd.FParseErrWhitelist.UnknownFlags = true
	rootCmd.SetupCmd.FParseErrWhitelist.UnknownFlags = true
	rootCmd.Execute()
} // end Launch()

func TviewFormItems(form *tview.Form, results map[string]any) []tview.FormItem {
	defaultBeatOpts := DefaultBeatOptions()
	b, _ := helper.JSONCustomTagMarshal(defaultBeatOpts, "query", "")
	json.Unmarshal(b, &results)
	inputCfgFile := tview.NewInputField().
		SetLabel("Config file: ").
		SetChangedFunc(func(str string) {
			if str == "" || regexp.MustCompile(`^[.]{,2}$`).MatchString(str) || !helper.PathExists(str) {
				str = defaultBeatOpts.ConfigFile
			} // end if
			results["config"] = str
		})
	inputDrainTO := tview.NewInputField().
		SetFieldWidth(6).
		SetChangedFunc(func(s string) {
			if d, e := time.ParseDuration(s); e != nil || d == 0 {
				s = defaultBeatOpts.DrainTimeout
			} // end if
			results["drainTimeout"] = s
		}).
		SetLabel("Drain timeout: ")
	return []tview.FormItem{inputCfgFile, inputDrainTO}
} // end TviewFormItems()

/*
References:
https://github.com/moby/moby/issues/33245#issuecomment-2444014496
https://blog.csdn.net/signmem/article/details/144232814
*/
