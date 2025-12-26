package ipc

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-zeromq/zmq4"
	"github.com/go-zeromq/zmq4/security/plain"
	"github.com/google/uuid"
	"github.com/hetiansu5/urlquery"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	"github.com/rivo/tview"
	"github.com/sirupsen/logrus"
	"github.com/tiendc/gofn"
)

type IPCOptions struct {
	Endpoint string `query:"-"`

	// PLAIN security
	PlainUsername string `query:"plain_username" mask:"zero"`
	PlainPassword string `query:"plain_password" mask:"zero"`
} // end type

func (opts *IPCOptions) QueryEncode() []byte {
	var b0 []byte
	if opts.Endpoint != "" {
		b0 = []byte(opts.Endpoint)
	} // end if
	var sep []byte = nil
	b1, _ := urlquery.Marshal(opts)
	if len(b1) > 0 && len(b0) > 0 {
		sep = []byte("?")
	} // end if
	return gofn.Concat(b0, sep, b1)
} // end QueryEncode()

func getIpcFrontendEndpoint() (string, error) {
	ex, errExe := os.Executable()
	if errExe != nil {
		return "", errExe
	} // end if
	exeDir := filepath.Dir(ex)
	socketDir := filepath.Join(exeDir, "tmp")
	if !helper.PathExists(socketDir) {
		os.MkdirAll(socketDir, 0644)
	} // end if
	return fmt.Sprintf("ipc://%s.%d", filepath.Join(socketDir, "IPC"), 5555), nil
} // end getIpcFrontendEndpoint()

func DefaultIPCOptions() IPCOptions {
	ep, _ := getIpcFrontendEndpoint()
	return IPCOptions{Endpoint: ep}
} // end DefaultIPCOptions()

func ParseIPCOptions(s string) *IPCOptions {
	posQ := strings.Index(s, "?")
	addrWithoutQuery := s
	if posQ >= 0 {
		addrWithoutQuery = s[0:posQ]
	} // end if
	options := DefaultIPCOptions()
	urlquery.Unmarshal([]byte(s[int(math.Max(0, float64(posQ+1))):]), &options)
	options.Endpoint = addrWithoutQuery
	return &options
} // end ParseIPCOptions()

type IPC struct {
	options      IPCOptions
	EndpointBack string
	fnCancel     context.CancelFunc
} // end type

func NewIPC(opts IPCOptions) *IPC {
	return &IPC{options: opts, EndpointBack: fmt.Sprintf("inproc://%s", uuid.New().String())}
} // end NewIPC()

func (ipc *IPC) Stop() {
	if ipc.fnCancel != nil {
		ipc.fnCancel()
	} // end if
} // end Stop()

func (ipc *IPC) Run() error {
	ctx, fnCancel := context.WithCancel(context.Background())
	ipc.fnCancel = fnCancel
	optsFront := []zmq4.Option{}
	if ipc.options.PlainUsername != "" && ipc.options.PlainPassword != "" {
		sec := plain.Security(ipc.options.PlainUsername, ipc.options.PlainPassword)
		optsFront = append(optsFront, zmq4.WithSecurity(sec))
	} // end if
	front := zmq4.NewRouter(ctx, optsFront...)
	if errFrontBind := front.Listen(ipc.options.Endpoint); errFrontBind != nil {
		return errFrontBind
	} // end if
	back := zmq4.NewRouter(ctx)
	if errBackBind := back.Listen(ipc.EndpointBack); errBackBind != nil {
		return errBackBind
	} // end if
	logrus.WithField("endpoint", ipc.options.Endpoint).Info("IPC proxxy starting")
	defer logrus.Info("IPC proxy stopped")

	/*
			// manually forward messages
			chFront := make(chan zmq4.Msg)
			go (func() {
				for {
					msg, err := front.Recv()
					if err != nil {
						if errors.Is(err, io.EOF) {
							logrus.Debug("IPC recv EOF")
						} else {
							logrus.Warnf("Error receiving from IPC client: %+v", err)
						} // end if
						continue
					} // end if
					logrus.WithField("msg", msg.String()).Debug("Received IPC message")
					chFront <- msg
				}
			})()
			chBack := make(chan zmq4.Msg)
			go (func() {
				for {
					msg, err := back.Recv()
					if err != nil {
						if errors.Is(err, io.EOF) {
							logrus.Debug("IPC recv EOF")
						} else {
							logrus.Warnf("Error receiving from IPC worker: %+v", err)
						} // end if
						continue
					} // end if
					logrus.WithField("msg", msg.String()).Debug("Received IPC results")
					chBack <- msg
				}
			})()
		LOOP_PROXY:
			for {
				select {
				case <-ctx.Done():
					break LOOP_PROXY
				case msg, ok := <-chFront:
					if !ok {
						break LOOP_PROXY
					} // end if
					if errSnd := back.SendMulti(msg); errSnd != nil {
						logrus.Warnf("Failed to forward IPC message: %+v", errSnd)
						continue
					} // end if
				case msg, ok := <-chBack:
					if !ok {
						break LOOP_PROXY
					} // end if
					if errSnd := front.SendMulti(msg); errSnd != nil {
						logrus.Warnf("Failed to reply IPC message: %+v", errSnd)
						continue
					} // end if
				} // end select
			} // end for
			return nil
	*/
	return zmq4.NewProxy(ctx, front, back, nil).Run() // use built-in proxy
} // end Run()

func TviewForm() map[string]any {
	results := map[string]any{}
	app := helper.NewMyTviewFormApplication(helper.MyDefaultTviewAppCustomizer, true, func(form *tview.Form) *tview.Form {
		helper.MyDefaultTviewFormCustomizer(form).SetTitle("IPC Configuration")
		return form
	})
	form := app.Form
	inputEp := tview.NewInputField().SetLabel("Endpoint: ").SetFieldWidth(0).SetChangedFunc(func(s string) {
		results["endpoint"] = s
	})
	app.AddInputFieldWithStatusIcon(inputEp, func(s string, _ rune) bool {
		for _, transport := range zmq4.Transports() {
			if strings.HasPrefix(s, fmt.Sprintf("%s:", transport)) {
				return true
			} // end if
		} // end for
		return false
	}, true)
	form.AddInputField("PLAIN username: ", "", 0, nil, func(s string) {
		results["plain_username"] = s
	})
	form.AddPasswordField("PLAIN password: ", "", 0, '*', func(s string) {
		results["plain_password"] = s
	})
	form.SetBorder(true).SetTitle("IPC Configuration").SetTitleAlign(tview.AlignLeft)
	form.AddButton("OK", func() {
		app.Stop()
	})
	app.Run()
	return results
} // end TviewForm()
