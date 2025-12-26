package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	zmq "github.com/go-zeromq/zmq4" // just want some of the enums, nothing else 😜
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	mymetrics "github.com/lqqyt2423/go-mitmproxy/metrics"
	mysnmp "github.com/lqqyt2423/go-mitmproxy/snmp"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	do "github.com/samber/do/v2"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// wrap tcpListener for remote client
type wrapListener struct {
	net.Listener
	proxy *Proxy
}

func (l *wrapListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	proxy := l.proxy
	wc := newWrapClientConn(c, proxy)
	connCtx := newConnContext(wc, proxy)
	wc.connCtx = connCtx

	for _, addon := range proxy.Addons {
		addon.ClientConnected(connCtx.ClientConn)
	}

	return wc, nil
}

// wrap tcpConn for remote client
type wrapClientConn struct {
	net.Conn
	r       *bufio.Reader
	proxy   *Proxy
	connCtx *ConnContext

	closeMu   sync.Mutex
	closed    bool
	closeErr  error
	closeChan chan struct{}
}

func newWrapClientConn(c net.Conn, proxy *Proxy) *wrapClientConn {
	return &wrapClientConn{
		Conn:      c,
		r:         bufio.NewReader(c),
		proxy:     proxy,
		closeChan: make(chan struct{}),
	}
}

func (c *wrapClientConn) Peek(n int) ([]byte, error) {
	return c.r.Peek(n)
}

func (c *wrapClientConn) Read(data []byte) (int, error) {
	return c.r.Read(data)
}

func (c *wrapClientConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}
	log.Debugln("in wrapClientConn close", c.connCtx.ClientConn.Conn.RemoteAddr())

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()
	close(c.closeChan)

	for _, addon := range c.proxy.Addons {
		addon.ClientDisconnected(c.connCtx.ClientConn)
	}

	if c.connCtx.ServerConn != nil && c.connCtx.ServerConn.Conn != nil {
		c.connCtx.ServerConn.Conn.Close()
	}

	return c.closeErr
}

// wrap tcpConn for remote server
type wrapServerConn struct {
	net.Conn
	proxy   *Proxy
	connCtx *ConnContext

	closeMu  sync.Mutex
	closed   bool
	closeErr error
}

func (c *wrapServerConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}
	log.Debugln("in wrapServerConn close", c.connCtx.ClientConn.Conn.RemoteAddr())

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()

	for _, addon := range c.proxy.Addons {
		addon.ServerDisconnected(c.connCtx)
	}

	if !c.connCtx.ClientConn.Tls {
		c.connCtx.ClientConn.Conn.(*wrapClientConn).Conn.(*net.TCPConn).CloseRead()
	} else {
		// if keep-alive connection close
		if !c.connCtx.closeAfterResponse {
			c.connCtx.ClientConn.Conn.Close()
		}
	}

	return c.closeErr
}

type entry struct {
	proxy  *Proxy
	server *http.Server
}

func newEntry(proxy *Proxy) *entry {
	e := &entry{proxy: proxy}
	e.server = &http.Server{
		Addr:    proxy.Opts.Addr,
		Handler: e,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey, c.(*wrapClientConn).connCtx)
		},
	}
	if e.proxy.Opts.TracingOptions != nil || e.proxy.Opts.MetricsOptions != nil {
		originalHandler := e.server.Handler // avoid call stack overflow
		opts := []otelhttp.Option{}
		if e.proxy.Opts.TracingOptions != nil {
			opts = append(opts, otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				return otelSpanNameFormatter(r)
			}))
		} // end if
		e.server.Handler = otelTraced(originalHandler, opts...)
	} // end if
	return e
}

func (e *entry) start() error {
	addr := e.server.Addr
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	if e.proxy.Opts.MetricsOptions != nil && e.proxy.Opts.MetricsOptions.Mode == string(zmq.Pull) {
		go (func() {
			switch e.proxy.Opts.MetricsOptions.Type {
			case "prometheus":
				logrus.WithField("type", e.proxy.Opts.MetricsOptions.Type).WithField("metrics_path", e.proxy.Opts.MetricsOptions.MetricsPath).Infof("Metrics exporter listening at %s", e.proxy.Opts.MetricsOptions.Addr)
				go (func() {
					h := promhttp.Handler()
					mux := http.NewServeMux()
					mux.Handle(e.proxy.Opts.MetricsOptions.MetricsPath, h)
					wrapped_handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // wrap the mux with a custom handler that returns 404 for all unmatched routes
						_, pattern := mux.Handler(r)
						if pattern == "" || (pattern == "/" && r.URL.Path != "/") {
							http.NotFound(w, r)
							return
						} // end if
						mux.ServeHTTP(w, r)
					})
					http.ListenAndServe(e.proxy.Opts.MetricsOptions.Addr, wrapped_handler)
				})()
			case "snmp":
				recorder := do.MustInvoke[*mymetrics.SNMPRecorder](e.proxy.injector)
				go mysnmp.StartSnmpd(e.proxy.Opts.MetricsOptions.Addr, e.proxy.Opts.MetricsOptions.SNMPCommunity, e.proxy.Opts.Addr, e.proxy.Version, recorder.OIDs())
			default:
				panic(fmt.Sprintf("unsupported metrics backend ‘%+v’", e.proxy.Opts.MetricsOptions.Type))
			} // end switch
		})()
	} // end if
	log.Infof("Proxy start listen at %v\n", e.server.Addr)
	pln := &wrapListener{
		Listener: ln,
		proxy:    e.proxy,
	}
	return e.server.Serve(pln)
}

func (e *entry) close() error {
	return e.server.Close()
}

func (e *entry) shutdown(ctx context.Context) error {
	return e.server.Shutdown(ctx)
}

func (e *entry) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	proxy := e.proxy

	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.ServeHTTP",
		"host": req.Host,
	})
	// Add entry proxy authentication
	if e.proxy.authProxy != nil {
		b, err := e.proxy.authProxy(res, req)
		if !b {
			log.Errorf("Proxy authentication failed: %s", err.Error())
			httpError(res, "", http.StatusProxyAuthRequired)
			return
		}
	}
	// proxy via connect tunnel
	if req.Method == "CONNECT" {
		e.handleConnect(res, req)
		return
	}

	if !req.URL.IsAbs() || req.URL.Host == "" {
		res = helper.NewResponseCheck(res)
		for _, addon := range proxy.Addons {
			addon.AccessProxyServer(req, res)
		}
		if res, ok := res.(*helper.ResponseCheck); ok {
			if !res.Wrote {
				res.WriteHeader(400)
				io.WriteString(res, "此为代理服务器，不能直接发起请求")
			}
		}
		return
	}

	// http proxy
	proxy.attacker.initHttpDialFn(req)
	proxy.attacker.attack(res, req)
}

func (e *entry) handleConnect(res http.ResponseWriter, req *http.Request) {
	proxy := e.proxy

	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.handleConnect",
		"host": req.Host,
	})

	shouldIntercept := proxy.shouldIntercept == nil || proxy.shouldIntercept(req)
	f := newFlow()
	f.Request = newRequest(req)
	f.ConnContext = req.Context().Value(connContextKey).(*ConnContext)
	f.ConnContext.Intercept = shouldIntercept
	defer f.finish()

	// trigger addon event Requestheaders
	for _, addon := range proxy.Addons {
		addon.Requestheaders(f)
	}

	if !shouldIntercept {
		log.Debugf("begin transpond %v", req.Host)
		e.directTransfer(res, req, f)
		return
	}

	if f.ConnContext.ClientConn.UpstreamCert {
		e.httpsDialFirstAttack(res, req, f)
		return
	}

	log.Debugf("begin intercept %v", req.Host)
	e.httpsDialLazyAttack(res, req, f)
}

func (e *entry) establishConnection(res http.ResponseWriter, f *Flow) (net.Conn, error) {
	cconn, _, err := res.(http.Hijacker).Hijack()
	if err != nil {
		res.WriteHeader(http.StatusBadGateway)
		return nil, err
	}
	_, err = io.WriteString(cconn, fmt.Sprintf("HTTP/1.1 %d Connection Established\r\n\r\n", http.StatusOK))
	if err != nil {
		cconn.Close()
		return nil, err
	}

	f.Response = &Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}

	// trigger addon event Responseheaders
	for _, addon := range e.proxy.Addons {
		addon.Responseheaders(f)
	}

	return cconn, nil
}

func (e *entry) directTransfer(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.directTransfer",
		"host": req.Host,
	})

	conn, err := proxy.getUpstreamConn(req.Context(), req)
	if err != nil {
		log.Error(err)
		res.WriteHeader(http.StatusBadGateway)
		return
	}
	defer conn.Close()

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		log.Error(err)
		return
	}
	defer cconn.Close()

	transfer(log, conn, cconn)
}

func (e *entry) httpsDialFirstAttack(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.httpsDialFirstAttack",
		"host": req.Host,
	})
	reqCtx := helper.ContextAddKey(req.Context(), "request.url", f.Request.URL)

	conn, err := proxy.attacker.httpsDial(reqCtx, req)
	if err != nil {
		log.Error(err)
		res.WriteHeader(http.StatusBadGateway)
		return
	}

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		conn.Close()
		log.Error(err)
		return
	}

	peek, err := cconn.(*wrapClientConn).Peek(3)
	if err != nil {
		cconn.Close()
		conn.Close()
		log.Error(err)
		return
	}
	if !helper.IsTls(peek) {
		// todo: http, ws
		transfer(log, conn, cconn)
		cconn.Close()
		conn.Close()
		return
	}

	// is tls
	f.ConnContext.ClientConn.Tls = true
	proxy.attacker.httpsTlsDial(reqCtx, cconn, conn)
}

func (e *entry) httpsDialLazyAttack(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	log := log.WithFields(log.Fields{
		"in":   "Proxy.entry.httpsDialLazyAttack",
		"host": req.Host,
	})
	reqCtx := helper.ContextAddKey(req.Context(), "request.url", f.Request.URL)

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		log.Error(err)
		return
	}

	peek, err := cconn.(*wrapClientConn).Peek(3)
	if err != nil {
		cconn.Close()
		log.Error(err)
		return
	}

	if !helper.IsTls(peek) {
		// todo: http, ws
		conn, err := proxy.attacker.httpsDial(reqCtx, req)
		if err != nil {
			cconn.Close()
			log.Error(err)
			return
		}
		transfer(log, conn, cconn)
		conn.Close()
		cconn.Close()
		return
	}

	// is tls
	f.ConnContext.ClientConn.Tls = true
	proxy.attacker.httpsLazyAttack(reqCtx, cconn, req)
}
