package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"

	"github.com/datasapiens/cachier"
	"github.com/lqqyt2423/go-mitmproxy/cert"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	myipc "github.com/lqqyt2423/go-mitmproxy/ipc"
	mymetrics "github.com/lqqyt2423/go-mitmproxy/metrics"
	mytracing "github.com/lqqyt2423/go-mitmproxy/tracing"
	do "github.com/samber/do/v2"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

const SERVICE_NAME string = "mitmproxy"
const APP_VERSION string = "1.8.5"

type Options struct {
	Debug             int
	Addr              string
	StreamLargeBodies int64 // 当请求或响应体大于此字节时，转为 stream 模式
	SslInsecure       bool
	CaRootPath        string
	NewCaFunc         func() (cert.CA, error) //创建 Ca 的函数
	Upstream          string

	MetricsOptions *mymetrics.MetricsOptions
	TracingOptions *mytracing.TracingOptions
	IPCOptions     *myipc.IPCOptions
}

type Proxy struct {
	Opts    *Options
	Version string
	Addons  []Addon

	injector        do.Injector
	entry           *entry
	attacker        *attacker
	shouldIntercept func(req *http.Request) bool              // req is received by proxy.server
	upstreamProxy   func(req *http.Request) (*url.URL, error) // req is received by proxy.server, not client request
	authProxy       func(res http.ResponseWriter, req *http.Request) (bool, error)
	cache           *cachier.Cache[any]
}

// proxy.server req context key
var proxyReqCtxKey = new(struct{})

func NewProxyWithDI(opts *Options, di do.Injector) (*Proxy, error) {
	if opts.StreamLargeBodies <= 0 {
		opts.StreamLargeBodies = 1024 * 1024 * 5 // default: 5mb
	}

	proxy := &Proxy{
		Opts:     opts,
		Version:  APP_VERSION,
		Addons:   make([]Addon, 0),
		injector: di,
	}

	if proxy.Opts.MetricsOptions != nil {
		if errMtr := initMeter(proxy, *proxy.Opts.MetricsOptions); errMtr != nil {
			return nil, errMtr
		} // end if
	} // end if
	if proxy.Opts.TracingOptions != nil {
		if errTp := initTracer(proxy, *proxy.Opts.TracingOptions); errTp != nil {
			return nil, errTp
		} // end if
	} // end if
	if proxy.Opts.IPCOptions != nil {
		ipc := myipc.NewIPC(*proxy.Opts.IPCOptions)
		do.Provide(proxy.injector, func(do.Injector) (*myipc.IPC, error) {
			return ipc, nil
		})
		go (func() {
			if err := ipc.Run(); err != nil {
				logrus.Errorf("IPC error: %+v", err)
			} // end if
		})()
	} // end if
	proxy.entry = newEntry(proxy)

	attacker, err := newAttacker(proxy)
	if err != nil {
		return nil, err
	}
	proxy.attacker = attacker

	return proxy, nil
}

func NewProxy(opts *Options) (*Proxy, error) {
	return NewProxyWithDI(opts, do.New())
} // end NewProxy()

func (proxy *Proxy) InitCache(engine cachier.CacheEngine) {
	proxy.cache = cachier.MakeCache[any](engine, log.StandardLogger())
} // end InitCache()

func (proxy *Proxy) Cache() *cachier.Cache[any] {
	return proxy.cache
} // end Cache()

func (proxy *Proxy) DI() do.Injector {
	return proxy.injector
} // end DI()

func (proxy *Proxy) AddAddon(addon Addon) {
	proxy.Addons = append(proxy.Addons, addon)
}

func (proxy *Proxy) Start() error {
	go func() {
		if err := proxy.attacker.start(); err != nil {
			log.Error(err)
		}
	}()
	return proxy.entry.start()
}

func (proxy *Proxy) Close() error {
	return proxy.entry.close()
}

func (proxy *Proxy) Shutdown(ctx context.Context) error {
	return proxy.entry.shutdown(ctx)
}

func (proxy *Proxy) GetCertificate() x509.Certificate {
	return *proxy.attacker.ca.GetRootCA()
}

func (proxy *Proxy) GetCertificateByCN(commonName string) (*tls.Certificate, error) {
	return proxy.attacker.ca.GetCert(commonName)
}

func (proxy *Proxy) SetShouldInterceptRule(rule func(req *http.Request) bool) {
	proxy.shouldIntercept = rule
}

func (proxy *Proxy) SetUpstreamProxy(fn func(req *http.Request) (*url.URL, error)) {
	proxy.upstreamProxy = fn
}

func (proxy *Proxy) realUpstreamProxy() func(*http.Request) (*url.URL, error) {
	return func(cReq *http.Request) (*url.URL, error) {
		req := cReq.Context().Value(proxyReqCtxKey).(*http.Request)
		return proxy.getUpstreamProxyUrl(req)
	}
}

func (proxy *Proxy) getUpstreamProxyUrl(req *http.Request) (*url.URL, error) {
	if proxy.upstreamProxy != nil {
		return proxy.upstreamProxy(req)
	}
	if len(proxy.Opts.Upstream) > 0 {
		return url.Parse(proxy.Opts.Upstream)
	}
	cReq := &http.Request{URL: &url.URL{Scheme: "https", Host: req.Host}}
	return http.ProxyFromEnvironment(cReq)
}

func (proxy *Proxy) getUpstreamConn(ctx context.Context, req *http.Request) (net.Conn, error) {
	proxyUrl, err := proxy.getUpstreamProxyUrl(req)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	address := helper.CanonicalAddr(req.URL)
	if proxyUrl != nil {
		conn, err = helper.GetProxyConn(ctx, proxyUrl, address, proxy.Opts.SslInsecure)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	return conn, err
}

func (proxy *Proxy) SetAuthProxy(fn func(res http.ResponseWriter, req *http.Request) (bool, error)) {
	proxy.authProxy = fn
}
