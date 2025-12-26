package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	"github.com/datasapiens/cachier"
	"github.com/golang/groupcache/singleflight"
	mycache "github.com/lqqyt2423/go-mitmproxy/cache"
	"github.com/lqqyt2423/go-mitmproxy/cert"
	log "github.com/sirupsen/logrus"
)

type TrustedCA struct {
	cache   *cachier.Cache[any]
	group   *singleflight.Group
	cacheMu sync.Mutex
}

func NewTrustedCA() (cert.CA, error) {
	cacheEngine, errCache := mycache.NewPkgzExpirableCache(100, cert.DEFAULT_CERT_TTL, true)
	if errCache != nil {
		return nil, errCache
	} // end if
	ca := &TrustedCA{
		cache: cachier.MakeCache[any](cacheEngine, log.StandardLogger()),
		group: new(singleflight.Group),
	}
	return ca, nil
}

func (ca *TrustedCA) GetRootCA() *x509.Certificate {
	panic("not supported")
}

func (ca *TrustedCA) GetCertWithTtl(commonName string, ttl time.Duration) (*tls.Certificate, error) {
	getter := func() (*tls.Certificate, error) {
		val, err := ca.group.Do(commonName, func() (interface{}, error) {
			return ca.loadCert(commonName)
		})
		if err != nil {
			return nil, err
		} // end if
		return val.(*tls.Certificate), nil
	}
	ca.cacheMu.Lock()
	defer ca.cacheMu.Unlock()
	var cert *tls.Certificate
	var err error
	ptrAny, _, ee := mycache.GetOrComputeValueWithTTL[*tls.Certificate](ca.cache, commonName, func() (*any, error) {
		var ptr any
		var err error
		ptr, err = getter()
		return &ptr, err
	}, ttl)
	err = ee
	if ptrAny != nil {
		cert = *ptrAny
	} // end if
	return cert, err
}

func (ca *TrustedCA) GetCert(commonName string) (*tls.Certificate, error) {
	return ca.GetCertWithTtl(commonName, cert.DEFAULT_CERT_TTL)
}

func (ca *TrustedCA) loadCert(commonName string) (*tls.Certificate, error) {
	switch commonName {
	case "your-domain.xx.com":
		certificate, err := tls.LoadX509KeyPair("cert Path", "key Path")
		if err != nil {
			return nil, err
		}
		return &certificate, err
	case "your-domain2.xx.com":
		certificate, err := tls.X509KeyPair([]byte("cert Block"), []byte("key Block"))
		if err != nil {
			return nil, err
		}
		return &certificate, err
	default:
		return nil, errors.New("invalid certificate name")
	}
}
