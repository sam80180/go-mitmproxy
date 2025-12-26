package cert

import (
	"crypto/tls"
	"crypto/x509"
	"time"
)

type CA interface {
	GetRootCA() *x509.Certificate
	GetCert(commonName string) (*tls.Certificate, error)
	GetCertWithTtl(string, time.Duration) (*tls.Certificate, error)
}
