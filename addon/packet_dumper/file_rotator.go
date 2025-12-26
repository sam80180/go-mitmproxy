package packet_dumper

import (
	"io"
	"os"
	"path/filepath"
	_ "unsafe" // required for go:linkname

	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	"github.com/sirupsen/logrus"
)

//go:linkname rotatelogs_genFilename github.com/lestrrat-go/file-rotatelogs.(*RotateLogs).genFilename
func rotatelogs_genFilename(rl *rotatelogs.RotateLogs) string

type RotaPrefixWriter struct {
	inner          io.Writer
	headerProvider func(string) []byte
	last           string
} // end type

func NewRotaPrefixWriter(p string, options ...rotatelogs.Option) (io.Writer, error) {
	rotator, err := rotatelogs.New(p, options...)
	if err != nil {
		return nil, err
	} // end if
	return &RotaPrefixWriter{inner: rotator}, nil
} // end NewRotaPrefixWriter()

func (p *RotaPrefixWriter) SetHeaderProvider(fn func(string) []byte) {
	p.headerProvider = fn
} // end SetHeaderProvider()

func (p *RotaPrefixWriter) Write(data []byte) (int, error) {
	rl, ok := p.inner.(*rotatelogs.RotateLogs)
	if !ok {
		return p.inner.Write(data)
	} // end if
	cur := rl.CurrentFileName()
	if p.last == "" && cur == "" {
		cur = rotatelogs_genFilename(rl)
	} // end if
	if cur != p.last {
		logrus.Debugf("Write new file ‘%s’", cur)
		p.last = cur
		if p.headerProvider != nil {
			if b := p.headerProvider(cur); len(b) > 0 {
				var err error
				if dir := filepath.Dir(cur); !helper.PathExists(dir) {
					if errMkdir := os.MkdirAll(dir, 0755); errMkdir != nil {
						logrus.Warnf("Failed to create directory ‘%s’: %+v", dir, err)
						goto WRITE_PACKET
					} // end if
				} // end if
				if f, err := os.OpenFile(cur, os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_TRUNC, 0644); err == nil {
					defer f.Close()
					if _, err = f.Write(b); err != nil {
						logrus.Warnf("Failed to prepend file ‘%s’: %+v", cur, err)
					} // end if
				} else {
					logrus.Warnf("Failed to open file ‘%s’: %+v", cur, err)
				} // end if
			} // end if
		} // end if
	} // end if
WRITE_PACKET:
	return p.inner.Write(data)
} // end Write()
