package udpclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
)

// Client maintains a pseudo-connection to a UDP server by dialing a fixed remote.
// If read/write fail, it closes the socket and re-dials with backoff.
type UdpClient struct {
	server *net.UDPAddr

	// runtime
	mu       sync.RWMutex
	conn     *net.UDPConn
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
	started  bool
	shutdown once

	// hooks & config
	onConnect    func(*net.UDPConn)
	onDisconnect func(error)
	onRead       func([]byte)
	logger       func(format string, args ...any)

	minBackoff time.Duration
	maxBackoff time.Duration
	readBuf    int
	queueSize  int

	// write queue
	writeQ chan []byte

	// behavior
	dropIfQueueFull bool
}

// once is a simple single-call guard.
type once struct {
	mu sync.Mutex
	x  bool
}

func (o *once) Do(f func()) {
	o.mu.Lock()
	if !o.x {
		o.x = true
		o.mu.Unlock()
		f()
		return
	}
	o.mu.Unlock()
}

// Options
type Option func(*UdpClient)

func WithBackoff(min, max time.Duration) Option {
	return func(c *UdpClient) { c.minBackoff, c.maxBackoff = min, max }
}

func WithQueueSize(n int) Option {
	return func(c *UdpClient) { c.queueSize = n }
}

func WithReadBuffer(bytes int) Option {
	return func(c *UdpClient) { c.readBuf = bytes }
}

func WithOnConnect(f func(*net.UDPConn)) Option {
	return func(c *UdpClient) { c.onConnect = f }
}

func WithOnDisconnect(f func(error)) Option {
	return func(c *UdpClient) { c.onDisconnect = f }
}

func WithOnRead(f func([]byte)) Option {
	return func(c *UdpClient) { c.onRead = f }
}

func WithLoggerf(f func(string, ...any)) Option {
	return func(c *UdpClient) { c.logger = f }
}

// If true, Send() will drop a packet instead of blocking when the queue is full.
func WithDropIfQueueFull(drop bool) Option {
	return func(c *UdpClient) { c.dropIfQueueFull = drop }
}

func NewUdpClient(server string, opts ...Option) (*UdpClient, error) {
	addr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, fmt.Errorf("resolve UDP: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &UdpClient{
		server:          addr,
		ctx:             ctx,
		cancel:          cancel,
		minBackoff:      200 * time.Millisecond,
		maxBackoff:      10 * time.Second,
		readBuf:         64 * 1024,
		queueSize:       1024,
		dropIfQueueFull: false,
		logger: func(format string, args ...any) {
			// default no-op
		},
	}

	for _, o := range opts {
		o(c)
	}

	c.writeQ = make(chan []byte, c.queueSize)
	return c, nil
}

// Start spawns the reconnect loop. Safe to call once.
func (c *UdpClient) Start() {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return
	}
	c.started = true
	c.mu.Unlock()

	c.wg.Add(1)
	go c.run()
}

// Stop gracefully shuts down the client and waits for workers to exit.
func (c *UdpClient) Stop() {
	c.shutdown.Do(func() {
		c.cancel()
		// close queue so writeLoop can exit if it's blocked
		close(c.writeQ)

		// close current conn to break read/write
		c.mu.Lock()
		if c.conn != nil {
			_ = c.conn.Close()
			c.conn = nil
		}
		c.mu.Unlock()

		c.wg.Wait()
	})
}

func (c *UdpClient) run() {
	defer c.wg.Done()

	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = c.minBackoff
	bo.MaxInterval = c.maxBackoff
	bo.MaxElapsedTime = 0 // retry forever

	for {
		// Respect context cancellation between retries
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		conn, err := net.DialUDP("udp", nil, c.server)
		if err != nil {
			c.logger("udp dial failed: %v", err)
			if !c.waitBackoff(bo) {
				return
			}
			continue
		}
		bo.Reset()

		c.mu.Lock()
		c.conn = conn
		c.mu.Unlock()

		if c.onConnect != nil {
			c.onConnect(conn)
		}

		// Spawn read & write loops bound to this conn
		readErr := make(chan error, 1)
		writeErr := make(chan error, 1)

		c.wg.Add(2)
		go c.readLoop(conn, readErr)
		go c.writeLoop(conn, writeErr)

		// Wait until something breaks or we are canceled
		var loopErr error
		select {
		case loopErr = <-readErr:
		case loopErr = <-writeErr:
		case <-c.ctx.Done():
			loopErr = context.Canceled
		}

		_ = conn.Close()
		c.mu.Lock()
		c.conn = nil
		c.mu.Unlock()

		if loopErr != nil && !errors.Is(loopErr, context.Canceled) {
			if c.onDisconnect != nil {
				c.onDisconnect(loopErr)
			}
			c.logger("conn closed: %v", loopErr)
		}

		// On context cancel: exit; otherwise backoff & re-dial
		if c.ctx.Err() != nil {
			return
		}
		if !c.waitBackoff(bo) {
			return
		}
	}
}

func (c *UdpClient) waitBackoff(bo backoff.BackOff) bool {
	// Sleep with backoff, but allow cancel
	next := bo.NextBackOff()
	if next == backoff.Stop {
		return false
	}
	t := time.NewTimer(next)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-c.ctx.Done():
		return false
	}
}

func (c *UdpClient) readLoop(conn *net.UDPConn, errCh chan<- error) {
	defer c.wg.Done()

	buf := make([]byte, c.readBuf)
	for {
		// Set a read deadline so we can notice ctx cancel periodically.
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Distinguish timeout vs hard error
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// Check for shutdown
				select {
				case <-c.ctx.Done():
					errCh <- context.Canceled
					return
				default:
					continue
				}
			}
			errCh <- err
			return
		}
		if c.onRead != nil && n > 0 {
			// copy out to avoid data race with next read
			cp := append([]byte(nil), buf[:n]...)
			c.onRead(cp)
		}
	}
}

func (c *UdpClient) writeLoop(conn *net.UDPConn, errCh chan<- error) {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			errCh <- context.Canceled
			return
		case pkt, ok := <-c.writeQ:
			if !ok {
				// queue closed on Stop()
				errCh <- context.Canceled
				return
			}
			// Set deadline so we can react to ctx cancel
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err := conn.Write(pkt)
			if err != nil {
				errCh <- err
				return
			}
		}
	}
}

// Send enqueues a datagram to be written. It copies the bytes.
// If the queue is full and dropIfQueueFull is false, it blocks.
func (c *UdpClient) Send(b []byte) error {
	select {
	case <-c.ctx.Done():
		return context.Canceled
	default:
	}

	p := append([]byte(nil), b...) // copy
	if c.dropIfQueueFull {
		select {
		case c.writeQ <- p:
			return nil
		default:
			return ErrQueueFull
		}
	}
	// blocking
	select {
	case c.writeQ <- p:
		return nil
	case <-c.ctx.Done():
		return context.Canceled
	}
}

var ErrQueueFull = errors.New("udpclient: send queue full")

// Connected reports whether there is a currently active UDPConn.
func (c *UdpClient) Connected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn != nil
}
