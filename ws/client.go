package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/inference-sh/recws"
	"github.com/inference-sh/goutils/logging"
)

// ClientConnection represents a WebSocket client connection with auto-reconnect
type ClientConnection struct {
	BaseConnection
	conn      *recws.RecConn
	sendChan  chan *sendOp
	done      chan struct{}
	closeOnce sync.Once
}

// Ensure ClientConnection implements Connection interface
var _ Connection = (*ClientConnection)(nil)

// ClientOptions contains configurable options for WebSocket client connections
type ClientOptions struct {
	Headers           http.Header
	// HeaderFunc, when set, supplies the request header for every dial
	// attempt in place of Headers. Use it when the credential can change
	// while the connection lives — a daemon that outlasts a login — so a
	// reconnect sends the current one rather than the one it started with.
	HeaderFunc        func() http.Header
	HandshakeTimeout  time.Duration
	EnableCompression bool
	ReadBufferSize    int
	WriteBufferSize   int
	// RecIntvlMin specifies the initial reconnecting interval
	RecIntvlMin time.Duration
	// RecIntvlMax specifies the maximum reconnecting interval
	RecIntvlMax time.Duration
	// RecIntvlFactor specifies the rate of increase of the reconnection interval
	RecIntvlFactor float64
	// KeepAliveTimeout is how long the connection may go without a pong or
	// a message from the server before it is closed and redialed. Pings go
	// out every KeepAliveTimeout/3. 0 disables keepalive.
	KeepAliveTimeout time.Duration
}

// DefaultClientOptions returns the default client connection options
func DefaultClientOptions() ClientOptions {
	return ClientOptions{
		Headers:           make(http.Header),
		HandshakeTimeout:  10 * time.Second,
		EnableCompression: true,
		ReadBufferSize:    32768,
		WriteBufferSize:   32768,
		RecIntvlMin:       2 * time.Second,
		RecIntvlMax:       30 * time.Second,
		RecIntvlFactor:    1.5,
		KeepAliveTimeout:  60 * time.Second,
	}
}

// NewClientConnection creates a new WebSocket client connection with default options
func NewClientConnection(url string, header http.Header) (*ClientConnection, error) {
	options := DefaultClientOptions()
	options.Headers = header
	return NewClientConnectionWithOptions(url, options)
}

// slogWrapper adapts recws's slog-style logger (message plus key/value
// pairs) to the logging package. The pairs are rendered as key=value; they
// are not printf arguments, and passing them as such printed
// "%!(EXTRA ...)" garbage in place of the one thing an operator needed to
// see, such as the status a refused handshake came back with.
type slogWrapper struct{}

func (l *slogWrapper) Debug(msg string, args ...any) {
	logging.Debug("ws").Msgf("%s", slogLine(msg, args))
}

func (l *slogWrapper) Info(msg string, args ...any) {
	logging.Info("ws").Msgf("%s", slogLine(msg, args))
}

func (l *slogWrapper) Warn(msg string, args ...any) {
	logging.Warn("ws").Msgf("%s", slogLine(msg, args))
}

func (l *slogWrapper) Error(msg string, args ...any) {
	logging.Error("ws").Msgf("%s", slogLine(msg, args))
}

// slogLine renders msg followed by args as key=value pairs, the way slog
// would; an odd trailing argument is kept rather than dropped.
func slogLine(msg string, args []any) string {
	if len(args) == 0 {
		return msg
	}
	var b strings.Builder
	b.WriteString(msg)
	for i := 0; i < len(args); i += 2 {
		b.WriteByte(' ')
		if i+1 < len(args) {
			fmt.Fprintf(&b, "%v=%v", args[i], args[i+1])
		} else {
			fmt.Fprintf(&b, "%v", args[i])
		}
	}
	return b.String()
}

// NewClientConnectionWithOptions creates a new WebSocket client connection with custom options
func NewClientConnectionWithOptions(url string, options ClientOptions) (*ClientConnection, error) {
	// Create a logger adapter that converts our utils.Logger to slog interface
	slogAdapter := &slogWrapper{}

	recConn := &recws.RecConn{
		HandshakeTimeout: options.HandshakeTimeout,
		RecIntvlMin:      options.RecIntvlMin,
		RecIntvlMax:      options.RecIntvlMax,
		RecIntvlFactor:   options.RecIntvlFactor,
		KeepAliveTimeout: options.KeepAliveTimeout,
		HeaderFunc:       options.HeaderFunc,
		Logger:           slogAdapter,
	}

	c := &ClientConnection{
		BaseConnection: NewBaseConnection(context.Background()),
		conn:           recConn,
		sendChan:       make(chan *sendOp),
		done:           make(chan struct{}),
	}

	logging.Info("ws").Msgf( "Starting WebSocket client send loop")
	go c.sendLoop()
	logging.Info("ws").Msgf( "Starting WebSocket client dial")
	recConn.Dial(url, options.Headers)
	logging.Info("ws").Msgf( "WebSocket client dialed")
	return c, nil
}

// IsConnected reports whether the socket is currently established. The dial
// runs in the background and reconnects on its own, so callers that must
// know — a daemon telling its operator "connected" — poll this rather than
// trusting that NewClientConnection returned.
func (c *ClientConnection) IsConnected() bool {
	return c.conn.IsConnected()
}

// LastDialError returns the most recent dial failure, or nil once connected.
func (c *ClientConnection) LastDialError() error {
	return c.conn.GetDialError()
}

// LastHandshakeStatus returns the HTTP status the server answered the most
// recent handshake with, or 0 when there was no answer (connection refused,
// timeout) or the dial has not happened yet.
func (c *ClientConnection) LastHandshakeStatus() int {
	resp := c.conn.GetHTTPResponse()
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}

// Handle registers a handler for a specific message type
func (c *ClientConnection) Handle(msgType string, handler TypedHandler) {
	c.handlers[msgType] = handler
}

// Send sends a message through the WebSocket
func (c *ClientConnection) Send(msgType string, data any) error {
	op := &sendOp{
		msgType: msgType,
		data:    data,
		done:    make(chan error, 1),
	}

	select {
	case c.sendChan <- op:
		return <-op.done
	case <-c.done:
		return ErrNotConnected
	}
}

func (c *ClientConnection) sendLoop() {
	for {
		select {
		case <-c.done:
			return
		case op := <-c.sendChan:
			if !c.conn.IsConnected() {
				op.done <- ErrNotConnected
				continue
			}

			msg := RawMessage{
				Type: op.msgType,
				Data: json.RawMessage{},
			}

			if op.data != nil {
				jsonData, err := json.Marshal(op.data)
				if err != nil {
					op.done <- fmt.Errorf("failed to marshal message data: %w", err)
					continue
				}
				msg.Data = jsonData
			}

			op.done <- c.conn.WriteJSON(msg)
		}
	}
}

// Listen starts listening for incoming messages
func (c *ClientConnection) Listen(ctx context.Context) {
	logging.Info("ws").Msgf( "Starting WebSocket client listener")
	defer c.Close()

	// Start message processor
	go c.BaseConnection.processMessages()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		default:
			if !c.conn.IsConnected() {
				time.Sleep(time.Second) // Wait before checking connection again
				continue
			}

			var msg RawMessage
			err := c.conn.ReadJSON(&msg)
			if err != nil {
				logging.Error("ws").Msgf( "Error reading message: %v", err)
				continue // Let recws handle reconnection
			}
			// recws answers a normal close with a nil error and nothing read;
			// that is the end of the connection, not a message to route.
			if msg.Type == "" {
				continue
			}

			if !c.enqueue(ctx, c.done, msg) {
				return
			}
		}
	}
}

// Close closes the WebSocket connection. Safe to call concurrently; only the
// first call closes.
func (c *ClientConnection) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		// Send a proper close frame so the server sees a clean disconnect
		// instead of a 1006 abnormal closure. Only when connected: recws writes
		// the frame on its embedded *websocket.Conn, which is nil when the dial
		// never succeeded (e.g. a daemon stuck on a refused handshake).
		if c.conn.IsConnected() {
			c.conn.Shutdown(5 * time.Second)
		} else {
			c.conn.Close()
		}
	})
	return nil
}
