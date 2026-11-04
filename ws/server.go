package ws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	idgen "github.com/inference-sh/goutils/id"
	"github.com/inference-sh/goutils/logging"
)

// DefaultServerReadTimeout is how long Listen waits for anything from the
// peer (a message, a ping or a pong) before it closes the connection. It is
// 3x the slowest heartbeat a healthy client sends: a goutils client pings
// every ClientOptions.KeepAliveTimeout/3 (20s by default), and recws v1.6.5
// and older pinged only every KeepAliveTimeout (60s). Engines also send a
// heartbeat message every 1s and belt remotes every 5s.
const DefaultServerReadTimeout = 90 * time.Second

// ServerConnection represents a WebSocket server connection
type ServerConnection struct {
	BaseConnection
	ID string
	// ReadTimeout is the read deadline Listen keeps on the connection: set
	// when Listen starts and pushed forward on every message, ping and pong.
	// A peer that sends nothing for this long, a hung or half-open one among
	// them, has its socket closed. Defaults to DefaultServerReadTimeout; set
	// it before Listen. 0 or less disables it.
	ReadTimeout time.Duration
	conn        *websocket.Conn
	sendChan    chan *sendOp
	done        chan struct{}
	closeOnce   sync.Once
}

// Ensure ServerConnection implements Connection interface
var _ Connection = (*ServerConnection)(nil)

// NewServerConnection creates a new WebSocket connection from an HTTP upgrade
func NewServerConnection(w http.ResponseWriter, r *http.Request) (*ServerConnection, error) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  32768,
		WriteBufferSize: 32768,
		CheckOrigin: func(r *http.Request) bool {
			return true // Override this in production
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to upgrade connection: %w", err)
	}

	connID := idgen.GenerateShortID(8)

	c := &ServerConnection{
		BaseConnection: NewBaseConnection(r.Context()),
		ID:             connID,
		ReadTimeout:    DefaultServerReadTimeout,
		conn:           conn,
		sendChan:       make(chan *sendOp),
		done:           make(chan struct{}),
	}

	go c.sendLoop()
	return c, nil
}

// Handle registers a handler for a specific message type
func (c *ServerConnection) Handle(msgType string, handler TypedHandler) {
	c.handlers[msgType] = handler
}

// Send sends a message through the WebSocket
func (c *ServerConnection) Send(msgType string, data any) error {
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

func (c *ServerConnection) sendLoop() {
	for {
		select {
		case <-c.done:
			return
		case op := <-c.sendChan:
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
func (c *ServerConnection) Listen(ctx context.Context) {
	logging.Info("ws").Msgf("Starting WebSocket server listener conn_id=%s", c.ID)
	defer c.Close()

	// Start message processor
	go c.BaseConnection.processMessages()

	c.keepReadDeadline()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		default:
			var msg RawMessage
			err := c.conn.ReadJSON(&msg)
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					return
				}
				logging.Error("ws").Msgf("Error reading message conn_id=%s: %v", c.ID, err)
				return
			}
			c.extendReadDeadline()

			if !c.enqueue(ctx, c.done, msg) {
				return
			}
		}
	}
}

// keepReadDeadline sets the first read deadline and has every ping and pong
// push it forward. Pings are still answered with a pong, as gorilla's
// default handler does.
func (c *ServerConnection) keepReadDeadline() {
	if c.ReadTimeout <= 0 {
		return
	}
	c.extendReadDeadline()
	c.conn.SetPingHandler(func(appData string) error {
		c.extendReadDeadline()
		err := c.conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(time.Second))
		if err == websocket.ErrCloseSent {
			return nil
		}
		var netErr net.Error
		if errors.As(err, &netErr) {
			return nil
		}
		return err
	})
	c.conn.SetPongHandler(func(string) error {
		c.extendReadDeadline()
		return nil
	})
}

// extendReadDeadline pushes the read deadline ReadTimeout past now.
func (c *ServerConnection) extendReadDeadline() {
	if c.ReadTimeout > 0 {
		c.conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	}
}

// Leave tells the peer this server is going away (close code 1001), so a
// reconnecting client moves to another instance at once, then closes.
func (c *ServerConnection) Leave() error {
	if c.conn != nil {
		msg := websocket.FormatCloseMessage(websocket.CloseGoingAway, "server shutting down")
		_ = c.conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(time.Second))
	}
	return c.Close()
}

// Close closes the WebSocket connection. Safe to call from several
// goroutines at once (the handler, a hub and a key revocation can all close
// the same socket); only the first call closes, the rest return nil.
func (c *ServerConnection) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.done)
		if c.conn != nil {
			err = c.conn.Close()
		}
	})
	return err
}
