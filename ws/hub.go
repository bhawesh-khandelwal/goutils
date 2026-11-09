package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/inference-sh/goutils/logging"
)

// Hub manages all active WebSocket server connections
type Hub struct {
	// Connections mapped by ID (e.g., engine ID)
	connections sync.Map
	// Optional PubSub interface for scaling
	connectionStore ConnectionStore
	// Instance ID to identify this hub instance
	instanceID string

	// pubsub ttl keys
	ttlMu   sync.RWMutex
	ttlKeys map[string]struct{}
}

// NewHub creates a new connection hub
func NewHub(instanceID string, connectionStore ConnectionStore) *Hub {
	hub := &Hub{
		instanceID:      instanceID,
		connectionStore: connectionStore,
		ttlKeys:         make(map[string]struct{}),
	}

	if connectionStore != nil {
		// Subscribe to direct messages for this instance
		connectionStore.Subscribe(fmt.Sprintf("instance_%s", instanceID), func(message []byte) {
			var msg struct {
				ConnectionID string          `json:"connection_id"`
				Type         string          `json:"type"`
				Data         json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(message, &msg); err != nil {
				logging.Error("ws").Msgf("failed to unmarshal instance message: %v", err)
				return
			}

			// Forward the message if this hub holds the connection. Every
			// hub on the instance (engines, remotes) receives every message
			// sent to the instance; the others ignore it.
			if c, ok := hub.connections.Load(msg.ConnectionID); ok {
				conn := c.(*ServerConnection)
				var data any
				if len(msg.Data) > 0 {
					if err := json.Unmarshal(msg.Data, &data); err != nil {
						logging.Error("ws").Msgf("failed to unmarshal message data: %v", err)
						return
					}
				}
				conn.Send(msg.Type, data)
			}
		})

		go hub.startTTLRefresh()
	}

	return hub
}

func (h *Hub) startTTLRefresh() {
	go func() {
		ticker := time.NewTicker(connectionRefreshEvery)
		defer ticker.Stop()

		for range ticker.C {
			h.ttlMu.RLock()
			ids := make([]string, 0, len(h.ttlKeys))
			for id := range h.ttlKeys {
				ids = append(ids, id)
			}
			h.ttlMu.RUnlock()
			heldElsewhere, err := h.connectionStore.Refresh(ids, h.instanceID)
			if err != nil {
				logging.Warn("ws").Msgf("failed to renew %d connection lease(s): %v", len(ids), err)
			}
			for _, id := range heldElsewhere {
				logging.Info("ws").Msgf("connection lease for %s is held by another instance; not renewing", id)
			}
		}
	}()
}

// Register adds a server connection to the hub with an identifier
func (h *Hub) Register(id string, conn *ServerConnection) {
	if prev, loaded := h.connections.Load(id); loaded {
		if sc, ok := prev.(*ServerConnection); ok {
			logging.Info("ws").Msgf("Replacing connection for %s: old_conn=%s new_conn=%s", id, sc.ID, conn.ID)
		}
	} else {
		logging.Info("ws").Msgf("Registering connection for %s: conn_id=%s", id, conn.ID)
	}
	h.connections.Store(id, conn)
	h.ttlMu.Lock()
	h.ttlKeys[id] = struct{}{}
	h.ttlMu.Unlock()
	if h.connectionStore != nil {
		if err := h.connectionStore.Register(id, h.instanceID); err != nil {
			logging.Error("ws").Msgf("failed to register connection in pubsub: %v", err)
		}
	}
}

// Unregister removes a connection from the hub and releases its lease, and
// reports whether this instance still held the connection: false when a newer
// connection replaced it here or on another instance. Only a true result means
// the connection is really gone; the caller should record a disconnect only
// then.
// If conn is provided, only removes if it matches the current connection (prevents race on reconnect).
func (h *Hub) Unregister(id string, conn *ServerConnection) bool {
	if conn != nil {
		// Only unregister if this is still the active connection
		current, loaded := h.connections.Load(id)
		if !loaded || current != conn {
			logging.Info("ws").Msgf("Skipping unregister for %s: conn_id=%s was already replaced", id, conn.ID)
			return false // Connection was replaced by a newer one
		}
	}

	connID := ""
	if c, ok := h.connections.LoadAndDelete(id); ok {
		if sc, ok := c.(*ServerConnection); ok {
			connID = sc.ID
			sc.Close()
		}
	}
	logging.Info("ws").Msgf("Unregistered connection for %s: conn_id=%s", id, connID)
	h.ttlMu.Lock()
	delete(h.ttlKeys, id)
	h.ttlMu.Unlock()
	if h.connectionStore == nil {
		return true
	}
	owned, err := h.connectionStore.Unregister(id, h.instanceID)
	if err != nil {
		logging.Error("ws").Msgf("failed to release connection lease for %s: %v", id, err)
		return false
	}
	if !owned {
		logging.Info("ws").Msgf("connection lease for %s is held by another instance; left in place", id)
	}
	return owned
}

// Live reports which of ids are connected, and on which instance. With a
// connection store that is the cross-instance leases; without one, this
// instance's own connections.
func (h *Hub) Live(ids []string) (map[string]string, error) {
	if h.connectionStore != nil {
		return h.connectionStore.Live(ids)
	}
	live := make(map[string]string, len(ids))
	for _, id := range ids {
		if _, ok := h.connections.Load(id); ok {
			live[id] = h.instanceID
		}
	}
	return live, nil
}

// ConnectionState represents the state of a connection
type ConnectionState int

const (
	ConnectionNotFound ConnectionState = iota
	ConnectionLocal
	ConnectionRemote
)

// locate resolves where a connection is and who holds it. With a connection
// store the lease is authoritative: a connection that reconnected to another
// instance is reported ConnectionRemote even while a stale local socket lingers
// here, so a message is forwarded to the holder rather than written to the dead
// socket and silently lost. A store error is returned, not swallowed: the local
// socket may be the stale one, so delivery must not fall back to it blindly;
// the caller decides. The returned instance is meaningful only for
// ConnectionRemote.
func (h *Hub) locate(id string) (ConnectionState, string, error) {
	_, local := h.connections.Load(id)
	if h.connectionStore == nil {
		if local {
			return ConnectionLocal, h.instanceID, nil
		}
		return ConnectionNotFound, "", nil
	}

	holder, err := h.connectionStore.Find(id)
	if err != nil {
		return ConnectionNotFound, "", fmt.Errorf("resolve connection %s: %w", id, err)
	}

	switch {
	case holder == nil:
		// No lease. A local socket whose lease lapsed is still served.
		if local {
			return ConnectionLocal, h.instanceID, nil
		}
		return ConnectionNotFound, "", nil
	case *holder == h.instanceID:
		if local {
			return ConnectionLocal, h.instanceID, nil
		}
		// The lease is this instance's but this hub has no socket for it: a
		// sibling hub on the same instance (engines and remotes share one) holds
		// it. Forward to the instance channel, where that hub delivers it.
		return ConnectionRemote, h.instanceID, nil
	default:
		return ConnectionRemote, *holder, nil
	}
}

// GetConnectionState returns detailed information about a connection's state.
// Presence is best-effort: when the store is unreachable it reports a local
// socket if one exists rather than fail, since a stale read here is harmless.
// Delivery does not share that leniency; see SendToConnection.
func (h *Hub) GetConnectionState(id string) ConnectionState {
	state, _, err := h.locate(id)
	if err != nil {
		if _, ok := h.connections.Load(id); ok {
			return ConnectionLocal
		}
		return ConnectionNotFound
	}
	return state
}

// GetConnection retrieves a server connection by ID
func (h *Hub) GetConnection(id string) (*ServerConnection, bool) {
	state := h.GetConnectionState(id)

	switch state {
	case ConnectionLocal:
		if conn, ok := h.connections.Load(id); ok {
			if c, ok := conn.(*ServerConnection); ok {
				return c, true
			}
		}
	case ConnectionRemote:
		logging.Info("ws").Msgf("Connection found on another instance, returning false")
		return nil, false
	case ConnectionNotFound:
		logging.Info("ws").Msgf("Connection not found anywhere")
		return nil, false
	}

	return nil, false
}

// IsConnectionAvailable checks if a connection exists either locally or remotely
func (h *Hub) IsConnectionAvailable(id string) bool {
	// Check local first
	if _, ok := h.connections.Load(id); ok {
		return true
	}

	// If we have pubsub, check other instances
	if h.connectionStore != nil {
		instanceID, err := h.connectionStore.Find(id)
		if err != nil {
			logging.Error("ws").Msgf("failed to find connection: %v", err)
			return false
		}
		return instanceID != nil
	}

	return false
}

// CanSendMessage checks if we can send a message to this connection (either locally or remotely)
func (h *Hub) CanSendMessage(id string) bool {
	// Check local first
	if _, ok := h.connections.Load(id); ok {
		return true
	}
	// If we have pubsub, check other instances
	if h.connectionStore != nil {
		instanceID, err := h.connectionStore.Find(id)
		if err != nil {
			logging.Error("ws").Msgf("Failed to find connection: %v", err)
			return false
		}
		if instanceID == nil {
			return false
		}
		return true
	}

	return false
}

// SendToConnection sends a message to a specific connection, local or held by
// another instance. locate consults the lease, so a connection that moved is
// forwarded to its new instance rather than delivered to a stale local socket.
// A store error fails the send rather than falling back to a possibly stale
// local socket, so a message is never silently delivered to a dead peer while
// the lease is unknown.
func (h *Hub) SendToConnection(id string, msgType string, data any) error {
	state, instance, err := h.locate(id)
	if err != nil {
		return err
	}

	switch state {
	case ConnectionLocal:
		if conn, ok := h.connections.Load(id); ok {
			if c, ok := conn.(*ServerConnection); ok {
				return c.Send(msgType, data)
			}
		}
		return fmt.Errorf("connection not found: %s", id)
	case ConnectionRemote:
		var dataBytes []byte
		if data != nil {
			var err error
			dataBytes, err = json.Marshal(data)
			if err != nil {
				return fmt.Errorf("failed to marshal message data: %w", err)
			}
		}
		if err := h.connectionStore.SendToInstance(instance, id, msgType, dataBytes); err != nil {
			return fmt.Errorf("failed to forward message: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("connection not found: %s", id)
	}
}

// BroadcastToChannel sends a message to all connections subscribed to a channel
func (h *Hub) BroadcastToChannel(channel string, msgType string, data any) error {
	if h.connectionStore != nil {
		// If we have a PubSub system, use it for scalable broadcasting
		msg := RawMessage{Type: msgType}
		if data != nil {
			jsonData, err := json.Marshal(data)
			if err != nil {
				return fmt.Errorf("failed to marshal message: %w", err)
			}
			msg.Data = jsonData
		}

		msgBytes, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("failed to marshal message: %w", err)
		}
		return h.connectionStore.Publish(channel, msgBytes)
	}

	// Local broadcast if no PubSub
	h.connections.Range(func(key, value any) bool {
		if conn, ok := value.(*ServerConnection); ok {
			conn.Send(msgType, data)
		}
		return true
	})
	return nil
}

// BroadcastToAll sends a message to all connected clients
func (h *Hub) BroadcastToAll(msgType string, data any) error {
	h.connections.Range(func(key, value any) bool {
		if conn, ok := value.(*ServerConnection); ok {
			conn.Send(msgType, data)
		}
		return true
	})
	return nil
}

// SubscribeToChannel subscribes to messages on a channel
func (h *Hub) SubscribeToChannel(ctx context.Context, channel string, callback func(msg RawMessage)) error {
	if h.connectionStore == nil {
		return fmt.Errorf("no pubsub system configured")
	}

	return h.connectionStore.Subscribe(channel, func(data []byte) {
		var msg RawMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			// Log error but don't stop processing
			logging.Error("ws").Msgf("failed to unmarshal message: %v", err)
			return
		}
		callback(msg)
	})
}

// UnsubscribeFromChannel unsubscribes from a channel
func (h *Hub) UnsubscribeFromChannel(channel string) error {
	if h.connectionStore == nil {
		return fmt.Errorf("no pubsub system configured")
	}
	return h.connectionStore.Unsubscribe(channel)
}

// LeaveAll sends every connection this hub holds away (Leave), for an
// instance shutting down: peers reconnect to the instance taking over now,
// not when this process exits. It returns the ids it held.
func (h *Hub) LeaveAll() []string {
	var ids []string
	h.connections.Range(func(key, value any) bool {
		if conn, ok := value.(*ServerConnection); ok {
			ids = append(ids, key.(string))
			_ = conn.Leave()
		}
		return true
	})
	return ids
}

// WaitMoved waits until each of ids is held by another instance (its peer
// reconnected there), or ctx ends; it reports whether all moved. Without a
// connection store there is nowhere to move to, and it returns at once.
func (h *Hub) WaitMoved(ctx context.Context, ids []string) bool {
	if h.connectionStore == nil || len(ids) == 0 {
		return true
	}
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		live, err := h.connectionStore.Live(ids)
		if err == nil {
			moved := 0
			for _, id := range ids {
				if at, ok := live[id]; ok && at != h.instanceID {
					moved++
				}
			}
			if moved == len(ids) {
				return true
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-tick.C:
		}
	}
}

// GetAllConnections returns all active connections
func (h *Hub) GetAllConnections() []*ServerConnection {
	var connections []*ServerConnection
	h.connections.Range(func(key, value any) bool {
		if conn, ok := value.(*ServerConnection); ok {
			connections = append(connections, conn)
		}
		return true
	})
	return connections
}

// GetConnectionCount returns the number of active connections
func (h *Hub) GetConnectionCount() int {
	count := 0
	h.connections.Range(func(key, value any) bool {
		count++
		return true
	})
	return count
}
