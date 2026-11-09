package ws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
)

// deadStub is a server connection whose socket is already gone: Send returns
// ErrNotConnected at once instead of blocking, standing in for the orphaned
// socket an instance keeps after its peer reconnected elsewhere.
func deadStub(id string) *ServerConnection {
	c := &ServerConnection{ID: id, done: make(chan struct{})}
	close(c.done)
	return c
}

// After a connection moves to another instance, the instance it left still
// holds a stale local entry. The lease must win: its old instance reports the
// connection remote, so a send is forwarded to the holder rather than written
// to the dead local socket.
func TestGetConnectionState_leaseWinsOverStaleLocalEntry(t *testing.T) {
	s, _ := newTestStore(t)
	a := &Hub{instanceID: "instance-a", connectionStore: s, ttlKeys: map[string]struct{}{}}
	b := &Hub{instanceID: "instance-b", connectionStore: s, ttlKeys: map[string]struct{}{}}

	a.Register("engine-1", stubConn("conn-a"))
	b.Register("engine-1", stubConn("conn-b")) // the engine reconnected to b

	if got := a.GetConnectionState("engine-1"); got != ConnectionRemote {
		t.Fatalf("state on the old instance = %v, want ConnectionRemote: the lease moved to instance-b", got)
	}
	if got := b.GetConnectionState("engine-1"); got != ConnectionLocal {
		t.Fatalf("state on the holding instance = %v, want ConnectionLocal", got)
	}
}

// One instance can run several hubs (engines and remotes share an instance ID).
// A hub asked to send to a connection its sibling holds must forward to the
// instance channel, where the sibling delivers it, not report it not found.
func TestGetConnectionState_siblingHubOnSameInstance(t *testing.T) {
	s, _ := newTestStore(t)
	engines := &Hub{instanceID: "node-1", connectionStore: s, ttlKeys: map[string]struct{}{}}
	remotes := &Hub{instanceID: "node-1", connectionStore: s, ttlKeys: map[string]struct{}{}}

	engines.Register("engine-1", stubConn("conn-a"))

	if got := remotes.GetConnectionState("engine-1"); got != ConnectionRemote {
		t.Fatalf("state on the sibling hub = %v, want ConnectionRemote so the send is forwarded to the instance channel", got)
	}
}

// The sibling-hub path end to end: two hubs share one instance id and the
// instance channel, the engine hub holds the real socket, and a send issued on
// the sibling remotes hub must reach that socket rather than report not found.
func TestSendToConnection_siblingHubDelivers(t *testing.T) {
	mr := miniredis.RunT(t)
	store := func() *RedisConnectionStore {
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = client.Close() })
		return NewRedisConnectionStore(client)
	}
	engines := NewHub("node-1", store())
	remotes := NewHub("node-1", store()) // same instance id, sibling hub

	registered := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := NewServerConnection(w, r)
		if err != nil {
			t.Error(err)
			return
		}
		engines.Register("engine-1", conn)
		close(registered)
		conn.Listen(context.Background())
	}))
	defer srv.Close()

	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	must(t, err)
	defer client.Close()
	<-registered

	got := make(chan RawMessage, 1)
	go func() {
		var msg RawMessage
		if err := client.ReadJSON(&msg); err == nil {
			got <- msg
		}
	}()

	// Resend until the engine hub's instance-channel subscription is up; the
	// sibling send must land on the socket the engine hub holds.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := remotes.SendToConnection("engine-1", "task_run", map[string]string{"task_id": "t1"}); err != nil {
			t.Fatalf("sibling send failed instead of forwarding to the instance channel: %v", err)
		}
		select {
		case msg := <-got:
			if msg.Type != "task_run" {
				t.Fatalf("got %q", msg.Type)
			}
			return
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("the sibling send never reached the socket the engine hub holds")
		}
	}
}

// A local socket whose lease lapsed (the store briefly lost it) is still served
// locally rather than reported gone, so a store blip does not drop delivery.
func TestGetConnectionState_lapsedLeaseStillServesLocalSocket(t *testing.T) {
	s, mr := newTestStore(t)
	h := &Hub{instanceID: "solo", connectionStore: s, ttlKeys: map[string]struct{}{}}
	h.Register("engine-1", stubConn("conn-1"))

	mr.FastForward(connectionTTL + time.Second) // lease lapses; the socket stays open

	if got := h.GetConnectionState("engine-1"); got != ConnectionLocal {
		t.Fatalf("state = %v, want ConnectionLocal while the socket is still held here", got)
	}
}

// When the lease store is unreachable, a send must fail loudly rather than fall
// back to the local socket: after a move that socket may be the stale one left
// behind, and writing to it would silently lose the message the fix exists to
// protect.
func TestSendToConnection_storeErrorDoesNotFallBackToStaleSocket(t *testing.T) {
	s, mr := newTestStore(t)
	h := &Hub{instanceID: "instance-a", connectionStore: s, ttlKeys: map[string]struct{}{}}
	h.Register("engine-1", deadStub("stale")) // the entry instance-a kept after the move
	mr.Close()                                 // the lease store is now unreachable

	err := h.SendToConnection("engine-1", "task_run", map[string]string{"task_id": "t1"})
	if err == nil {
		t.Fatal("send succeeded with the lease unknown; it fell back to the stale local socket")
	}
	if !strings.Contains(err.Error(), "resolve connection") {
		t.Fatalf("send failed with %q, want a resolve error rather than a local-socket fallback", err)
	}
}

// The end-to-end lost-message case: an engine on instance-a reconnects to
// instance-b, instance-a keeps its stale entry, and a send issued on instance-a
// must still reach the engine on instance-b instead of hitting the dead socket.
func TestSendToConnection_forwardsAfterTheConnectionMoved(t *testing.T) {
	mr := miniredis.RunT(t)
	store := func() *RedisConnectionStore {
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = client.Close() })
		return NewRedisConnectionStore(client)
	}
	a := NewHub("instance-a", store())
	b := NewHub("instance-b", store())

	// instance-a held the engine before the move; its entry is now stale.
	a.Register("engine-1", deadStub("stale"))

	registered := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := NewServerConnection(w, r)
		if err != nil {
			t.Error(err)
			return
		}
		b.Register("engine-1", conn) // the engine reconnected to instance-b
		close(registered)
		conn.Listen(context.Background())
	}))
	defer srv.Close()

	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	must(t, err)
	defer client.Close()
	<-registered

	got := make(chan RawMessage, 1)
	go func() {
		var msg RawMessage
		if err := client.ReadJSON(&msg); err == nil {
			got <- msg
		}
	}()

	// Redis delivers only to subscriptions that exist when the message is
	// published; resend until instance-b's subscription is up.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := a.SendToConnection("engine-1", "task_run", map[string]string{"task_id": "t1"}); err != nil {
			t.Fatalf("send from the old instance failed instead of forwarding: %v", err)
		}
		select {
		case msg := <-got:
			if msg.Type != "task_run" {
				t.Fatalf("got %q", msg.Type)
			}
			return
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("the message never reached the engine on instance-b; it went to the stale local socket")
		}
	}
}
