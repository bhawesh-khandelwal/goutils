package ws

import (
	"sync"
	"testing"

	"github.com/inference-sh/recws"
)

// Several goroutines closing the same connection at once (the handler's
// deferred Close, Hub.Unregister, a key revocation) must not panic with
// "close of closed channel".
func TestServerConnectionClose_concurrent(t *testing.T) {
	for i := 0; i < 200; i++ {
		c := &ServerConnection{done: make(chan struct{})}
		closeConcurrently(t, c.Close)
		select {
		case <-c.done:
		default:
			t.Fatal("done not closed")
		}
	}
}

func TestClientConnectionClose_concurrent(t *testing.T) {
	for i := 0; i < 200; i++ {
		c := &ClientConnection{conn: &recws.RecConn{}, done: make(chan struct{})}
		closeConcurrently(t, c.Close)
	}
}

func closeConcurrently(t *testing.T, closeFn func() error) {
	t.Helper()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := closeFn(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
}
