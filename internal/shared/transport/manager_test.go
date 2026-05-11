package transport

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// mockTransport is a test implementation of Transport.
type mockTransport struct {
	name      string
	priority  int
	available bool
	response  *Response
	err       error
	called    bool
}

func (m *mockTransport) Name() string  { return m.name }
func (m *mockTransport) Priority() int { return m.priority }

func (m *mockTransport) IsAvailable(ctx context.Context) (bool, error) {
	return m.available, nil
}

func (m *mockTransport) Send(ctx context.Context, req *Request, timeout time.Duration) (*Response, error) {
	m.called = true
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

type stableTransport struct {
	name     string
	priority int
	response *Response
}

func (s *stableTransport) Name() string  { return s.name }
func (s *stableTransport) Priority() int { return s.priority }
func (s *stableTransport) IsAvailable(ctx context.Context) (bool, error) {
	return true, nil
}
func (s *stableTransport) Send(ctx context.Context, req *Request, timeout time.Duration) (*Response, error) {
	return s.response, nil
}

func TestManager_Send_PriorityOrder(t *testing.T) {
	m := NewManager()

	// Register transports in non-priority order
	high := &mockTransport{name: "high", priority: 1, available: true, response: &Response{ID: "high"}}
	low := &mockTransport{name: "low", priority: 50, available: true, response: &Response{ID: "low"}}
	medium := &mockTransport{name: "medium", priority: 10, available: true, response: &Response{ID: "medium"}}

	m.Register(low)
	m.Register(high)
	m.Register(medium)

	resp, err := m.Send(context.Background(), &Request{ID: "test"}, time.Second)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Should use highest priority (lowest number) transport
	if resp.ID != "high" {
		t.Errorf("expected 'high' transport, got %s", resp.ID)
	}

	// Only highest priority should be called
	if !high.called {
		t.Error("high priority transport should be called")
	}
	if medium.called || low.called {
		t.Error("lower priority transports should not be called when higher succeeds")
	}
}

func TestManager_Send_Fallback(t *testing.T) {
	m := NewManager()

	// High priority fails, should fall back to medium
	high := &mockTransport{name: "high", priority: 1, available: true, err: errors.New("failed")}
	medium := &mockTransport{name: "medium", priority: 10, available: true, response: &Response{ID: "medium"}}

	m.Register(high)
	m.Register(medium)

	resp, err := m.Send(context.Background(), &Request{ID: "test"}, time.Second)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if resp.ID != "medium" {
		t.Errorf("expected fallback to 'medium', got %s", resp.ID)
	}

	if !high.called || !medium.called {
		t.Error("both transports should be tried")
	}
}

func TestManager_Send_SkipUnavailable(t *testing.T) {
	m := NewManager()

	// High priority unavailable, should skip to medium
	high := &mockTransport{name: "high", priority: 1, available: false}
	medium := &mockTransport{name: "medium", priority: 10, available: true, response: &Response{ID: "medium"}}

	m.Register(high)
	m.Register(medium)

	resp, err := m.Send(context.Background(), &Request{ID: "test"}, time.Second)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if resp.ID != "medium" {
		t.Errorf("expected 'medium', got %s", resp.ID)
	}

	if high.called {
		t.Error("unavailable transport should not be called")
	}
}

func TestManager_Send_NoTransports(t *testing.T) {
	m := NewManager()

	_, err := m.Send(context.Background(), &Request{ID: "test"}, time.Second)
	if !errors.Is(err, ErrNoTransports) {
		t.Errorf("expected ErrNoTransports, got %v", err)
	}
}

func TestManager_Send_AllFail(t *testing.T) {
	m := NewManager()

	m.Register(&mockTransport{name: "a", priority: 1, available: true, err: errors.New("fail a")})
	m.Register(&mockTransport{name: "b", priority: 2, available: true, err: errors.New("fail b")})

	_, err := m.Send(context.Background(), &Request{ID: "test"}, time.Second)
	if err == nil {
		t.Error("expected error when all transports fail")
	}

	// Should be a TransportError with the last transport's error
	var tErr *TransportError
	if !errors.As(err, &tErr) {
		t.Errorf("expected TransportError, got %T", err)
	}
}

func TestManager_Send_ConcurrentAccess(t *testing.T) {
	m := NewManager()
	m.Register(&stableTransport{name: "fast", priority: 1, response: &Response{ID: "fast"}})
	m.Register(&stableTransport{name: "slow", priority: 2, response: &Response{ID: "slow"}})

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := m.Send(context.Background(), &Request{ID: "test"}, time.Second)
			if err != nil {
				t.Errorf("Send failed: %v", err)
				return
			}
			if resp.ID != "fast" {
				t.Errorf("response ID = %q, want fast", resp.ID)
			}
		}()
	}

	wg.Wait()
}
