package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/clarifiedlabs/ackagent-monorepo/oobsign-cli/internal/shared/client"
)

func TestRelayTransportSend_ReturnsExpiredStatus(t *testing.T) {
	t.Parallel()

	exchangeID := "exchange-123"
	expiresAt := time.Date(2026, time.April, 14, 12, 0, 0, 0, time.UTC)
	var createBody map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/exchanges":
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Fatalf("decode create request: %v", err)
			}
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(map[string]any{
				"id":         exchangeID,
				"expires_at": expiresAt.Format(time.RFC3339Nano),
				"routable":   true,
			}); err != nil {
				t.Fatalf("encode create response: %v", err)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/exchanges/"+exchangeID:
			if err := json.NewEncoder(w).Encode(map[string]any{
				"id":         exchangeID,
				"status":     "expired",
				"expires_at": expiresAt.Format(time.RFC3339Nano),
			}); err != nil {
				t.Fatalf("encode get response: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	rt := NewRelayTransport(server.URL, "device-1")
	resp, err := rt.Send(context.Background(), &Request{
		ID:               "request-123",
		EphemeralPublic:  []byte{0x01, 0x02, 0x03},
		EncryptedPayload: []byte("payload"),
		PayloadNonce:     []byte("nonce"),
		ClientRequestID:  []byte("0123456789abcdef"),
	}, time.Second)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if resp == nil {
		t.Fatal("Send() returned nil response")
	}
	if resp.Status != "expired" {
		t.Fatalf("Send() status = %q, want %q", resp.Status, "expired")
	}
	if resp.ID != exchangeID {
		t.Fatalf("Send() response ID = %q, want %q", resp.ID, exchangeID)
	}
	if !resp.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("Send() expiresAt = %s, want %s", resp.ExpiresAt.Format(time.RFC3339Nano), expiresAt.Format(time.RFC3339Nano))
	}
	if _, ok := createBody["wake_handle"]; ok {
		t.Fatalf("create request unexpectedly included wake_handle")
	}
	if _, ok := createBody["wrapped_keys"]; !ok {
		t.Fatalf("create request missing wrapped_keys")
	}
}

func TestRelayTransportSend_AcceptsCreateStatusOK(t *testing.T) {
	t.Parallel()

	exchangeID := "exchange-200"
	expiresAt := time.Date(2026, time.April, 14, 12, 5, 0, 0, time.UTC)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/exchanges":
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(map[string]any{
				"id":         exchangeID,
				"expires_at": expiresAt.Format(time.RFC3339Nano),
				"routable":   true,
			}); err != nil {
				t.Fatalf("encode create response: %v", err)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/exchanges/"+exchangeID:
			if err := json.NewEncoder(w).Encode(map[string]any{
				"id":         exchangeID,
				"status":     "expired",
				"expires_at": expiresAt.Format(time.RFC3339Nano),
			}); err != nil {
				t.Fatalf("encode get response: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	rt := NewRelayTransport(server.URL, "device-1")
	resp, err := rt.Send(context.Background(), &Request{
		ID:               "request-200",
		EphemeralPublic:  []byte{0x01, 0x02, 0x03},
		EncryptedPayload: []byte("payload"),
		PayloadNonce:     []byte("nonce"),
		ClientRequestID:  []byte("0123456789abcdef"),
	}, time.Second)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if resp == nil {
		t.Fatal("Send() returned nil response")
	}
	if resp.Status != "expired" {
		t.Fatalf("Send() status = %q, want %q", resp.Status, "expired")
	}
	if resp.ID != exchangeID {
		t.Fatalf("Send() response ID = %q, want %q", resp.ID, exchangeID)
	}
}

func TestRelayTransportSend_BacksOffAfterTransientLongPollErrors(t *testing.T) {
	t.Parallel()

	exchangeID := "exchange-456"
	expiresAt := time.Date(2026, time.April, 14, 12, 30, 0, 0, time.UTC)

	var mu sync.Mutex
	var getTimes []time.Time

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/exchanges":
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(map[string]any{
				"id":         exchangeID,
				"expires_at": expiresAt.Format(time.RFC3339Nano),
				"routable":   true,
			}); err != nil {
				t.Fatalf("encode create response: %v", err)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/exchanges/"+exchangeID:
			mu.Lock()
			getTimes = append(getTimes, time.Now())
			attempt := len(getTimes)
			mu.Unlock()

			if attempt <= 2 {
				hijacker, ok := w.(http.Hijacker)
				if !ok {
					t.Fatal("response writer does not support hijacking")
				}
				conn, _, err := hijacker.Hijack()
				if err != nil {
					t.Fatalf("hijack response: %v", err)
				}
				_ = conn.Close()
				return
			}

			if err := json.NewEncoder(w).Encode(map[string]any{
				"id":         exchangeID,
				"status":     "expired",
				"expires_at": expiresAt.Format(time.RFC3339Nano),
			}); err != nil {
				t.Fatalf("encode get response: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	rt := NewRelayTransport(server.URL, "device-1")
	rt.SetPollConfig(client.PollConfig{
		InitialInterval: 50 * time.Millisecond,
		MaxInterval:     50 * time.Millisecond,
		Multiplier:      1,
	})

	start := time.Now()
	resp, err := rt.Send(context.Background(), &Request{
		ID:               "request-456",
		EphemeralPublic:  []byte{0x01, 0x02, 0x03},
		EncryptedPayload: []byte("payload"),
		PayloadNonce:     []byte("nonce"),
		ClientRequestID:  []byte("0123456789abcdef"),
	}, time.Second)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if resp == nil {
		t.Fatal("Send() returned nil response")
	}

	mu.Lock()
	defer mu.Unlock()

	if len(getTimes) < 3 {
		t.Fatalf("expected at least 3 GET attempts, got %d", len(getTimes))
	}
	if elapsed < 40*time.Millisecond {
		t.Fatalf("expected retry backoff after transient errors, Send() completed in %v", elapsed)
	}
}
