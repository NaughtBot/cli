package main

import (
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestBuildKeyHandle_EncodesPayloadLength(t *testing.T) {
	payload := map[string]interface{}{
		"v": 1,
		"k": "key-1",
	}

	handle := buildKeyHandle(payload)
	jsonPayload := mustMarshalJSON(payload)

	if got := binary.LittleEndian.Uint32(handle[:4]); got != 0x41505052 {
		t.Fatalf("magic = %#x, want %#x", got, uint32(0x41505052))
	}
	if got := binary.LittleEndian.Uint32(handle[4:8]); got != uint32(len(jsonPayload)) {
		t.Fatalf("length = %d, want %d", got, len(jsonPayload))
	}
	if string(handle[8:]) != string(jsonPayload) {
		t.Fatalf("payload = %q, want %q", string(handle[8:]), string(jsonPayload))
	}
}

func TestMustMarshalJSON_PanicsOnMarshalError(t *testing.T) {
	t.Helper()

	type unsupported struct {
		Fn func()
	}

	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("expected panic for unsupported JSON payload")
		}
	}()

	_ = json.Valid(mustMarshalJSON(unsupported{Fn: func() {}}))
}
