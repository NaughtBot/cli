package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"
)

// KeyHandleData contains the data stored in a key handle.
type KeyHandleData struct {
	Version     int    `json:"v"`
	IOSKeyID    string `json:"k"`
	IOSDeviceID string `json:"d"`
	Application string `json:"a"`
	CreatedAt   int64  `json:"t"`
}

const keyHandleMagic uint32 = 0x41505052 // serialized as little-endian bytes in the key handle header

func buildKeyHandle(iosKeyID, iosDeviceID, application string) []byte {
	data := KeyHandleData{
		Version:     1,
		IOSKeyID:    iosKeyID,
		IOSDeviceID: iosDeviceID,
		Application: application,
		CreatedAt:   time.Now().Unix(),
	}

	jsonData, _ := json.Marshal(data)

	// Format: [4-byte magic][4-byte length][JSON data]
	result := make([]byte, 8+len(jsonData))
	magic := keyHandleMagic
	length := uint32(len(jsonData))
	binary.LittleEndian.PutUint32(result[0:4], magic)
	binary.LittleEndian.PutUint32(result[4:8], length)
	copy(result[8:], jsonData)

	return result
}

func parseKeyHandle(handle []byte) (*KeyHandleData, error) {
	if len(handle) < 8 {
		return nil, fmt.Errorf("key handle too short")
	}

	magic := binary.LittleEndian.Uint32(handle[0:4])
	if magic != keyHandleMagic {
		return nil, fmt.Errorf("invalid key handle magic")
	}

	length := binary.LittleEndian.Uint32(handle[4:8])
	if int(length) > len(handle)-8 {
		return nil, fmt.Errorf("key handle length mismatch")
	}

	var data KeyHandleData
	if err := json.Unmarshal(handle[8:8+length], &data); err != nil {
		return nil, err
	}

	return &data, nil
}
