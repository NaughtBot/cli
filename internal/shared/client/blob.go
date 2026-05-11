package client

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// WrappedKey mirrors the legacy blob.WrappedKey envelope row used by the
// multidevice blob-sync layer.
type WrappedKey struct {
	EncryptionPublicKeyHex string `json:"encryption_public_key_hex"`
	EphemeralPublicHex     string `json:"ephemeral_public_hex"`
	WrappedKey             []byte `json:"wrapped_key"`
	WrappedKeyNonce        []byte `json:"wrapped_key_nonce"`
}

// BlobResponse mirrors the per-version blob payload returned by the legacy
// blob service.
type BlobResponse struct {
	BlobNonce     []byte       `json:"blob_nonce"`
	EncryptedBlob []byte       `json:"encrypted_blob"`
	UpdatedAt     time.Time    `json:"updated_at"`
	Version       int32        `json:"version"`
	WrappedKeys   []WrappedKey `json:"wrapped_keys"`
}

// BlobResult contains the blob data and version (ETag) for optimistic locking.
type BlobResult struct {
	BlobResponse
	ETag string // used for If-Match header on updates
}

// ErrVersionConflict is returned when an update fails due to version mismatch.
var ErrVersionConflict = fmt.Errorf("version conflict - please refetch and retry")

// BlobClient handles communication with the blob service.
//
// The network methods below return ErrNotImplemented until the rewire against
// github.com/naughtbot/api/blob is complete; the constructor and the response
// shapes are kept so dependent sync code keeps compiling.
type BlobClient struct {
	baseURL string
}

// NewBlobClient creates a new blob service client.
func NewBlobClient(baseURL string) (*BlobClient, error) {
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}
	return &BlobClient{baseURL: baseURL}, nil
}

// GetBlob stubs the legacy GET /api/v1/blob endpoint.
func (c *BlobClient) GetBlob(ctx context.Context, accessToken string) (*BlobResult, error) {
	_ = ctx
	_ = accessToken
	httpLog.Debug("blob.GetBlob: stub")
	return nil, ErrNotImplemented
}

// HistoryListResponse mirrors the legacy blob history index response.
type HistoryListResponse struct {
	Items []HistoryListItem `json:"items"`
}

// HistoryListItem is a row in HistoryListResponse.
type HistoryListItem struct {
	Version   int32     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

// HistoryDetailResponse mirrors the legacy blob history detail response.
type HistoryDetailResponse struct {
	BlobResponse
}

// GetBlobHistory stubs the legacy blob history index endpoint.
func (c *BlobClient) GetBlobHistory(ctx context.Context, accessToken string, limit int) (*HistoryListResponse, error) {
	_ = ctx
	_ = accessToken
	_ = limit
	httpLog.Debug("blob.GetBlobHistory: stub")
	return nil, ErrNotImplemented
}

// GetBlobHistoryVersion stubs the legacy blob history detail endpoint.
func (c *BlobClient) GetBlobHistoryVersion(ctx context.Context, accessToken string, version int) (*HistoryDetailResponse, error) {
	_ = ctx
	_ = accessToken
	_ = version
	httpLog.Debug("blob.GetBlobHistoryVersion: stub")
	return nil, ErrNotImplemented
}
