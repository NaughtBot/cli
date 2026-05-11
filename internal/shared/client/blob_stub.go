//go:build !legacy_api

package client

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// WrappedKey mirrors the legacy blob.WrappedKey schema. WS3.3 will replace
// this with the regenerated type from github.com/naughtbot/api/blob or the
// new e2ee-payloads envelope schema.
type WrappedKey struct {
	EncryptionPublicKeyHex string `json:"encryptionPublicKeyHex"`
	EphemeralPublicHex     string `json:"ephemeralPublicHex"`
	WrappedKey             []byte `json:"wrappedKey"`
	WrappedKeyNonce        []byte `json:"wrappedKeyNonce"`
}

// BlobResponse mirrors the legacy blob.BlobResponse schema.
//
// TODO(WS3.3): swap to the regenerated type once the new blob surface is
// finalised.
type BlobResponse struct {
	BlobNonce     []byte       `json:"blobNonce"`
	EncryptedBlob []byte       `json:"encryptedBlob"`
	UpdatedAt     time.Time    `json:"updatedAt"`
	Version       int32        `json:"version"`
	WrappedKeys   []WrappedKey `json:"wrappedKeys"`
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
// TODO(WS3.3): Rewire to the regenerated github.com/naughtbot/api/blob client.
// The new client surface uses key-scoped Get/Put/Delete/ListBlobs and is not
// directly compatible with the legacy /api/v1/blob endpoint set.
type BlobClient struct {
	baseURL string
}

// NewBlobClient creates a new blob service client.
//
// TODO(WS3.3): Wire to the regenerated github.com/naughtbot/api/blob client.
func NewBlobClient(baseURL string) (*BlobClient, error) {
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}
	return &BlobClient{baseURL: baseURL}, nil
}

// GetBlob is a stub. WS3.3 will rewire.
func (c *BlobClient) GetBlob(ctx context.Context, accessToken string) (*BlobResult, error) {
	_ = ctx
	_ = accessToken
	httpLog.Debug("blob.GetBlob: stub (WS3.3)")
	return nil, errors.New("blob: not yet rewired to naughtbot/api/blob (WS3.3)")
}

// HistoryListResponse mirrors the legacy blob.HistoryListResponse schema.
//
// TODO(WS3.3): replace with the regenerated type once the history surface is
// defined in github.com/naughtbot/api/blob.
type HistoryListResponse struct {
	Items []HistoryListItem `json:"items"`
}

// HistoryListItem is a row in HistoryListResponse.
type HistoryListItem struct {
	Version   int32     `json:"version"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// HistoryDetailResponse mirrors the legacy blob.HistoryDetailResponse schema.
type HistoryDetailResponse struct {
	BlobResponse
}

// GetBlobHistory is a stub. WS3.3 will rewire.
func (c *BlobClient) GetBlobHistory(ctx context.Context, accessToken string, limit int) (*HistoryListResponse, error) {
	_ = ctx
	_ = accessToken
	_ = limit
	httpLog.Debug("blob.GetBlobHistory: stub (WS3.3)")
	return nil, errors.New("blob: not yet rewired to naughtbot/api/blob (WS3.3)")
}

// GetBlobHistoryVersion is a stub. WS3.3 will rewire.
func (c *BlobClient) GetBlobHistoryVersion(ctx context.Context, accessToken string, version int) (*HistoryDetailResponse, error) {
	_ = ctx
	_ = accessToken
	_ = version
	httpLog.Debug("blob.GetBlobHistoryVersion: stub (WS3.3)")
	return nil, errors.New("blob: not yet rewired to naughtbot/api/blob (WS3.3)")
}
