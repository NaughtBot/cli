package audit

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"sort"
	"time"
)

const (
	merkleLeafPrefix byte = 0x00
	merkleNodePrefix byte = 0x01
)

// writeField writes a length-prefixed variable-length field to h,
// preventing field boundary ambiguity in hash concatenation.
func writeField(h hash.Hash, data []byte) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(len(data)))
	h.Write(buf[:])
	h.Write(data)
}

func normalizeMerkleLeaf(leaf []byte) []byte {
	if len(leaf) == 0 {
		return make([]byte, sha256.Size)
	}
	return leaf
}

func hashMerkleLeaf(leaf []byte) []byte {
	h := sha256.New()
	h.Write([]byte{merkleLeafPrefix})
	h.Write(normalizeMerkleLeaf(leaf))
	return h.Sum(nil)
}

func hashMerkleNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{merkleNodePrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func marshalRequesterContext(ctx RequesterContext) []byte {
	data, err := json.Marshal(ctx)
	if err != nil {
		return []byte("{}")
	}
	return data
}

func groupDeviceEntriesByDevice(entries []*DeviceChainEntry) map[string][]*DeviceChainEntry {
	groups := make(map[string][]*DeviceChainEntry)
	for _, entry := range entries {
		groups[entry.DeviceID] = append(groups[entry.DeviceID], entry)
	}
	return groups
}

func sortDeviceEntries(entries []*DeviceChainEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Sequence < entries[j].Sequence })
}

func sortRequestEntries(entries []*RequestChainEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Sequence < entries[j].Sequence })
}

func sortTransparencyEntries(entries []*TransparencyLogEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Sequence < entries[j].Sequence })
}

func computeDeviceEntryHash(e *DeviceChainEntry) []byte {
	h := sha256.New()
	writeField(h, []byte(e.EntryID))
	writeField(h, []byte(e.OrgID))
	writeField(h, []byte(e.DeviceID))
	h.Write(int64Bytes(e.Sequence))
	h.Write(timeBytes(e.Timestamp))
	writeField(h, e.PrevHash)
	writeField(h, []byte(e.EntryType))
	writeField(h, e.RequestHash)
	writeField(h, e.ChallengeHash)
	writeField(h, []byte(e.ChallengeContext))
	writeField(h, e.EncryptedPayloadHash)
	writeField(h, e.PlaintextHash)
	writeField(h, e.DeviceSignature)
	writeField(h, e.DevicePublicKey)
	writeField(h, []byte(e.DeviceAuthPublicKeyHex))
	writeField(h, e.AttestationData)
	writeField(h, []byte(e.AttestationType))
	return h.Sum(nil)
}

func computeDeviceSigningData(e *DeviceChainEntry) []byte {
	h := sha256.New()
	writeField(h, []byte(e.EntryID))
	writeField(h, []byte(e.OrgID))
	writeField(h, []byte(e.DeviceID))
	h.Write(int64Bytes(e.Sequence))
	h.Write(timeBytes(e.Timestamp))
	writeField(h, e.PrevHash)
	writeField(h, []byte(e.EntryType))
	writeField(h, e.RequestHash)
	writeField(h, e.ChallengeHash)
	writeField(h, []byte(e.ChallengeContext))
	writeField(h, e.EncryptedPayloadHash)
	writeField(h, e.PlaintextHash)
	return h.Sum(nil)
}

func computeRequestEntryHash(e *RequestChainEntry) []byte {
	h := sha256.New()
	writeField(h, []byte(e.EntryID))
	writeField(h, []byte(e.OrgID))
	h.Write(int64Bytes(e.Sequence))
	h.Write(timeBytes(e.Timestamp))
	writeField(h, e.PrevHash)
	writeField(h, []byte(e.EntryType))
	writeField(h, []byte(e.RequestID))
	writeField(h, []byte(e.RequesterID))
	writeField(h, marshalRequesterContext(e.RequesterContext))
	writeField(h, []byte(e.SigningPublicKey))
	writeField(h, e.EncryptedPayloadHash)
	writeField(h, e.PlaintextHash)
	var expiresAt []byte
	if e.ExpiresAt != nil {
		expiresAt = timeBytes(*e.ExpiresAt)
	}
	writeField(h, expiresAt)
	writeField(h, e.RequestEntryHash)
	writeField(h, []byte(e.Outcome))
	writeField(h, []byte(e.WinningDeviceID))
	writeField(h, e.WinningDeviceEntryHash)
	return h.Sum(nil)
}

func computeTransparencyEntryHash(e *TransparencyLogEntry) []byte {
	h := sha256.New()
	h.Write(int64Bytes(e.Sequence))
	writeField(h, []byte(e.EntryID))
	h.Write(timeBytes(e.Timestamp))
	writeField(h, []byte(e.OrgID))
	h.Write(int64Bytes(e.TreeSequence))
	writeField(h, e.MerkleRoot)
	writeField(h, e.PrevEntryHash)
	return h.Sum(nil)
}

func computeMerkleRoot(requestTipHash []byte, deviceTips []DeviceChainTip) []byte {
	var leaves [][]byte

	leaves = append(leaves, normalizeMerkleLeaf(requestTipHash))

	for _, tip := range deviceTips {
		leaves = append(leaves, tip.Hash)
	}

	return computeMerkleRootFromLeaves(leaves)
}

func computeMerkleRootFromLeaves(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return make([]byte, 32)
	}

	// Hash each leaf with domain separation prefix (RFC 6962 §2.1)
	nodes := make([][]byte, len(leaves))
	for i, leaf := range leaves {
		nodes[i] = hashMerkleLeaf(leaf)
	}

	// Pad to power of 2 by duplicating last node
	for len(nodes)&(len(nodes)-1) != 0 {
		nodes = append(nodes, nodes[len(nodes)-1])
	}

	// Build tree bottom-up with internal node prefix
	for len(nodes) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(nodes); i += 2 {
			nextLevel = append(nextLevel, hashMerkleNode(nodes[i], nodes[i+1]))
		}
		nodes = nextLevel
	}

	return nodes[0]
}

func computeTreeSigningData(tree *MerkleTree) []byte {
	h := sha256.New()
	writeField(h, []byte(tree.TreeID))
	writeField(h, []byte(tree.OrgID))
	h.Write(int64Bytes(tree.Sequence))
	h.Write(timeBytes(tree.Timestamp))
	writeField(h, tree.PrevRoot)
	writeField(h, tree.RequestChainTipHash)
	writeField(h, tree.MerkleRoot)
	return h.Sum(nil)
}

func verifyDeviceSignature(entry *DeviceChainEntry) error {
	pubKey, err := x509.ParsePKIXPublicKey(entry.DevicePublicKey)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an ECDSA public key")
	}

	signingData := computeDeviceSigningData(entry)

	if !ecdsa.VerifyASN1(ecdsaKey, signingData, entry.DeviceSignature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func int64Bytes(n int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(n))
	return b
}

func timeBytes(t time.Time) []byte {
	return int64Bytes(t.UnixNano())
}
