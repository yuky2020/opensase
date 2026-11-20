// Package pqsession implements the shared pieces of the post-quantum session-setup channel
// (ADR-0002): the TLS configuration that only allows hybrid X25519MLKEM768, and the
// derivation of the WireGuard pre-shared key from the TLS 1.3 exporter.
package pqsession

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
)

// ExporterLabel is the TLS exporter label for the WireGuard PSK (versioned for crypto agility).
const ExporterLabel = "EXPORTER-opensase-wg-psk-v1"

// PSKSize is the size of a WireGuard pre-shared key.
const PSKSize = 32

// ErrNotPostQuantum is returned when a connection was not established with the hybrid KEX.
var ErrNotPostQuantum = errors.New("pqsession: connection did not negotiate X25519MLKEM768")

// Harden restricts cfg to TLS 1.3 and the hybrid X25519MLKEM768 key exchange only.
// There is deliberately no classic fallback: a peer that cannot do ML-KEM fails the handshake.
func Harden(cfg *tls.Config) *tls.Config {
	cfg.MinVersion = tls.VersionTLS13
	cfg.MaxVersion = tls.VersionTLS13
	cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	return cfg
}

// CheckPostQuantum verifies that a completed handshake used X25519MLKEM768.
func CheckPostQuantum(cs tls.ConnectionState) error {
	if !cs.HandshakeComplete {
		return errors.New("pqsession: handshake not complete")
	}
	if cs.Version != tls.VersionTLS13 || cs.CurveID != tls.X25519MLKEM768 {
		return fmt.Errorf("%w (version=%#x curve=%v)", ErrNotPostQuantum, cs.Version, cs.CurveID)
	}
	return nil
}

// Context builds the exporter context that binds the PSK to both WireGuard public keys, the
// session and the epoch: len-prefixed client key || edge key || session id, then epoch (u64 BE).
func Context(clientWGPub, edgeWGPub []byte, sessionID string, epoch uint64) []byte {
	var b []byte
	for _, part := range [][]byte{clientWGPub, edgeWGPub, []byte(sessionID)} {
		b = binary.BigEndian.AppendUint16(b, uint16(len(part)))
		b = append(b, part...)
	}
	return binary.BigEndian.AppendUint64(b, epoch)
}

// DerivePSK derives the 32-byte WireGuard PSK from a post-quantum TLS connection state.
func DerivePSK(cs tls.ConnectionState, clientWGPub, edgeWGPub []byte, sessionID string, epoch uint64) ([PSKSize]byte, error) {
	var psk [PSKSize]byte
	if err := CheckPostQuantum(cs); err != nil {
		return psk, err
	}
	if len(clientWGPub) != 32 || len(edgeWGPub) != 32 {
		return psk, errors.New("pqsession: WireGuard public keys must be 32 bytes")
	}
	km, err := cs.ExportKeyingMaterial(ExporterLabel, Context(clientWGPub, edgeWGPub, sessionID, epoch), PSKSize)
	if err != nil {
		return psk, fmt.Errorf("pqsession: export keying material: %w", err)
	}
	copy(psk[:], km)
	clear(km)
	return psk, nil
}
