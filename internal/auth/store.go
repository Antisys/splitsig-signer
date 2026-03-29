package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

const (
	challengeExpiry = 10 * time.Minute
	maxChallenges   = 5000
)

type Challenge struct {
	ID        string // random, used by browser to poll status
	K1        string // deterministic, signed by wallet
	Context   string
	ExpiresAt time.Time
	Verified  *VerifiedAuth // set when wallet responds
}

type VerifiedAuth struct {
	LinkingPubKey string
	Signature     string
	SessionToken  string // created once on first status poll
}

type Store struct {
	mu         sync.Mutex
	challenges map[string]*Challenge // keyed by challenge ID
	k1Index    map[string][]string   // k1 → list of challenge IDs (for callback lookup)
}

func NewStore() *Store {
	return &Store{
		challenges: make(map[string]*Challenge),
		k1Index:    make(map[string][]string),
	}
}

func (s *Store) GenerateChallenge(prefix, context string) *Challenge {
	s.mu.Lock()
	defer s.mu.Unlock()

	h := sha256.Sum256([]byte(prefix + "\x00" + context))
	k1 := hex.EncodeToString(h[:])

	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	id := hex.EncodeToString(idBytes)

	ch := &Challenge{
		ID:        id,
		K1:        k1,
		Context:   context,
		ExpiresAt: time.Now().Add(challengeExpiry),
	}
	s.challenges[id] = ch
	s.k1Index[k1] = append(s.k1Index[k1], id)

	if len(s.challenges) > maxChallenges {
		s.cleanupExpired()
	}

	return ch
}

func (s *Store) VerifyCallback(k1, sigHex, keyHex string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids, ok := s.k1Index[k1]
	if !ok || len(ids) == 0 {
		return fmt.Errorf("challenge not found")
	}

	if err := verifyLNURLSignature(k1, sigHex, keyHex); err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	// Mark all pending challenges for this k1 as verified.
	// Different wallets produce different sigs, but only one wallet
	// responds per challenge. Each browser gets the sig from its own poll.
	now := time.Now()
	verified := &VerifiedAuth{LinkingPubKey: keyHex, Signature: sigHex}
	found := false
	for _, id := range ids {
		ch := s.challenges[id]
		if ch != nil && now.Before(ch.ExpiresAt) && ch.Verified == nil {
			ch.Verified = verified
			found = true
		}
	}
	if !found {
		return fmt.Errorf("challenge expired")
	}

	return nil
}

// GetStatus returns the challenge by ID. Returns nil if not found or expired.
// On first verified poll, creates a session token and cleans up the challenge.
func (s *Store) GetStatus(challengeID string) *Challenge {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.challenges[challengeID]
	if !ok {
		return nil
	}
	if time.Now().After(ch.ExpiresAt) {
		s.deleteChallenge(challengeID)
		return nil
	}
	if ch.Verified != nil && ch.Verified.SessionToken == "" {
		// First poll after verification — create token and remove from k1Index
		tokenBytes := make([]byte, 32)
		rand.Read(tokenBytes)
		ch.Verified.SessionToken = hex.EncodeToString(tokenBytes)
		s.removeFromK1Index(ch.K1, challengeID)
	}
	return ch
}

func (s *Store) deleteChallenge(id string) {
	ch := s.challenges[id]
	if ch != nil {
		s.removeFromK1Index(ch.K1, id)
	}
	delete(s.challenges, id)
}

func (s *Store) removeFromK1Index(k1, id string) {
	ids := s.k1Index[k1]
	for i, v := range ids {
		if v == id {
			s.k1Index[k1] = append(ids[:i], ids[i+1:]...)
			break
		}
	}
	if len(s.k1Index[k1]) == 0 {
		delete(s.k1Index, k1)
	}
}

func (s *Store) cleanupExpired() {
	now := time.Now()
	for id, ch := range s.challenges {
		if now.After(ch.ExpiresAt) {
			s.deleteChallenge(id)
		}
	}
}

func verifyLNURLSignature(k1Hex, sigHex, pubkeyHex string) error {
	k1Bytes, err := hex.DecodeString(k1Hex)
	if err != nil || len(k1Bytes) != 32 {
		return fmt.Errorf("invalid k1")
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("invalid signature hex")
	}
	pubkeyBytes, err := hex.DecodeString(pubkeyHex)
	if err != nil || len(pubkeyBytes) != 33 {
		return fmt.Errorf("invalid pubkey")
	}
	pubkey, err := btcec.ParsePubKey(pubkeyBytes)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	sig, err := btcecdsa.ParseDERSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("invalid DER signature: %w", err)
	}
	if !sig.Verify(k1Bytes, pubkey) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func TestPrivKey() *btcec.PrivateKey {
	var seed [32]byte
	copy(seed[:], []byte("test-splitsig-key-seed-00000"))
	key, _ := btcec.PrivKeyFromBytes(seed[:])
	return key
}

func TestLinkingPubKey() string {
	return hex.EncodeToString(TestPrivKey().PubKey().SerializeCompressed())
}
