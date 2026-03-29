package auth

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

type Config struct {
	BaseURL string // public URL for LNURL callback
	Prefix  string // k1 prefix (e.g. "splitsig")
}

// Mount registers auth routes on an external mux.
func Mount(mux *http.ServeMux, store *Store, cfg Config) {
	h := &handler{store: store, cfg: cfg}
	mux.HandleFunc("GET /auth/challenge", h.challenge)
	mux.HandleFunc("GET /auth/callback", h.callback)
	mux.HandleFunc("GET /auth/status/{id}", h.status)
	mux.HandleFunc("POST /test/auth", h.testAuth)
}

type handler struct {
	store *Store
	cfg   Config
}

func (h *handler) challenge(w http.ResponseWriter, r *http.Request) {
	context := r.URL.Query().Get("context")
	if context == "" {
		context = "nostr"
	}

	ch := h.store.GenerateChallenge(h.cfg.Prefix, context)
	callbackURL := fmt.Sprintf("%s/auth/callback?k1=%s&tag=login", h.cfg.BaseURL, ch.K1)

	lnurl, err := EncodeLNURL(callbackURL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to encode LNURL")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"challenge_id":       ch.ID,
		"k1":                 ch.K1,
		"lnurl":              lnurl,
		"qr_content":         strings.ToUpper(lnurl),
		"expires_in_seconds": int(time.Until(ch.ExpiresAt).Seconds()),
	})
}

func (h *handler) callback(w http.ResponseWriter, r *http.Request) {
	k1 := r.URL.Query().Get("k1")
	sig := r.URL.Query().Get("sig")
	key := r.URL.Query().Get("key")

	respond := func(status, reason string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": status, "reason": reason})
	}

	if r.URL.Query().Get("tag") != "login" {
		respond("ERROR", "unsupported tag")
		return
	}
	if k1 == "" || sig == "" || key == "" {
		respond("ERROR", "missing parameters")
		return
	}

	if err := h.store.VerifyCallback(k1, sig, key); err != nil {
		respond("ERROR", err.Error())
		return
	}

	respond("OK", "")
}

func (h *handler) status(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	ch := h.store.GetStatus(id)
	if ch == nil {
		writeError(w, http.StatusNotFound, "challenge not found")
		return
	}

	if ch.Verified == nil {
		writeJSON(w, http.StatusOK, map[string]any{"verified": false})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"verified":      true,
		"linking_pubkey": ch.Verified.LinkingPubKey,
		"signature":      ch.Verified.Signature,
		"session_token":  ch.Verified.SessionToken,
	})
}

func (h *handler) testAuth(w http.ResponseWriter, r *http.Request) {
	var req struct {
		K1 string `json:"k1"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.K1 == "" {
		writeError(w, http.StatusBadRequest, "k1 is required")
		return
	}

	testKey := TestPrivKey()
	k1Bytes, err := hex.DecodeString(req.K1)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid k1")
		return
	}

	sig := btcecdsa.Sign(testKey, k1Bytes)
	sigHex := hex.EncodeToString(sig.Serialize())

	if err := h.store.VerifyCallback(req.K1, sigHex, TestLinkingPubKey()); err != nil {
		writeError(w, http.StatusInternalServerError, "auth failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":    "OK",
		"pubkey":    TestLinkingPubKey(),
		"signature": sigHex,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
