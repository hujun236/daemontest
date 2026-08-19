package main

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustScalar(t *testing.T, s string) *big.Int {
	t.Helper()
	if s == "" {
		s = "123456"
	}
	return scalarFromPassword(s)
}

func TestSpake2GeneratorsValid(t *testing.T) {
	if !spake2M.valid(elliptic.P256()) || !spake2N.valid(elliptic.P256()) {
		t.Fatal("M/N must be valid P-256 points")
	}
	if spake2M.x.Cmp(spake2N.x) == 0 && spake2M.y.Cmp(spake2N.y) == 0 {
		t.Fatal("M and N must be distinct")
	}
}

func TestSpake2RoundTrip(t *testing.T) {
	w := mustScalar(t, "123456")
	client, err := NewSpake2Client(w)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSpake2Server(w)
	if err != nil {
		t.Fatal(err)
	}

	if err := client.SetPeerShare(server.Share()); err != nil {
		t.Fatal(err)
	}
	if err := server.SetPeerShare(client.Share()); err != nil {
		t.Fatal(err)
	}

	sid := []byte("0123456789abcdef")
	accesskey := "TestAccessKey0123456789"
	kc, err := client.Finish(sid, accesskey)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := server.Finish(sid, accesskey)
	if err != nil {
		t.Fatal(err)
	}

	if kc.Kc2s != ks.Kc2s || kc.Ks2c != ks.Ks2c || kc.Kca != ks.Kca || kc.Kcd != ks.Kcd {
		t.Fatal("both sides must derive identical keys")
	}

	// tag_a produced by the client must verify on the server side
	if !VerifyTag(TagA(kc, client.tt), TagA(ks, server.tt)) {
		t.Fatal("tag_a mismatch between client and server")
	}
	if !VerifyTag(TagB(ks, server.tt), TagB(kc, client.tt)) {
		t.Fatal("tag_b mismatch between client and server")
	}
}

func TestSpake2WrongPassword(t *testing.T) {
	client, _ := NewSpake2Client(mustScalar(t, "123456"))
	server, _ := NewSpake2Server(mustScalar(t, "654321")) // wrong code

	client.SetPeerShare(server.Share())
	server.SetPeerShare(client.Share())

	sid := []byte("0123456789abcdef")
	kc, err := client.Finish(sid, "ak")
	if err != nil {
		t.Fatal(err)
	}
	ks, err := server.Finish(sid, "ak")
	if err != nil {
		t.Fatal(err)
	}

	if kc.Kc2s == ks.Kc2s {
		t.Fatal("wrong password must derive different keys")
	}
	// Confirmation tag must fail on the wrong-password side.
	if VerifyTag(TagA(kc, client.tt), TagA(ks, server.tt)) {
		t.Fatal("tag_a must NOT match on wrong password")
	}
}

func TestSpake2MalformedShare(t *testing.T) {
	client, _ := NewSpake2Client(mustScalar(t, "123456"))
	if err := client.SetPeerShare([]byte("garbage")); err == nil {
		t.Fatal("malformed share must be rejected")
	}
	// On-curve check: a 65-byte point not on the curve must be rejected.
	offCurve := append([]byte{4}, make([]byte, 64)...)
	if err := client.SetPeerShare(offCurve); err == nil {
		t.Fatal("off-curve point must be rejected")
	}
	// Peer share missing → Finish must fail.
	server, _ := NewSpake2Server(mustScalar(t, "123456"))
	if _, err := server.Finish([]byte("sid"), "ak"); err == nil {
		t.Fatal("Finish without peer share must fail")
	}
}

// vectorJSON is the cross-language test vector record. Values are hex.
type vectorJSON struct {
	Code      string `json:"code"`
	Sid       string `json:"sid"`
	Accesskey string `json:"accesskey"`
	X         string `json:"x"`
	Y         string `json:"y"`
	A         string `json:"a"`
	B         string `json:"b"`
	TT        string `json:"tt"`
	KMain     string `json:"k_main"`
	Kca       string `json:"kca"`
	Kcd       string `json:"kcd"`
	Kc2s      string `json:"kc2s"`
	Ks2c      string `json:"ks2c"`
	TagA      string `json:"tag_a"`
	TagB      string `json:"tag_b"`
}

func vectorPath() string { return filepath.Join("testdata", "vectors.json") }

// TestGenerateVectors regenerates testdata/vectors.json when GENERATE=1.
// Both the Go and Dart test suites consume this file to lock byte-for-byte
// compatibility between the two SPAKE2 implementations.
func TestGenerateVectors(t *testing.T) {
	if os.Getenv("GENERATE") != "1" {
		t.Skip("set GENERATE=1 to regenerate vectors.json")
	}
	vec := buildVectors(t)
	out, err := json.MarshalIndent(vec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorPath(), out, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d vectors to %s", len(vec), vectorPath())
}

func buildVectors(t *testing.T) []vectorJSON {
	t.Helper()
	accesskeys := []string{"TestAccessKey0123456789", "Cq9vT2xL8mNpK"}
	sids := []string{"0123456789abcdef", "fedcba9876543210"}
	codes := []string{"123456", "000000"}
	xs := []string{"2", "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
	ys := []string{"3", "17"}

	vec := make([]vectorJSON, 0, 2)
	for i := 0; i < 2; i++ {
		w := scalarFromPassword(codes[i])
		x := mustBigInt(t, xs[i])
		y := mustBigInt(t, ys[i])

		client, err := newSpake2StateFixed(true, w, x)
		if err != nil {
			t.Fatal(err)
		}
		server, err := newSpake2StateFixed(false, w, y)
		if err != nil {
			t.Fatal(err)
		}
		sid, err := hex.DecodeString(sids[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := client.SetPeerShare(server.Share()); err != nil {
			t.Fatal(err)
		}
		if err := server.SetPeerShare(client.Share()); err != nil {
			t.Fatal(err)
		}
		kc, err := client.Finish(sid, accesskeys[i])
		if err != nil {
			t.Fatal(err)
		}
		ks, err := server.Finish(sid, accesskeys[i])
		if err != nil {
			t.Fatal(err)
		}
		if *kc != *ks {
			t.Fatal("keys must match")
		}

		// Recompute TT and K_main independently to expose them in the vector.
		a, _ := pointFromBytes(elliptic.P256(), client.Share())
		b, _ := pointFromBytes(elliptic.P256(), server.Share())
		tt := buildTranscript(sid, accesskeys[i], a, b)
		wN := pointScalar(elliptic.P256(), spake2N, w)
		zC := pointScalar(elliptic.P256(), pointSub(elliptic.P256(), b, wN), x)
		kMain := kMainFromZ(zC, tt)

		vec = append(vec, vectorJSON{
			Code:      codes[i],
			Sid:       sids[i],
			Accesskey: accesskeys[i],
			X:         hex.EncodeToString(x.FillBytes(make([]byte, 32))),
			Y:         hex.EncodeToString(y.FillBytes(make([]byte, 32))),
			A:         hex.EncodeToString(client.Share()),
			B:         hex.EncodeToString(server.Share()),
			TT:        hex.EncodeToString(tt),
			KMain:     hex.EncodeToString(kMain),
			Kca:       hex.EncodeToString(kc.Kca[:]),
			Kcd:       hex.EncodeToString(kc.Kcd[:]),
			Kc2s:      hex.EncodeToString(kc.Kc2s[:]),
			Ks2c:      hex.EncodeToString(kc.Ks2c[:]),
			TagA:      hex.EncodeToString(TagA(kc, tt)),
			TagB:      hex.EncodeToString(TagB(kc, tt)),
		})
	}
	return vec
}

// TestVectors asserts the committed vectors reproduce from first principles:
// given code/sid/accesskey and fixed scalars, every derived value must match.
func TestVectors(t *testing.T) {
	raw, err := os.ReadFile(vectorPath())
	if err != nil {
		t.Fatalf("read %s: %v", vectorPath(), err)
	}
	var vec []vectorJSON
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	if len(vec) < 2 {
		t.Fatalf("expected >=2 vectors, got %d", len(vec))
	}

	for i, v := range vec {
		w := scalarFromPassword(v.Code)
		x := mustBigInt(t, "0x"+v.X)
		y := mustBigInt(t, "0x"+v.Y)
		sid := mustHex(t, v.Sid)

		client, err := newSpake2StateFixed(true, w, x)
		if err != nil {
			t.Fatalf("vec %d: %v", i, err)
		}
		server, err := newSpake2StateFixed(false, w, y)
		if err != nil {
			t.Fatalf("vec %d: %v", i, err)
		}
		if hex.EncodeToString(client.Share()) != strings.ToLower(v.A) {
			t.Fatalf("vec %d: A mismatch\n got %s\n want %s", i, hex.EncodeToString(client.Share()), v.A)
		}
		if hex.EncodeToString(server.Share()) != strings.ToLower(v.B) {
			t.Fatalf("vec %d: B mismatch", i)
		}

		client.SetPeerShare(server.Share())
		server.SetPeerShare(client.Share())
		kc, err := client.Finish(sid, v.Accesskey)
		if err != nil {
			t.Fatalf("vec %d: %v", i, err)
		}
		ks, err := server.Finish(sid, v.Accesskey)
		if err != nil {
			t.Fatalf("vec %d: %v", i, err)
		}

		if hex.EncodeToString(kc.Kca[:]) != v.Kca || hex.EncodeToString(ks.Kca[:]) != v.Kca {
			t.Fatalf("vec %d: Kca mismatch", i)
		}
		if hex.EncodeToString(kc.Kcd[:]) != v.Kcd {
			t.Fatalf("vec %d: Kcd mismatch", i)
		}
		if hex.EncodeToString(kc.Kc2s[:]) != v.Kc2s {
			t.Fatalf("vec %d: Kc2s mismatch", i)
		}
		if hex.EncodeToString(kc.Ks2c[:]) != v.Ks2c {
			t.Fatalf("vec %d: Ks2c mismatch", i)
		}
		if hex.EncodeToString(TagA(kc, client.tt)) != strings.ToLower(v.TagA) {
			t.Fatalf("vec %d: tag_a mismatch", i)
		}
		if hex.EncodeToString(TagB(kc, client.tt)) != strings.ToLower(v.TagB) {
			t.Fatalf("vec %d: tag_b mismatch", i)
		}
		if hex.EncodeToString(client.tt) != strings.ToLower(v.TT) {
			t.Fatalf("vec %d: TT mismatch", i)
		}
	}
}

func mustBigInt(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
	if !ok {
		t.Fatalf("bad bigint %q", s)
	}
	return n
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}
