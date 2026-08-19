package main

// SPAKE2 (Abdalla–Pointcheval, classic two-generator PAKE) over NIST P-256 —
// self-contained implementation.
//
// This is the ONLY place the 6-digit security code is used: it is turned into
// a password scalar and fed into the PAKE. The code itself is never transmitted,
// and an eavesdropper (the relay) cannot do an offline dictionary attack from
// the transcript — every guess must be tried online, which the daemon's
// 10-attempt shutdown budget bounds.
//
// Construction (multiplicative notation adapted to additive EC):
//   A: X = x·G + w·M      B: Y = y·G + w·N
//   shared Z = x·(Y − w·N) = y·(X − w·M) = x·y·G
// An eavesdropper who sees X and Y cannot compute Z without solving CDH, so a
// wrong-password guess can only be tested online (via the confirmation tag).
// We do NOT use the RFC 9383 (SPAKE2+) augmented variant — both parties know
// the code, so w0/w1/V are unnecessary; key confirmation is done with explicit
// HMAC tags over the transcript.
//
// The Flutter app mirrors this byte-for-byte in
// app/lib/services/crypto/spake2.dart. Cross-language compatibility is locked
// by the shared test vectors in daemon_go/cmd/claw/testdata/vectors.json and
// app/test/vectors.json. If you change ANY byte layout here, regenerate the
// vectors and update the Dart side.

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"hash"
	"math/big"
)

const (
	spake2Domain   = "CAW-SPAKE2-v1"
	spake2KeySalt  = "caw.v1.keys"
	spake2KeyInfo  = "caw-secure-channel"
	spake2PwPrefix = "caw.v1:" // password normalization prefix (never send the raw code)
	spake2MSeed    = "CAW-SPAKE2-M-v1"
	spake2NSeed    = "CAW-SPAKE2-N-v1"
)

// spake2Error is a non-descript error type: on the wire we never reveal WHY a
// handshake failed (only "wrong code"), to avoid leaking oracle information.
type spake2Error string

func (e spake2Error) Error() string { return string(e) }

func errSpake2(m string) error { return spake2Error(m) }

// ── Point arithmetic over P-256 (affine via crypto/elliptic) ──

type ecPoint struct{ x, y *big.Int }

func (p ecPoint) valid(curve elliptic.Curve) bool {
	return p.x != nil && p.y != nil && curve.IsOnCurve(p.x, p.y)
}

func pointNeg(curve elliptic.Curve, p ecPoint) ecPoint {
	if p.x == nil || p.y == nil {
		return p
	}
	return ecPoint{p.x, new(big.Int).Sub(curve.Params().P, p.y)}
}

func pointAdd(curve elliptic.Curve, a, b ecPoint) ecPoint {
	if a.x == nil {
		return b
	}
	if b.x == nil {
		return a
	}
	x, y := curve.Add(a.x, a.y, b.x, b.y)
	return ecPoint{x, y}
}

func pointSub(curve elliptic.Curve, a, b ecPoint) ecPoint {
	return pointAdd(curve, a, pointNeg(curve, b))
}

func pointScalar(curve elliptic.Curve, p ecPoint, k *big.Int) ecPoint {
	if p.x == nil {
		return p
	}
	x, y := curve.ScalarMult(p.x, p.y, k.Bytes())
	return ecPoint{x, y}
}

func pointBaseScalar(curve elliptic.Curve, k *big.Int) ecPoint {
	x, y := curve.ScalarBaseMult(k.Bytes())
	return ecPoint{x, y}
}

// pointFromBytes decodes an uncompressed SEC1 point (65B) and validates it.
func pointFromBytes(curve elliptic.Curve, b []byte) (ecPoint, error) {
	if len(b) != 65 || b[0] != 4 {
		return ecPoint{}, errSpake2("malformed point")
	}
	p := ecPoint{
		new(big.Int).SetBytes(b[1:33]),
		new(big.Int).SetBytes(b[33:65]),
	}
	if !p.valid(curve) {
		return ecPoint{}, errSpake2("point not on curve")
	}
	return p, nil
}

func pointToBytes(p ecPoint) []byte {
	out := make([]byte, 65)
	out[0] = 4
	p.x.FillBytes(out[1:33])
	p.y.FillBytes(out[33:65])
	return out
}

// modSqrt computes sqrt(a) mod p for P-256 (p ≡ 3 mod 4). Returns nil if a is
// not a quadratic residue. Both Go and Dart compute the same principal root,
// so both sides derive identical M/N points.
func modSqrt(a *big.Int, p *big.Int) *big.Int {
	// Legendre symbol check: a^((p-1)/2) mod p == 1 → QR
	exp := new(big.Int).Sub(p, big.NewInt(1))
	exp.Rsh(exp, 1)
	if new(big.Int).Exp(a, exp, p).Cmp(big.NewInt(1)) != 0 {
		return nil
	}
	return new(big.Int).Exp(a, new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(1)), 2), p)
}

// hashToPoint deterministically maps a seed to a P-256 point via
// try-and-increment over SHA-256. Both sides hash the same seeds so M and N are
// identical everywhere, and their discrete-log relation to each other and to G
// is unknown.
func hashToPoint(curve elliptic.Curve, seed string) (ecPoint, error) {
	p := curve.Params().P
	for i := 0; i < 256; i++ {
		h := sha256.Sum256(append([]byte(seed), byte(i)))
		x := new(big.Int).SetBytes(h[:])
		x.Mod(x, p)
		// y² = x³ - 3x + b
		x3 := new(big.Int).Mul(x, x)
		x3.Mul(x3, x)
		threeX := new(big.Int).Mul(big.NewInt(3), x)
		rhs := new(big.Int).Sub(x3, threeX)
		rhs.Add(rhs, curve.Params().B)
		rhs.Mod(rhs, p)
		if y := modSqrt(rhs, p); y != nil {
			return ecPoint{x, y}, nil
		}
	}
	return ecPoint{}, errSpake2("hashToPoint: no point found")
}

// M and N generator points (both sides derive them identically at init).
var spake2M, spake2N ecPoint

func init() {
	curve := elliptic.P256()
	m, err := hashToPoint(curve, spake2MSeed)
	if err != nil {
		panic("spake2: derive M: " + err.Error())
	}
	n, err := hashToPoint(curve, spake2NSeed)
	if err != nil {
		panic("spake2: derive N: " + err.Error())
	}
	spake2M, spake2N = m, n
}

// ── Scalars and password ──

// scalarFromPassword derives the SPAKE2 password scalar from the security code.
// The raw code is never put on the wire; only this 256-bit digest reduced mod q.
func scalarFromPassword(code string) *big.Int {
	h := sha256.Sum256([]byte(spake2PwPrefix + code))
	s := new(big.Int).SetBytes(h[:])
	return s.Mod(s, elliptic.P256().Params().N)
}

func randomScalar() (*big.Int, error) {
	q := elliptic.P256().Params().N
	for {
		k, err := rand.Int(rand.Reader, q)
		if err != nil {
			return nil, err
		}
		if k.Sign() > 0 {
			return k, nil
		}
	}
}

// ── HKDF-SHA256 (RFC 5869), stdlib-only ──

func hkdfExtract(h func() hash.Hash, secret, salt []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, h().Size())
	}
	mac := hmac.New(h, salt)
	mac.Write(secret)
	return mac.Sum(nil)
}

func hkdfExpand(h func() hash.Hash, prk, info []byte, n int) ([]byte, error) {
	out := make([]byte, 0, n)
	var t []byte
	counter := byte(1)
	for len(out) < n {
		mac := hmac.New(h, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out = append(out, t...)
		if counter == 255 {
			return nil, errSpake2("hkdf expand too long")
		}
		counter++
	}
	return out[:n], nil
}

// ── SPAKE2 state machine ──

// Spake2Keys holds the derived key material after a successful handshake.
// Kca/Kcd key the confirmation tags; Kc2s/Ks2c are the traffic keys.
type Spake2Keys struct {
	Kca, Kcd, Kc2s, Ks2c [32]byte
}

// Spake2State is one side of a SPAKE2 exchange.
type Spake2State struct {
	client    bool
	curve     elliptic.Curve
	w         *big.Int
	scalar    *big.Int
	share     ecPoint // own point (A for client, B for server)
	peer      ecPoint // peer point
	hasPeer   bool
	sid       []byte
	accesskey string
	tt        []byte // transcript, filled by Finish (used for key confirmation tags)
}

// NewSpake2Client creates the client (A) side. w is the password scalar.
func NewSpake2Client(w *big.Int) (*Spake2State, error) { return newSpake2State(true, w) }

// NewSpake2Server creates the server (B) side. w is the password scalar.
func NewSpake2Server(w *big.Int) (*Spake2State, error) { return newSpake2State(false, w) }

func newSpake2State(client bool, w *big.Int) (*Spake2State, error) {
	scalar, err := randomScalar()
	if err != nil {
		return nil, err
	}
	return newSpake2StateFixed(client, w, scalar)
}

// newSpake2StateFixed is used by the cross-language vector generator and tests:
// it builds a side from an explicit scalar so outputs are deterministic.
func newSpake2StateFixed(client bool, w, scalar *big.Int) (*Spake2State, error) {
	if w == nil || w.Sign() <= 0 || scalar == nil || scalar.Sign() <= 0 {
		return nil, errSpake2("bad password scalar or ephemeral")
	}
	curve := elliptic.P256()
	// client:  A = x·G + w·M
	// server:  B = y·G + w·N
	gen := spake2M
	if !client {
		gen = spake2N
	}
	share := pointAdd(curve, pointBaseScalar(curve, scalar), pointScalar(curve, gen, w))
	return &Spake2State{client: client, curve: curve, w: w, scalar: scalar, share: share}, nil
}

// Share returns this side's 65-byte uncompressed SEC1 point.
func (s *Spake2State) Share() []byte { return pointToBytes(s.share) }

// SetPeerShare records the peer's public share (65B SEC1).
func (s *Spake2State) SetPeerShare(peer []byte) error {
	p, err := pointFromBytes(s.curve, peer)
	if err != nil {
		return err
	}
	s.peer = p
	s.hasPeer = true
	return nil
}

// Finish derives the shared keys after SetPeerShare. sid is the 16-byte session
// id generated by the client and echoed by the server; accesskey binds the keys
// to this device+session so they can't be replayed elsewhere.
func (s *Spake2State) Finish(sid []byte, accesskey string) (*Spake2Keys, error) {
	if !s.hasPeer {
		return nil, errSpake2("peer share not set")
	}
	curve := s.curve

	// Z = scalar·(peerShare − w·opponentGenerator):
	//   client: Z = x·(B − w·N)      server: Z = y·(A − w·M)
	// both equal x·y·G.
	oppGen := spake2N
	if !s.client {
		oppGen = spake2M
	}
	z := pointScalar(curve, pointSub(curve, s.peer, pointScalar(curve, oppGen, s.w)), s.scalar)
	if !z.valid(curve) {
		return nil, errSpake2("bad shared secret")
	}

	// Transcript: A = client share, B = server share.
	a, b := s.share, s.peer
	if !s.client {
		a, b = s.peer, s.share
	}
	s.sid = sid
	s.accesskey = accesskey
	s.tt = buildTranscript(sid, accesskey, a, b)

	kMain := kMainFromZ(z, s.tt)
	return deriveSpake2Keys(kMain)
}

// buildTranscript produces the exact byte layout both sides must match:
//
//	domain(13B) || len(sid)2B || sid || len("client")2B || "client"
//	|| len("server")2B || "server" || 0x00 || len(A)2B || A
//	|| 0x01 || len(B)2B || B || len(accesskey)2B || accesskey
func buildTranscript(sid []byte, accesskey string, a, b ecPoint) []byte {
	writeLen2 := func(buf *[]byte, b []byte) {
		*buf = append(*buf, byte(len(b)>>8), byte(len(b)))
	}
	var buf []byte
	buf = append(buf, []byte(spake2Domain)...)
	writeLen2(&buf, sid)
	buf = append(buf, sid...)
	client := []byte("client")
	server := []byte("server")
	writeLen2(&buf, client)
	buf = append(buf, client...)
	writeLen2(&buf, server)
	buf = append(buf, server...)
	pa := pointToBytes(a)
	buf = append(buf, 0x00)
	writeLen2(&buf, pa)
	buf = append(buf, pa...)
	pb := pointToBytes(b)
	buf = append(buf, 0x01)
	writeLen2(&buf, pb)
	buf = append(buf, pb...)
	ak := []byte(accesskey)
	writeLen2(&buf, ak)
	buf = append(buf, ak...)
	return buf
}

// kMainFromZ computes K_main = SHA256(0x04‖Zx‖Zy ‖ TT).
func kMainFromZ(z ecPoint, tt []byte) []byte {
	h := sha256.New()
	h.Write([]byte{4})
	var xb, yb [32]byte
	z.x.FillBytes(xb[:])
	h.Write(xb[:])
	z.y.FillBytes(yb[:])
	h.Write(yb[:])
	h.Write(tt)
	return h.Sum(nil)
}

func deriveSpake2Keys(kMain []byte) (*Spake2Keys, error) {
	prk := hkdfExtract(sha256.New, kMain, []byte(spake2KeySalt))
	okm, err := hkdfExpand(sha256.New, prk, []byte(spake2KeyInfo), 128)
	if err != nil {
		return nil, err
	}
	var k Spake2Keys
	copy(k.Kca[:], okm[0:32])
	copy(k.Kcd[:], okm[32:64])
	copy(k.Kc2s[:], okm[64:96])
	copy(k.Ks2c[:], okm[96:128])
	return &k, nil
}

// ── Key confirmation tags ──

// TagA is the app→daemon confirmation tag (proves the app knows the code).
func TagA(k *Spake2Keys, tt []byte) []byte {
	mac := hmac.New(sha256.New, k.Kca[:])
	mac.Write(tt)
	return mac.Sum(nil)[:16]
}

// TagB is the daemon→app confirmation tag.
func TagB(k *Spake2Keys, tt []byte) []byte {
	mac := hmac.New(sha256.New, k.Kcd[:])
	mac.Write(tt)
	return mac.Sum(nil)[:16]
}

// VerifyTag constant-time tag comparison.
func VerifyTag(actual, expected []byte) bool {
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

// Transcript returns the computed transcript (valid only after Finish).
func (s *Spake2State) Transcript() []byte { return s.tt }
