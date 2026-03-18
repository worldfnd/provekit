package circuit

import (
	"bytes"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"sort"

	arkSerialize "github.com/reilabs/go-ark-serialize"
)

// BN254 scalar field modulus
var bn254Modulus, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

var skyscraperSigma, _ = new(big.Int).SetString(
	"9915499612839321149637521777990102151350674507940716049588462388200839649614", 10)

var rcPow [18]*big.Int

func init() {
	strs := [18]string{
		"0",
		"17829420340877239108687448009732280677191990375576158938221412342251481978692",
		"5852100059362614845584985098022261541909346143980691326489891671321030921585",
		"17048088173265532689680903955395019356591870902241717143279822196003888806966",
		"71577923540621522166602308362662170286605786204339342029375621502658138039",
		"1630526119629192105940988602003704216811347521589219909349181656165466494167",
		"7807402158218786806372091124904574238561123446618083586948014838053032654983",
		"13329560971460034925899588938593812685746818331549554971040309989641523590611",
		"16971509144034029782226530622087626979814683266929655790026304723118124142299",
		"8608910393531852188108777530736778805001620473682472554749734455948859886057",
		"10789906636021659141392066577070901692352605261812599600575143961478236801530",
		"18708129585851494907644197977764586873688181219062643217509404046560774277231",
		"8383317008589863184762767400375936634388677459538766150640361406080412989586",
		"10555553646766747611187318546907885054893417621612381305146047194084618122734",
		"18278062107303135832359716534360847832111250949377506216079581779892498540823",
		"9307964587880364850754205696017897664821998926660334400055925260019288889718",
		"13066217995902074168664295654459329310074418852039335279433003242098078040116",
		"0",
	}
	for i, s := range strs {
		rcPow[i], _ = new(big.Int).SetString(s, 10)
	}
}

func nativeSboxByte(b byte) byte {
	x := bits.RotateLeft8(^b, 1)
	y := bits.RotateLeft8(b, 2)
	z := bits.RotateLeft8(b, 3)
	return bits.RotateLeft8(b^(x&y&z), 1)
}

func nativeSquare(l *big.Int) *big.Int {
	r := new(big.Int).Mul(l, l)
	r.Mul(r, skyscraperSigma)
	r.Mod(r, bn254Modulus)
	return r
}

func nativeBar(l *big.Int) *big.Int {
	var buf [32]byte
	b := l.Bytes()
	copy(buf[32-len(b):], b)

	// Swap 16-byte halves
	var swapped [32]byte
	copy(swapped[:16], buf[16:32])
	copy(swapped[16:], buf[:16])

	for i := range swapped {
		swapped[i] = nativeSboxByte(swapped[i])
	}
	return new(big.Int).SetBytes(swapped[:])
}

// Rounds 6, 7, 10, 11 use bar; all others use square.
var isBarRound = [18]bool{
	false, false, false, false, false, false,
	true, true,
	false, false,
	true, true,
	false, false, false, false, false, false,
}

func nativePermuteV2(state *[2]*big.Int) {
	l := new(big.Int).Set(state[0])
	r := new(big.Int).Set(state[1])

	for i := 0; i < 18; i++ {
		var f *big.Int
		if isBarRound[i] {
			f = nativeBar(l)
		} else {
			f = nativeSquare(l)
		}
		newL := new(big.Int).Add(r, f)
		newL.Add(newL, rcPow[i])
		newL.Mod(newL, bn254Modulus)
		r = l
		l = newL
	}

	state[0] = l
	state[1] = r
}

// ---------------------------------------------------------------------------
// NativeSponge: duplex sponge over BN254 scalars using PermuteV2
// Matches Rust DuplexSponge<Skyscraper, 64, 32> with byte-level position
// tracking. State is 64 bytes (2 field elements), rate R = 32 bytes.
// ---------------------------------------------------------------------------

const spongeRate = 32

type NativeSponge struct {
	state      [64]byte
	absorbPos  int // 0..spongeRate (byte-level)
	squeezePos int // 0..spongeRate (byte-level)
}

func newNativeSponge() *NativeSponge {
	return &NativeSponge{
		squeezePos: spongeRate,
	}
}

func (s *NativeSponge) permute() {
	left := leBytesToNativeBigInt(s.state[:32])
	right := leBytesToNativeBigInt(s.state[32:])
	st := [2]*big.Int{left, right}
	nativePermuteV2(&st)
	lBytes := nativeBigIntToLeBytes(st[0])
	rBytes := nativeBigIntToLeBytes(st[1])
	copy(s.state[:32], lBytes[:])
	copy(s.state[32:], rBytes[:])
}

// Absorb writes input bytes into the rate portion of the state, permuting
// when the rate is full. Matches DuplexSponge::absorb exactly.
func (s *NativeSponge) Absorb(input []byte) {
	if len(input) == 0 {
		return
	}
	if s.absorbPos == spongeRate {
		s.absorbPos = 0
		s.squeezePos = spongeRate
		s.permute()
	}
	chunkLen := min(len(input), spongeRate-s.absorbPos)
	copy(s.state[s.absorbPos:s.absorbPos+chunkLen], input[:chunkLen])
	s.absorbPos += chunkLen
	s.Absorb(input[chunkLen:])
}

// Squeeze reads output bytes from the rate portion of the state, permuting
// when the rate is exhausted. Matches DuplexSponge::squeeze exactly.
func (s *NativeSponge) Squeeze(output []byte) {
	if len(output) == 0 {
		return
	}
	if s.squeezePos == spongeRate {
		s.squeezePos = 0
		s.absorbPos = 0
		s.permute()
	}
	chunkLen := min(len(output), spongeRate-s.squeezePos)
	copy(output[:chunkLen], s.state[s.squeezePos:s.squeezePos+chunkLen])
	s.squeezePos += chunkLen
	s.Squeeze(output[chunkLen:])
}

// InitFromProtocolID initializes the sponge by absorbing the 64-byte protocol_id
// (as 2 LE field elements) and the 32-byte session_id (as 1 LE field element).
// If sessionID is nil or shorter than 32 bytes, session_id is absorbed as Fr(0).
// This matches spongefish's DomainSeparator initialization.
func (s *NativeSponge) InitFromProtocolID(protocolID [64]byte, sessionID []byte) {
	s.state = [64]byte{}
	s.absorbPos = 0
	s.squeezePos = spongeRate
	sessionID = make([]byte, 32)

	s.AbsorbFr(leBytesToNativeBigInt(protocolID[:32]))
	s.AbsorbFr(leBytesToNativeBigInt(protocolID[32:]))
	var sessionFr *big.Int
	if len(sessionID) >= 32 {
		sessionFr = leBytesToNativeBigInt(sessionID[:32])
	} else {
		sessionFr = big.NewInt(0)
	}
	s.AbsorbFr(sessionFr)
}

// AbsorbFr absorbs a field element as 32 LE bytes.
func (s *NativeSponge) AbsorbFr(val *big.Int) {
	leBytes := nativeBigIntToLeBytes(val)
	s.Absorb(leBytes[:])
}

// SqueezeFr squeezes 32 bytes and interprets them as a LE field element.
func (s *NativeSponge) SqueezeFr() *big.Int {
	var buf [32]byte
	s.Squeeze(buf[:])
	return leBytesToNativeBigInt(buf[:])
}

func leBytesToNativeBigInt(b []byte) *big.Int {
	val := new(big.Int)
	for i := len(b) - 1; i >= 0; i-- {
		val.Lsh(val, 8)
		val.Or(val, big.NewInt(int64(b[i])))
	}
	val.Mod(val, bn254Modulus)
	return val
}

func nativeBigIntToLeBytes(v *big.Int) [32]byte {
	var buf [32]byte
	vv := new(big.Int).Set(v)
	vv.Mod(vv, bn254Modulus)
	for i := 0; i < 32; i++ {
		var m big.Int
		vv.DivMod(vv, big.NewInt(256), &m)
		buf[i] = byte(m.Int64())
	}
	return buf
}

// stateTo64Hex returns the sponge state as 64 bytes LE, hex-encoded.
func stateTo64Hex(state *[64]byte) string {
	return fmt.Sprintf("%x%x", state[:32], state[32:])
}

// ---------------------------------------------------------------------------
// NativeArthur: native transcript reader mirroring the in-circuit Arthur.
// Reads scalars from nargString (prover messages), squeezes challenges
// from the sponge, and reads hints from a separate buffer.
// ---------------------------------------------------------------------------

type NativeArthur struct {
	sponge     *NativeSponge
	nargString []byte
	hints      *bytes.Reader
}

func NewNativeArthur(protocolID [64]byte, sessionID []byte, nargString []byte, hints []byte) *NativeArthur {
	sponge := newNativeSponge()
	sponge.InitFromProtocolID(protocolID, sessionID)
	return &NativeArthur{
		sponge:     sponge,
		nargString: nargString,
		hints:      bytes.NewReader(hints),
	}
}

// FillNextScalars reads n field elements (32 bytes each, LE) from the
// transcript and absorbs them into the sponge.
func (a *NativeArthur) FillNextScalars(n int) ([]*big.Int, error) {
	out := make([]*big.Int, n)
	for i := range n {
		if len(a.nargString) < 32 {
			return nil, fmt.Errorf("FillNextScalars: need 32 bytes, have %d", len(a.nargString))
		}
		out[i] = leBytesToNativeBigInt(a.nargString[:32])
		out[i].Mod(out[i], bn254Modulus)
		a.nargString = a.nargString[32:]
	}
	for _, v := range out {
		a.sponge.AbsorbFr(v)
	}
	return out, nil
}

// FillChallengeScalars squeezes n field elements from the sponge.
// Each challenge requires 64 bytes (two sponge squeezes) to match spongefish's
// DecodingFieldBuffer which uses (MODULUS_BIT_SIZE.div_ceil(8) + 32) = 64 bytes
// per field element for statistical uniformity, then reduces mod p.
func (a *NativeArthur) FillChallengeScalars(n int) ([]*big.Int, error) {
	fmt.Println("fillChallengeScalars", n)
	out := make([]*big.Int, n)
	for i := range n {
		// Squeeze two field elements (64 bytes total) and combine as LE integer mod p.
		lo := a.sponge.SqueezeFr() // first 32 bytes
		hi := a.sponge.SqueezeFr() // next 32 bytes
		// combined = hi << 256 | lo, then mod p
		combined := new(big.Int).Lsh(hi, 256)
		combined.Add(combined, lo)
		combined.Mod(combined, bn254Modulus)
		out[i] = combined
	}
	return out, nil
}

// FillNextBytes reads n bytes from the transcript and absorbs each byte
// as an individual field element (matching spongefish behavior).
func (a *NativeArthur) FillNextBytes(n int) ([]byte, error) {
	if len(a.nargString) < n {
		return nil, fmt.Errorf("FillNextBytes: need %d bytes, have %d", n, len(a.nargString))
	}
	raw := make([]byte, n)
	copy(raw, a.nargString[:n])
	a.nargString = a.nargString[n:]
	a.sponge.Absorb(raw)
	return raw, nil
}

// FillChallengeBytes squeezes n bytes directly from the sponge.
// Uses byte-level squeeze tracking, matching Rust DuplexSponge exactly.
func (a *NativeArthur) FillChallengeBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	a.sponge.Squeeze(out)
	return out, nil
}

// ProverHint reads exactly n raw bytes from the hints buffer (NargDeserialize).
func (a *NativeArthur) ProverHint(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(a.hints, buf)
	if err != nil {
		return nil, fmt.Errorf("ProverHint: %w", err)
	}
	return buf, nil
}

// ProverHintArk reads an Arkworks compressed-serialized value from the hints buffer.
func (a *NativeArthur) ProverHintArk(target interface{}) error {
	_, err := arkSerialize.CanonicalDeserializeWithMode(a.hints, target, false, false)
	if err != nil {
		return fmt.Errorf("ProverHintArk: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Native challenge index derivation (mirrors Rust challenge_indices)
// ---------------------------------------------------------------------------

func nativeGetStirChallenges(
	arthur *NativeArthur,
	numLeaves int,
	count int,
	deduplicate bool,
) ([]int, error) {
	if count == 0 {
		return []int{}, nil
	}
	if numLeaves == 1 {
		if deduplicate {
			return []int{0}, nil
		}
		return make([]int, count), nil
	}

	sizeBytes := (bits.Len(uint(numLeaves)) - 1 + 7) / 8

	fmt.Println("entropy bytes:", count*sizeBytes)
	entropy, err := arthur.FillChallengeBytes(count * sizeBytes)
	if err != nil {
		return nil, err
	}
	fmt.Println("entropy:", entropy)

	indices := make([]int, count)
	for i := range count {
		chunk := entropy[i*sizeBytes : (i+1)*sizeBytes]
		value := 0
		for _, b := range chunk {
			value = (value << 8) | int(b)
		}
		indices[i] = value % numLeaves
	}

	if deduplicate {
		sort.Ints(indices)
		indices = dedup(indices)
	}

	return indices, nil
}

// ---------------------------------------------------------------------------
// Merkle tree hint consumption
// Reads sibling hashes from the hints buffer following the same traversal
// order as whir's merkle_tree::verify.
// ---------------------------------------------------------------------------

// countMerkleHints determines the number of 32-byte sibling hashes in the
// hints buffer for a Merkle multi-opening at the given leaf indices.
// It also returns the FullMultiPath reconstructed from the hints.
func consumeMerkleHints(arthur *NativeArthur, indices []int, treeHeight int) (FullMultiPath[KeccakDigest], error) {
	if len(indices) == 0 {
		return FullMultiPath[KeccakDigest]{}, nil
	}

	sorted := make([]int, len(indices))
	copy(sorted, indices)
	sort.Ints(sorted)
	sorted = dedup(sorted)

	proofs := make(map[int]*Path[KeccakDigest])
	for _, idx := range sorted {
		proofs[idx] = &Path[KeccakDigest]{
			LeafIndex: uint64(idx),
			AuthPath:  make([]KeccakDigest, 0, treeHeight),
		}
	}

	currentIndices := sorted
	for level := 0; level < treeHeight; level++ {
		var nextIndices []int
		i := 0
		for i < len(currentIndices) {
			a := currentIndices[i]
			if i+1 < len(currentIndices) && currentIndices[i+1] == a^1 {
				// Sibling pair in the query set — no hint needed
				nextIndices = append(nextIndices, a>>1)
				i += 2
			} else {
				// Need sibling hash from hints
				siblingHash, err := arthur.ProverHint(32)
				if err != nil {
					return FullMultiPath[KeccakDigest]{}, fmt.Errorf("merkle level %d, index %d: %w", level, a, err)
				}
				var digest KeccakDigest
				copy(digest.KeccakDigest[:], siblingHash)

				sibling := a ^ 1
				if level == 0 {
					for _, idx := range sorted {
						if idx == a {
							proofs[idx].LeafSiblingHash = digest
						} else if idx == sibling {
							proofs[idx].LeafSiblingHash = digest
						}
					}
				}

				// Store sibling hash in auth path for all original indices
				// that trace through this node
				for _, origIdx := range sorted {
					ancestorIdx := origIdx >> uint(level)
					if ancestorIdx == a {
						if level > 0 {
							proofs[origIdx].AuthPath = append(proofs[origIdx].AuthPath, digest)
						}
					}
				}

				nextIndices = append(nextIndices, a>>1)
				i++
			}
		}
		sort.Ints(nextIndices)
		nextIndices = dedup(nextIndices)
		currentIndices = nextIndices
	}

	// Build the FullMultiPath from collected proofs (in original index order)
	paths := make([]Path[KeccakDigest], 0, len(sorted))
	for _, idx := range sorted {
		paths = append(paths, *proofs[idx])
	}
	return FullMultiPath[KeccakDigest]{Proofs: paths}, nil
}

func dedup(sorted []int) []int {
	if len(sorted) <= 1 {
		return sorted
	}
	result := sorted[:1]
	for _, v := range sorted[1:] {
		if v != result[len(result)-1] {
			result = append(result, v)
		}
	}
	return result
}
