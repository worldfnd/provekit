package circuit

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/bits"
	"net/http"
	"os"
	"sort"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	arkSerialize "github.com/reilabs/go-ark-serialize"

	"reilabs/whir-verifier-circuit/app/common"
)

func FrDecimalToHexLE(decimal string) string {
	n := new(big.Int)
	_, ok := n.SetString(decimal, 10)
	if !ok {
		return ""
	}

	be := n.Bytes() // big-endian

	// pad to 32 bytes
	buf := make([]byte, 32)
	copy(buf[32-len(be):], be)

	// convert to little-endian
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}

	return hex.EncodeToString(buf)
}

// ---------------------------------------------------------------------------
// PrepareAndVerifyCircuit: replays the spongefish Fiat-Shamir transcript
// natively to determine hint offsets, reads hints, and builds the data
// structures needed by the gnark circuit. Currently skips the actual
// circuit call (the goal is to make parameter passing functional first).
// ---------------------------------------------------------------------------

func PrepareAndVerifyCircuit(config Config, r1cs R1CS, pk *groth16.ProvingKey, vk *groth16.VerifyingKey, buildOps common.BuildOps) error {
	if len(config.ProtocolID) < 64 {
		return fmt.Errorf("protocol_id must be 64 bytes, got %d", len(config.ProtocolID))
	}
	var pid [64]byte
	copy(pid[:], config.ProtocolID[:64])

	arthur := NewNativeArthur(pid, config.SessionID, config.NargString, config.Hints)
	blindedCommitmentWhirConfig := NewWhirParams(config.BlindedCommitmentWhirConfig)
	blindingCommitmentWhirConfig := NewWhirParams(config.BlindingCommitmentWhirConfig)

	// ---------------------------------------------------------------
	// 1. parseBatchedCommitment for commitment 1 (witness)
	// ---------------------------------------------------------------
	blindedCommitmentPolyRoot, blindedCommitmentOODPoint, blindedCommitmentOODMatrix, err := nativeParseBatchedCommitment(arthur, blindedCommitmentWhirConfig)
	fmt.Println("blindedCommitmentPolyRoot", FrDecimalToHexLE(blindedCommitmentPolyRoot.String()))
	fmt.Println("blindedCommitmentOODPoint", blindedCommitmentOODPoint)
	fmt.Println("blindedCommitmentOODMatrix", blindedCommitmentOODMatrix)
	fmt.Println("err", err)
	if err != nil {
		return fmt.Errorf("parse commitment 1: %w", err)
	}

	blindingCommitmentPolyRoot, blindingCommitmentOODPoint, blindingCommitmentOODMatrix, err := nativeParseBatchedCommitment(arthur, blindingCommitmentWhirConfig)
	fmt.Println("blindingCommitmentPolyRoot", FrDecimalToHexLE(blindingCommitmentPolyRoot.String()))
	fmt.Println("blindingCommitmentOODPoint", blindingCommitmentOODPoint)
	fmt.Println("blindingCommitmentOODMatrix", blindingCommitmentOODMatrix)
	fmt.Println("err", err)
	if err != nil {
		return fmt.Errorf("parse commitment 1: %w", err)
	}
	// Pass a deferred array of at least 4 elements to satisfy the expected size
	// The first element corresponds to hidingSpartanLinearStatementEvaluations[0], the next 3 to witnessLinearStatementEvaluations[0..2] in single mode (no public inputs)
	fmt.Println("config.BlindedCommitmentWhirConfig", config.BlindedCommitmentWhirConfig)
	fmt.Println("config.BlindingCommitmentWhirConfig", config.BlindingCommitmentWhirConfig)

	// ---------------------------------------------------------------
	// 2. If dual mode: squeeze logup challenges, parse commitment 2
	// ---------------------------------------------------------------
	if config.NumChallenges > 0 {
		a, err := arthur.FillChallengeScalars(config.NumChallenges)
		fmt.Println("challenges", a)
		if err != nil {
			return fmt.Errorf("logup challenges: %w", err)
		}
		e, f, g, err := nativeParseBatchedCommitment(arthur, blindingCommitmentWhirConfig)
		fmt.Println("e", e)
		fmt.Println("f", f)
		fmt.Println("g", g)
		if err != nil {
			return fmt.Errorf("parse commitment 2: %w", err)
		}
	}

	// ---------------------------------------------------------------
	// 3. Spartan sumcheck: squeeze tRand, then run ZK sumcheck
	// ---------------------------------------------------------------
	// 3a. tRand (Spartan verifier randomness)
	tRand, err := arthur.FillChallengeScalars(config.LogNumConstraints)
	fmt.Println("tRand", tRand)
	if err != nil {
		return fmt.Errorf("tRand: %w", err)
	}

	err = verifyCircuit([]Fp256{
		{}, // hidingSpartanLinearStatementEvaluations[0]
		{}, // witnessLinearStatementEvaluations[0]
		{}, // witnessLinearStatementEvaluations[1]
		{}, // witnessLinearStatementEvaluations[2]
	}, config, Hints{}, pk, vk, ClaimedEvaluations{}, ClaimedEvaluations{}, [2]Fp256{}, r1cs, Interner{}, buildOps, PublicInputs{})
	if err != nil {
		return fmt.Errorf("failed to verify circuit: %w", err)
	}
	return nil
	// 3b. ZK Sumcheck: parseBatchedCommitment for hiding spartan, sumcheck rounds, unblind,
	//     then RunZKWhir for the hiding spartan blinding polynomial.
	//     For now we need the WHIRConfig for hiding spartan. Since it was removed from Config,
	//     we use the witness config parameters to drive the replay (they share the same protocol structure).
	//     TODO: Re-add hiding spartan config or derive it.
	spartanHidingHints, err := nativeRunZKSumcheck(arthur, config, blindingCommitmentWhirConfig)
	if err != nil {
		return fmt.Errorf("zk sumcheck: %w", err)
	}

	// ---------------------------------------------------------------
	// 4. Public inputs hash + x challenge
	// ---------------------------------------------------------------
	if _, err = arthur.FillNextScalars(1); err != nil {
		return fmt.Errorf("public inputs hash: %w", err)
	}
	if _, err = arthur.FillChallengeScalars(1); err != nil {
		return fmt.Errorf("x challenge: %w", err)
	}

	// ---------------------------------------------------------------
	// 5. Read claimed evaluations and deferred values from hints
	// ---------------------------------------------------------------
	var evals1 []Fp256
	if err = arthur.ProverHintArk(&evals1); err != nil {
		return fmt.Errorf("evals_1: %w", err)
	}
	log.Printf("Read %d claimed evaluations (commitment 1)", len(evals1))

	var evals2 []Fp256
	if config.NumChallenges > 0 {
		if err = arthur.ProverHintArk(&evals2); err != nil {
			return fmt.Errorf("evals_2: %w", err)
		}
		log.Printf("Read %d claimed evaluations (commitment 2)", len(evals2))
	}

	if !config.PublicInputs.IsEmpty() {
		var publicEval Fp256
		if err = arthur.ProverHintArk(&publicEval); err != nil {
			return fmt.Errorf("public_eval: %w", err)
		}
		log.Printf("Read public weight evaluation")
	}

	// ---------------------------------------------------------------
	// 6. Witness WHIR verify — reads submatrix hints + merkle siblings
	// ---------------------------------------------------------------
	witnessHints, err := nativeWhirVerify(arthur, blindingCommitmentWhirConfig, config.BlindedCommitmentWhirConfig)
	if err != nil {
		return fmt.Errorf("witness whir verify commitment 1: %w", err)
	}

	var witnessHints2 ZKHint
	if config.NumChallenges > 0 {
		witnessHints2, err = nativeWhirVerify(arthur, blindingCommitmentWhirConfig, config.BlindedCommitmentWhirConfig)
		if err != nil {
			return fmt.Errorf("witness whir verify commitment 2: %w", err)
		}
	}

	// ---------------------------------------------------------------
	// Build the Hints struct from what we consumed
	// ---------------------------------------------------------------
	var witnessFirstRoundHints []FirstRoundHint
	if config.NumChallenges > 0 {
		witnessFirstRoundHints = []FirstRoundHint{
			witnessHints.firstRoundMerklePaths,
			witnessHints2.firstRoundMerklePaths,
		}
	} else {
		witnessFirstRoundHints = []FirstRoundHint{witnessHints.firstRoundMerklePaths}
	}

	hints := Hints{
		spartanHidingHint:      spartanHidingHints,
		WitnessFirstRoundHints: witnessFirstRoundHints,
		WitnessRoundHints:      witnessHints,
	}

	remainingHints := arthur.hints.Len()
	remainingTranscript := len(arthur.nargString)
	log.Printf("Hint consumption complete. Remaining: %d hint bytes, %d transcript bytes", remainingHints, remainingTranscript)
	log.Printf("Parsed hints: spartan=%d merkle paths, witness=%d merkle paths",
		len(hints.spartanHidingHint.roundHints.merklePaths),
		len(hints.WitnessRoundHints.roundHints.merklePaths))

	// ---------------------------------------------------------------
	// 7. Interner deserialization (needed for circuit, kept for reference)
	// ---------------------------------------------------------------
	internerBytes, err := hex.DecodeString(r1cs.Interner.Values)
	if err != nil {
		return fmt.Errorf("failed to decode interner values: %w", err)
	}
	var interner Interner
	_, err = arkSerialize.CanonicalDeserializeWithMode(
		bytes.NewReader(internerBytes), &interner, false, false,
	)
	if err != nil {
		return fmt.Errorf("failed to deserialize interner: %w", err)
	}

	// Skip the circuit call for now — parameter passing is functional.
	log.Printf("Parameter passing functional. Skipping circuit call.")
	_ = hints
	_ = interner
	_ = pk
	_ = vk
	_ = buildOps

	return nil
}

// ---------------------------------------------------------------------------
// Native protocol replay helpers
// ---------------------------------------------------------------------------

func nativeParseBatchedCommitment(arthur *NativeArthur, whirParams WHIRParams) (
	rootHash *big.Int,
	oodPoints []*big.Int,
	oodAnswers [][]*big.Int,
	err error,
) {
	roots, e := arthur.FillNextScalars(1)
	if e != nil {
		err = e
		return
	}
	rootHash = roots[0]

	oodSamples := whirParams.RoundParametersOODSamples[0]
	oodPts, e := arthur.FillChallengeScalars(oodSamples)
	if e != nil {
		err = e
		return
	}
	oodPoints = oodPts

	fmt.Println("whirParams.BatchSize", whirParams.BatchSize)
	oodAnswers = make([][]*big.Int, whirParams.BatchSize*oodSamples)
	for i := range whirParams.BatchSize * oodSamples {
		ans, e := arthur.FillNextScalars(1)
		if e != nil {
			err = e
			return
		}
		oodAnswers[i] = ans
	}

	return
}

// nativeRunZKSumcheck replays the ZK sumcheck transcript operations and
// the embedded hiding-spartan WHIR verify.
func nativeRunZKSumcheck(arthur *NativeArthur, config Config, whirParams WHIRParams) (ZKHint, error) {
	// Parse commitment for hiding spartan blinding polynomial
	if _, _, _, err := nativeParseBatchedCommitment(arthur, whirParams); err != nil {
		return ZKHint{}, fmt.Errorf("spartan commitment: %w", err)
	}

	// sum_g + rho
	if _, err := arthur.FillNextScalars(1); err != nil {
		return ZKHint{}, fmt.Errorf("sum_g: %w", err)
	}
	if _, err := arthur.FillChallengeScalars(1); err != nil {
		return ZKHint{}, fmt.Errorf("rho: %w", err)
	}

	// Sumcheck rounds
	for range config.LogNumConstraints {
		// 4 coefficients per round (degree-3 polynomial evaluated at 0,1,2,3)
		if _, err := arthur.FillNextScalars(4); err != nil {
			return ZKHint{}, fmt.Errorf("sumcheck coeff: %w", err)
		}
		if _, err := arthur.FillChallengeScalars(1); err != nil {
			return ZKHint{}, fmt.Errorf("folding randomness: %w", err)
		}
	}

	// Polynomial sums (blinding evals)
	if _, err := arthur.FillNextScalars(2); err != nil {
		return ZKHint{}, fmt.Errorf("polynomial sums: %w", err)
	}

	// RunZKWhir for hiding spartan
	zkHint, err := nativeWhirVerify(arthur, whirParams, config.BlindedCommitmentWhirConfig)
	if err != nil {
		return ZKHint{}, fmt.Errorf("hiding spartan whir: %w", err)
	}

	return zkHint, nil
}

// nativeWhirVerify replays the full WHIR verification protocol, consuming
// transcript messages and hints. Returns the parsed Merkle proofs as a ZKHint.
func nativeWhirVerify(arthur *NativeArthur, whirParams WHIRParams, whirConfig WHIRConfig) (ZKHint, error) {
	var allMerklePaths []FullMultiPath[KeccakDigest]
	var allStirAnswers [][][]Fp256

	domainSize := whirParams.DomainSize
	nRounds := whirParams.ParamNRounds

	// --- OOD matrix (initial commitment has CommittmentOODSamples OOD evaluations) ---
	// The initial commitment's OOD entries are already on the transcript from
	// parseBatchedCommitment. The WHIR verifier now reads cross-terms for
	// the evaluation matrix if batch_size > 1.
	// For now we skip cross-term OOD reads (single vector case).

	// --- Geometric challenges: vector_rlc_coeffs ---
	numVectors := whirParams.BatchSize
	if numVectors >= 2 {
		if _, err := arthur.FillChallengeScalars(1); err != nil {
			return ZKHint{}, fmt.Errorf("vector_rlc: %w", err)
		}
	}

	// --- Geometric challenges: constraint_rlc_coeffs ---
	numConstraints := whirParams.CommittmentOODSamples + 0 // + len(linear_forms) handled by caller
	if numConstraints >= 2 {
		if _, err := arthur.FillChallengeScalars(1); err != nil {
			return ZKHint{}, fmt.Errorf("constraint_rlc: %w", err)
		}
	}

	// --- Initial sumcheck ---
	foldingFactor0 := whirParams.FoldingFactorArray[0]
	for range foldingFactor0 {
		// c0, c2 (quadratic sumcheck polynomial)
		if _, err := arthur.FillNextScalars(2); err != nil {
			return ZKHint{}, fmt.Errorf("initial sumcheck coeff: %w", err)
		}
		// Round PoW (if any)
		// Skipped if pow bits == 0
		// folding randomness
		if _, err := arthur.FillChallengeScalars(1); err != nil {
			return ZKHint{}, fmt.Errorf("initial folding: %w", err)
		}
	}

	// --- Main rounds ---
	for r := range nRounds {
		// receive_commitment: root hash
		if _, err := arthur.FillNextScalars(1); err != nil {
			return ZKHint{}, fmt.Errorf("round %d root: %w", r, err)
		}

		// OOD points + answers for this round
		oodSamples := whirParams.RoundParametersOODSamples[r]
		if oodSamples > 0 {
			if _, err := arthur.FillChallengeScalars(oodSamples); err != nil {
				return ZKHint{}, fmt.Errorf("round %d ood points: %w", r, err)
			}
			if _, err := arthur.FillNextScalars(oodSamples); err != nil {
				return ZKHint{}, fmt.Errorf("round %d ood answers: %w", r, err)
			}
		}

		// PoW
		if whirParams.PowBits[r] > 0 {
			if _, err := arthur.FillChallengeBytes(32); err != nil {
				return ZKHint{}, fmt.Errorf("round %d pow challenge: %w", r, err)
			}
			if _, err := arthur.FillNextBytes(8); err != nil {
				return ZKHint{}, fmt.Errorf("round %d pow nonce: %w", r, err)
			}
		}

		// Challenge indices (squeeze bytes → indices)
		foldingFactorPower := 1 << whirParams.FoldingFactorArray[r]
		indices, err := nativeGetStirChallenges(
			arthur,
			whirParams.RoundParametersNumOfQueries[r],
			domainSize,
			foldingFactorPower,
		)
		if err != nil {
			return ZKHint{}, fmt.Errorf("round %d stir challenges: %w", r, err)
		}

		// irs_commit.verify: submatrix + merkle hints
		// Submatrix is ark-serialized Vec<F>
		var submatrix []Fp256
		if err = arthur.ProverHintArk(&submatrix); err != nil {
			return ZKHint{}, fmt.Errorf("round %d submatrix: %w", r, err)
		}
		allStirAnswers = append(allStirAnswers, [][]Fp256{submatrix})

		// Merkle tree hints
		foldedDomainSize := domainSize / foldingFactorPower
		treeHeight := bits.Len(uint(foldedDomainSize)) - 1
		dedupedIndices := make([]int, len(indices))
		copy(dedupedIndices, indices)
		sort.Ints(dedupedIndices)
		dedupedIndices = dedup(dedupedIndices)

		merklePath, err := consumeMerkleHints(arthur, dedupedIndices, treeHeight)
		if err != nil {
			return ZKHint{}, fmt.Errorf("round %d merkle: %w", r, err)
		}
		allMerklePaths = append(allMerklePaths, merklePath)

		// Geometric challenge (combination randomness)
		if _, err := arthur.FillChallengeScalars(1); err != nil {
			return ZKHint{}, fmt.Errorf("round %d comb randomness: %w", r, err)
		}

		// Sumcheck for this round
		ff := whirParams.FoldingFactorArray[r]
		if r+1 < len(whirParams.FoldingFactorArray) {
			ff = whirParams.FoldingFactorArray[r+1]
		}
		for range ff {
			if _, err := arthur.FillNextScalars(2); err != nil {
				return ZKHint{}, fmt.Errorf("round %d sumcheck coeff: %w", r, err)
			}
			if _, err := arthur.FillChallengeScalars(1); err != nil {
				return ZKHint{}, fmt.Errorf("round %d sumcheck folding: %w", r, err)
			}
		}

		domainSize /= 2
	}

	// --- Final round: receive full vector ---
	finalSize := 1 << whirParams.FinalSumcheckRounds
	if _, err := arthur.FillNextScalars(finalSize); err != nil {
		return ZKHint{}, fmt.Errorf("final vector: %w", err)
	}

	// --- Final PoW ---
	if whirParams.FinalPowBits > 0 {
		if _, err := arthur.FillChallengeBytes(32); err != nil {
			return ZKHint{}, fmt.Errorf("final pow challenge: %w", err)
		}
		if _, err := arthur.FillNextBytes(8); err != nil {
			return ZKHint{}, fmt.Errorf("final pow nonce: %w", err)
		}
	}

	// --- Final opening (irs_commit.verify for last round) ---
	finalFoldingFactorPower := 1 << whirParams.FoldingFactorArray[nRounds]
	finalIndices, err := nativeGetStirChallenges(
		arthur,
		whirParams.FinalQueries,
		domainSize,
		finalFoldingFactorPower,
	)
	if err != nil {
		return ZKHint{}, fmt.Errorf("final stir challenges: %w", err)
	}

	var finalSubmatrix []Fp256
	if err = arthur.ProverHintArk(&finalSubmatrix); err != nil {
		return ZKHint{}, fmt.Errorf("final submatrix: %w", err)
	}
	allStirAnswers = append(allStirAnswers, [][]Fp256{finalSubmatrix})

	foldedDomainSize := domainSize / finalFoldingFactorPower
	treeHeight := bits.Len(uint(foldedDomainSize)) - 1
	dedupedFinal := make([]int, len(finalIndices))
	copy(dedupedFinal, finalIndices)
	sort.Ints(dedupedFinal)
	dedupedFinal = dedup(dedupedFinal)

	finalMerklePath, err := consumeMerkleHints(arthur, dedupedFinal, treeHeight)
	if err != nil {
		return ZKHint{}, fmt.Errorf("final merkle: %w", err)
	}
	allMerklePaths = append(allMerklePaths, finalMerklePath)

	// --- Deferred weight evaluations ---
	var deferred []Fp256
	if err = arthur.ProverHintArk(&deferred); err != nil {
		return ZKHint{}, fmt.Errorf("deferred: %w", err)
	}
	log.Printf("Read %d deferred weight evaluations", len(deferred))

	// --- Final sumcheck ---
	for range whirParams.FinalSumcheckRounds {
		if _, err := arthur.FillNextScalars(2); err != nil {
			return ZKHint{}, fmt.Errorf("final sumcheck coeff: %w", err)
		}
		if _, err := arthur.FillChallengeScalars(1); err != nil {
			return ZKHint{}, fmt.Errorf("final sumcheck folding: %w", err)
		}
	}

	// --- Final folding PoW ---
	if whirParams.FinalFoldingPowBits > 0 {
		if _, err := arthur.FillChallengeBytes(32); err != nil {
			return ZKHint{}, fmt.Errorf("final folding pow challenge: %w", err)
		}
		if _, err := arthur.FillNextBytes(8); err != nil {
			return ZKHint{}, fmt.Errorf("final folding pow nonce: %w", err)
		}
	}

	// Build ZKHint from parsed data
	zkHint := consumeWhirData(whirConfig, &allMerklePaths, &allStirAnswers)

	return zkHint, nil
}

// ---------------------------------------------------------------------------
// Key management utilities (unchanged)
// ---------------------------------------------------------------------------

func GetPkAndVkFromPath(pkPath string, vkPath string) (*groth16.ProvingKey, *groth16.VerifyingKey, error) {
	var pk *groth16.ProvingKey
	var vk *groth16.VerifyingKey
	if pkPath != "" && vkPath != "" {
		log.Printf("Loading PK/VK from %s, %s", pkPath, vkPath)
		restoredPk, restoredVk, err := keysFromFiles(pkPath, vkPath)
		if err != nil {
			log.Printf("Failed to load keys from files: %v", err)
			return nil, nil, fmt.Errorf("failed to load keys from files: %w", err)
		}
		pk = &restoredPk
		vk = &restoredVk
		log.Printf("Successfully loaded PK/VK")
	}
	return pk, vk, nil
}

func GetPkAndVkFromUrl(pkUrl string, vkUrl string) (*groth16.ProvingKey, *groth16.VerifyingKey, error) {
	var pk *groth16.ProvingKey
	var vk *groth16.VerifyingKey

	if pkUrl != "" && vkUrl != "" {
		log.Printf("Downloading PK/VK from %s, %s", pkUrl, vkUrl)
		restoredPk, restoredVk, err := keysFromUrl(pkUrl, vkUrl)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load keys from url: %w", err)
		}
		pk = &restoredPk
		vk = &restoredVk
		log.Printf("Successfully downloaded and loaded PK/VK")
	}

	return pk, vk, nil
}

func GetR1csFromUrl(r1csUrl string) ([]byte, error) {
	log.Printf("Downloading R1CS from %s", r1csUrl)
	r1csFile, err := downloadFromUrl(r1csUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to download r1cs file from url: %w", err)
	}
	log.Printf("Successfully downloaded")
	return r1csFile, nil
}

func keysFromFiles(pkPath string, vkPath string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pkFile, err := os.Open(pkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open proving key file: %w", err)
	}
	defer func() {
		if err := pkFile.Close(); err != nil {
			log.Printf("failed to close proving key file: %v", err)
		}
	}()

	pk := groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(pkFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to restore proving key: %w", err)
	}

	vkFile, err := os.Open(vkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open verifying key file: %w", err)
	}
	defer func() {
		if err := vkFile.Close(); err != nil {
			log.Printf("failed to close verifying key file: %v", err)
		}
	}()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to restore verifying key: %w", err)
	}

	return pk, vk, nil
}

func keysFromUrl(pkUrl string, vkUrl string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	vkBytes, err := downloadFromUrl(vkUrl)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to download verifying key: %w", err)
	}
	log.Printf("Downloaded VK")

	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.UnsafeReadFrom(bytes.NewReader(vkBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to deserialize verifying key: %w", err)
	}
	log.Printf("Loaded VK")

	pkBytes, err := downloadFromUrl(pkUrl)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to download proving key: %v", err)
	}
	log.Printf("Downloaded PK")

	pk := groth16.NewProvingKey(ecc.BN254)
	_, err = pk.UnsafeReadFrom(bytes.NewReader(pkBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to deserialize proving key: %w", err)
	}
	log.Printf("Loaded PK")

	return pk, vk, nil
}

func downloadFromUrl(url string) ([]byte, error) {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("failed to download from %s: %w", url, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("Warning: failed to close response body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d when downloading from %s", resp.StatusCode, url)
	}

	buffer := &bytes.Buffer{}
	_, err = io.Copy(buffer, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to copy to buffer: %w", err)
	}

	return buffer.Bytes(), nil
}
