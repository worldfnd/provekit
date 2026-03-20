package whir

import (
	"math"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

// BN254 scalar field: MODULUS_BIT_SIZE = 254, extension_degree = 1.
const fieldSizeBits = 254

// ProtocolConfig mirrors the Rust ProtocolParameters struct and holds the
// complete set of protocol inputs from which WHIRParams are derived.
// Field order and cbor tags must exactly match the Rust declaration order,
// since ciborium serializes as a map with keys in declaration order.
type ProtocolConfig struct {
	InitialStatement   bool          `cbor:"initial_statement"`
	StartingLogInvRate uint64        `cbor:"starting_log_inv_rate"`
	FoldingFactor      FoldingFactor `cbor:"folding_factor"`
	SoundnessType      SoundnessType `cbor:"soundness_type"`
	SecurityLevel      uint64        `cbor:"security_level"`
	PowBits            uint64        `cbor:"pow_bits"`
	BatchSize          uint64        `cbor:"batch_size"`
	HashID             engineIDCBOR  `cbor:"hash_id"`
	NumVariables       int           `cbor:"-"` // not part of Rust ProtocolParameters
}

// NewProtocolConfig returns a ProtocolConfig with the standard constant fields
// (InitialStatement, StartingLogInvRate, SecurityLevel, HashID) filled in,
// matching the Rust defaults.
func NewProtocolConfig(batchSize, numVariables int, ff FoldingFactor, st SoundnessType, powBits int) ProtocolConfig {
	return ProtocolConfig{
		InitialStatement:   true,
		StartingLogInvRate: 2,
		SecurityLevel:      128,
		HashID:             engineIDCBOR(poseidon2EngineID),
		BatchSize:          uint64(batchSize),
		NumVariables:       numVariables,
		FoldingFactor:      ff,
		SoundnessType:      st,
		PowBits:            uint64(powBits),
	}
}

// NewParams derives a fully-initialised WHIRParams from the base protocol inputs.
func NewParams(cfg ProtocolConfig) WHIRParams {
	numVariables := cfg.NumVariables
	powBits := int(cfg.PowBits)
	ff := cfg.FoldingFactor
	st := cfg.SoundnessType
	secLevel := int(cfg.SecurityLevel)

	protocolSecurityLevel := secLevel - powBits
	if protocolSecurityLevel < 0 {
		protocolSecurityLevel = 0
	}

	logInvRate := int(cfg.StartingLogInvRate)
	nv := numVariables
	domainSize := 1 << (numVariables + logInvRate)

	numRounds, finalSumcheckRounds := ff.ComputeNumberOfRounds(numVariables)

	logEtaStart := logEta(st, float64(logInvRate))

	// Initial OOD samples
	commitmentOODSamples := 0
	if cfg.InitialStatement {
		commitmentOODSamples = oodSamples(secLevel, st, nv, float64(logInvRate), logEtaStart)
	}

	// Starting folding PoW bits
	var startingFoldingPowBitsF float64
	if cfg.InitialStatement {
		startingFoldingPowBitsF = foldingPowBits(secLevel, st, nv, float64(logInvRate), logEtaStart)
	} else {
		proxGapsError := rbrSoundnessFoldProxGaps(st, nv, float64(logInvRate), logEtaStart) +
			math.Log2(float64(ff.AtRound(0)))
		startingFoldingPowBitsF = math.Max(0, float64(secLevel)-proxGapsError)
	}
	_ = startingFoldingPowBitsF // used only for the initial sumcheck PoW threshold, not stored in WHIRParams

	// Build per-round arrays.
	// The verifier accesses RoundParametersNumOfQueries[0] for the initial
	// commitment even before the round loop, so we always prepend the initial
	// queries count. When numRounds > 0, round 0 uses the same logInvRate so
	// the value is identical and the loop entries start at index 1.
	foldingFactorArray := make([]int, 0, numRounds+1)
	roundOODSamples := make([]int, 0, numRounds)
	roundPowBits := make([]int, 0, numRounds)

	initialQueries := queries(st, protocolSecurityLevel, logInvRate)
	roundNumQueries := []int{initialQueries}

	// Record the initial folding factor
	foldingFactorArray = append(foldingFactorArray, ff.AtRound(0))

	nv -= ff.AtRound(0)

	for round := 0; round < numRounds; round++ {
		nextRate := logInvRate + (ff.AtRound(round) - 1)
		logNextEta := logEta(st, float64(nextRate))

		nq := queries(st, protocolSecurityLevel, logInvRate)
		ood := oodSamples(secLevel, st, nv, float64(nextRate), logNextEta)

		queryError := rbrQueries(st, float64(logInvRate), nq)
		combinationError := rbrSoundnessQueriesCombination(st, nv, float64(nextRate), logNextEta, ood, nq)

		rpb := math.Max(0, float64(secLevel)-math.Min(queryError, combinationError))

		nextFoldingFactor := ff.AtRound(round + 1)
		foldingFactorArray = append(foldingFactorArray, nextFoldingFactor)

		roundOODSamples = append(roundOODSamples, ood)
		// Round 0 queries == initialQueries (same logInvRate), so skip to avoid duplicate.
		if round > 0 {
			roundNumQueries = append(roundNumQueries, nq)
		}
		roundPowBits = append(roundPowBits, int(math.Ceil(rpb)))

		nv -= nextFoldingFactor
		logInvRate = nextRate
		domainSize /= 2
	}

	// Final parameters
	finalQueriesVal := queries(st, protocolSecurityLevel, logInvRate)

	finalPowBitsF := math.Max(0, float64(secLevel)-rbrQueries(st, float64(logInvRate), finalQueriesVal))
	finalFoldingPowBitsF := math.Max(0, float64(secLevel)-float64(fieldSizeBits-1))

	// Compute the domain generator for the starting domain of size 2^(numVariables + startingLogInvRate).
	startingDomainSize := 1 << (numVariables + int(cfg.StartingLogInvRate))
	domainGen := computeDomainGenerator(uint64(startingDomainSize))

	return WHIRParams{
		Config:                               cfg,
		ParamNRounds:                         numRounds,
		FoldingFactorArray:                   foldingFactorArray,
		RoundParametersOODSamples:            roundOODSamples,
		RoundParametersNumOfQueries:          roundNumQueries,
		PowBits:                              roundPowBits,
		FinalQueries:                         finalQueriesVal,
		FinalPowBits:                         int(math.Ceil(finalPowBitsF)),
		FinalFoldingPowBits:                  int(math.Ceil(finalFoldingPowBitsF)),
		StartingDomainBackingDomainGenerator: domainGen,
		DomainSize:                           1 << (numVariables + int(cfg.StartingLogInvRate)),
		CommittmentOODSamples:                commitmentOODSamples,
		FinalSumcheckRounds:                  finalSumcheckRounds,
		MVParamsNumberOfVariables:            numVariables,
		BatchSize:                            int(cfg.BatchSize),
	}
}

// computeDomainGenerator returns the generator of the multiplicative subgroup
// of the BN254 scalar field with the given size (must be a power of 2).
func computeDomainGenerator(domainSize uint64) *fr.Element {
	domain := fft.NewDomain(domainSize)
	gen := new(fr.Element).Set(&domain.Generator)
	return gen
}

// --- Soundness helper functions (mirrors Rust Config methods) ---

func logEta(st SoundnessType, logInvRate float64) float64 {
	switch st {
	case ProvableList:
		return -(0.5*logInvRate + math.Log2(10) + 1.0)
	case UniqueDecoding:
		return 0.0
	case ConjectureList:
		return -(logInvRate + 1.0)
	}
	return 0.0
}

func listSizeBits(st SoundnessType, numVariables int, logInvRate, logEtaVal float64) float64 {
	switch st {
	case ConjectureList:
		return float64(numVariables) + logInvRate - logEtaVal
	case ProvableList:
		logInvSqrtRate := logInvRate / 2.0
		return logInvSqrtRate - (1.0 + logEtaVal)
	case UniqueDecoding:
		return 0.0
	}
	return 0.0
}

func rbrOODSample(st SoundnessType, numVariables int, logInvRate, logEtaVal float64, oodSamplesVal int) float64 {
	lsb := listSizeBits(st, numVariables, logInvRate, logEtaVal)
	errorVal := 2.0*lsb + float64(numVariables*oodSamplesVal)
	return float64(oodSamplesVal*fieldSizeBits) + 1.0 - errorVal
}

func oodSamples(secLevel int, st SoundnessType, numVariables int, logInvRate, logEtaVal float64) int {
	if st == UniqueDecoding {
		return 0
	}
	for s := 1; s < 64; s++ {
		if rbrOODSample(st, numVariables, logInvRate, logEtaVal, s) >= float64(secLevel) {
			return s
		}
	}
	panic("could not find an appropriate number of OOD samples")
}

func rbrSoundnessFoldProxGaps(st SoundnessType, numVariables int, logInvRate, logEtaVal float64) float64 {
	var errorVal float64
	switch st {
	case ConjectureList:
		errorVal = float64(numVariables) + logInvRate - logEtaVal
	case ProvableList:
		errorVal = math.Log2(10) + 3.5*logInvRate + 2.0*float64(numVariables)
	case UniqueDecoding:
		errorVal = float64(numVariables) + logInvRate
	}
	return float64(fieldSizeBits) - errorVal
}

func rbrSoundnessFoldSumcheck(st SoundnessType, numVariables int, logInvRate, logEtaVal float64) float64 {
	ls := listSizeBits(st, numVariables, logInvRate, logEtaVal)
	return float64(fieldSizeBits) - (ls + 1.0)
}

func foldingPowBits(secLevel int, st SoundnessType, numVariables int, logInvRate, logEtaVal float64) float64 {
	proxGaps := rbrSoundnessFoldProxGaps(st, numVariables, logInvRate, logEtaVal)
	sumcheck := rbrSoundnessFoldSumcheck(st, numVariables, logInvRate, logEtaVal)
	errorVal := math.Min(proxGaps, sumcheck)
	return math.Max(0, float64(secLevel)-errorVal)
}

func queries(st SoundnessType, protocolSecLevel int, logInvRate int) int {
	var nq float64
	switch st {
	case UniqueDecoding:
		rate := 1.0 / float64(int(1)<<logInvRate)
		denom := math.Log2(0.5 * (1.0 + rate))
		nq = -float64(protocolSecLevel) / denom
	case ProvableList:
		nq = float64(2*protocolSecLevel) / float64(logInvRate)
	case ConjectureList:
		nq = float64(protocolSecLevel) / float64(logInvRate)
	}
	return int(math.Ceil(nq))
}

func rbrQueries(st SoundnessType, logInvRate float64, numQueries int) float64 {
	nq := float64(numQueries)
	switch st {
	case UniqueDecoding:
		rate := 1.0 / math.Exp2(logInvRate)
		denom := -math.Log2(0.5 * (1.0 + rate))
		return nq * denom
	case ProvableList:
		return nq * 0.5 * logInvRate
	case ConjectureList:
		return nq * logInvRate
	}
	return 0.0
}

func rbrSoundnessQueriesCombination(st SoundnessType, numVariables int, logInvRate, logEtaVal float64, oodSamplesVal, numQueries int) float64 {
	ls := listSizeBits(st, numVariables, logInvRate, logEtaVal)
	logComb := math.Log2(float64(oodSamplesVal + numQueries))
	return float64(fieldSizeBits) - (logComb + ls + 1.0)
}
