package whir

import (
	"math/big"

	"github.com/consensys/gnark/frontend"

	"reilabs/whir-verifier-circuit/pkg/verifier/types"
)

// NewParams creates WHIR parameters derived from the provided configuration.
func NewParams(cfg types.WHIRConfig) types.WHIRParams {
	startingDomainGen, _ := new(big.Int).SetString(cfg.DomainGenerator, 10)
	mvParamsNumberOfVariables := cfg.NVars

	foldingFactor := make([]int, len(cfg.FoldingFactor))
	copy(foldingFactor, cfg.FoldingFactor)

	var finalSumcheckRounds int
	if len(foldingFactor) > 1 {
		foldingFactor = append(foldingFactor, foldingFactor[len(foldingFactor)-1])
		finalSumcheckRounds = mvParamsNumberOfVariables % foldingFactor[len(foldingFactor)-1]
	} else {
		foldingFactor = []int{4}
		finalSumcheckRounds = mvParamsNumberOfVariables % 4
	}

	domainSize := (2 << mvParamsNumberOfVariables) * (1 << cfg.Rate) / 2

	return types.WHIRParams{
		ParamNRounds:                         cfg.NRounds,
		FoldingFactorArray:                   foldingFactor,
		RoundParametersOODSamples:            cfg.OODSamples,
		RoundParametersNumOfQueries:          cfg.NumQueries,
		PowBits:                              cfg.PowBits,
		FinalQueries:                         cfg.FinalQueries,
		FinalPowBits:                         cfg.FinalPowBits,
		FinalFoldingPowBits:                  cfg.FinalFoldingPowBits,
		StartingDomainBackingDomainGenerator: frontend.Variable(startingDomainGen),
		DomainSize:                           domainSize,
		CommittmentOODSamples:                1,
		FinalSumcheckRounds:                  finalSumcheckRounds,
		MVParamsNumberOfVariables:            mvParamsNumberOfVariables,
		BatchSize:                            cfg.BatchSize,
	}
}
