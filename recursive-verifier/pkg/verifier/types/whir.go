package types

import (
	"github.com/consensys/gnark/frontend"
)

// WHIRConfig describes the on-chain configuration for a WHIR instance.
type WHIRConfig struct {
	NRounds             int    `json:"n_rounds"`
	Rate                int    `json:"rate"`
	NVars               int    `json:"n_vars"`
	FoldingFactor       []int  `json:"folding_factor"`
	OODSamples          []int  `json:"ood_samples"`
	NumQueries          []int  `json:"num_queries"`
	PowBits             []int  `json:"pow_bits"`
	FinalQueries        int    `json:"final_queries"`
	FinalPowBits        int    `json:"final_pow_bits"`
	FinalFoldingPowBits int    `json:"final_folding_pow_bits"`
	DomainGenerator     string `json:"domain_generator"`
	BatchSize           int    `json:"batch_size"`
}

// WHIRParams contains values derived from WHIRConfig used inside the circuit.
type WHIRParams struct {
	ParamNRounds                         int
	FoldingFactorArray                   []int
	RoundParametersOODSamples            []int
	RoundParametersNumOfQueries          []int
	PowBits                              []int
	FinalQueries                         int
	FinalPowBits                         int
	FinalFoldingPowBits                  int
	StartingDomainBackingDomainGenerator frontend.Variable
	DomainSize                           int
	CommittmentOODSamples                int
	FinalSumcheckRounds                  int
	MVParamsNumberOfVariables            int
	BatchSize                            int
}

// InitialSumcheckData records the initial sumcheck state.
type InitialSumcheckData struct {
	InitialOODQueries            []frontend.Variable
	InitialCombinationRandomness []frontend.Variable
}

// MainRoundData stores per-round randomness and evaluation data.
type MainRoundData struct {
	OODPoints             [][]frontend.Variable
	StirChallengesPoints  [][]frontend.Variable
	CombinationRandomness [][]frontend.Variable
}
