package whir

import (
	"math/big"
	"math/bits"
	"reilabs/keccacheck/poseidon2"
	"reilabs/keccacheck/transcript"

	"github.com/consensys/gnark/frontend"
)

// initialSumcheck mirrors the Rust WHIR verifier's initial sumcheck phase.
// The sum has already been computed by the caller (theSum). This function
// runs the sumcheck rounds to reduce the claim, and stores the OOD queries
// and RLC coefficients for the final W polynomial verification.
func initialSumcheck(
	api frontend.API,
	v *transcript.Verifier,
	theSum frontend.Variable,
	oodPoints []frontend.Variable,
	oodsRlcCoeffs []frontend.Variable,
	initialFormRlcCoeffs []frontend.Variable,
	whirParams WHIRParams,
) (InitialSumcheckData, frontend.Variable, []frontend.Variable, error) {

	// Run the core Whir sumcheck rounds to reduce the claim.
	// Mirrors Rust: self.initial_sumcheck.verify(verifier_state, &mut the_sum)
	initialSumcheckFoldingRandomness, lastEval, err := runWhirSumcheckRounds(api, theSum, v, whirParams.FoldingFactorArray[0])
	if err != nil {
		return InitialSumcheckData{}, nil, nil, err
	}

	// Store OOD queries and the full constraint RLC coefficients for computeWPoly.
	combinedRlcCoeffs := make([]frontend.Variable, len(oodsRlcCoeffs)+len(initialFormRlcCoeffs))
	copy(combinedRlcCoeffs, oodsRlcCoeffs)
	copy(combinedRlcCoeffs[len(oodsRlcCoeffs):], initialFormRlcCoeffs)

	return InitialSumcheckData{
		InitialOODQueries:            oodPoints,
		InitialCombinationRandomness: combinedRlcCoeffs,
	}, lastEval, initialSumcheckFoldingRandomness, nil
}

// Reads a single commitment covering numVectors vectors from the transcript:
//  1. Read Merkle root hash (prover message)
//  2. Generate outDomainSamples OOD challenge points (verifier messages)
//  3. Read outDomainSamples * numVectors OOD answers flat (prover messages)
func ReceiveCommitment(v *transcript.Verifier, api frontend.API, outDomainSamples int, numVectors int) ParsedCommitment {
	// 1. Read the Merkle Root hash committed by the prover.
	rootHash := v.Read(api)
	// 2. Generate Out-Of-Domain (OOD) query points (challenges) from the transcript.
	oodPoints := v.GenerateVector(api, uint(outDomainSamples))

	// 3. Read the Prover's OOD answers: outDomainSamples * numVectors values, flat.
	oodAnswers := v.ReadVector(api, uint(outDomainSamples*numVectors))

	return ParsedCommitment{
		Root:       rootHash,
		OodPoints:  oodPoints,
		OodAnswers: oodAnswers,
	}
}

// runWhirSumcheckRounds mirrors the Rust WHIR quadratic sumcheck verifier
// (whir/src/protocols/sumcheck.rs Config::verify).
//
// Each round the prover sends two coefficients (c0, c2) of a quadratic
// polynomial P(x) = c0 + c1·x + c2·x². The third coefficient c1 is derived
// from the sum constraint P(0) + P(1) = sum, giving c1 = sum − 2·c0 − c2.
// After squeezing a folding challenge r, the sum is updated to P(r).
func runWhirSumcheckRounds(
	api frontend.API,
	sum frontend.Variable,
	verifier *transcript.Verifier,
	numRounds int,
) ([]frontend.Variable, frontend.Variable, error) {
	foldingRandomness := make([]frontend.Variable, numRounds)

	for i := range numRounds {
		// Receive sumcheck polynomial coefficients c0 and c2
		c0 := verifier.Read(api)
		c2 := verifier.Read(api)

		// Derive c1 from the sum constraint: P(0)+P(1) = sum
		// P(0) = c0, P(1) = c0+c1+c2, so c0 + (c0+c1+c2) = sum → c1 = sum - 2·c0 - c2
		c1 := api.Sub(sum, api.Add(api.Add(c0, c0), c2))

		// Receive the random evaluation point
		foldingRandomness[i] = verifier.Generate(api)

		// Update the sum: sum = P(r) = (c2·r + c1)·r + c0
		r := foldingRandomness[i]
		sum = api.Add(api.Mul(api.Add(api.Mul(c2, r), c1), r), c0)
	}
	return foldingRandomness, sum, nil
}

func getStirChallenges(
	api frontend.API,
	verifier *transcript.Verifier,
	numQueries int,
	domainSize int,
	foldingFactorPower int,
) ([]frontend.Variable, error) {

	foldedDomainSize := domainSize / foldingFactorPower
	bitLength := bits.Len(uint(foldedDomainSize - 1))

	indexes := make([]frontend.Variable, numQueries)

	for i := 0; i < numQueries; i++ {
		challenge := verifier.Generate(api)
		challengeBits := api.ToBinary(challenge)
		indexes[i] = api.FromBinary(challengeBits[:bitLength]...)
	}

	return indexes, nil
}

func generateEmptyMainRoundData(circuit WHIRParams) MainRoundData {
	return MainRoundData{
		OODPoints:             make([][]frontend.Variable, len(circuit.RoundParametersOODSamples)),
		StirChallengesPoints:  make([][]frontend.Variable, len(circuit.RoundParametersOODSamples)),
		CombinationRandomness: make([][]frontend.Variable, len(circuit.RoundParametersOODSamples)),
	}
}

// readLeavesFromHints reads leaf values from the hint stream.
// Corresponds to a single Rust prover_hint_ark(Vec<F>) call that writes
// all leaves (numLeaves × numCols elements) as one length-prefixed block.
func readLeavesFromHints(hr *HintReader, numLeaves, numCols int) [][]frontend.Variable {
	flat := hr.ReadVec(numLeaves * numCols)
	leaves := make([][]frontend.Variable, numLeaves)
	for i := range leaves {
		leaves[i] = flat[i*numCols : (i+1)*numCols]
	}
	return leaves
}

// verifyMerklePaths verifies Merkle membership proofs for a batch of opened leaves.
// Reads treeHeight sibling hashes per leaf from the hint stream via HintReader.
// Each sibling corresponds to a Rust prover_hint(Hash) call (32 raw bytes).
//
// For each leaf:
//  1. Hashes the leaf elements to compute the leaf hash
//  2. Navigates bottom-up using leaf index bits
//  3. Reads sibling hashes from hints at each level
//  4. Asserts the computed root equals rootHash
func verifyMerklePaths(
	api frontend.API,
	hr *HintReader,
	leaves [][]frontend.Variable,
	leafIndexes []frontend.Variable,
	rootHash frontend.Variable,
	treeHeight int,
) {
	for i := range leaves {
		leafIndexBits := api.ToBinary(leafIndexes[i], treeHeight)

		// Hash all leaf elements at once to get the leaf hash.
		// Matches Rust matrix_commit::verify which calls hash_rows on the
		// full row, then passes the result to merkle_tree::verify_naive.
		claimedLeafHash := poseidon2.Compress(api, leaves[i])
		// Walk up the tree, reading one sibling hash from hints per level
		currentHash := claimedLeafHash
		for level := 0; level < treeHeight; level++ {
			siblingHash := hr.ReadHash()
			indexBit := leafIndexBits[level]

			left := api.Select(indexBit, siblingHash, currentHash)
			right := api.Select(indexBit, currentHash, siblingHash)

			currentHash = poseidon2.Compress(api, []frontend.Variable{left, right})
		}

		api.AssertIsEqual(currentHash, rootHash)
	}
}

// ExponentVar computes base^exp using square-and-multiply with a field element exponent.
// numBits determines how many bits of exp to consider.
func ExponentVar(api frontend.API, base frontend.Variable, exp frontend.Variable, numBits int) frontend.Variable {
	expBits := api.ToBinary(exp, numBits)
	output := frontend.Variable(1)
	multiply := base
	for i := range expBits {
		output = api.Select(expBits[i], api.Mul(output, multiply), output)
		multiply = api.Mul(multiply, multiply)
	}
	return output
}

func PoW(api frontend.API, v *transcript.Verifier, difficulty int) (frontend.Variable, frontend.Variable, error) {
	challenge := v.Generate(api)
	nonce := v.Read(api)
	err := CheckPoW(api, challenge, nonce, difficulty)
	if err != nil {
		return nil, nil, err
	}
	return challenge, nonce, nil
}

func CheckPoW(api frontend.API, challenge frontend.Variable, nonce frontend.Variable, difficulty int) error {
	// Assert nonce is a valid 64-bit number
	maxUint64, _ := new(big.Int).SetString("18446744073709551615", 10) // 2^64 - 1
	api.AssertIsLessOrEqual(nonce, maxUint64)

	hash := poseidon2.Compress(api, []frontend.Variable{challenge, nonce})

	d0, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	d1, _ := new(big.Int).SetString("10944121435919637611123202872628637544274182200208017171849102093287904247808", 10)
	d2, _ := new(big.Int).SetString("5472060717959818805561601436314318772137091100104008585924551046643952123904", 10)
	d3, _ := new(big.Int).SetString("2736030358979909402780800718157159386068545550052004292962275523321976061952", 10)
	d4, _ := new(big.Int).SetString("1368015179489954701390400359078579693034272775026002146481137761660988030976", 10)
	d5, _ := new(big.Int).SetString("684007589744977350695200179539289846517136387513001073240568880830494015488", 10)
	d6, _ := new(big.Int).SetString("342003794872488675347600089769644923258568193756500536620284440415247007744", 10)
	d7, _ := new(big.Int).SetString("171001897436244337673800044884822461629284096878250268310142220207623503872", 10)
	d8, _ := new(big.Int).SetString("85500948718122168836900022442411230814642048439125134155071110103811751936", 10)
	d9, _ := new(big.Int).SetString("42750474359061084418450011221205615407321024219562567077535555051905875968", 10)
	d10, _ := new(big.Int).SetString("21375237179530542209225005610602807703660512109781283538767777525952937984", 10)
	d11, _ := new(big.Int).SetString("10687618589765271104612502805301403851830256054890641769383888762976468992", 10)
	d12, _ := new(big.Int).SetString("5343809294882635552306251402650701925915128027445320884691944381488234496", 10)
	d13, _ := new(big.Int).SetString("2671904647441317776153125701325350962957564013722660442345972190744117248", 10)
	d14, _ := new(big.Int).SetString("1335952323720658888076562850662675481478782006861330221172986095372058624", 10)
	d15, _ := new(big.Int).SetString("667976161860329444038281425331337740739391003430665110586493047686029312", 10)
	d16, _ := new(big.Int).SetString("333988080930164722019140712665668870369695501715332555293246523843014656", 10)
	d17, _ := new(big.Int).SetString("166994040465082361009570356332834435184847750857666277646623261921507328", 10)
	d18, _ := new(big.Int).SetString("83497020232541180504785178166417217592423875428833138823311630960753664", 10)
	d19, _ := new(big.Int).SetString("41748510116270590252392589083208608796211937714416569411655815480376832", 10)
	d20, _ := new(big.Int).SetString("20874255058135295126196294541604304398105968857208284705827907740188416", 10)
	d21, _ := new(big.Int).SetString("10437127529067647563098147270802152199052984428604142352913953870094208", 10)
	d22, _ := new(big.Int).SetString("5218563764533823781549073635401076099526492214302071176456976935047104", 10)
	d23, _ := new(big.Int).SetString("2609281882266911890774536817700538049763246107151035588228488467523552", 10)
	d24, _ := new(big.Int).SetString("1304640941133455945387268408850269024881623053575517794114244233761776", 10)
	d25, _ := new(big.Int).SetString("652320470566727972693634204425134512440811526787758897057122116880888", 10)
	d26, _ := new(big.Int).SetString("326160235283363986346817102212567256220405763393879448528561058440444", 10)
	d27, _ := new(big.Int).SetString("163080117641681993173408551106283628110202881696939724264280529220222", 10)

	var arr = [28]*big.Int{d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15, d16, d17, d18, d19, d20, d21, d22, d23, d24, d25, d26, d27}
	api.AssertIsLessOrEqual(hash, arr[difficulty])
	return nil
}
