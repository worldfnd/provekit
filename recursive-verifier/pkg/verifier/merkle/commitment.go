package merkle

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"

	"reilabs/whir-verifier-circuit/pkg/crypto/polynomial"
	"reilabs/whir-verifier-circuit/pkg/encoding/typeconv"
	"reilabs/whir-verifier-circuit/pkg/verifier/types"
)

// New builds a merkle witness from the supplied transcript hints.
func New(hint types.Hint, isContainer bool) types.Merkle {
	totalAuthPath := make([][][]frontend.Variable, len(hint.MerklePaths))
	totalLeaves := make([][][]frontend.Variable, len(hint.MerklePaths))
	totalLeafSiblingHashes := make([][]frontend.Variable, len(hint.MerklePaths))
	totalLeafIndexes := make([][]uints.U64, len(hint.MerklePaths))

	for i, merklePath := range hint.MerklePaths {
		numLeaves := len(merklePath.Proofs)
		treeHeight := len(merklePath.Proofs[0].AuthPath)

		totalAuthPath[i] = make([][]frontend.Variable, numLeaves)
		totalLeaves[i] = make([][]frontend.Variable, numLeaves)
		totalLeafSiblingHashes[i] = make([]frontend.Variable, numLeaves)
		totalLeafIndexes[i] = make([]uints.U64, numLeaves)

		for j := 0; j < numLeaves; j++ {
			totalAuthPath[i][j] = make([]frontend.Variable, treeHeight)
			totalLeaves[i][j] = make([]frontend.Variable, len(hint.StirAnswers[i][j]))
		}

		if isContainer {
			continue
		}

		for j := 0; j < numLeaves; j++ {
			proof := merklePath.Proofs[j]
			for z := 0; z < treeHeight; z++ {
				totalAuthPath[i][j][z] = typeconv.LittleEndianUint8ToBigInt(proof.AuthPath[treeHeight-1-z].KeccakDigest[:])
			}

			totalLeafSiblingHashes[i][j] = typeconv.LittleEndianUint8ToBigInt(proof.LeafSiblingHash.KeccakDigest[:])
			totalLeafIndexes[i][j] = uints.NewU64(proof.LeafIndex)

			for k := range hint.StirAnswers[i][j] {
				totalLeaves[i][j][k] = typeconv.LimbsToBigIntMod(hint.StirAnswers[i][j][k].Limbs)
			}
		}
	}

	return types.Merkle{
		Leaves:            totalLeaves,
		LeafIndexes:       totalLeafIndexes,
		LeafSiblingHashes: totalLeafSiblingHashes,
		AuthPaths:         totalAuthPath,
	}
}

// OODAnswers collapses batched answers using the provided randomness.
func OODAnswers(api frontend.API, answers [][]frontend.Variable, randomness frontend.Variable) []frontend.Variable {
	if len(answers) == 0 {
		return nil
	}

	result := make([]frontend.Variable, len(answers[0]))
	copy(result, answers[0])

	multiplier := frontend.Variable(1)
	for i := 1; i < len(answers); i++ {
		multiplier = api.Mul(multiplier, randomness)
		for j := range answers[i] {
			term := api.Mul(answers[i][j], multiplier)
			result[j] = api.Add(result[j], term)
		}
	}

	return result
}

// InitialSumcheck prepares the initial sumcheck state and returns the updated
// evaluation as well as the folding randomness.
func InitialSumcheck(
	api frontend.API,
	arthur gnarkNimue.Arthur,
	batchingRandomness frontend.Variable,
	initialOODQueries []frontend.Variable,
	initialOODAnswers []frontend.Variable,
	whirParams types.WHIRParams,
	linearStatementEvaluations [][]frontend.Variable,
	evaluationStatementClaimedValues [][]frontend.Variable,
) (types.InitialSumcheckData, frontend.Variable, []frontend.Variable, error) {
	linearLen := len(linearStatementEvaluations[0])
	evaluationLen := len(evaluationStatementClaimedValues[0])

	initialCombinationRandomness, err := GenerateCombinationRandomness(api, arthur, len(initialOODAnswers)+linearLen+evaluationLen)
	if err != nil {
		return types.InitialSumcheckData{}, 0, nil, err
	}

	combinedLinear := make([]frontend.Variable, linearLen)
	for idx := 0; idx < linearLen; idx++ {
		sum := frontend.Variable(0)
		mult := frontend.Variable(1)
		for j := range linearStatementEvaluations {
			sum = api.Add(sum, api.Mul(linearStatementEvaluations[j][idx], mult))
			mult = api.Mul(mult, batchingRandomness)
		}
		combinedLinear[idx] = sum
	}

	combinedEvaluations := make([]frontend.Variable, evaluationLen)
	for idx := 0; idx < evaluationLen; idx++ {
		sum := frontend.Variable(0)
		mult := frontend.Variable(1)
		for j := range evaluationStatementClaimedValues {
			sum = api.Add(sum, api.Mul(evaluationStatementClaimedValues[j][idx], mult))
			mult = api.Mul(mult, batchingRandomness)
		}
		combinedEvaluations[idx] = sum
	}

	oodAndStatements := append(append(initialOODAnswers, combinedLinear...), combinedEvaluations...)
	lastEval := polynomial.DotProduct(api, initialCombinationRandomness, oodAndStatements)

	initialFoldingRandomness, lastEval, err := RunWhirSumcheckRounds(api, lastEval, arthur, whirParams.FoldingFactorArray[0], 3)
	if err != nil {
		return types.InitialSumcheckData{}, 0, nil, err
	}

	return types.InitialSumcheckData{
		InitialOODQueries:            initialOODQueries,
		InitialCombinationRandomness: initialCombinationRandomness,
	}, lastEval, initialFoldingRandomness, nil
}

// ParseCommitment reads a Merkle commitment from the transcript.
func ParseCommitment(arthur gnarkNimue.Arthur, whirParams types.WHIRParams) (types.Commitment, error) {
	rootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(rootHash); err != nil {
		return types.Commitment{}, err
	}

	oodPoints := make([]frontend.Variable, 1)
	if err := arthur.FillChallengeScalars(oodPoints); err != nil {
		return types.Commitment{}, err
	}

	oodAnswers := make([][]frontend.Variable, whirParams.BatchSize)
	for i := 0; i < whirParams.BatchSize; i++ {
		oodAnswer := make([]frontend.Variable, 1)
		if err := arthur.FillNextScalars(oodAnswer); err != nil {
			return types.Commitment{}, err
		}
		oodAnswers[i] = oodAnswer
	}

	batchingRandomness := frontend.Variable(0)
	if whirParams.BatchSize > 1 {
		rand := make([]frontend.Variable, 1)
		if err := arthur.FillChallengeScalars(rand); err != nil {
			return types.Commitment{}, err
		}
		batchingRandomness = rand[0]
	}

	return types.Commitment{
		RootHash:           rootHash[0],
		BatchingRandomness: batchingRandomness,
		InitialOODQueries:  oodPoints,
		InitialOODAnswers:  oodAnswers,
	}, nil
}

// GenerateFinalCoefficientsAndRandomnessPoints extracts the final-round
// coefficients and evaluation points from the transcript.
func GenerateFinalCoefficientsAndRandomnessPoints(
	api frontend.API,
	arthur gnarkNimue.Arthur,
	whirParams types.WHIRParams,
	circuit types.Merkle,
	uapi *uints.BinaryField[uints.U64],
	sc *skyscraper.Skyscraper,
	domainSize int,
	expDomainGenerator frontend.Variable,
) ([]frontend.Variable, []frontend.Variable, error) {
	finalCoefficients := make([]frontend.Variable, 1<<whirParams.FinalSumcheckRounds)
	if err := arthur.FillNextScalars(finalCoefficients); err != nil {
		return nil, nil, err
	}

	if err := RunPoW(api, sc, arthur, whirParams.FinalPowBits); err != nil {
		return nil, nil, err
	}

	finalRandomnessPoints, err := GenerateStirChallengePoints(
		api,
		arthur,
		whirParams.FinalQueries,
		circuit.LeafIndexes[len(circuit.LeafIndexes)-1],
		domainSize,
		uapi,
		expDomainGenerator,
		whirParams.FoldingFactorArray[len(whirParams.FoldingFactorArray)-1],
	)
	if err != nil {
		return nil, nil, err
	}

	return finalCoefficients, finalRandomnessPoints, nil
}

// RLCBatchedLeaves collapses a batched leaf using the supplied randomness.
func RLCBatchedLeaves(api frontend.API, leaves [][]frontend.Variable, foldSize int, batchSize int, base frontend.Variable) [][]frontend.Variable {
	collapsed := make([][]frontend.Variable, len(leaves))
	for i := range leaves {
		collapsed[i] = make([]frontend.Variable, foldSize)
		for j := 0; j < foldSize; j++ {
			sum := frontend.Variable(0)
			mult := frontend.Variable(1)
			for b := 0; b < batchSize; b++ {
				idx := b*foldSize + j
				sum = api.Add(sum, api.Mul(mult, leaves[i][idx]))
				mult = api.Mul(mult, base)
			}
			collapsed[i][j] = sum
		}
	}
	return collapsed
}

func GenerateCombinationRandomness(api frontend.API, arthur gnarkNimue.Arthur, length int) ([]frontend.Variable, error) {
	gen := make([]frontend.Variable, 1)
	if err := arthur.FillChallengeScalars(gen); err != nil {
		return nil, err
	}
	return polynomial.ExpandRandomness(api, gen[0], length), nil
}

// RunPoW executes a proof-of-work challenge with the provided difficulty.
func RunPoW(api frontend.API, sc *skyscraper.Skyscraper, arthur gnarkNimue.Arthur, difficulty int) error {
	if difficulty <= 0 {
		return nil
	}

	challenge := make([]uints.U8, 32)
	if err := arthur.FillChallengeBytes(challenge); err != nil {
		return err
	}

	nonce := make([]uints.U8, 8)
	if err := arthur.FillNextBytes(nonce); err != nil {
		return err
	}

	challengeElt := typeconv.LittleEndianFromUints(api, challenge)
	nonceElt := typeconv.BigEndianFromUints(api, nonce)

	return checkPoW(api, sc, challengeElt, nonceElt, difficulty)
}

// GenerateStirChallengePoints produces stir challenge points consistent with the transcript.
func GenerateStirChallengePoints(
	api frontend.API,
	arthur gnarkNimue.Arthur,
	queries int,
	leafIndexes []uints.U64,
	domainSize int,
	uapi *uints.BinaryField[uints.U64],
	expDomainGenerator frontend.Variable,
	foldingFactor int,
) ([]frontend.Variable, error) {
	foldingPower := 1 << foldingFactor
	indexes, err := getStirChallenges(api, arthur, queries, domainSize, foldingPower)
	if err != nil {
		return nil, err
	}

	if err = assertIndexesEqual(api, uapi, indexes, leafIndexes); err != nil {
		return nil, err
	}

	points := make([]frontend.Variable, len(leafIndexes))
	for i := range leafIndexes {
		points[i] = exponent(api, uapi, expDomainGenerator, leafIndexes[i])
	}

	return points, nil
}

// RunWhirSumcheckRounds executes the quadratic sumcheck rounds used throughout WHIR.
func RunWhirSumcheckRounds(
	api frontend.API,
	lastEval frontend.Variable,
	arthur gnarkNimue.Arthur,
	foldingFactor int,
	polynomialDegree int,
) ([]frontend.Variable, frontend.Variable, error) {
	sumcheckPolynomial := make([]frontend.Variable, polynomialDegree)
	foldingRandomness := make([]frontend.Variable, foldingFactor)
	temp := make([]frontend.Variable, 1)

	for i := 0; i < foldingFactor; i++ {
		if err := arthur.FillNextScalars(sumcheckPolynomial); err != nil {
			return nil, 0, err
		}
		if err := arthur.FillChallengeScalars(temp); err != nil {
			return nil, 0, err
		}
		foldingRandomness[i] = temp[0]
		checkSumOverBool(api, lastEval, sumcheckPolynomial)
		lastEval = polynomial.EvaluateQuadraticFromEvaluations(api, sumcheckPolynomial, foldingRandomness[i])
	}

	return foldingRandomness, lastEval, nil
}

func getStirChallenges(api frontend.API, arthur gnarkNimue.Arthur, numQueries int, domainSize int, foldingFactorPower int) ([]frontend.Variable, error) {
	foldedDomainSize := domainSize / foldingFactorPower
	domainSizeBytes := (bits.Len(uint(foldedDomainSize*2-1)) - 1 + 7) / 8

	stirQueries := make([]uints.U8, domainSizeBytes*numQueries)
	if err := arthur.FillChallengeBytes(stirQueries); err != nil {
		return nil, err
	}

	bitLength := bits.Len(uint(foldedDomainSize)) - 1
	indexes := make([]frontend.Variable, numQueries)
	for i := 0; i < numQueries; i++ {
		value := frontend.Variable(0)
		for j := 0; j < domainSizeBytes; j++ {
			value = api.Add(stirQueries[j+i*domainSizeBytes].Val, api.Mul(value, 256))
		}
		bitsOfValue := api.ToBinary(value)
		indexes[i] = api.FromBinary(bitsOfValue[:bitLength]...)
	}

	return indexes, nil
}

func assertIndexesEqual(api frontend.API, uapi *uints.BinaryField[uints.U64], indexes []frontend.Variable, merkleIndexes []uints.U64) error {
	if len(indexes) != len(merkleIndexes) {
		return fmt.Errorf("indexes length mismatch")
	}

	for i := range indexes {
		api.AssertIsEqual(indexes[i], uapi.ToValue(merkleIndexes[i]))
	}
	return nil
}

func exponent(api frontend.API, uapi *uints.BinaryField[uints.U64], base frontend.Variable, exp uints.U64) frontend.Variable {
	result := frontend.Variable(1)
	binary := api.ToBinary(uapi.ToValue(exp))
	acc := base
	for i := range binary {
		result = api.Select(binary[i], api.Mul(result, acc), result)
		acc = api.Mul(acc, acc)
	}
	return result
}

func checkSumOverBool(api frontend.API, value frontend.Variable, polyEvals []frontend.Variable) {
	sum := api.Add(polyEvals[0], polyEvals[1])
	api.AssertIsEqual(value, sum)
}

func checkPoW(api frontend.API, sc *skyscraper.Skyscraper, challenge frontend.Variable, nonce frontend.Variable, difficulty int) error {
	hash := sc.CompressV2(challenge, nonce)

	constants := []*big.Int{
		mustBigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617"),
		mustBigInt("10944121435919637611123202872628637544274182200208017171849102093287904247808"),
		mustBigInt("5472060717959818805561601436314318772137091100104008585924551046643952123904"),
		mustBigInt("2736030358979909402780800718157159386068545550052004292962275523321976061952"),
		mustBigInt("1368015179489954701390400359078579693034272775026002146481137761660988030976"),
		mustBigInt("684007589744977350695200179539289846517136387513001073240568880830494015488"),
		mustBigInt("342003794872488675347600089769644923258568193756500536620284440415247007744"),
		mustBigInt("171001897436244337673800044884822461629284096878250268310142220207623503872"),
		mustBigInt("85500948718122168836900022442411230814642048439125134155071110103811751936"),
		mustBigInt("42750474359061084418450011221205615407321024219562567077535555051905875968"),
		mustBigInt("21375237179530542209225005610602807703660512109781283538767777525952937984"),
		mustBigInt("10687618589765271104612502805301403851830256054890641769383888762976468992"),
		mustBigInt("5343809294882635552306251402650701925915128027445320884691944381488234496"),
		mustBigInt("2671904647441317776153125701325350962957564013722660442345972190744117248"),
		mustBigInt("1335952323720658888076562850662675481478782006861330221172986095372058624"),
		mustBigInt("667976161860329444038281425331337740739391003430665110586493047686029312"),
		mustBigInt("333988080930164722019140712665668870369695501715332555293246523843014656"),
		mustBigInt("166994040465082361009570356332834435184847750857666277646623261921507328"),
		mustBigInt("83497020232541180504785178166417217592423875428833138823311630960753664"),
		mustBigInt("41748510116270590252392589083208608796211937714416569411655815480376832"),
		mustBigInt("20874255058135295126196294541604304398105968857208284705827907740188416"),
		mustBigInt("10437127529067647563098147270802152199052984428604142352913953870094208"),
		mustBigInt("5218563764533823781549073635401076099526492214302071176456976935047104"),
		mustBigInt("2609281882266911890774536817700538049763246107151035588228488467523552"),
		mustBigInt("1304640941133455945387268408850269024881623053575517794114244233761776"),
		mustBigInt("652320470566727972693634204425134512440811526787758897057122116880888"),
		mustBigInt("326160235283363986346817102212567256220405763393879448528561058440444"),
		mustBigInt("163080117641681993173408551106283628110202881696939724264280529220222"),
	}

	if difficulty < 0 || difficulty >= len(constants) {
		return fmt.Errorf("difficulty %d out of range", difficulty)
	}

	api.AssertIsLessOrEqual(hash, constants[difficulty])
	return nil
}

func mustBigInt(value string) *big.Int {
	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		panic("invalid big.Int constant")
	}
	return n
}
