package circuit

import (
	"log"
	"math/bits"
	"os"

	"reilabs/whir-verifier-circuit/app/typeConverters"
	"reilabs/whir-verifier-circuit/app/utilities"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

type Circuit struct {
	// Inputs
	WitnessLinearStatementEvaluations       []frontend.Variable
	HidingSpartanLinearStatementEvaluations []frontend.Variable
	LogNumConstraints                       int
	LogNumVariables                         int
	LogANumTerms                            int
	WitnessClaimedEvaluations               []frontend.Variable
	WitnessBlindingEvaluations              []frontend.Variable
	HidingSpartanFirstRound                 Merkle
	HidingSpartanMerkle                     Merkle
	WitnessMerkle                           Merkle
	WitnessFirstRound                       Merkle
	WHIRParamsWitness                       WHIRParams
	WHIRParamsHidingSpartan                 WHIRParams

	MatrixA []MatrixCell
	MatrixB []MatrixCell
	MatrixC []MatrixCell
	// Public Input
	IO         []byte
	Transcript []uints.U8 `gnark:",public"`
}

func log2(n int) int {
	if n <= 0 {
		return 0
	}
	return bits.Len(uint(n)) - 1
}

func verifyCapContainer(api frontend.API, sc *skyscraper.Skyscraper, uapi *uints.BinaryField[uints.U64], capContainer []frontend.Variable, leaves [][]frontend.Variable, leafIndexes []uints.U64, leafSiblingHashes []frontend.Variable, authPaths [][]frontend.Variable) error {
	// api.Println(capContainer)
	// api.Println(len(capContainer))
	if len(capContainer) > 0 {
		for i := ((len(capContainer) / 2) - 1); i > 0; i-- {
			supposedHash := sc.CompressV2(capContainer[2*i], capContainer[2*i+1])
			actualHash := api.Select(api.IsZero(capContainer[2*i]), capContainer[i], supposedHash)
			api.AssertIsEqual(actualHash, capContainer[i])
		}
	}

	capDepth := log2(len(capContainer) / 2)
	// api.Println(capDepth)
	dedupedLUT := logderivlookup.New(api)

	for i := (len(capContainer) / 2); i < len(capContainer); i++ {
		// api.Println(capContainer[i])
		dedupedLUT.Insert(capContainer[i])
	}

	// api.AssertIsEqual(x, searchRes[0])

	numOfLeavesProved := len(leaves)
	// api.Println(numOfLeavesProved)

	for i := range numOfLeavesProved {
		treeHeight := len(authPaths[i]) + 1
		leafIndexBits := api.ToBinary(uapi.ToValue(leafIndexes[i]), treeHeight)

		// api.Println(uapi.ToValue(leafIndexes[i]))
		// api.Println(1 << treeHeight)
		// api.Println(leafIndexBits[treeHeight-capDepth:])
		rootIndex := api.FromBinary(leafIndexBits[treeHeight-capDepth:]...)
		// api.Println(rootIndex)
		searchRes := dedupedLUT.Lookup(rootIndex)
		rootHash := searchRes[0]
		// api.Println(rootHash)

		leafSiblingHash := leafSiblingHashes[i]
		claimedLeafHash := sc.CompressV2(leaves[i][0], leaves[i][1])
		for x := range len(leaves[i]) - 2 {
			claimedLeafHash = sc.CompressV2(claimedLeafHash, leaves[i][x+2])
		}
		dir := leafIndexBits[0]

		xLeftChild := api.Select(dir, leafSiblingHash, claimedLeafHash)
		xRightChild := api.Select(dir, claimedLeafHash, leafSiblingHash)

		currentHash := sc.CompressV2(xLeftChild, xRightChild)
		for level := 1; level < treeHeight-capDepth; level++ {
			indexBit := leafIndexBits[level]

			siblingHash := authPaths[i][level-1]

			dir := api.And(indexBit, 1)
			left := api.Select(dir, siblingHash, currentHash)
			right := api.Select(dir, currentHash, siblingHash)

			currentHash = sc.CompressV2(left, right)
		}
		// api.Println(currentHash)
		api.AssertIsEqual(currentHash, rootHash)
	}
	return nil
}

func (circuit *Circuit) Define(api frontend.API) error {
	sc, arthur, uapi, err := initializeComponents(api, circuit)
	if err != nil {
		return err
	}

	rootHash, batchingRandomness, initialOODQueries, initialOODAnswers, err := parseBatchedCommitment(arthur, circuit.WHIRParamsWitness)
	if err != nil {
		return err
	}

	tRand := make([]frontend.Variable, circuit.LogNumConstraints)
	err = arthur.FillChallengeScalars(tRand)
	if err != nil {
		return err
	}

	spartanSumcheckRand, spartanSumcheckLastValue, err := runZKSumcheck(api, sc, uapi, circuit, arthur, frontend.Variable(0), circuit.LogNumConstraints, 4, circuit.WHIRParamsHidingSpartan)
	if err != nil {
		return err
	}

	whirFoldingRandomness, err := RunZKWhir(api, arthur, uapi, sc, circuit.WitnessMerkle, circuit.WitnessFirstRound, circuit.WHIRParamsWitness, [][]frontend.Variable{circuit.WitnessClaimedEvaluations, circuit.WitnessBlindingEvaluations}, circuit.WitnessLinearStatementEvaluations, batchingRandomness, initialOODQueries, initialOODAnswers, rootHash)
	if err != nil {
		return err
	}

	x := api.Mul(api.Sub(api.Mul(circuit.WitnessClaimedEvaluations[0], circuit.WitnessClaimedEvaluations[1]), circuit.WitnessClaimedEvaluations[2]), calculateEQ(api, spartanSumcheckRand, tRand))
	api.AssertIsEqual(spartanSumcheckLastValue, x)

	matrixExtensionEvals := evaluateR1CSMatrixExtension(api, circuit, spartanSumcheckRand, whirFoldingRandomness)

	for i := 0; i < 3; i++ {
		api.AssertIsEqual(matrixExtensionEvals[i], circuit.WitnessLinearStatementEvaluations[i])
	}

	return nil
}

func verifyCircuit(
	deferred []Fp256, cfg Config, hints Hints, pk *groth16.ProvingKey, vk *groth16.VerifyingKey, outputCcsPath string, claimedEvaluations ClaimedEvaluations, internedR1CS R1CS, interner Interner,
) error {
	transcriptT := make([]uints.U8, len(cfg.Transcript))
	contTranscript := make([]uints.U8, len(cfg.Transcript))

	for i := range cfg.Transcript {
		transcriptT[i] = uints.NewU8(cfg.Transcript[i])
	}

	witnessLinearStatementEvaluations := make([]frontend.Variable, 3)
	hidingSpartanLinearStatementEvaluations := make([]frontend.Variable, 1)
	contWitnessLinearStatementEvaluations := make([]frontend.Variable, 3)
	contHidingSpartanLinearStatementEvaluations := make([]frontend.Variable, 1)

	hidingSpartanLinearStatementEvaluations[0] = typeConverters.LimbsToBigIntMod(deferred[0].Limbs)
	witnessLinearStatementEvaluations[0] = typeConverters.LimbsToBigIntMod(deferred[1].Limbs)
	witnessLinearStatementEvaluations[1] = typeConverters.LimbsToBigIntMod(deferred[2].Limbs)
	witnessLinearStatementEvaluations[2] = typeConverters.LimbsToBigIntMod(deferred[3].Limbs)

	fSums, gSums := parseClaimedEvaluations(claimedEvaluations, true)

	matrixA := make([]MatrixCell, len(internedR1CS.A.Values))
	for i := range len(internedR1CS.A.RowIndices) {
		end := len(internedR1CS.A.Values) - 1
		if i < len(internedR1CS.A.RowIndices)-1 {
			end = int(internedR1CS.A.RowIndices[i+1] - 1)
		}
		for j := int(internedR1CS.A.RowIndices[i]); j <= end; j++ {
			matrixA[j] = MatrixCell{
				row:    i,
				column: int(internedR1CS.A.ColIndices[j]),
				value:  typeConverters.LimbsToBigIntMod(interner.Values[internedR1CS.A.Values[j]].Limbs),
			}
		}
	}

	matrixB := make([]MatrixCell, len(internedR1CS.B.Values))
	for i := range len(internedR1CS.B.RowIndices) {
		end := len(internedR1CS.B.Values) - 1
		if i < len(internedR1CS.B.RowIndices)-1 {
			end = int(internedR1CS.B.RowIndices[i+1] - 1)
		}
		for j := int(internedR1CS.B.RowIndices[i]); j <= end; j++ {
			matrixB[j] = MatrixCell{
				row:    i,
				column: int(internedR1CS.B.ColIndices[j]),
				value:  typeConverters.LimbsToBigIntMod(interner.Values[internedR1CS.B.Values[j]].Limbs),
			}
		}
	}

	matrixC := make([]MatrixCell, len(internedR1CS.C.Values))
	for i := range len(internedR1CS.C.RowIndices) {
		end := len(internedR1CS.C.Values) - 1
		if i < len(internedR1CS.C.RowIndices)-1 {
			end = int(internedR1CS.C.RowIndices[i+1] - 1)
		}
		for j := int(internedR1CS.C.RowIndices[i]); j <= end; j++ {
			matrixC[j] = MatrixCell{
				row:    i,
				column: int(internedR1CS.C.ColIndices[j]),
				value:  typeConverters.LimbsToBigIntMod(interner.Values[internedR1CS.C.Values[j]].Limbs),
			}
		}
	}

	var circuit = Circuit{
		IO:                                      []byte(cfg.IOPattern),
		Transcript:                              contTranscript,
		LogNumConstraints:                       cfg.LogNumConstraints,
		LogNumVariables:                         cfg.LogNumVariables,
		LogANumTerms:                            cfg.LogANumTerms,
		WitnessClaimedEvaluations:               fSums,
		WitnessBlindingEvaluations:              gSums,
		WitnessLinearStatementEvaluations:       contWitnessLinearStatementEvaluations,
		HidingSpartanLinearStatementEvaluations: contHidingSpartanLinearStatementEvaluations,
		HidingSpartanFirstRound:                 newMerkle(hints.spartanHidingHint.firstRoundMerklePaths.path, true),
		HidingSpartanMerkle:                     newMerkle(hints.spartanHidingHint.roundHints, true),
		WitnessMerkle:                           newMerkle(hints.witnessHints.roundHints, true),
		WitnessFirstRound:                       newMerkle(hints.witnessHints.firstRoundMerklePaths.path, true),

		WHIRParamsWitness:       NewWhirParams(cfg.WHIRConfigWitness),
		WHIRParamsHidingSpartan: NewWhirParams(cfg.WHIRConfigHidingSpartan),

		MatrixA: matrixA,
		MatrixB: matrixB,
		MatrixC: matrixC,
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("Failed to compile circuit: %v", err)
	}
	if outputCcsPath != "" {
		ccsFile, err := os.Create(outputCcsPath)
		if err != nil {
			log.Printf("Cannot create ccs file %s: %v", outputCcsPath, err)
		} else {
			_, err = ccs.WriteTo(ccsFile)
			if err != nil {
				log.Printf("Cannot write ccs file %s: %v", outputCcsPath, err)
			}
		}
		log.Printf("ccs written to %s", outputCcsPath)
	}

	if pk == nil || vk == nil {
		log.Printf("PK/VK not provided, generating new keys unsafely. Consider providing keys from an MPC ceremony.")
		unsafePk, unsafeVk, err := groth16.Setup(ccs)
		if err != nil {
			log.Fatalf("Failed to setup groth16: %v", err)
		}
		pk = &unsafePk
		vk = &unsafeVk
	}

	fSums, gSums = parseClaimedEvaluations(claimedEvaluations, false)

	assignment := Circuit{
		IO:                []byte(cfg.IOPattern),
		Transcript:        transcriptT,
		LogNumConstraints: cfg.LogNumConstraints,

		WitnessClaimedEvaluations:               fSums,
		WitnessBlindingEvaluations:              gSums,
		WitnessLinearStatementEvaluations:       witnessLinearStatementEvaluations,
		HidingSpartanLinearStatementEvaluations: hidingSpartanLinearStatementEvaluations,

		HidingSpartanFirstRound: newMerkle(hints.spartanHidingHint.firstRoundMerklePaths.path, false),
		HidingSpartanMerkle:     newMerkle(hints.spartanHidingHint.roundHints, false),
		WitnessMerkle:           newMerkle(hints.witnessHints.roundHints, false),
		WitnessFirstRound:       newMerkle(hints.witnessHints.firstRoundMerklePaths.path, false),

		WHIRParamsWitness:       NewWhirParams(cfg.WHIRConfigWitness),
		WHIRParamsHidingSpartan: NewWhirParams(cfg.WHIRConfigHidingSpartan),

		MatrixA: matrixA,
		MatrixB: matrixB,
		MatrixC: matrixC,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, *pk, witness, backend.WithSolverOptions(solver.WithHints(utilities.IndexOf)))
	err = groth16.Verify(proof, *vk, publicWitness)
	if err != nil {
		log.Printf("Failed to verify proof: %v", err)
		return err
	}
	return nil
}

func parseClaimedEvaluations(claimedEvaluations ClaimedEvaluations, isContainer bool) ([]frontend.Variable, []frontend.Variable) {
	fSums := make([]frontend.Variable, len(claimedEvaluations.FSums))
	gSums := make([]frontend.Variable, len(claimedEvaluations.GSums))

	if !isContainer {
		for i := range claimedEvaluations.FSums {
			fSums[i] = typeConverters.LimbsToBigIntMod(claimedEvaluations.FSums[i].Limbs)
			gSums[i] = typeConverters.LimbsToBigIntMod(claimedEvaluations.GSums[i].Limbs)
		}
	}

	return fSums, gSums
}
