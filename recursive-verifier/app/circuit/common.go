package circuit

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math/bits"
	"sort"

	"github.com/consensys/gnark/backend/groth16"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	arkSerialize "github.com/reilabs/go-ark-serialize"
)

type IndexPair struct {
	depth uint64
	index uint64
}

func convertMultiIndexMTProofsToFullMultiPath(
	merklePaths []MultiIndexMerkleTreeProof[Digest],
	stirAnswers [][][]Fp256,
	fullMerklePaths *[]FullMultiPath[Digest],
) {
	for mIndex, mp := range merklePaths {
		depth := mp.Depth
		proofIter := 0

		currentMPAnswers := stirAnswers[mIndex]
		if len(currentMPAnswers) != len(mp.Indices) {
			panic(fmt.Sprintf("mismatched stirAnswers (%d) and indices (%d)", len(currentMPAnswers), len(mp.Indices)))
		}

		leafHashes := make(map[uint64]Digest)
		for i := range mp.Indices {
			leafHashes[mp.Indices[i]] = HashLeafData(currentMPAnswers[i])
		}

		uniqueIndices := make(map[uint64]bool)
		for _, idx := range mp.Indices {
			uniqueIndices[idx] = true
		}

		indices := make([]uint64, 0, len(uniqueIndices))
		for idx := range uniqueIndices {
			indices = append(indices, idx)
		}
		sort.Slice(indices, func(i, j int) bool {
			return indices[i] < indices[j]
		})

		treeElements := make(map[IndexPair]Digest, len(indices))

		cappedDepth := 0
		cappedDepth = bits.Len(uint(len(mp.Indices))) - 1

		if cappedDepth >= int(mp.Depth) {
			cappedDepth = int(mp.Depth) - 1
		}
		capContainer := make([]Digest, 2<<cappedDepth)
		for i := range capContainer {
			capContainer[i] = Digest{Digest: [32]uint8{}}
		}
		for d := depth; d > 0; d-- {
			nextIndices := make([]uint64, 0, len(indices))
			capIndices := make([]uint64, 0, 1<<depth)
			i := 0
			for i < len(indices) {
				idx := indices[i]
				var node Digest
				if d == depth {
					node = leafHashes[idx]
				} else {
					node = treeElements[IndexPair{depth: d, index: idx}]
				}

				if idx%2 == 0 {
					treeElements[IndexPair{depth: d, index: idx}] = node
					if i+1 < len(indices) && indices[i+1] == idx+1 {
						var otherNode Digest
						if d == depth {
							otherNode = leafHashes[idx+1]
						} else {
							otherNode = treeElements[IndexPair{depth: d, index: idx + 1}]
						}
						capIndices = append(capIndices, idx)
						capIndices = append(capIndices, idx+1)
						parentHash := HashTwoDigests(node, otherNode)
						treeElements[IndexPair{depth: d, index: idx + 1}] = otherNode
						treeElements[IndexPair{depth: d - 1, index: idx / 2}] = parentHash
						nextIndices = append(nextIndices, idx/2)
						i += 2
					} else {
						// missing right sibling → from proof
						if proofIter >= len(mp.Proof) {
							panic("insufficient siblings")
						}
						sib := mp.Proof[proofIter]
						capIndices = append(capIndices, idx)
						capIndices = append(capIndices, idx+1)
						treeElements[IndexPair{depth: d, index: idx + 1}] = sib
						treeElements[IndexPair{depth: d - 1, index: idx / 2}] = HashTwoDigests(node, sib)
						proofIter++
						nextIndices = append(nextIndices, idx/2)
						i++
					}
				} else {
					// right child
					if proofIter >= len(mp.Proof) {
						panic("insufficient siblings")
					}
					sib := mp.Proof[proofIter]
					capIndices = append(capIndices, idx-1)
					capIndices = append(capIndices, idx)
					treeElements[IndexPair{depth: d, index: idx - 1}] = sib
					treeElements[IndexPair{depth: d - 1, index: idx / 2}] = HashTwoDigests(sib, node)

					proofIter++
					nextIndices = append(nextIndices, idx/2)
					i++
				}
			}
			if d <= (uint64(cappedDepth)) {
				for j := range capIndices {
					offset := 1 << d
					capContainer[int(offset)+int(capIndices[j])] = treeElements[IndexPair{depth: d, index: uint64(capIndices[j])}]
				}
			}
			indices = nextIndices
		}

		capContainer[1] = treeElements[IndexPair{depth: 0, index: 0}]

		var paths []Path[Digest]
		for _, origIdx := range mp.Indices {
			leafSibling, authPath, err := ExtractAuthPath(treeElements, origIdx, depth)
			if err != nil {
				panic(fmt.Sprintf("failed to extract auth path for index %d: %v", origIdx, err))
			}

			// fmt.Println("authPath length", len(authPath))
			// fmt.Println("cappedDepth", cappedDepth)
			paths = append(paths, Path[Digest]{
				LeafHash:        leafHashes[origIdx],
				LeafIndex:       origIdx,
				LeafSiblingHash: leafSibling,
				AuthPath:        authPath, //[:len(authPath)-cappedDepth],
			})
		}

		*fullMerklePaths = append(*fullMerklePaths, FullMultiPath[Digest]{Proofs: paths, CapContainer: capContainer})
	}
}

func PrepareAndVerifyCircuit(config Config, r1cs R1CS, pk *groth16.ProvingKey, vk *groth16.VerifyingKey, outputCcsPath string) error {
	io := gnarkNimue.IOPattern{}
	err := io.Parse([]byte(config.IOPattern))
	if err != nil {
		return fmt.Errorf("failed to parse IO pattern: %w", err)
	}

	var pointer uint64
	var truncated []byte

	var merklePaths []MultiIndexMerkleTreeProof[Digest]
	var stirAnswers [][][]Fp256
	var deferred []Fp256
	var claimedEvaluations ClaimedEvaluations

	for _, op := range io.Ops {
		switch op.Kind {
		case gnarkNimue.Hint:
			if pointer+4 > uint64(len(config.Transcript)) {
				return fmt.Errorf("insufficient bytes for hint length")
			}
			hintLen := binary.LittleEndian.Uint32(config.Transcript[pointer : pointer+4])
			start := pointer + 4
			end := start + uint64(hintLen)

			if end > uint64(len(config.Transcript)) {
				return fmt.Errorf("insufficient bytes for merkle proof")
			}

			switch string(op.Label) {
			case "merkle_proof":
				var path MultiIndexMerkleTreeProof[Digest]
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&path,
					false, false,
				)
				fmt.Println("path depth", path.Depth)
				fmt.Println("path indices", len(path.Indices))
				merklePaths = append(merklePaths, path)

			case "stir_answers":
				var stirAnswersTemporary [][]Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&stirAnswersTemporary,
					false, false,
				)
				stirAnswers = append(stirAnswers, stirAnswersTemporary)

			case "deferred_weight_evaluations":
				var deferredTemporary []Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&deferredTemporary,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize deferred hint: %w", err)
				}
				deferred = append(deferred, deferredTemporary...)
			case "claimed_evaluations":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&claimedEvaluations,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize claimed_evaluations: %w", err)
				}
			}

			if err != nil {
				return fmt.Errorf("failed to deserialize merkle proof: %w", err)
			}

			pointer = end

		case gnarkNimue.Absorb:
			start := pointer
			if string(op.Label) == "pow-nonce" {
				pointer += op.Size
			} else {
				pointer += op.Size * 32
			}

			if pointer > uint64(len(config.Transcript)) {
				return fmt.Errorf("absorb exceeds transcript length")
			}

			truncated = append(truncated, config.Transcript[start:pointer]...)
		}
	}

	config.Transcript = truncated

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

	var fullMerklePaths []FullMultiPath[Digest]
	convertMultiIndexMTProofsToFullMultiPath(merklePaths, stirAnswers, &fullMerklePaths)
	var hidingSpartanData = consumeWhirData(config.WHIRConfigHidingSpartan, &fullMerklePaths, &stirAnswers)

	var witnessData = consumeWhirData(config.WHIRConfigWitness, &fullMerklePaths, &stirAnswers)

	hints := Hints{
		witnessHints:      witnessData,
		spartanHidingHint: hidingSpartanData,
	}

	err = verifyCircuit(deferred, config, hints, pk, vk, outputCcsPath, claimedEvaluations, r1cs, interner)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	return nil
}

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

func ExtractAuthPath(
	treeElements map[IndexPair]Digest,
	leafIndex uint64,
	depth uint64,
) (leafSiblingHash Digest, authPath []Digest, err error) {
	leafSiblingIdx := leafIndex ^ 1
	leafSibling, ok := treeElements[IndexPair{depth: depth, index: leafSiblingIdx}]
	if !ok {
		return Digest{}, nil, fmt.Errorf("missing leaf sibling at depth=%d, index=%d", depth, leafSiblingIdx)
	}

	authPath = make([]Digest, 0, depth-1)
	currentIdx := leafIndex

	for d := depth - 1; d >= 1; d-- {
		parentIdx := currentIdx / 2
		siblingIdx := parentIdx ^ 1

		sibling, ok := treeElements[IndexPair{depth: d, index: siblingIdx}]
		if !ok {
			return Digest{}, nil, fmt.Errorf("missing sibling at depth=%d, index=%d (parent=%d)", d, siblingIdx, parentIdx)
		}

		authPath = append(authPath, sibling)
		currentIdx = parentIdx
	}

	return leafSibling, authPath, nil
}

func VerifyAuthPath(
	leafHash Digest,
	leafSiblingHash Digest,
	authPath []Digest,
	leafIndex uint64,
	depth uint64,
	expectedRoot Digest,
) error {
	var currentHash Digest
	if leafIndex%2 == 0 {
		currentHash = HashTwoDigests(leafHash, leafSiblingHash)
	} else {
		currentHash = HashTwoDigests(leafSiblingHash, leafHash)
	}

	currentIdx := leafIndex
	for level := 0; level < len(authPath); level++ {
		parentIdx := currentIdx / 2
		sibling := authPath[level]
		if parentIdx%2 == 0 {
			currentHash = HashTwoDigests(currentHash, sibling)
		} else {
			currentHash = HashTwoDigests(sibling, currentHash)
		}
		currentIdx = parentIdx
	}

	if currentHash != expectedRoot {
		return fmt.Errorf("root mismatch: got %x, expected %x", currentHash, expectedRoot)
	}

	return nil
}

func TestExtractAndVerifyAuthPaths(
	treeElements map[IndexPair]Digest,
	leafHashes map[uint64]Digest,
	indices []uint64,
	depth uint64,
) error {
	root, ok := treeElements[IndexPair{depth: 0, index: 0}]
	if !ok {
		return fmt.Errorf("root not found in treeElements")
	}

	for _, idx := range indices {
		leafSibling, authPath, err := ExtractAuthPath(treeElements, idx, depth)
		if err != nil {
			return fmt.Errorf("failed to extract auth path for index %d: %w", idx, err)
		}

		leafHash, ok := leafHashes[idx]
		if !ok {
			return fmt.Errorf("leaf hash not found for index %d", idx)
		}

		err = VerifyAuthPath(leafHash, leafSibling, authPath, idx, depth, root)
		if err != nil {
			return fmt.Errorf("failed to verify auth path for index %d: %w", idx, err)
		}

		fmt.Printf("✓ Index %d: verified successfully (auth path length: %d)\n", idx, len(authPath))
	}

	return nil
}
