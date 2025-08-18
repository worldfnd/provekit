package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"

	"reilabs/whir-verifier-circuit/app/circuit"

	gnark_nimue "github.com/reilabs/gnark-nimue"
	go_ark_serialize "github.com/reilabs/go-ark-serialize"
)

func main() {
	fiberConfig := fiber.Config{
		// ReadTimeout:   5 * time.Second,
		WriteTimeout: 10 * 60 * time.Second,  // timeout of 10 mins
		BodyLimit:    2 * 1024 * 1024 * 1024, // 2GB limit
		// Prefork:       true,
		// CaseSensitive: true,
		// StrictRouting: true,
		ServerHeader: "Fiber",
		AppName:      "Whir Verifier Server",
	}

	app := fiber.New(fiberConfig)

	corsConfig := cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Content-Length, Authorization, Cookie",
		AllowMethods: "GET, POST, PUT, DELETE, PATCH",
		MaxAge:       12 * 3600,
	}
	app.Use(cors.New(corsConfig))

	api := app.Group("/api")
	v1 := api.Group("/v1")

	v1.Get("/ping", ping)
	v1.Post("/verify", getFileAndVerify)
	v1.Post("/verifybasic2", verifybasic2)

	log.Fatal(app.Listen(":3000"))
}

func ping(c *fiber.Ctx) error {
	return c.SendString("pong")
}

func verifybasic2(c *fiber.Ctx) error {
    outputCcsPath := ""

	vkPath := "keys/basic2_vk.bin"
	pkPath := "keys/basic2_pk.bin"
	
    r1csFile, err := getFile(c, "r1cs")
    if err != nil {
        log.Printf("Failed to get R1CS file: %v", err)
        return c.Status(400).SendString("Failed to get R1CS file")
    }

    configFile, err := getFile(c, "config")
    if err != nil {
        log.Printf("Failed to get config file: %v", err)
        return c.Status(400).SendString("Failed to get config file")
    }

    err = verify(configFile, r1csFile, vkPath, pkPath, outputCcsPath)
    if err != nil {
        log.Printf("Verification failed: %v", err)
        return c.Status(400).SendString("Verification failed")
    }

    return c.SendString("Verification successful")
}

func getFileAndVerify(c *fiber.Ctx) error {
	outputCcsPath := "" // TODO
	
	r1csFile, err := getFile(c, "r1cs")
	if err != nil {
		return err
	}

	configFile, err := getFile(c, "config")
	if err != nil {
		return err
	}

	err = verify(configFile, r1csFile, "", "", outputCcsPath)
	if err != nil {
		return err
	}

	return c.SendString("Verification successful")
}

func verify(configFile []byte, r1csFile []byte, vkPath string, pkPath string, outputCcsPath string) error {
	// outputCcsPath := "" // TODO : Handle returning/saving, what to do with Ccs File

	var config circuit.Config
	if err := json.Unmarshal(configFile, &config); err != nil {
		return fmt.Errorf("failed to unmarshal config JSON: %w", err)
	}

	io := gnark_nimue.IOPattern{}
	err := io.Parse([]byte(config.IOPattern))
	if err != nil {
		return fmt.Errorf("failed to parse IO pattern: %w", err)
	}

	var pointer uint64
	var truncated []byte

	var merklePaths []circuit.MultiPath[circuit.KeccakDigest]
	var stirAnswers [][][]circuit.Fp256
	var deferred []circuit.Fp256
	var claimedEvaluations []circuit.Fp256

	for _, op := range io.Ops {
		switch op.Kind {
		case gnark_nimue.Hint:
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
				var path circuit.MultiPath[circuit.KeccakDigest]
				_, err = go_ark_serialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&path,
					false, false,
				)
				merklePaths = append(merklePaths, path)
			case "stir_answers":
				var stirAnswersTemporary [][]circuit.Fp256
				_, err = go_ark_serialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&stirAnswersTemporary,
					false, false,
				)
				stirAnswers = append(stirAnswers, stirAnswersTemporary)
			case "deferred_weight_evaluations":
				var deferredTemporary []circuit.Fp256
				_, err = go_ark_serialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&deferredTemporary,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize deferred hint: %w", err)
				}
				deferred = append(deferred, deferredTemporary...)
			case "claimed_evaluations":
				_, err = go_ark_serialize.CanonicalDeserializeWithMode(
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

		case gnark_nimue.Absorb:
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

	var r1cs circuit.R1CS
	if err = json.Unmarshal(r1csFile, &r1cs); err != nil {
		return fmt.Errorf("failed to unmarshal r1cs JSON: %w", err)
	}

	internerBytes, err := hex.DecodeString(r1cs.Interner.Values)
	if err != nil {
		return fmt.Errorf("failed to decode interner values: %w", err)
	}

	var interner circuit.Interner
	_, err = go_ark_serialize.CanonicalDeserializeWithMode(
		bytes.NewReader(internerBytes), &interner, false, false,
	)
	if err != nil {
		return fmt.Errorf("failed to deserialize interner: %w", err)
	}

	var pk *groth16.ProvingKey
	var vk *groth16.VerifyingKey
	if pkPath != "" && vkPath != "" {
		log.Printf("Loading PK/VK from %s, %s", pkPath, vkPath)
		restoredPk, restoredVk, err := circuit.KeysFromFiles(pkPath, vkPath)
		if err != nil {
			return err
		}
		pk = &restoredPk
		vk = &restoredVk
		log.Printf("Successfully loaded PK/VK")
	}

	spartanEnd := config.WHIRConfigCol.NRounds + 1

	hints := circuit.Hints{
		ColHints: circuit.Hint{
			MerklePaths: merklePaths[:spartanEnd],
			StirAnswers: stirAnswers[:spartanEnd],
		},
	}

	err = circuit.VerifyCircuit(deferred, config, hints, pk, vk, outputCcsPath, claimedEvaluations, r1cs, interner)
	if err != nil {
		return fmt.Errorf("failed to verify circuit: %w", err)
	}

	return nil
}

func getFile(c *fiber.Ctx, name string) ([]byte, error) {

	fileHeader, err := c.FormFile(name)
	if err != nil {
		return nil, fmt.Errorf("no %s file provided: %w", name, err)
	}

	f, err := fileHeader.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open %s file: %w", name, err)
	}
	defer func() {
		err := f.Close()
		if err != nil {
			log.Printf("failed to close %s file: %v", name, err)
		}
	}()

	file, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s file: %w", name, err)
	}

	return file, nil
}