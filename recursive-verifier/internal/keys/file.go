package keys

import (
	"context"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
)

// FileProvider loads Groth16 keys from disk.
type FileProvider struct {
	curve ecc.ID
}

// NewFileProvider constructs a FileProvider for the supplied curve.
func NewFileProvider(curve ecc.ID) *FileProvider {
	return &FileProvider{curve: curve}
}

// LoadProvingKey restores a proving key from the given file path.
func (f *FileProvider) LoadProvingKey(ctx context.Context, path string) (groth16.ProvingKey, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("keys: failed to open proving key file %s: %w", path, err)
	}
	defer func() {
		_ = file.Close()
	}()

	pk := groth16.NewProvingKey(f.curve)
	if _, err := pk.ReadFrom(file); err != nil {
		return nil, fmt.Errorf("keys: failed to decode proving key: %w", err)
	}
	return pk, nil
}

// LoadVerifyingKey restores a verifying key from the given file path.
func (f *FileProvider) LoadVerifyingKey(ctx context.Context, path string) (groth16.VerifyingKey, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("keys: failed to open verifying key file %s: %w", path, err)
	}
	defer func() {
		_ = file.Close()
	}()

	vk := groth16.NewVerifyingKey(f.curve)
	if _, err := vk.ReadFrom(file); err != nil {
		return nil, fmt.Errorf("keys: failed to decode verifying key: %w", err)
	}
	return vk, nil
}

// LoadBoth restores both proving and verifying keys from the supplied paths.
func (f *FileProvider) LoadBoth(ctx context.Context, pkPath, vkPath string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pk, err := f.LoadProvingKey(ctx, pkPath)
	if err != nil {
		return nil, nil, err
	}
	vk, err := f.LoadVerifyingKey(ctx, vkPath)
	if err != nil {
		return nil, nil, err
	}
	return pk, vk, nil
}
