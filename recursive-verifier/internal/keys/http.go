package keys

import (
	"bytes"
	"context"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"

	"reilabs/whir-verifier-circuit/internal/storage"
)

// URLProvider loads Groth16 keys over HTTP.
type URLProvider struct {
	curve  ecc.ID
	loader *storage.HTTPLoader
}

// NewURLProvider constructs a URLProvider with the supplied curve and loader.
func NewURLProvider(curve ecc.ID, loader *storage.HTTPLoader) *URLProvider {
	return &URLProvider{
		curve:  curve,
		loader: loader,
	}
}

// LoadProvingKey downloads and restores a proving key.
func (u *URLProvider) LoadProvingKey(ctx context.Context, url string) (groth16.ProvingKey, error) {
	data, err := u.loader.Load(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("keys: failed to download proving key: %w", err)
	}

	pk := groth16.NewProvingKey(u.curve)
	if _, err := pk.UnsafeReadFrom(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("keys: failed to decode proving key: %w", err)
	}
	return pk, nil
}

// LoadVerifyingKey downloads and restores a verifying key.
func (u *URLProvider) LoadVerifyingKey(ctx context.Context, url string) (groth16.VerifyingKey, error) {
	data, err := u.loader.Load(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("keys: failed to download verifying key: %w", err)
	}

	vk := groth16.NewVerifyingKey(u.curve)
	if _, err := vk.UnsafeReadFrom(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("keys: failed to decode verifying key: %w", err)
	}
	return vk, nil
}

// LoadBoth downloads both proving and verifying keys from the provided URLs.
func (u *URLProvider) LoadBoth(ctx context.Context, pkURL, vkURL string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pk, err := u.LoadProvingKey(ctx, pkURL)
	if err != nil {
		return nil, nil, err
	}
	vk, err := u.LoadVerifyingKey(ctx, vkURL)
	if err != nil {
		return nil, nil, err
	}
	return pk, vk, nil
}
