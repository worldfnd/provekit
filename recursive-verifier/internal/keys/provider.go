package keys

import (
	"context"
	"fmt"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"

	"reilabs/whir-verifier-circuit/internal/storage"
)

// Provider loads proving and verifying keys from a specific source.
type Provider interface {
	LoadProvingKey(ctx context.Context, source string) (groth16.ProvingKey, error)
	LoadVerifyingKey(ctx context.Context, source string) (groth16.VerifyingKey, error)
	LoadBoth(ctx context.Context, pkSource, vkSource string) (groth16.ProvingKey, groth16.VerifyingKey, error)
}

// CompositeProvider multiplexes between file and HTTP providers.
type CompositeProvider struct {
	file Provider
	url  Provider
}

// NewCompositeProvider builds a CompositeProvider for BN254 keys.
func NewCompositeProvider() *CompositeProvider {
	fileProvider := &FileProvider{curve: ecc.BN254}
	urlProvider := &URLProvider{
		curve:  ecc.BN254,
		loader: storage.NewHTTPLoader(),
	}
	return &CompositeProvider{
		file: fileProvider,
		url:  urlProvider,
	}
}

// LoadProvingKey delegates to the appropriate provider based on source.
func (c *CompositeProvider) LoadProvingKey(ctx context.Context, source string) (groth16.ProvingKey, error) {
	return c.provider(source).LoadProvingKey(ctx, source)
}

// LoadVerifyingKey delegates to the appropriate provider based on source.
func (c *CompositeProvider) LoadVerifyingKey(ctx context.Context, source string) (groth16.VerifyingKey, error) {
	return c.provider(source).LoadVerifyingKey(ctx, source)
}

// LoadBoth delegates to the appropriate provider for the supplied sources.
func (c *CompositeProvider) LoadBoth(ctx context.Context, pkSource, vkSource string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	if pkSource == "" || vkSource == "" {
		return nil, nil, fmt.Errorf("keys: both proving and verifying key sources must be provided")
	}

	if isHTTP(pkSource) != isHTTP(vkSource) {
		return nil, nil, fmt.Errorf("keys: proving and verifying key sources must use the same scheme")
	}

	return c.provider(pkSource).LoadBoth(ctx, pkSource, vkSource)
}

func (c *CompositeProvider) provider(source string) Provider {
	if isHTTP(source) {
		return c.url
	}
	return c.file
}

func isHTTP(source string) bool {
	lower := strings.ToLower(source)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}
