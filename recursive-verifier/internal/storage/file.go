package storage

import (
	"context"
	"fmt"
	"os"
)

// FileLoader loads byte slices from the local filesystem.
type FileLoader struct{}

// Load reads the file at the supplied path.
func (f *FileLoader) Load(ctx context.Context, path string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to read file %s: %w", path, err)
	}
	return data, nil
}
