package storage

import (
	"context"
	"strings"
)

// MultiLoader dispatches to file or HTTP loaders based on the source string.
type MultiLoader struct {
	file *FileLoader
	http *HTTPLoader
}

// NewMultiLoader returns a MultiLoader with default strategies.
func NewMultiLoader() *MultiLoader {
	return &MultiLoader{
		file: &FileLoader{},
		http: NewHTTPLoader(),
	}
}

// Load chooses the appropriate loader by inspecting the source prefix.
func (m *MultiLoader) Load(ctx context.Context, source string) ([]byte, error) {
	if isHTTP(source) {
		return m.http.Load(ctx, source)
	}
	return m.file.Load(ctx, source)
}

func isHTTP(source string) bool {
	lower := strings.ToLower(source)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}
