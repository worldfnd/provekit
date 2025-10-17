package storage

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPLoader fetches byte slices over HTTP(S).
type HTTPLoader struct {
	client *http.Client
}

// NewHTTPLoader constructs an HTTPLoader with a sensible default timeout.
func NewHTTPLoader() *HTTPLoader {
	return &HTTPLoader{
		client: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

// Load fetches the contents at the provided URL.
func (h *HTTPLoader) Load(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to construct request: %w", err)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to download %s: %w", url, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("storage: HTTP error %d when downloading %s", resp.StatusCode, url)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to read response body: %w", err)
	}
	return data, nil
}
