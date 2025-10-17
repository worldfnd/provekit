package storage

import "context"

// Loader abstracts the retrieval of binary blobs required by the verifier.
type Loader interface {
	Load(ctx context.Context, source string) ([]byte, error)
}
