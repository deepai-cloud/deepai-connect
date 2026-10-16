package unified

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
)

func infrastructureAPI(store *coordinator.KubernetesStore) cluster.InfrastructureAPI {
	return func(ctx context.Context, method, path string, data []byte) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(store.BaseURL, "/")+path, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		token := store.Token
		if store.TokenFile != "" {
			data, err := os.ReadFile(store.TokenFile)
			if err != nil {
				return nil, err
			}
			token = strings.TrimSpace(string(data))
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if method == http.MethodPatch {
			req.Header.Set("Content-Type", "application/merge-patch+json")
		}
		response, err := store.Client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("Kubernetes infrastructure API unavailable: %w", err)
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return nil, fmt.Errorf("Kubernetes %s %s: HTTP %d", method, path, response.StatusCode)
		}
		return io.ReadAll(io.LimitReader(response.Body, 4<<20))
	}
}
