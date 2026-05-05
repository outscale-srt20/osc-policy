package collector

import (
	"bytes"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

const (
	retryMax      = 5
	retryBase     = 500 * time.Millisecond
	retryMaxDelay = 30 * time.Second
)

// retryTransport est un http.RoundTripper qui relance automatiquement les
// requêtes sur 429 (Too Many Requests) et 503 (Service Unavailable) avec
// backoff exponentiel + jitter. Il respecte l'en-tête Retry-After si présent.
type retryTransport struct {
	base http.RoundTripper
}

func newRetryTransport() *retryTransport {
	return &retryTransport{base: http.DefaultTransport}
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Mettre le body en mémoire une fois pour pouvoir le rejouer.
	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		body, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("lecture body requête: %w", err)
		}
	}

	var resp *http.Response
	var err error

	for attempt := 0; attempt <= retryMax; attempt++ {
		// Reconstruire la requête avec un body frais à chaque tentative.
		r := req.Clone(req.Context())
		if body != nil {
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}

		resp, err = t.base.RoundTrip(r)
		if err != nil {
			return nil, err
		}

		if !isRetryable(resp.StatusCode) {
			return resp, nil
		}

		// Dernière tentative : on retourne la réponse telle quelle.
		if attempt == retryMax {
			break
		}

		delay := retryDelay(attempt, resp.Header.Get("Retry-After"))
		_ = resp.Body.Close()

		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(delay):
		}
	}

	return resp, nil
}

func isRetryable(code int) bool {
	return code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable
}

// retryDelay calcule la durée à attendre avant la prochaine tentative.
// Si l'en-tête Retry-After est présent et valide, il est prioritaire.
// Sinon : backoff exponentiel (base * 2^attempt) avec jitter ±20 %.
func retryDelay(attempt int, retryAfter string) time.Duration {
	if retryAfter != "" {
		if secs, err := strconv.Atoi(retryAfter); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}

	delay := retryBase * (1 << uint(attempt))
	if delay > retryMaxDelay {
		delay = retryMaxDelay
	}
	// Jitter ±20 % pour éviter le thundering herd.
	jitter := time.Duration(rand.Int64N(int64(delay / 5)))
	return delay + jitter
}
