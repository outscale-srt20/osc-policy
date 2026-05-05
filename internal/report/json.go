package report

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteJSON sérialise le résultat au format JSON indenté.
func WriteJSON(w io.Writer, r ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}
