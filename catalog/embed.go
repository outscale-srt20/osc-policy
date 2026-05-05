package catalog

import (
	"embed"
	_ "embed"
)

//go:embed prices.yaml
var PricesYAML []byte

//go:embed frameworks/*.yaml
var FrameworksFS embed.FS
