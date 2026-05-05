package policies

import "embed"

//go:embed lib/*.rego security/*.rego finops/*.rego compliance/*.rego
var FS embed.FS
