.PHONY: build test lint docs docker clean install uninstall

VERSION ?= dev

# Where to install the binary. Defaults to ~/.local/bin (no sudo needed).
# Override with: make install PREFIX=/usr/local/bin
PREFIX ?= $(HOME)/.local/bin

build:
	go build -ldflags="-s -w -X github.com/outscale-srt20/osc-policy/version.Version=$(VERSION)" -o osc-policy .

test:
	go test ./...

lint:
	golangci-lint run

docs: build
	@mkdir -p docs/rules
	./osc-policy docs generate --output-dir docs/rules

docker:
	docker build -t osc-policy:$(VERSION) .

clean:
	rm -f osc-policy

# Install osc-policy into $PREFIX (default ~/.local/bin) and shell completion.
# - Skip completion if shell unsupported.
# - Warn if $PREFIX is not in $PATH.
install: build
	@mkdir -p $(PREFIX)
	@install -m 0755 osc-policy $(PREFIX)/osc-policy
	@echo "✓ osc-policy installé dans $(PREFIX)/osc-policy"
	@case ":$$PATH:" in \
		*":$(PREFIX):"*) ;; \
		*) echo "⚠ $(PREFIX) n'est pas dans \$$PATH. Ajouter à votre ~/.bashrc ou ~/.zshrc :"; \
		   echo "    export PATH=\"$(PREFIX):\$$PATH\"";; \
	esac
	@echo
	@echo "Pour activer la complétion shell :"
	@echo "  bash : osc-policy completion bash | sudo tee /etc/bash_completion.d/osc-policy >/dev/null"
	@echo "  zsh  : osc-policy completion zsh > \"$${fpath[1]}/_osc-policy\""
	@echo "  fish : osc-policy completion fish > ~/.config/fish/completions/osc-policy.fish"
	@echo
	@echo "Premier scan :"
	@echo "  osc-policy init                 # générer .osc-policy.yaml"
	@echo "  osc-policy scan live --severity HIGH"

uninstall:
	@rm -f $(PREFIX)/osc-policy
	@echo "✓ osc-policy désinstallé de $(PREFIX)"
