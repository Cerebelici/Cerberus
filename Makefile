.PHONY: build-headless build-desktop build-helper-macos setcap-nmap lint

build-headless:
	CGO_ENABLED=0 go build -o bin/sentinel ./cmd/sentinel

build-desktop:
	cd desktop && wails build -tags webkit2_41 -platform linux/amd64

build-helper-macos:
	./scripts/build_helper_macos.sh

setcap-nmap:
	@NMAP_PATH=$$(command -v nmap 2>/dev/null); \
	if [ -n "$$NMAP_PATH" ]; then \
		echo "Applying capabilities to $$NMAP_PATH..."; \
		sudo setcap cap_net_raw,cap_net_admin+eip "$$NMAP_PATH"; \
	else \
		echo "nmap binary not found in PATH"; \
		exit 1; \
	fi

lint:
	go vet ./...
