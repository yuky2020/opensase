JAVA_HOME ?= $(HOME)/opt/jdk21
ANDROID_HOME ?= $(HOME)/Android/Sdk
ANDROID_NDK_HOME ?= $(ANDROID_HOME)/ndk/28.2.13676358
GOMOBILE ?= $(HOME)/go/bin/gomobile
FLUTTER ?= $(shell command -v flutter 2>/dev/null || echo $(HOME)/opt/flutter/bin/flutter)
AAR := clients/mobile/android/app/libs/opensase-core.aar

.PHONY: test vet lint aar apk app-test portal portal-test bins dev-up dev-down e2e fmt sectest sectest-unit docs docs-serve

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run

aar:
	mkdir -p $(dir $(AAR))
	env JAVA_HOME=$(JAVA_HOME) ANDROID_HOME=$(ANDROID_HOME) ANDROID_NDK_HOME=$(ANDROID_NDK_HOME) \
		$(GOMOBILE) bind -target=android/arm64,android/amd64 -androidapi 29 -javapkg eu.opensase.core -o $(AAR) ./mobile

apk: aar
	cd clients/mobile && env JAVA_HOME=$(JAVA_HOME) ANDROID_HOME=$(ANDROID_HOME) $(FLUTTER) build apk --debug

app-test:
	cd clients/mobile && $(FLUTTER) analyze && $(FLUTTER) test

# Admin portal (Flutter web), served by the Control Plane at /admin/ (-portal-dir clients/admin/build/web).
# --no-web-resources-cdn bundles CanvasKit so the portal does not load code from a CDN.
portal:
	cd clients/admin && $(FLUTTER) pub get && $(FLUTTER) build web --release --base-href /admin/ --no-web-resources-cdn

portal-test:
	cd clients/admin && $(FLUTTER) analyze && $(FLUTTER) test

bins:
	go build -o bin/ ./cmd/...

dev-up:
	cd deploy/dev && docker compose up -d --build

dev-down:
	cd deploy/dev && docker compose down

e2e:
	deploy/dev/e2e.sh

# Security suite (test/security/README.md). sectest: black box + Go checks against the
# running dev stack (deploy/dev/bootstrap.sh); SECTEST_DESTRUCTIVE=1 adds floods.
# sectest-unit: the Go checks that need no stack.
sectest:
	test/security/run.sh

sectest-unit:
	go test -count=1 -race -v -run '^TestUnit' ./test/security/go/

# Documentation site (GitHub Pages, mkdocs.yml). Needs: pip install -r docs/requirements.txt
docs:
	scripts/docs-prepare.sh
	NO_MKDOCS_2_WARNING=1 mkdocs build --strict

docs-serve:
	scripts/docs-prepare.sh
	NO_MKDOCS_2_WARNING=1 mkdocs serve

fmt:
	gofmt -w pkg cmd internal mobile
