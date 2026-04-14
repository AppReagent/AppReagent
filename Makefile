# this was added by make improve
SHELL := /bin/bash
BUILD_DIR ?= /tmp/area-build

all:
	cmake -B $(BUILD_DIR) && cmake --build $(BUILD_DIR) -j$$(nproc)

test:
	cmake -B $(BUILD_DIR) && cmake --build $(BUILD_DIR) -j$$(nproc) --target area_tests && cd $(BUILD_DIR) && ctest --output-on-failure

debug:
	cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Debug && cmake --build $(BUILD_DIR)
	gdb --args ./area $(ARGS)

watch:
	@set -m; while true; do \
		cmake -B $(BUILD_DIR) 2>&1 | tail -1; \
		cmake --build $(BUILD_DIR) -j$$(nproc) 2>&1; \
		if [ -x ./area ]; then \
			printf '\033[32m[ok]\033[0m\n'; \
			./area; \
		else \
			printf '\033[31m[build failed]\033[0m\n'; \
		fi; \
	done

AGENT ?= claude
IMPROVE_IMAGE := area-improve-$(AGENT)
TASK ?= Read scripts/improve-prompt.md and follow its instructions step by step.

DOCKER_COMMON = --network host \
	-v $(HOME)/.claude:/home/builder/.claude \
	-v $(HOME)/.claude.json:/home/builder/.claude.json \
	-e ANTHROPIC_API_KEY -e OPENAI_API_KEY \
	-e AGENT=$(AGENT) -e TASK="$(TASK)"

improve-build:
	@echo "Building $(AGENT) improve image..."
	@sudo docker build -f Dockerfile.improve -t $(IMPROVE_IMAGE) \
		--build-arg UID=$$(id -u) --build-arg GID=$$(id -g) \
		--build-arg AGENT=$(AGENT) -q .

improve: improve-build
	$(eval RUN_ID := $(shell date +%s)-$(shell head -c4 /dev/urandom | xxd -p))
	@mkdir -p $(CURDIR)/.improve-output/$(RUN_ID)
	@echo "$(TASK)" > $(CURDIR)/.improve-output/$(RUN_ID)/task.txt
	@echo "Run $(RUN_ID) starting..."
	sudo docker run --rm $(DOCKER_COMMON) \
		-v $(CURDIR)/.improve-output/$(RUN_ID):/output \
		-e AGENT_MODE=headless \
		$(IMPROVE_IMAGE)
	@if [ -f $(CURDIR)/.improve-output/$(RUN_ID)/improve.patch ]; then \
		echo ""; \
		echo "Applying patch from .improve-output/$(RUN_ID)/improve.patch ..."; \
		git apply $(CURDIR)/.improve-output/$(RUN_ID)/improve.patch && \
			echo "Patch applied. Rebuilding..." && \
			$(MAKE) all || \
			echo "Patch failed — saved at .improve-output/$(RUN_ID)/improve.patch"; \
	fi

improve-tui: improve-build
	$(eval RUN_ID := $(shell date +%s)-$(shell head -c4 /dev/urandom | xxd -p))
	@mkdir -p $(CURDIR)/.improve-output/$(RUN_ID)
	sudo docker run --rm -it $(DOCKER_COMMON) \
		-v $(CURDIR)/.improve-output/$(RUN_ID):/output \
		-e AGENT_MODE=interactive \
		$(IMPROVE_IMAGE)
	@if [ -f $(CURDIR)/.improve-output/$(RUN_ID)/improve.patch ]; then \
		echo ""; \
		echo "Applying patch from .improve-output/$(RUN_ID)/improve.patch ..."; \
		git apply $(CURDIR)/.improve-output/$(RUN_ID)/improve.patch && \
			echo "Patch applied. Rebuilding..." && \
			$(MAKE) all || \
			echo "Patch failed — saved at .improve-output/$(RUN_ID)/improve.patch"; \
	else \
		echo "No changes."; \
	fi

improve-bg: improve-build
	@CID=$$(sudo docker run -dt $(DOCKER_COMMON) \
		-e AGENT_MODE=interactive \
		--name area-improve-session \
		$(IMPROVE_IMAGE)) && \
	echo "Container: $$CID" && \
	echo "Attach:    sudo docker attach area-improve-session" && \
	echo "Task:      written to /workspace/.task.md inside container"

improve-attach:
	sudo docker attach area-improve-session

lint:
	./scripts/lint-no-comments.sh .
	cpplint --recursive src/ include/
	cppcheck --enable=warning,performance,portability --error-exitcode=1 --suppress=missingIncludeSystem --inline-suppr -j$$(nproc) -I include src/
	./scripts/lint-iwyu.sh

lint-diff:
	@FILES=$$(git diff --name-only --diff-filter=d HEAD -- 'src/*.cpp' 'src/*.h' 'include/*.h' 'include/*.cpp' 2>/dev/null; \
	          git diff --name-only --diff-filter=d --cached -- 'src/*.cpp' 'src/*.h' 'include/*.h' 'include/*.cpp' 2>/dev/null); \
	if [ -z "$$FILES" ]; then echo "No changed source files."; exit 0; fi; \
	echo "Linting $$(echo $$FILES | wc -w) changed files..."; \
	./scripts/lint-no-comments.sh . && \
	echo $$FILES | xargs cpplint && \
	cppcheck --language=c++ --enable=warning,performance,portability --error-exitcode=1 --suppress=missingIncludeSystem --inline-suppr -j$$(nproc) -I include $$FILES && \
	CPPS=$$(echo $$FILES | tr ' ' '\n' | grep '\.cpp$$' || true); \
	if [ -n "$$CPPS" ]; then ./scripts/lint-iwyu.sh $$CPPS; fi

hooks:
	./scripts/setup-hooks.sh

install: all hooks install-systemd

install-systemd:
	ln -sf $(CURDIR)/area /bin/area
	cp $(CURDIR)/area.service /etc/systemd/system/area.service
	systemctl daemon-reload
	systemctl enable area.service

uninstall:
	systemctl disable area.service || true
	rm -f /etc/systemd/system/area.service
	rm -f /bin/area
	systemctl daemon-reload

clean:
	rm -rf $(BUILD_DIR) area area_tests
