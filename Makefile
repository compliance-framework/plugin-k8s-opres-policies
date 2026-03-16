# Check if OPA CLI is installed
OPA := $(shell command -v opa 2> /dev/null)
ifeq ($(OPA),)
$(error "opa CLI not found. Please install it: https://www.openpolicyagent.org/docs/latest/cli/")
endif

##@ Help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\033[1mUsage\033[0m\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Policies
test: ## Test policy files
	@opa test policies/ -v

validate: ## Validate policy files
	@opa check policies/

clean: ## Cleanup build artifacts
	@rm -rf dist/

build: clean ## Build the policy bundle
	@mkdir -p dist/
	@opa build -b policies/ -o dist/bundle.tar.gz
