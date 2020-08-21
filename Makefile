build: ## Builds sample app.
	@docker run --rm -v ${PWD}:/usr/src/myapp -w /usr/src/myapp golang:1.14 go build -v

run: ## Runs main.go on a host machine.
	@go run main.go

help: ## This help message.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'