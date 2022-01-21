.PHONY: build
build:
	docker-compose up --build

.PHONY: run
run:
	docker-compose up

.PHONY: test
test:
   docker run -d -p 18888:18888 oauth-client
