.PHONY: run
run:
	docker-compose up --build

.PHONY: stop
stop:
	docker-compose down