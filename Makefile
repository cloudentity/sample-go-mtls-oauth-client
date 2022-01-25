#
# See the README.md for instructions how to obtain CLIENT_ID, CLIENT_SECRET and ISSUER_URL.
#
# CLIENT_ID	= default-demo
# CLIENT_SECRET	= n8HF35qzZkmsukHJzzz9LnN8m9Mf97uq

CLIENT_ID	= c7niscs3tlitkp4rubsg
CLIENT_SECRET	= vP-wqzcIowQg1rQrSY_FN_XgumW9MRO6-MqMk6_KFcQ
ISSUER_URL	= https://host.docker.internal:8443/default/default

CERT_PATH	= certs/acp_cert.pem
KEY_PATH	= certs/acp_key.pem
ROOT_CA		= certs/ca.pem

# Do not edit
PORT		= 18888
REDIRECT_HOST	= localhost


fmt:
	go fmt ./...

lint:
	golangci-lint run --disable varnamelen

vet:
	go vet ./...

test:	vet
	go test -test.v -cover -test.run '.' ./...

build:	test
	go build

run:	build
	./sample-go-mtls-oauth-client \
	--clientId=${CLIENT_ID} \
	--clientSecret=${CLIENT_SECRET} \
	--issuerUrl=${ISSUER_URL}
