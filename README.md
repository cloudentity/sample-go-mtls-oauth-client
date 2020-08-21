# sample-go-mtls-oauth-client
Sample Go OAuth client using mTLS certificates for authentication.

## Prerequisites

* Docker
* Golang


## How to build and run

If you do not have Golang installed on your machine you can simply
build it within a Docker container to do that simply execute 
```
make build
```
in a root directory of this project. Once build is finished just run the 
application 
```
./sample-go-mtls-oauth-client
```

If you have Golang installed you can start the application by running 
```
make run
```

You can check the usage of the sample-go-mtls-oauth-client app by running 
application with help flag.
```
./sample-go-mtls-oauth-client --help
```