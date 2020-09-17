# sample-go-mtls-oauth-client

Sample Go OAuth client using mTLS certificates for authentication with Cloudentity’s Authorization Control Plane. In this
example self-signed certificate will be used.

## Prerequisites

* Docker
* Golang
* Signed certificate

## How to build and run

If you do not have Golang installed on your machine you can simply
build it within a Docker container to do that simply execute 
```
make build
```
in a root directory of this project. Once the build is finished just run the 
application 
```
./sample-go-mtls-oauth-client
```

If you have Golang installed you can start the application by running 
```
make run
```

After successful run application will print the following logs:

```
Login endpoint available at: http://localhost:18888/login
Callback endpoint available at: http://localhost:18888/callback
```

URLs will vary depends on your setup.

You can check the usage of the sample-go-mtls-oauth-client app by running 
application with help flag.
```
./sample-go-mtls-oauth-client --help
```

## How to configure the sample app

1. Go to "Applications" and create a new "Server Web Application" in the ACP dashboard and do the following instructions: 
    * Change "Token Endpoint Authentication Method" to "tls_client_auth".
    * Change "Redirect URL" to the value from "Callback endpoint" presented in sample application logs.
    * Copy the "Client ID" value it will be used later.

2. Go to "Settings", "Authorization" and fill "Root CAs" with your certificate.

3. Start sample application:

```
./sample-go-mtls-oauth-client --clientId <Client ID> -key <Path to private key> -cert <Path to certificate> -issuerUrl https://localhost:8443/default/default -port 18888 
```

## Tutorial

Here you can find detailed instructions about mTLS configuration in Cloudentity’s Authorization Control Plane.