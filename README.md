# sample-go-mtls-oauth-client

This is a sample Go OAuth client using mTLS certificates for authentication with Cloudentity’s Authorization Control Plane SAAS. 

## Prerequisites

* Docker
* Golang
* Signed certificate

## To run the sample Oauth client requires two primary tasks:
1. Prepare your Cloudentity SAAS workspace
2. Run the sample oauth client app

### How to configure the Cloudentity SAAS workspace
1. Sign in [Cloudentity](https://authz.cloudentity.io/)
![sign in](https://docs.authorization.cloudentity.com/uploads/tut_auth_login.png)
2. Choose your workspace. This example uses the "mtls-workspace" workspace.
![choose workspace](https://docs.authorization.cloudentity.com/uploads/tut_mtls_select_workspace.png)
3. Go to "Applications" in the left side bar and choose "Create Application". Then choose "Create"
![workspace overview](https://docs.authorization.cloudentity.com/uploads/tut_mtls_create_application.png)
4. Give the new application a name and choose "Server Web Application"
![create new application](https://docs.authorization.cloudentity.com/uploads/tut_mtls_provide_new_app_details.png)
5. Choose the "Scopes" tab and scroll down and toggle "OpenID" to on
![scopes overview](https://docs.authorization.cloudentity.com/uploads/tut_mtls_provide_new_app_scopes.png)
6. Choose the "Oauth" tab and scroll down to "Token Endpoint Authentication Method". Click it and choose "TLS Client Authentication" from the dropdown menu.
7. While still on the "Oauth" tab scroll down and find "Certificate Metadata". Click it to see the menu. Depending on how you want to enter the information from your certificate choose the appropriate selection. If using the included certs in thie repo choose "TLS_CLIENT_AUTH_SAN_DNS". The textfield beneath this entry will given instructions on what to enter. In this example "TLS_CLIENT_AUTH_SAN_DNS" is chosen so "DNS Name SAN entry" appears above the textfield below.
8. In the textfield below "Certificate Metadata" (if you chose "TLS_CLIENT_AUTH_SAN_DNS" it will have the title "DNS Name SAN entry") enter the appropriate value. For the included cert it is "acp".
9. Scroll down and choose "Save Changes"
10. On the right-hand side, choose "Setup a redirect URI for your application". Enter your redirecit URI. For the sample application enter `http://localhost:18888/callback` then click "Save".
11. While here copy the "Client ID". This will be used in the environment variables for running the sample oauth client.
12. On the left navigation menu choose "Settings"
![workspace overview](https://docs.authorization.cloudentity.com/uploads/tut_mtls_create_application.png)
13. Choose the "Authorization" tab.
![settings overview](https://docs.authorization.cloudentity.com/uploads/tut_mtls_select_settings_auth.png)
14. Scroll to the bottom of the "Authorizations" tab and paste in "Trusted client certificates" your rootCA contents. In the example provided it is the contents of `ca.pem`.
![pasting in rootCA](https://docs.authorization.cloudentity.com/uploads/tut_mtls_add_root_ca.png)

Your workspace is now prepare. 

### How to build and run the Go oauth client sample

1. Go to the .env file in the root directory.
2. Enter your Client ID.
3. Enter your .well-known URI
Optionally
4. Replace the certs in /certs and update .env to use your desired certs. 
5. From the root directory of the project run the following to build and run the sample client app
```
make build
```
After successfully starting the application will print the following logs:

```
Login endpoint available at: http://localhost:18888/login
Callback endpoint available at: http://localhost:18888/callback
```

To stop the application run
```
make stop
```

## Documentation

The steps for this example can be found at
[Cloudentity Run Sample MTLS App](https://docs.authorization.cloudentity.com/guides/developer/mtls/?q=mtls#run-sample-application)

An overview of mTLS-based client Authentication can be found
[mTLS-based Client Authentication](https://docs.authorization.cloudentity.com/features/oauth/client_auth/tls_client_auth/?q=mtls)

Authorization Control Plane extensive documentation can be found at [Cloudentity Docs](https://docs.authorization.cloudentity.com/)
