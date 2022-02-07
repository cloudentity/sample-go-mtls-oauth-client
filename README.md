# sample-go-mtls-OAuth-client

This is a sample Go OAuth client using mTLS certificates for authentication with Cloudentity’s Authorization Control Plane SaaS. Additionally, this example demonstrates 
using the Cloudentity Pyron API Gateway.

## Prerequisites

* Docker
* Golang
* Signed certificate

## To run the sample OAuth client requires two primary tasks and a third, optional, task:
1. [Prepare your Cloudentity SAAS workspace](#configure-cloudentity-saas-workspace)
2. [Run the sample OAuth client app](#build-and-run-the-go-OAuth-client-sample)
3. [Prepare the Pyron Authorizer](#using-pyron-api-gateway)

### Configure Cloudentity SAAS workspace
1. Sign in [Cloudentity](https://authz.cloudentity.io/)
![sign in](https://docs.authorization.cloudentity.com/uploads/tut_auth_login.png)
2. Choose your workspace. This example uses the "mtls-workspace" workspace.
![choose workspace](https://docs.authorization.cloudentity.com/uploads/tut_mtls_select_workspace.png)
3. Go to "Applications" in the left side bar and choose "Create Application". Then choose "Create"
![workspace overview](https://github.com/cloudentity/sample-go-mtls-OAuth-client/blob/feature/aut-5045/img/crea-ap.png?raw=true)
4. Give the new application a name and choose "Server Web Application"
![create new application](https://docs.authorization.cloudentity.com/uploads/tut_mtls_provide_new_app_details.png)
5. Choose the "Scopes" tab and scroll down and toggle "OpenID" to on
![scopes overview](https://docs.authorization.cloudentity.com/uploads/tut_mtls_provide_new_app_scopes.png)
6. Choose the "OAuth" tab and scroll down to "Token Endpoint Authentication Method". Click it and choose "TLS Client Authentication" from the dropdown menu.
7. While still on the "OAuth" tab scroll down and find "Certificate Metadata". Click it to see the menu. Depending on how you want to enter the information from your certificate choose the appropriate selection. If using the included certs in thie repo choose "TLS_CLIENT_AUTH_SAN_DNS". The textfield beneath this entry will given instructions on what to enter. In this example "TLS_CLIENT_AUTH_SAN_DNS" is chosen so "DNS Name SAN entry" appears above the textfield below.
![tls configuration](https://github.com/cloudentity/sample-go-mtls-OAuth-client/blob/feature/aut-5045/img/tls-cl-au.png?raw=true)
8. In the textfield below "Certificate Metadata" (if you chose "TLS_CLIENT_AUTH_SAN_DNS" it will have the title "DNS Name SAN entry") enter the appropriate value. For the included cert it is "acp".
9. Check "Certificate bound access tokens".
10. Scroll down and choose "Save Changes"
11. On the right-hand side, choose "Setup a redirect URI for your application". Enter your redirecit URI. For the sample application enter `http://localhost:18888/callback` then click "Save".
![redirect url location](https://github.com/cloudentity/sample-go-mtls-OAuth-client/blob/feature/aut-5045/img/redi.png?raw=true)
12. While here copy the "Client ID". This will be used in the environment variables for running the sample OAuth client.
13. On the left navigation menu choose "Settings"
![settings overview](https://docs.authorization.cloudentity.com/uploads/tut_mtls_select_settings_auth.png)
14. Choose the "Authorization" tab.
![settings OAuth tab overview](https://github.com/cloudentity/sample-go-mtls-OAuth-client/blob/feature/aut-5045/img/oau-ta.png?raw=true)
15. Scroll to the bottom of the "Authorizations" tab and paste in "Trusted client certificates" your rootCA contents. In the example provided it is the contents of `ca.pem`.
![pasting in rootCA](https://docs.authorization.cloudentity.com/uploads/tut_mtls_add_root_ca.png)

Your workspace is now prepared. 

### Build and run the Go OAuth client sample

1. Go to the .env file in the root directory.
2. Enter your Client ID.
3. Enter your .well-known URI. The .well-known uri can be found at https://your-tenant.mtls.us.authz.cloudentity.io/your-tenant/default/.well-known/openid-configuration where 'your-tenant' should be replaced by your own tenant ID.
4. Optionally: Replace the certs in /certs and update .env to use your desired certs. 
5. From the root directory of the project run the following to build and run the sample client app
```
make run
```
After successfully starting the application you will see the following console logs:

```
Login endpoint available at: http://localhost:18888/login
Callback endpoint available at: http://localhost:18888/callback
```

### Using Pyron API Gateway

1. Sign in [Cloudentity](https://authz.cloudentity.io/)
![sign in](https://docs.authorization.cloudentity.com/uploads/tut_auth_login.png)
2. Choose your workspace. This example uses the "mtls-workspace" workspace.
![choose workspace](https://docs.authorization.cloudentity.com/uploads/tut_mtls_select_workspace.png)
3. Choose "APIs" on the left side bar.
![choose apis](https://github.com/cloudentity/sample-go-mtls-OAuth-client/blob/feature/aut-5045/img/apis.png?raw=true)
4. Choose the "Gateways" tab.
![choose gateway tab](https://github.com/cloudentity/sample-go-mtls-OAuth-client/blob/feature/aut-5045/img/gtwy_tab.png?raw=true)
5. Choose "Add Gateway".
![add gateway](https://github.com/cloudentity/sample-go-mtls-OAuth-client/blob/feature/aut-5045/img/add_gtwy.png?raw=true)
6. Select "Pyron API Gateway" and give it a name, description, and check "Create and bind services automatically".
![bind services and save](https://github.com/cloudentity/sample-go-mtls-OAuth-client/blob/feature/aut-5045/img/bind.png?raw=true)
7. If not selected, choose the "Quickstart" tab. Follow the instructions shown for downloading and running Pyron.
![choose apis](https://github.com/cloudentity/sample-go-mtls-OAuth-client/blob/feature/aut-5045/img/quickstart.png?raw=true)
8. After running Pyron, go to the .env file in the root of this project repository and change "USE_PYRON" to true and set "X_SSL_CERT_HASH" equal to your "x5t#S256"
   certificate thumbprint which you can get from the access token retreived above.
9. Run the sample OAuth client app
```
make run
```
10. Now, after getting an access token you will have the option to choose 'Call Resource Server API' on the access token screen.
11. Create a sample policy (link below with step by step instructions and screen shots.)
 1. Choose "Policies" on the left menu.
 2. Choose "Create Policy". Choose "API Request" as the Policy type. Give the policy a name and choose "Cloudentity" as the policy language and choose "Create".
 3. In the policy editor, Delete the existing policy. Then click the "+" sign to add a new validator.
 4. Choose "Attributes" then choose "Add field".
 5. From the "Source" drop down choose "Access Token".
 6. In the field, choose "Custom Value" from the drop down menu.
 7. Under "Full Path" enter "cnf.x5t#S256".
 8. Choose "Equals" and from the "Target" drop down choose "Request".
 9. In the "field attribute name" choose "Request Headers". 
 10. In "full path" after "headers." enter "x-ssl-cert-hash".
 11. Add another validator again choosing "Attributes" -> "Add Field". The from "Source" choose "Access Token". 
 12. Under "Field/attribute" choose "Custom Value".
 13. In "full path" enter "cnf.x5t#S256" and choose "present".

Now if you enter an incorrect hash or omit the header or the hash you will fail the validation.

## Documentation

The steps for this example can be found at
[Cloudentity Run Sample MTLS App](https://docs.authorization.cloudentity.com/guides/developer/mtls/?q=mtls#run-sample-application)

An overview of mTLS-based client Authentication can be found
[mTLS-based Client Authentication](https://docs.authorization.cloudentity.com/features/OAuth/client_auth/tls_client_auth/?q=mtls)

Authorization Control Plane extensive documentation can be found at [Cloudentity Docs](https://docs.authorization.cloudentity.com/)

Protecting API on Pyron API Gateway can be found at [Protecting API on Pyron API Gateway](https://docs.authorization.cloudentity.com/guides/developer/protect/pyron/pyron/?q=pyron)