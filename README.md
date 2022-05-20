# go-sam-oauth-2
A go package to demonstrate similar functionality to the ruby sam-oauth2 gem.

This contains an example validator that can take in either an issuer from Keycloak or Auth0.
The main.go file runs a simple web server that responds to get requests with the token details if it is valid.
