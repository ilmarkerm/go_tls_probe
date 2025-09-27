# go_tls_probe

Module for GO that does TLS handshake and returns information about the endpoint with support for some STARTTLS services.

This module is intended for monitoring of TLS secured services, mainly monitoring their certificate validity.

Supported STARTTLS protocols:
* MySQL
* PostgreSQL

To run unit tests, copy constants_test.go.sample to constants_test.go and fill in the service endpoints for testing.
