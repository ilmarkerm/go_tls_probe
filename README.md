# go_tls_probe

Module for GO that does TLS handshake and returns information about the endpoint with support for some STARTTLS services.

This module is intended for monitoring of TLS secured services, mainly monitoring their certificate validity.
For certificate monitoring it is better to connect to the monitored service directly, instead of monitoring the certificate file on filesystem, because:
* Ofter the service also needs to be restarted or reloaded for the certificate rotation to take effect
* Can also monitor 3rd party systems remotely, where you don't have access to the filesystem

Supported STARTTLS protocols:
* MySQL
* PostgreSQL

To run unit tests, copy constants_test.go.sample to constants_test.go and fill in the service endpoints for testing.
