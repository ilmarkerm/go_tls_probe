package go_tls_probe

/*
	Connect to TLS secured port and return information about the established TLS session and all the certificates
	2025 Ilmar Kerm
*/

import (
	"crypto/tls"
	"time"
	"net"
	"strconv"
	//"errors"
)


func GetLocalIP() string {
	conn, err := net.DialTimeout("udp", "1.1.1.1:80", time.Second)
	localAddress := "127.0.0.1"
	if err == nil {
		defer conn.Close()
		localAddress = conn.LocalAddr().(*net.UDPAddr).IP.String()
	}
	return localAddress
}

func CheckTlsPort(host_addr string, port_number int, startTlsProtocol string) (*tls.ConnectionState,error) {
	timeout := time.Second
	// Make regular TCP connection with a very short timeout
	conn, connerr := net.DialTimeout("tcp", net.JoinHostPort(host_addr, strconv.Itoa(port_number)), timeout)
	if connerr != nil {
		return nil, connerr
	} else {
		defer conn.Close()
		// Perform STARTTLS if necessary
		var err error
		if startTlsProtocol == "mysql" {
			err = startTlsMysql(conn)
		} else if startTlsProtocol == "postgres" {
			err = startTlsPostgres(conn)
		}
		// Fail, if starttls failed
		if err != nil {
			return nil, err
		}
		// Connect TLS and do the Handshake
		tlsconn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
		})
		err = tlsconn.Handshake()
		if err != nil {
			return nil, err
		}
		tlsState := tlsconn.ConnectionState()
		return &tlsState, nil
	}
}

func CertValidUntil(t tls.ConnectionState) (time.Time, int64) {
	// Get the valid until time of the chain, both as a date and seconds until expiration
	var minExpiration time.Time

	for idx, cert := range t.PeerCertificates {
		if (idx == 0) || (minExpiration.After(cert.NotAfter)) {
			minExpiration = cert.NotAfter
		}
	}
	return minExpiration, minExpiration.Unix()-time.Now().Unix()
}

func TlsVersionCheck(t tls.ConnectionState, minVersion uint16) bool {return t.Version >= minVersion}
func TlsVersionSupported(t tls.ConnectionState) bool {return TlsVersionCheck(t, tls.VersionTLS12)}
