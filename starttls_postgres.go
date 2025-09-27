package go_tls_probe

/*
	Send STARTTLS handshake to PostgreSQL
	2025 Ilmar Kerm
*/

import (
	"errors"
	"encoding/binary"
	"net"
	"time"
)

func startTlsPostgres(conn net.Conn) error {
	// Do what is needed for Postgres to start TLS
	const (
		// PostgreSQL SSL request code
		sslRequestCode = 80877103
	)
	// Send STARTTLS request
    sslRequest := make([]byte, 8)
    binary.BigEndian.PutUint32(sslRequest[0:4], 8) // Packet length (including these 4 bytes)
    binary.BigEndian.PutUint32(sslRequest[4:8], sslRequestCode) // SSL request code
    _, err := conn.Write(sslRequest)
	if err != nil {
		return err
	}
	// Read response
	response := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second));
    _, readerr := conn.Read(response)
    if readerr != nil {
        return readerr
    }
	if string(response[0]) != "S" {
		// If TLS is not supported
		return errors.New("TLS not supported")
	}
	return nil
}
