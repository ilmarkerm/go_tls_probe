package go_tls_probe

/*
	Send STARTTLS handshake to MySQL
	2025 Ilmar Kerm
*/

import (
	"bytes"
	"encoding/binary"
	"net"
	"io"
	"errors"
)

const (
	// https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__capabilities__flags.html
	clientProtocol41 = 512
	clientSSL        = 2048
	clientSecureConn = 32768
)

func readMySQLPacket(conn net.Conn) ([]byte, error) {
    // Read packet header (4 bytes)
    header := make([]byte, 4)
    if _, err := io.ReadFull(conn, header); err != nil {
        return nil, err
    }
	
    // Parse packet length (3 bytes) and sequence ID (1 byte)
    length := uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16
    // sequenceID := header[3] // Not used

    // Read packet body
    body := make([]byte, length)
    if _, err := io.ReadFull(conn, body); err != nil {
        return nil, err
    }

    return body, nil
}

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_response.html
func writeMysqlHandshakeResponse(conn net.Conn) error {
    packet := make([]byte, 32)
    
    // Client capability flags (with SSL flag set)
    capabilityFlags := uint32(clientSSL | clientProtocol41 | clientSecureConn)
    binary.LittleEndian.PutUint32(packet[0:4], capabilityFlags)
    // Max packet size
    binary.LittleEndian.PutUint32(packet[4:8], 0x00ffffff)
    // Character set (utf8mb4 = 45)
    packet[8] = 45

	// Create packet header
    header := make([]byte, 4)
    length := len(packet)
    header[0] = byte(length)
    header[1] = byte(length >> 8)
    header[2] = byte(length >> 16)
    header[3] = 1 // SequenceID

    // Write header and data
    if _, err := conn.Write(header); err != nil {
        return err
    }
    if _, err := conn.Write(packet); err != nil {
        return err
    }

	return nil
}

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
func readMysqlHandshake(conn net.Conn) error {
	initialPacket, err := readMySQLPacket(conn)
	if err != nil {
		return err
	}
	if len(initialPacket) < 36 {
        return errors.New("initial packet too short")
    }
    if initialPacket[0] != 10 {
        return errors.New("unsupported protocol version")
    }
	// Get server capabilities
	pos := 1 /* protocol version */ + bytes.IndexByte(initialPacket[1:], 0x00) + 1 /* server version, NUL terminated */ + 4 /* thread id */ + 8 /* auth-plugin-data-part-1 */ + 1 /* filler */
	capabilityFlags := binary.LittleEndian.Uint16(initialPacket[pos : pos+2])
	if capabilityFlags&clientProtocol41 == 0 {
		return errors.New("unsupported client protocol version")
	}
	if capabilityFlags&clientSSL == 0 {
		return errors.New("TLS not supported by the server")
	}
	return nil
}

func startTlsMysql(conn net.Conn) error {
	if err := readMysqlHandshake(conn); err != nil {
		return err
	}
	if err := writeMysqlHandshakeResponse(conn); err != nil {
		return err
	}
	return nil
}
