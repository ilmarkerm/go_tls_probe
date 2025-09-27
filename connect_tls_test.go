package go_tls_probe

import (
	"testing"
)

func TestRegularTcps(t *testing.T) {
	tls,err := CheckTlsPort(testRegularHost, testRegularPort, "")
	if err != nil {
		t.Error(err)
	} else {
		t.Logf("Negiotiated protocol: %x", tls.Version)
	}
}

func TestMysql(t *testing.T) {
	tls,err := CheckTlsPort(testMysqlHost, testMysqlPort, "mysql")
	if err != nil {
		t.Error(err)
	} else {
		t.Logf("Negiotiated protocol: %x", tls.Version)
	}
}

func TestPostgres(t *testing.T) {
	tls,err := CheckTlsPort(testPostgresHost, testPostgresPort, "postgres")
	if err != nil {
		t.Error(err)
	} else {
		t.Logf("Negiotiated protocol: %x", tls.Version)
	}
}

func TestInvalidPort(t *testing.T) {
	_,err := CheckTlsPort("1.1.1.109", 3344, "")
	if err != nil {
		t.Log(err)
	} else {
		t.Error("It should not have connected")
	}
}

func TestValidProtocol(t *testing.T) {
	tls,err := CheckTlsPort(testRegularHost, testRegularPort, "")
	if err != nil {
		t.Error(err)
	} else {
		if ! TlsVersionSupported(*tls) {
			t.Errorf("Extected a supported protocol, actual negiotiated protocol: %x", tls.Version)
		}
	}
}

func TestCertValidity(t *testing.T) {
	tls,err := CheckTlsPort(testRegularHost, testRegularPort, "")
	if err != nil {
		t.Error(err)
	} else {
		_,validSeconds := CertValidUntil(*tls)
		if validSeconds > 0 {
			t.Logf("Certificate is valid for %d seconds", validSeconds)
		} else {
			t.Errorf("Invalid output: %d", validSeconds)
		}
	}
}

func TestGetLocalIP(t *testing.T) {
	localAddr := GetLocalIP()
	t.Logf("Local IP: %s", localAddr)
	if localAddr == "127.0.0.1" {
		t.Error("Failed to get local IP")
	}
}
