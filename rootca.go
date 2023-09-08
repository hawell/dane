package dane

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
)

func Load(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		default:
		}
	}
	return certs, nil
}

func CreateCertPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

func MozillaCertPool() (*x509.CertPool, error) {
	resp, err := http.Get("https://curl.se/ca/cacert.pem")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad http response: %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	certs, err := Load(data)
	if err != nil {
		return nil, err
	}
	return CreateCertPool(certs), nil
}

func AcmeCertPool() (*x509.CertPool, error) {
	data, err := os.ReadFile("acme.ca")
	if err != nil {
		return nil, err
	}
	certs, err := Load(data)
	if err != nil {
		return nil, err
	}
	return CreateCertPool(certs), nil
}
