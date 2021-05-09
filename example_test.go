package dane_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/hawell/dane"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"time"
)

func ExampleHTTP() {
	t := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}

			conn, err := tls.DialWithDialer(dialer, network, addr, &tls.Config{
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return dane.VerifyPeerCertificate(network, addr, rawCerts, nil)
				},
			})
			if err != nil {
				return conn, err
			}
			return conn, nil
		},
	}
	client := http.Client{Transport: t}

	_, err := client.Get("https://www.fedoraproject.org")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("success")

	// Output:
	// success
}

func ExampleSMTP() {
	// Connect to the SMTP Server
	servername := "open.nlnet.nl:25"

	host, _, _ := net.SplitHostPort(servername)

	// TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return dane.VerifyPeerCertificate("tcp", servername, rawCerts, nil)
		},
	}

	c, err := smtp.Dial(servername)
	if err != nil {
		panic(err)
	}

	err = c.StartTLS(tlsConfig)
	if err != nil {
		panic(err)
	}

	err = c.Quit()
	if err != nil {
		panic(err)
	}

	fmt.Println("success")
	// Output:
	// success
}
