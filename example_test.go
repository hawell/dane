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
    "time"
)

func Example() {
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

    resp, err := client.Get("https://www.fedoraproject.org")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(resp)
    // Output:
}
