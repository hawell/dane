# DANE

Go library for DANE TLSA authentication

## Usage

```go
t := &http.Transport{
    DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
        dialer := &net.Dialer{
            Timeout:   30 * time.Second,
            KeepAlive: 30 * time.Second,
        }

        conn, err := tls.DialWithDialer(dialer, network, addr, &tls.Config{
            InsecureSkipVerify: true,
            VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
                return dane.VerifyPeerCertificate(addr, rawCerts, nil)
            },
        })
        if err != nil {
            return conn, err
        }
        return conn, nil
    },
}
client := http.Client{Transport: t}

resp, err := client.Get("https://getfedora.org")
if err != nil {
    log.Fatal(err)
}
fmt.Println(resp)

```

the only requirement is to set  `InsecureSkipVerify` to `true` and use `dane.VerifyPeerCertificate()` for custom verification.
all dnssec query and validation are done transparently.