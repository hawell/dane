package dane_test

import (
    "crypto/tls"
    "fmt"
    "github.com/hawell/dane"
    "log"
    "net/http"
)

func Example() {
    config := &tls.Config{
        InsecureSkipVerify: true,
        VerifyPeerCertificate: dane.VerifyPeerCertificate(nil),
    }
    t := &http.Transport{
        TLSClientConfig: config,
        DialTLSContext: dane.DialTLSContext(config),
    }
    client := http.Client{Transport: t}

    resp, err := client.Get("https://getfedora.org")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(resp)
    // Output:
}
