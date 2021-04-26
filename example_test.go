package dane_test

import (
    "crypto/tls"
    "fmt"
    "github.com/hawell/dane"
    "log"
    "net/http"
    "time"
)

func Example() {
    r := dane.NewResolver()

    config := &tls.Config{
        InsecureSkipVerify: true,
        VerifyPeerCertificate: dane.VerifyPeerCertificate(r, nil),
    }
    t := &http.Transport{
        TLSClientConfig: config,
        DialTLSContext: dane.DialTLSContext(r, config),
    }
    client := http.Client{Transport: t}
    start := time.Now()

    resp, err := client.Get("https://torproject.org")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(resp)
    fmt.Println(time.Since(start))

    resp, err = client.Get("https://torproject.org")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(resp)
    fmt.Println(time.Since(start))

    // Output:
}
