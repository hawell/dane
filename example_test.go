package dane_test

import (
    "github.com/hawell/dane"
    "github.com/miekg/dns"
    "log"
    "net/http"
)

func Example() {
    dane.InitVerifiedKeys()
    tlsa, err := dane.GetTLSA("www.torproject.org.", dns.TypeTLSA)
    if err != nil {
        log.Fatal(err)
    }

    config := dane.NewTlsConfigWithDane(tlsa)
    t := &http.Transport{
        TLSClientConfig: config,
    }
    client := http.Client{Transport: t}
    _, err = client.Get("https://www.torproject.org")
    if err != nil {
        log.Fatal(err)
    }
    // Output:
}
