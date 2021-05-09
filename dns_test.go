package dane

import (
    "fmt"
    "github.com/miekg/dns"
    "testing"
    "time"
)

func TestResolver_Get(t *testing.T) {
    resp, err := resolver.Get("fedoraproject.org.", dns.TypeA)
    if err != nil {
        t.Fail()
    }
    if resp == nil {
        t.Fail()
    }
    if resp.Rcode != dns.RcodeSuccess {
        t.Fail()
    }
    start := time.Now()
    _, _ = resolver.Get("fedoraproject.org.", dns.TypeA)
    fmt.Println(time.Since(start))
}