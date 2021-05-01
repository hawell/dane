package dane

import (
    "encoding/xml"
    "fmt"
    "github.com/miekg/dns"
    "io/ioutil"
    "net/http"
    "strings"
)

// TrustAnchor is a struct that represents a trust anchor xml object
// defined in https://tools.ietf.org/html/rfc7958#section-2.1.1
type TrustAnchor struct {
    Id string `xml:"id,attr"`
    Source string `xml:"source,attr"`
    Zone string `xml:"Zone"`
    KeyDigests []KeyDigest `xml:"KeyDigest"`
}

// KeyDigest is part of TrustAnchor xml object representation
type KeyDigest struct {
    Id string `xml:"id,attr"`
    ValidFrom string `xml:"validFrom,attr"`
    ValidUntil string `xml:"validUntil,attr"`
    KeyTag uint16 `xml:"KeyTag"`
    Algorithm uint8 `xml:"Algorithm"`
    DigestType uint8 `xml:"DigestType"`
    Digest string `xml:"Digest"`
}

// trust anchor retrieve url; see: https://tools.ietf.org/html/rfc7958#section-3.1
var trustAnchorURL = "https://data.iana.org/root-anchors/root-anchors.xml"

// GetTrustAnchor tries to fetch xml file using trustAnchorURL
func GetTrustAnchor() (*TrustAnchor, error) {
    resp, err := http.Get(trustAnchorURL)
    if err != nil {
        return nil, err
    }
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("bad http response: %d", resp.StatusCode)
    }
    byteValue, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    var trustAnchor TrustAnchor
    if err := xml.Unmarshal(byteValue, &trustAnchor); err != nil {
        return nil, err
    }
    fmt.Println(trustAnchor)
    return &trustAnchor, nil
}

// TrustAnchorToDS converts a TrustAnchor xml object to DS RRSet
// see: https://tools.ietf.org/html/rfc7958#section-2.1.3
func TrustAnchorToDS(anchor *TrustAnchor) []*dns.DS {
    var res []*dns.DS
    for _, keyDigest := range anchor.KeyDigests {
        ds := &dns.DS{
            Hdr:        dns.RR_Header{
                Name:     ".",
                Rrtype:   dns.TypeDS,
                Class:    dns.ClassINET,
            },
            KeyTag:     keyDigest.KeyTag,
            Algorithm:  keyDigest.Algorithm,
            DigestType: keyDigest.DigestType,
            Digest:     strings.ToLower(keyDigest.Digest),
        }
        res = append(res, ds)
    }
    return res
}