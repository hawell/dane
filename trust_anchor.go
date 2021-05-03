package dane

import (
	"encoding/xml"
	"fmt"
	"github.com/miekg/dns"
	"io/ioutil"
	"net/http"
	"strings"
)

// trustAnchor is a struct that represents a trust anchor xml object
// defined in https://tools.ietf.org/html/rfc7958#section-2.1.1
type trustAnchor struct {
	Id         string      `xml:"id,attr"`
	Source     string      `xml:"source,attr"`
	Zone       string      `xml:"Zone"`
	KeyDigests []keyDigest `xml:"keyDigest"`
}

// keyDigest is part of trustAnchor xml object representation
type keyDigest struct {
	Id         string `xml:"id,attr"`
	ValidFrom  string `xml:"validFrom,attr"`
	ValidUntil string `xml:"validUntil,attr"`
	KeyTag     uint16 `xml:"KeyTag"`
	Algorithm  uint8  `xml:"Algorithm"`
	DigestType uint8  `xml:"DigestType"`
	Digest     string `xml:"Digest"`
}

// trust anchor retrieve url; see: https://tools.ietf.org/html/rfc7958#section-3.1
var trustAnchorURL = "https://data.iana.org/root-anchors/root-anchors.xml"

// getTrustAnchor tries to fetch xml file using trustAnchorURL
func getTrustAnchor() (*trustAnchor, error) {
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
	var anchor trustAnchor
	if err := xml.Unmarshal(byteValue, &anchor); err != nil {
		return nil, err
	}
	return &anchor, nil
}

// trustAnchorToDS converts a trustAnchor xml object to DS RRSet
// see: https://tools.ietf.org/html/rfc7958#section-2.1.3
func trustAnchorToDS(anchor *trustAnchor) []*dns.DS {
	var res []*dns.DS
	for _, key := range anchor.KeyDigests {
		ds := &dns.DS{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeDS,
				Class:  dns.ClassINET,
			},
			KeyTag:     key.KeyTag,
			Algorithm:  key.Algorithm,
			DigestType: key.DigestType,
			Digest:     strings.ToLower(key.Digest),
		}
		res = append(res, ds)
	}
	return res
}
