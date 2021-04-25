package main

import (
    "crypto/sha256"
    "crypto/sha512"
    "crypto/tls"
    "crypto/x509"
    "encoding/hex"
    "fmt"
    "github.com/miekg/dns"
    "log"
    "net/http"
)

const (
    PkixTA = 0 // Certificate Authority Constraint
    PkixEE = 1 // Service Certificate Constraint
    DaneTA = 2 // Trust Anchor Assertion
    DaneEE = 3 // Domain Issued Certificate
)

func HashCert(cert *x509.Certificate, selector uint8, hash uint8) (string, error) {

    var input []byte
    switch selector {
    case 0: // whole certificate
        input = cert.Raw
    case 1: // only public key
        input = cert.RawSubjectPublicKeyInfo
    default:
        return "", fmt.Errorf("invalid TLSA selector: %d", selector)
    }

    var output []byte
    switch hash {
    case 0: // no hash
        output = input
    case 1: // SHA256 hash
        tmp := sha256.Sum256(input)
        output = tmp[:]
    case 2: // SHA512 hash
        tmp := sha512.Sum512(input)
        output = tmp[:]
    default:
        return "", fmt.Errorf("unknown TLSA matching type: %d", hash)
    }
    return hex.EncodeToString(output), nil
}

func NewTlsConfigWithDane(tlsaRecords []*dns.TLSA) *tls.Config {
    config := &tls.Config{
        InsecureSkipVerify: true,
    }
    config.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
        certs := make([]*x509.Certificate, len(rawCerts))
        for i, asn1Data := range rawCerts {
            cert, err := x509.ParseCertificate(asn1Data)
            if err != nil {
                return fmt.Errorf("failed to parse server certificate: %s", err.Error())
            }
            certs[i] = cert
        }

        for _, tlsa := range tlsaRecords {
            switch tlsa.Usage {
            case PkixTA:
                /*
                	tlsa certificate MUST be found in any of the PKIX certification paths
					for the end entity certificate given by the server in TLS.
					The presented certificate MUST pass PKIX certification path
					validation, and a CA certificate that matches the TLSA record MUST
					be included as part of a valid certification path
                */
                var opts x509.VerifyOptions
                opts.Roots = config.RootCAs
                opts.Intermediates = x509.NewCertPool()
                for _, cert := range certs[1:] {
                    opts.Intermediates.AddCert(cert)
                }
                chains, err := certs[0].Verify(opts)
                if err != nil {
                    log.Printf("chain verification failed: %s\n", err.Error())
                    continue
                }
                for _, chain := range chains {
                    for _, cert := range chain[1:] {
                        hash, err := HashCert(cert, tlsa.Selector, tlsa.MatchingType)
                        if err != nil {
                            log.Printf("hash failed: %s\n", err.Error())
                            continue
                        }
                        if hash == tlsa.Certificate {
                            log.Printf("cert hash matched with tlsa\n")
                            return nil
                        }
                    }
                }
            case PkixEE:
				/*
					The target certificate MUST pass PKIX certification path validation and MUST
					match the TLSA record.
				*/
				var opts x509.VerifyOptions
				opts.Roots = config.RootCAs
				_, err := certs[0].Verify(opts)
				if err != nil {
					continue
				}
				hash, err := HashCert(certs[0], tlsa.Selector, tlsa.MatchingType)
				if err != nil {
					continue
				}
				if hash == tlsa.Certificate {
					return nil
				}

            case DaneTA:
            	/*
            		The target certificate MUST pass PKIX certification path validation, with any
            		certificate matching the TLSA record considered to be a trust
            		anchor for this certification path validation.
            	 */
				var opts x509.VerifyOptions
				opts.Roots = config.RootCAs
				for _, cert := range certs[1:] {
					hash, err := HashCert(certs[0], tlsa.Selector, tlsa.MatchingType)
					if err == nil && hash == tlsa.Certificate {
						opts.Roots.AddCert(cert)
					}
				}
				_, err := certs[0].Verify(opts)
				if err == nil {
					return nil
				}

			case DaneEE:
				/*
					The target certificate MUST match the TLSA record.
					PKIX validation is not tested for certificate usage 3.
				 */
                hash, err := HashCert(certs[0], tlsa.Selector, tlsa.MatchingType)
                if err != nil {
                    continue
                }
                if hash == tlsa.Certificate {
                    return nil
                }
            default:
                log.Printf("invalid tlsa usage: %d\n", tlsa.Usage)
            }
        }

        return fmt.Errorf("no valid certification found")
    }
    return config
}

func main() {
    InitVerifiedKeys()
    tlsa, err := GetTLSA("www.torproject.org.", dns.TypeTLSA)
    fmt.Println(tlsa, err)

    config := NewTlsConfigWithDane(tlsa)
    t := &http.Transport{
        TLSClientConfig: config,
    }
    client := http.Client{Transport: t}
    resp, err := client.Get("https://www.torproject.org")
    fmt.Println(resp, err)
}
