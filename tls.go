package dane

import (
    "context"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/tls"
    "crypto/x509"
    "encoding/hex"
    "fmt"
    "github.com/miekg/dns"
    "log"
    "net"
)

// TLSA Certificate Usages Registry
const (
    pkixTA = 0 // Certificate Authority Constraint
    pkixEE = 1 // Service Certificate Constraint
    daneTA = 2 // Trust Anchor Assertion
    daneEE = 3 // Domain Issued Certificate
)

// TLSA Selectors
const (
    certSelector = 0 // Full certificate
    spkiSelector = 1 // SubjectPublicKeyInfo
)

// TLSA Matching Types
const (
    fullMatch = 0 // No hash used
    sha2_256  = 1 // 256 bit hash by SHA2
    sha2_512  = 2 // 512 bit hash by SHA2
)

func hashCert(cert *x509.Certificate, selector uint8, hash uint8) (string, error) {

    var input []byte
    switch selector {
    case certSelector:
        input = cert.Raw
    case spkiSelector:
        input = cert.RawSubjectPublicKeyInfo
    default:
        return "", fmt.Errorf("invalid TLSA selector: %d", selector)
    }

    var output []byte
    switch hash {
    case fullMatch:
        output = input
    case sha2_256:
        tmp := sha256.Sum256(input)
        output = tmp[:]
    case sha2_512:
        tmp := sha512.Sum512(input)
        output = tmp[:]
    default:
        return "", fmt.Errorf("unknown TLSA matching type: %d", hash)
    }
    return hex.EncodeToString(output), nil
}

func VerifyPeerCertificate(roots *x509.CertPool) func (rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
    return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
        certs := make([]*x509.Certificate, len(rawCerts))
        for i, asn1Data := range rawCerts {
            cert, err := x509.ParseCertificate(asn1Data)
            if err != nil {
                return fmt.Errorf("failed to parse server certificate: %s", err.Error())
            }
            certs[i] = cert
        }
        tlsaRecords := resolver.FindTlsaRecords(certs[0].DNSNames)

        for _, tlsa := range tlsaRecords {
            switch tlsa.Usage {
            case pkixTA:
                /*
                    tlsa certificate MUST be found in any of the PKIX certification paths
                    for the end entity certificate given by the server in TLS.
                    The presented certificate MUST pass PKIX certification path
                    validation, and a CA certificate that matches the TLSA record MUST
                    be included as part of a valid certification path
                */
                var opts x509.VerifyOptions
                opts.Roots = roots
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
                        hash, err := hashCert(cert, tlsa.Selector, tlsa.MatchingType)
                        if err != nil {
                            log.Printf("hash failed: %s\n", err.Error())
                            continue
                        }
                        if hash == tlsa.Certificate {
                            return nil
                        }
                    }
                }
            case pkixEE:
                /*
                	The target certificate MUST pass PKIX certification path validation and MUST
                	match the TLSA record.
                */
                var opts x509.VerifyOptions
                opts.Roots = roots
                _, err := certs[0].Verify(opts)
                if err != nil {
                    continue
                }
                hash, err := hashCert(certs[0], tlsa.Selector, tlsa.MatchingType)
                if err != nil {
                    continue
                }
                if hash == tlsa.Certificate {
                    return nil
                }

            case daneTA:
                /*
                	The target certificate MUST pass PKIX certification path validation, with any
                	certificate matching the TLSA record considered to be a trust
                	anchor for this certification path validation.
                */
                var opts x509.VerifyOptions
                opts.Roots = roots
                for _, cert := range certs[1:] {
                    hash, err := hashCert(certs[0], tlsa.Selector, tlsa.MatchingType)
                    if err == nil && hash == tlsa.Certificate {
                        opts.Roots.AddCert(cert)
                    }
                }
                _, err := certs[0].Verify(opts)
                if err == nil {
                    return nil
                }

            case daneEE:
                /*
                	The target certificate MUST match the TLSA record.
                	PKIX validation is not tested for certificate usage 3.
                */
                hash, err := hashCert(certs[0], tlsa.Selector, tlsa.MatchingType)
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
}

func DialTLSContext(config *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
    return func(ctx context.Context, network, addr string) (net.Conn, error) {
        // FIXME: use correct port
        host, _, err := net.SplitHostPort(addr)
        if err != nil {
            return nil, err
        }
        err = resolver.GetTLSA(dns.Fqdn(host))
        if err != nil {
            return nil, err
        }
        c, err := tls.Dial(network, addr, config)
        if err != nil {
            return nil, err
        }
        return c, c.Handshake()
    }
}