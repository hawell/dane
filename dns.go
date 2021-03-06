package dane

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"time"
)

type zoneKeySet struct {
	ZSK []*dns.DNSKEY
	KSK []*dns.DNSKEY
}

type recordSetKey struct {
	QName string
	QType uint16
}

type queryRespKey struct {
	QName string
	QType uint16
	NS    string
}

func (r queryRespKey) String() string {
	return r.QName + "-" + dns.TypeToString[r.QType] + "-" + r.NS
}

// Resolver contains cached query responses
// and a dns client for querying
type Resolver struct {
	client        *dns.Client
	zoneDS        *cache.Cache
	verifiedZones *cache.Cache
	tlsaRecords   *cache.Cache
	verified      *cache.Cache
}

// resolver is the internal resolver used for TLSA queries
var resolver *Resolver

func init() {
	resolver = NewResolver()
}

// NewResolver creates a new dns resolver with root keys set
func NewResolver() *Resolver {
	trustAnchor, err := getTrustAnchor()
	if err != nil {
		return nil
	}
	rootDS := trustAnchorToDS(trustAnchor)

	r := &Resolver{
		client: &dns.Client{
			Net:     "udp",
			Timeout: 2000 * time.Millisecond,
		},
		zoneDS:        cache.New(5*time.Minute, 10*time.Minute),
		verifiedZones: cache.New(5*time.Minute, 10*time.Minute),
		tlsaRecords:   cache.New(5*time.Minute, 10*time.Minute),
		verified:      cache.New(5*time.Minute, 10*time.Minute),
	}

	r.zoneDS.Set(".", rootDS, cache.NoExpiration)

	return r
}

// query sends a dnssec enabled dns request and wait for the response
// minimum ttl from Answer and Authority parts is used for cache timeout
func (r *Resolver) query(qname string, qtype uint16, ns string) (*dns.Msg, error) {
	if queryResp, ok := r.verified.Get(queryRespKey{QName: qname, QType: qtype, NS: ns}.String()); ok {
		return queryResp.(*dns.Msg), nil
	}
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.SetEdns0(4096, true)
	resp, _, err := r.client.Exchange(m, ns+":53")
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns error: %d", resp.Rcode)
	}

	var ttl uint32 = 0
	final := false
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == qtype {
			final = true
		}
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}
	for _, rr := range resp.Ns {
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}
	if final {
		r.verified.Set(queryRespKey{QName: qname, QType: qtype, NS: ""}.String(), resp, time.Duration(ttl)*time.Second)
	} else {
		r.verified.Set(queryRespKey{QName: qname, QType: qtype, NS: ns}.String(), resp, time.Duration(ttl)*time.Second)
	}

	return resp, nil
}

// isZSK Return true if, and only if, this is a zone key with the SEP bit unset. This implies a ZSK (rfc4034 2.1.1).
func isZSK(k *dns.DNSKEY) bool {
	return k.Flags&(1<<8) == (1<<8) && k.Flags&1 == 0
}

// isKSK Return true if, and only if, this is a zone key with the SEP bit set. This implies a KSK (rfc4034 2.1.1).
func isKSK(k *dns.DNSKEY) bool {
	return k.Flags&(1<<8) == (1<<8) && k.Flags&1 == 1
}

// addKey extract DNSKEY RRSets from response and verify them against DS record
// already retrieved from parent zone and store then in cache
func (r *Resolver) addKeys(z string, msg *dns.Msg) error {
	if _, ok := r.verifiedZones.Get(z); ok {
		return nil
	}
	var (
		zsk []*dns.DNSKEY
		ksk []*dns.DNSKEY
		ttl uint32
	)
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeDNSKEY {
			ttl = rr.Header().Ttl
			key := rr.(*dns.DNSKEY)
			if isZSK(key) {
				zsk = append(zsk, key)
			}
			if isKSK(key) {
				ksk = append(ksk, key)
			}
		}
	}
	verified := false
Success:
	for _, key := range ksk {
		if v, ok := r.zoneDS.Get(z); ok {
			for _, ds := range v.([]*dns.DS) {
				parentDsDigest := ds.Digest
				DsDigest := key.ToDS(ds.DigestType).Digest
				if DsDigest == parentDsDigest {
					verified = true
					break Success
				}
			}
		}
	}
	if !verified {
		return fmt.Errorf("ds not found for %s", z)
	}
	r.verifiedZones.Set(z, &zoneKeySet{
		ZSK: zsk,
		KSK: ksk,
	}, time.Duration(ttl)*time.Second)

	return nil
}

// addDS extract DS RRSets from response and store them in cache
func (r *Resolver) addDS(msg *dns.Msg) {
	var rrs []*dns.DS
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeDS {
			rrs = append(rrs, rr.(*dns.DS))
		}
	}
	if rrs != nil {
		ttl := rrs[0].Hdr.Ttl
		name := rrs[0].Hdr.Name
		r.zoneDS.Set(name, rrs, time.Duration(ttl)*time.Second)
	}
}

// splitSets split Resource Records in a response and group them
// based on qname and qtype
func splitSets(rrs []dns.RR) map[recordSetKey][]dns.RR {
	m := make(map[recordSetKey][]dns.RR)

	for _, r := range rrs {
		if r.Header().Rrtype == dns.TypeRRSIG || r.Header().Rrtype == dns.TypeOPT {
			continue
		}

		if s, ok := m[recordSetKey{r.Header().Name, r.Header().Rrtype}]; ok {
			s = append(s, r)
			m[recordSetKey{r.Header().Name, r.Header().Rrtype}] = s
			continue
		}

		s := make([]dns.RR, 1, 3)
		s[0] = r
		m[recordSetKey{r.Header().Name, r.Header().Rrtype}] = s
	}

	if len(m) > 0 {
		return m
	}
	return nil
}

func (r *Resolver) verify(z string, msg *dns.Msg) error {
	v, ok := r.verifiedZones.Get(z)
	if !ok {
		return fmt.Errorf("zone %s keys not verified", z)
	}
	zoneKeys := v.(*zoneKeySet)
	for _, rrs := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		sets := splitSets(rrs)
		rrsigSets := make(map[recordSetKey]map[uint16]*dns.RRSIG)
		for _, rr := range rrs {
			if rrsig, ok := rr.(*dns.RRSIG); ok {
				rrsigs := rrsigSets[recordSetKey{QName: rrsig.Hdr.Name, QType: rrsig.TypeCovered}]
				if rrsigs == nil {
					rrsigs = make(map[uint16]*dns.RRSIG)
				}
				rrsigs[rrsig.KeyTag] = rrsig
				rrsigSets[recordSetKey{QName: rrsig.Hdr.Name, QType: rrsig.TypeCovered}] = rrsigs
			}
		}
		for _, set := range sets {
			rrsigs := rrsigSets[recordSetKey{QName: set[0].Header().Name, QType: set[0].Header().Rrtype}]
			if rrsigs == nil {
				continue
			}
			var keys []*dns.DNSKEY
			if set[0].Header().Rrtype == dns.TypeDNSKEY {
				keys = zoneKeys.KSK
			} else {
				keys = zoneKeys.ZSK
			}
			verified := false
			for _, key := range keys {
				rrsig, ok := rrsigs[key.KeyTag()]
				if !ok {
					continue
				}
				if err := rrsig.Verify(key, set); err == nil {
					verified = true
					break
				}
			}
			if !verified {
				return fmt.Errorf("verification failed")
			}
		}
	}
	return nil
}

// queryAndVerify send a dns request to the specified ns and verify and cache the response.
// since DNSKEY records are verified against themselves they need to be added before; they
// also have to match with a DS record obtained from parent zone
func (r *Resolver) queryAndVerify(qname string, qtype uint16, auth string, ns string) (*dns.Msg, error) {
	queryResp, err := r.query(qname, qtype, ns)
	if err != nil {
		return nil, err
	}
	if qtype == dns.TypeDNSKEY {
		if err := r.addKeys(auth, queryResp); err != nil {
			return nil, err
		}
	}
	if err := r.verify(auth, queryResp); err != nil {
		return nil, err
	}
	if qtype == dns.TypeDS {
		r.addDS(queryResp)
	}
	return queryResp, nil
}

// Get starts a recursive dnssec query from root zone
// and verify responses along the way
func (r *Resolver) Get(qname string, qtype uint16) (*dns.Msg, error) {
	if queryResp, ok := r.verified.Get(queryRespKey{QName: qname, QType: qtype}.String()); ok {
		return queryResp.(*dns.Msg), nil
	}

	auth := "."
	ns := "m.root-servers.net."
	if _, ok := r.verifiedZones.Get("."); !ok {
		if _, err := r.queryAndVerify(".", dns.TypeDNSKEY, ".", ns); err != nil {
			return nil, err
		}
	}

	for {
		queryResp, err := r.queryAndVerify(qname, dns.TypeDNSKEY, auth, ns)
		if err != nil {
			return nil, err
		}

		// referral
		if len(queryResp.Answer) == 0 && len(queryResp.Ns) != 0 && queryResp.Ns[0].Header().Rrtype == dns.TypeNS {
			parentAuth := auth
			auth = queryResp.Ns[0].Header().Name
			if _, err := r.queryAndVerify(auth, dns.TypeDS, parentAuth, ns); err != nil {
				return nil, err
			}
			ns = queryResp.Ns[0].(*dns.NS).Ns
			if _, err := r.queryAndVerify(auth, dns.TypeDNSKEY, auth, ns); err != nil {
				return nil, err
			}
			continue
		}

		var res []dns.RR

		// cname
		for _, rr := range queryResp.Answer {
			if rr.Header().Rrtype == dns.TypeCNAME {
				res = append(res, rr)
			}
		}
		if len(res) > 0 {
			qname = res[len(res)-1].(*dns.CNAME).Target
			auth = "."
			ns = "m.root-servers.net."
			continue
		}
		break
	}
	queryResp, err := r.queryAndVerify(qname, qtype, auth, ns)
	if err != nil {
		return nil, err
	}
	return queryResp, nil
}

// GetTLSA create a valid qname for TLSA from network, qname and port
// and retrieve the results using Resolver.Get()
// for example with network = "tcp" and port = "443" and qname = "www.example.com
// the resulting qname would be: "_443._tcp.www.example.com."
func (r *Resolver) GetTLSA(network string, qname string, port string) ([]*dns.TLSA, error) {
	qname = "_" + port + "._" + network + "." + dns.Fqdn(qname)
	if v, ok := r.tlsaRecords.Get(qname); ok {
		return v.([]*dns.TLSA), nil
	}
	queryResp, err := r.Get(qname, dns.TypeTLSA)
	if err != nil {
		return nil, err
	}
	var res []*dns.TLSA
	for _, rr := range queryResp.Answer {
		if rr.Header().Rrtype == dns.TypeTLSA {
			res = append(res, rr.(*dns.TLSA))
		}
	}
	if res != nil {
		r.tlsaRecords.Set(qname, res, time.Duration(res[0].Hdr.Ttl)*time.Second)
	}
	return res, nil
}
