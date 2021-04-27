package dane

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"strings"
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
	NS string
}

func (r queryRespKey) String() string {
	return r.QName + "-" + dns.TypeToString[r.QType] + "-" + r.NS
}
type Resolver struct {
	client        *dns.Client
	zoneDS        *cache.Cache
	verifiedZones *cache.Cache
	tlsaRecords   *cache.Cache
	verified      *cache.Cache
}

var resolver *Resolver

func init() {
	resolver = NewResolver()
}

func NewResolver() *Resolver {
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

	rootZSK := ". 172800 IN DNSKEY 256 3 8 AwEAAa+HvD7XXjmL+1htThUQyZW7oWGnjzKHJASg3TSR5Bmu5LfnSVW7 fxqZa2oAYo2ionIQWyqAj/loApzg8GNMhyIibftPJso54uWRQ2GaoMrw LD5SLu676kf7urJq6nqdjNC0aJM/C888li69lVH6tiu2tZm1NH3cmgfn MUJpD60bsrDUqs7XwftmNkdkHa4ltQbM3UNPyfTaNBQYoH3wpOpSjdk3 tyDRnreBO6Idrw+DGf/rve4sL3qiSaXfYIkcwAwozxR34iHU5dbCDs8S 6FmZYhoSVKVgNSUkudxhd9/6RrZkYRgvwRsQXl3UwsacU1DsXcORqIC+ 7NlQ6M2OJVU="
	rootKSK := ". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3 +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF 0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN R1AkUTV74bU="

	zsk, _ := dns.NewRR(rootZSK)
	ksk, _ := dns.NewRR(rootKSK)

	r.verifiedZones.Set(".", &zoneKeySet{
		ZSK: []*dns.DNSKEY{zsk.(*dns.DNSKEY)},
		KSK: []*dns.DNSKEY{ksk.(*dns.DNSKEY)},
	}, 172800*time.Second)

	return r
}

func (r *Resolver) query(qname string, qtype uint16, ns string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.SetEdns0(4096, true)
	resp, _, err := r.client.Exchange(m, ns + ":53")
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns error: %d", resp.Rcode)
	}

	return resp, nil
}

// Return true if, and only if, this is a zone key with the SEP bit unset. This implies a ZSK (rfc4034 2.1.1).
func isZSK(k *dns.DNSKEY) bool {
	return k.Flags&(1<<8) == (1<<8) && k.Flags&1 == 0
}

// Return true if, and only if, this is a zone key with the SEP bit set. This implies a KSK (rfc4034 2.1.1).
func isKSK(k *dns.DNSKEY) bool {
	return k.Flags&(1<<8) == (1<<8) && k.Flags&1 == 1
}

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

func (r *Resolver) queryAndVerify(qname string, qtype uint16, auth string, ns string) (*dns.Msg, error) {
	if queryResp, ok := r.verified.Get(queryRespKey{QName: qname, QType: qtype, NS: ns}.String()); ok {
		return queryResp.(*dns.Msg), nil
	}
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
	var ttl uint32 = 0
	for _, s := range [][]dns.RR{queryResp.Answer, queryResp.Ns} {
		for _, rr := range s {
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	}
	r.verified.Set(queryRespKey{QName: qname, QType: qtype, NS: ns}.String(), queryResp, time.Duration(ttl)*time.Second)
	return queryResp, nil
}

func (r *Resolver) GetTLSA(qname string) error {
	originalQName := dns.Fqdn(qname)
	if _, ok := r.tlsaRecords.Get(originalQName); ok {
		return nil
	}
	qname = "_443._tcp." + originalQName
	auth := "."
	ns := "m.root-servers.net."

	for {
		queryResp, err := r.queryAndVerify(qname, dns.TypeDNSKEY, auth, ns)
		if err != nil {
			return err
		}

		// referral
		if len(queryResp.Answer) == 0 && len(queryResp.Ns) != 0 && queryResp.Ns[0].Header().Rrtype == dns.TypeNS {
			parentAuth := auth
			auth = queryResp.Ns[0].Header().Name
			if _, err := r.queryAndVerify(auth, dns.TypeDS, parentAuth, ns); err != nil {
				return err
			}
			ns = queryResp.Ns[0].(*dns.NS).Ns
			if _, err := r.queryAndVerify(auth, dns.TypeDNSKEY, auth, ns); err != nil {
				return err
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
	queryResp, err := r.queryAndVerify(qname, dns.TypeTLSA, auth, ns)
	if err != nil {
		return err
	}
	var res []*dns.TLSA
	for _, rr := range queryResp.Answer {
		if rr.Header().Rrtype == dns.TypeTLSA {
			res = append(res, rr.(*dns.TLSA))
		}
	}
	if res != nil {
		r.tlsaRecords.Set(originalQName, res, time.Duration(res[0].Hdr.Ttl)*time.Second)
	}
	return nil
}

func (r *Resolver) FindTlsaRecords(names []string) []*dns.TLSA {
	var res []*dns.TLSA
	for _, name := range names {
		name = dns.Fqdn(name)
		if strings.HasPrefix(name, "*.") {
			name = strings.TrimPrefix(name, "*.")
			for qname, items := range r.tlsaRecords.Items() {
				tlsaRecords := items.Object.([]*dns.TLSA)
				if qname != name && strings.HasSuffix(qname, name) {
					res = append(res, tlsaRecords...)
				}
			}
		} else {
			for qname, items := range r.tlsaRecords.Items() {
				tlsaRecords := items.Object.([]*dns.TLSA)
				if qname == name {
					res = append(res, tlsaRecords...)
				}
			}
		}
	}
	return res
}
