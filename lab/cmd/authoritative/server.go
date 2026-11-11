package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/miekg/dns"
)

const listenAddress = "127.0.0.2:53"
const parentZoneFilePath = "/home/vboxuser/dnssec-testzone/db.mut.test.signed"
const childZoneFilePath = "/home/vboxuser/dnssec-testzone/db.child.mut.test.signed"
const nsec3ZoneFilePath = "/home/vboxuser/dnssec-testzone/db.nsec3.mut.test.signed"
const authoritativeLogPath = "/tmp/dns_mutation_authoritative.jsonl"

var zoneRecords []dns.RR
var zoneRecordsByOrigin = map[string][]dns.RR{}
var authoritativeLogMutex sync.Mutex

func recordsForOrigin(origin string) []dns.RR {
	return zoneRecordsByOrigin[dns.Fqdn(origin)]
}

func equalDNSName(left string, right string) bool {
	return strings.EqualFold(dns.Fqdn(left), dns.Fqdn(right))
}

func isWithinMutTest(name string) bool {
	return dns.IsSubDomain(
		"mut.test.",
		strings.ToLower(dns.Fqdn(name)),
	)
}

type EDNSOptionInfo struct {
	Code          uint16 `json:"code"`
	Name          string `json:"name,omitempty"`
	Length        int    `json:"length"`
	DataHex       string `json:"data_hex,omitempty"`
	DataSHA256    string `json:"data_sha256,omitempty"`
	UTF8Valid     bool   `json:"utf8_valid,omitempty"`
	PrintableUTF8 bool   `json:"printable_utf8,omitempty"`
	UTF8Text      string `json:"utf8_text,omitempty"`
}

type AuthoritativeLogEvent struct {
	Timestamp   string `json:"timestamp"`
	Direction   string `json:"direction"`
	Transport   string `json:"transport"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	MessageID   uint16 `json:"message_id"`

	QName         string `json:"qname"`
	QType         string `json:"qtype"`
	QTypeNumeric  uint16 `json:"qtype_numeric"`
	QClass        string `json:"qclass"`
	QClassNumeric uint16 `json:"qclass_numeric"`

	RD                     bool   `json:"rd"`
	AD                     bool   `json:"ad"`
	CD                     bool   `json:"cd"`
	QR                     bool   `json:"qr"`
	AA                     bool   `json:"aa"`
	TC                     bool   `json:"tc"`
	RA                     bool   `json:"ra"`
	Z                      bool   `json:"z"`
	Opcode                 int    `json:"opcode"`
	OpcodeName             string `json:"opcode_name"`
	RequestRcode           int    `json:"request_rcode"`
	RequestRcodeName       string `json:"request_rcode_name"`
	RequestQuestionCount   int    `json:"request_question_count"`
	RequestAnswerCount     int    `json:"request_answer_count"`
	RequestAuthorityCount  int    `json:"request_authority_count"`
	RequestAdditionalCount int    `json:"request_additional_count"`

	RequestWireSize          int              `json:"request_wire_size"`
	RequestWireSHA256        string           `json:"request_wire_sha256,omitempty"`
	RequestOPTCount          int              `json:"request_opt_count"`
	RequestEDNSOptions       []EDNSOptionInfo `json:"request_edns_options"`
	RequestAdditionalRRTypes []string         `json:"request_additional_rrtypes"`

	RequestTKEYPresent     bool   `json:"request_tkey_present"`
	RequestTKEYCount       int    `json:"request_tkey_count"`
	RequestTKEYMode        uint16 `json:"request_tkey_mode"`
	RequestTKEYError       uint16 `json:"request_tkey_error"`
	RequestTKEYAlgorithm   string `json:"request_tkey_algorithm"`
	RequestTKEYKeyLength   int    `json:"request_tkey_key_length"`
	RequestTKEYOtherLength int    `json:"request_tkey_other_length"`
	RequestTKEYSection     string `json:"request_tkey_section"`
	RequestTKEYOwner       string `json:"request_tkey_owner"`
	RequestTKEYClass       string `json:"request_tkey_class"`
	RequestTKEYTTL         uint32 `json:"request_tkey_ttl"`
	RequestTKEYInception   uint32 `json:"request_tkey_inception"`
	RequestTKEYExpiration  uint32 `json:"request_tkey_expiration"`
	RequestKEYPresent      bool   `json:"request_key_rr_present"`
	RequestKEYCount        int    `json:"request_key_rr_count"`
	RequestKEYSection      string `json:"request_key_rr_section,omitempty"`
	RequestKEYOwner        string `json:"request_key_rr_owner,omitempty"`
	RequestKEYAlgorithm    uint8  `json:"request_key_rr_algorithm,omitempty"`

	EDNSPresent       bool   `json:"edns_present"`
	EDNSVersion       int    `json:"edns_version"`
	UDPPayloadSize    uint16 `json:"udp_payload_size"`
	DO                bool   `json:"do"`
	EDNSZFlags        uint16 `json:"edns_z_flags"`
	EDNSExtendedRcode uint8  `json:"edns_extended_rcode"`
	EDNSOwnerName     string `json:"edns_owner_name"`

	ResponseMessageID     uint16 `json:"response_message_id"`
	ResponseRcode         string `json:"response_rcode"`
	ResponseRcodeNumeric  int    `json:"response_rcode_numeric"`
	ResponseRcodeBase     int    `json:"response_rcode_base"`
	ResponseRcodeExtended int    `json:"response_rcode_extended"`

	ResponseAA bool `json:"response_aa"`
	ResponseAD bool `json:"response_ad"`
	ResponseCD bool `json:"response_cd"`
	ResponseRD bool `json:"response_rd"`
	ResponseRA bool `json:"response_ra"`
	ResponseTC bool `json:"response_tc"`

	ResponseSizeBytes  int    `json:"response_size_bytes"`
	ResponseWireSHA256 string `json:"response_wire_sha256,omitempty"`

	ResponseAnswerCount     int `json:"response_answer_count"`
	ResponseAuthorityCount  int `json:"response_authority_count"`
	ResponseAdditionalCount int `json:"response_additional_count"`

	ResponseAnswerRRTypes     []string `json:"response_answer_rrtypes"`
	ResponseAuthorityRRTypes  []string `json:"response_authority_rrtypes"`
	ResponseAdditionalRRTypes []string `json:"response_additional_rrtypes"`

	ResponseContainsRRSIG  bool `json:"response_contains_rrsig"`
	ResponseContainsDNSKEY bool `json:"response_contains_dnskey"`
	ResponseContainsDS     bool `json:"response_contains_ds"`
	ResponseContainsNSEC   bool `json:"response_contains_nsec"`
	ResponseContainsNSEC3  bool `json:"response_contains_nsec3"`
	ResponseContainsSOA    bool `json:"response_contains_soa"`

	ResponseEDEPresent  bool   `json:"response_ede_present"`
	ResponseEDEInfoCode uint16 `json:"response_ede_info_code"`
	ResponseEDEText     string `json:"response_ede_text,omitempty"`

	ResponseTKEYPresent     bool   `json:"response_tkey_present"`
	ResponseTKEYCount       int    `json:"response_tkey_count"`
	ResponseTKEYMode        uint16 `json:"response_tkey_mode,omitempty"`
	ResponseTKEYError       uint16 `json:"response_tkey_error,omitempty"`
	ResponseTKEYAlgorithm   string `json:"response_tkey_algorithm,omitempty"`
	ResponseTKEYKeyLength   int    `json:"response_tkey_key_length,omitempty"`
	ResponseTKEYOtherLength int    `json:"response_tkey_other_length,omitempty"`
	ResponseTKEYSection     string `json:"response_tkey_section,omitempty"`
}

func writeAuthoritativeLog(event AuthoritativeLogEvent) {
	authoritativeLogMutex.Lock()
	defer authoritativeLogMutex.Unlock()

	file, err := os.OpenFile(
		authoritativeLogPath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		log.Printf("failed to open authoritative log: %v", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(event); err != nil {
		log.Printf("failed to write authoritative log: %v", err)
	}
}

func loadSignedZone(path string, origin string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open zone file: %w", err)
	}
	defer file.Close()

	parser := dns.NewZoneParser(
		file,
		origin,
		path,
	)

	origin = dns.Fqdn(origin)

	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		zoneRecords = append(zoneRecords, rr)
		zoneRecordsByOrigin[origin] = append(zoneRecordsByOrigin[origin], rr)
	}

	if err := parser.Err(); err != nil {
		return fmt.Errorf("failed to parse zone file: %w", err)
	}

	log.Printf(
		"loaded signed zone origin=%s path=%s total_records=%d",
		origin,
		path,
		len(zoneRecords),
	)

	return nil
}

func findRecordsInOrigin(
	origin string,
	name string,
	qtype uint16,
	includeRRSIG bool,
) []dns.RR {
	var result []dns.RR

	for _, rr := range recordsForOrigin(origin) {
		header := rr.Header()

		if !strings.EqualFold(header.Name, name) {
			continue
		}

		if header.Rrtype == qtype {
			result = append(result, rr)
			continue
		}

		if includeRRSIG && header.Rrtype == dns.TypeRRSIG {
			rrsig, ok := rr.(*dns.RRSIG)
			if ok && rrsig.TypeCovered == qtype {
				result = append(result, rr)
			}
		}
	}

	return result
}

func allRecordsAtName(
	origin string,
	name string,
	includeDNSSEC bool,
) []dns.RR {
	var result []dns.RR

	for _, rr := range recordsForOrigin(origin) {
		header := rr.Header()
		if !strings.EqualFold(header.Name, name) {
			continue
		}

		if !includeDNSSEC {
			switch header.Rrtype {
			case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
				continue
			}
		}

		result = append(result, rr)
	}

	return result
}

// Returns exact, CNAME or wildcard answers from the selected zone.
func findRecords(
	name string,
	qtype uint16,
	includeRRSIG bool,
) []dns.RR {
	origin := lookupOriginForQuestion(name, qtype)

	if qtype == dns.TypeANY {
		result := allRecordsAtName(origin, name, includeRRSIG)
		if len(result) > 0 {
			return result
		}
		wildcard := wildcardAt(closestEncloser(origin, name))
		return synthesizeWildcardOwner(allRecordsAtName(origin, wildcard, includeRRSIG), name)
	}

	result := findRecordsInOrigin(origin, name, qtype, includeRRSIG)
	if len(result) > 0 || qtype == dns.TypeCNAME {
		return result
	}

	result = findRecordsInOrigin(origin, name, dns.TypeCNAME, includeRRSIG)
	if len(result) > 0 {
		return result
	}

	wildcard := wildcardAt(closestEncloser(origin, name))
	result = findRecordsInOrigin(origin, wildcard, qtype, includeRRSIG)
	if len(result) == 0 && qtype != dns.TypeCNAME {
		result = findRecordsInOrigin(origin, wildcard, dns.TypeCNAME, includeRRSIG)
	}
	return synthesizeWildcardOwner(result, name)
}

func synthesizeWildcardOwner(records []dns.RR, owner string) []dns.RR {
	result := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		copyRR := dns.Copy(rr)
		copyRR.Header().Name = dns.Fqdn(owner)
		result = append(result, copyRR)
	}
	return result
}

func zoneOriginForName(name string) string {
	name = strings.ToLower(dns.Fqdn(name))

	if dns.IsSubDomain("nsec3.mut.test.", name) {
		return "nsec3.mut.test."
	}

	if dns.IsSubDomain("child.mut.test.", name) {
		return "child.mut.test."
	}

	return "mut.test."
}

// Reads delegation DS records from the parent zone.
func lookupOriginForQuestion(name string, qtype uint16) string {
	name = dns.Fqdn(name)

	if (strings.EqualFold(name, "child.mut.test.") ||
		strings.EqualFold(name, "nsec3.mut.test.")) &&
		qtype == dns.TypeDS {
		return "mut.test."
	}

	return zoneOriginForName(name)
}

func exactNameExistsInOrigin(origin string, name string) bool {
	for _, rr := range recordsForOrigin(origin) {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		if strings.EqualFold(rr.Header().Name, name) {
			return true
		}
	}
	return false
}

func nameExistsInOrigin(origin string, name string) bool {
	queryName := strings.ToLower(dns.Fqdn(name))

	for _, rr := range recordsForOrigin(origin) {
		header := rr.Header()
		if header.Rrtype == dns.TypeRRSIG {
			continue
		}

		ownerName := strings.ToLower(dns.Fqdn(header.Name))
		if ownerName == queryName || dns.IsSubDomain(queryName, ownerName) {
			return true
		}
	}

	return false
}

func nameExists(name string) bool {
	return nameExistsInOrigin(zoneOriginForName(name), name)
}

func exactNameExists(name string) bool {
	return exactNameExistsInOrigin(zoneOriginForName(name), name)
}

func findSOARecords(origin string, includeRRSIG bool) []dns.RR {
	return findRecordsInOrigin(origin, origin, dns.TypeSOA, includeRRSIG)
}

func appendUniqueRRs(target []dns.RR, records ...dns.RR) []dns.RR {
	seen := make(map[string]struct{}, len(target)+len(records))
	for _, rr := range target {
		seen[rr.String()] = struct{}{}
	}
	for _, rr := range records {
		key := rr.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		target = append(target, rr)
	}
	return target
}

func denialRRSet(origin string, proof dns.RR, includeDNSSEC bool) []dns.RR {
	if proof == nil || !includeDNSSEC {
		return nil
	}

	result := []dns.RR{proof}
	for _, rr := range recordsForOrigin(origin) {
		rrsig, ok := rr.(*dns.RRSIG)
		if !ok || rrsig.TypeCovered != proof.Header().Rrtype {
			continue
		}
		if strings.EqualFold(rr.Header().Name, proof.Header().Name) {
			result = append(result, rr)
		}
	}
	return result
}

func exactNSECProof(origin string, name string) dns.RR {
	for _, rr := range recordsForOrigin(origin) {
		nsec, ok := rr.(*dns.NSEC)
		if ok && strings.EqualFold(nsec.Hdr.Name, name) {
			return rr
		}
	}
	return nil
}

func exactNSEC3Proof(origin string, name string) dns.RR {
	for _, rr := range recordsForOrigin(origin) {
		nsec3, ok := rr.(*dns.NSEC3)
		if ok && strings.EqualFold(nsec3.Hdr.Name, name) {
			return rr
		}
	}
	return nil
}

func canonicalWireLabels(name string) ([][]byte, bool) {
	wire := make([]byte, 255)
	offset, err := dns.PackDomainName(dns.Fqdn(name), wire, 0, nil, false)
	if err != nil {
		return nil, false
	}
	wire = wire[:offset]

	labels := make([][]byte, 0, dns.CountLabel(dns.Fqdn(name)))
	for index := 0; index < len(wire); {
		length := int(wire[index])
		index++
		if length == 0 {
			break
		}
		if length > 63 || index+length > len(wire) {
			return nil, false
		}

		label := append([]byte(nil), wire[index:index+length]...)
		for position, value := range label {
			if value >= 'A' && value <= 'Z' {
				label[position] = value + ('a' - 'A')
			}
		}
		labels = append(labels, label)
		index += length
	}
	return labels, true
}

// Orders DNS names by the canonical wire-label rules (RFC 4034).
func canonicalNameCompare(left string, right string) int {
	leftLabels, leftOK := canonicalWireLabels(left)
	rightLabels, rightOK := canonicalWireLabels(right)
	if !leftOK || !rightOK {
		return strings.Compare(
			strings.ToLower(dns.Fqdn(left)),
			strings.ToLower(dns.Fqdn(right)),
		)
	}

	leftIndex := len(leftLabels) - 1
	rightIndex := len(rightLabels) - 1
	for leftIndex >= 0 && rightIndex >= 0 {
		if comparison := bytes.Compare(leftLabels[leftIndex], rightLabels[rightIndex]); comparison != 0 {
			return comparison
		}
		leftIndex--
		rightIndex--
	}

	switch {
	case leftIndex < 0 && rightIndex < 0:
		return 0
	case leftIndex < 0:
		return -1
	default:
		return 1
	}
}

// Checks the exclusive NSEC interval, including wraparound.
func nsecCoversName(nsec *dns.NSEC, name string) bool {
	if nsec == nil {
		return false
	}

	owner := dns.Fqdn(nsec.Hdr.Name)
	next := dns.Fqdn(nsec.NextDomain)
	target := dns.Fqdn(name)

	if canonicalNameCompare(target, owner) == 0 || canonicalNameCompare(target, next) == 0 {
		return false
	}

	ownerToNext := canonicalNameCompare(owner, next)
	targetAfterOwner := canonicalNameCompare(target, owner) > 0
	targetBeforeNext := canonicalNameCompare(target, next) < 0

	switch {
	case ownerToNext < 0:
		return targetAfterOwner && targetBeforeNext
	case ownerToNext > 0:
		return targetAfterOwner || targetBeforeNext
	default:
		return true
	}
}

func coveringNSECProof(origin string, name string) dns.RR {
	if !dns.IsSubDomain(dns.Fqdn(origin), dns.Fqdn(name)) {
		return nil
	}

	for _, rr := range recordsForOrigin(origin) {
		nsec, ok := rr.(*dns.NSEC)
		if ok && nsecCoversName(nsec, name) {
			return rr
		}
	}
	return nil
}

func matchingNSEC3Proof(origin string, name string) dns.RR {
	for _, rr := range recordsForOrigin(origin) {
		nsec3, ok := rr.(*dns.NSEC3)
		if ok && nsec3.Match(name) {
			return rr
		}
	}
	return nil
}

func coveringNSEC3Proof(origin string, name string) dns.RR {
	for _, rr := range recordsForOrigin(origin) {
		nsec3, ok := rr.(*dns.NSEC3)
		if ok && nsec3.Cover(name) {
			return rr
		}
	}
	return nil
}

func closestEncloser(origin string, name string) string {
	labels := dns.SplitDomainName(name)
	for index := 0; index < len(labels); index++ {
		candidate := dns.Fqdn(strings.Join(labels[index:], "."))
		if nameExistsInOrigin(origin, candidate) {
			return candidate
		}
	}
	return dns.Fqdn(origin)
}

func nextCloserName(name string, closest string) string {
	nameLabels := dns.SplitDomainName(name)
	closestLabels := dns.SplitDomainName(closest)
	if len(nameLabels) <= len(closestLabels) {
		return dns.Fqdn(name)
	}
	start := len(nameLabels) - len(closestLabels) - 1
	return dns.Fqdn(strings.Join(nameLabels[start:], "."))
}

func wildcardAt(closest string) string {
	return "*." + dns.Fqdn(closest)
}

func wildcardSourceForQuery(name string, qtype uint16) (string, string, bool) {
	origin := lookupOriginForQuestion(name, qtype)
	if exactNameExistsInOrigin(origin, name) {
		return origin, "", false
	}

	wildcard := wildcardAt(closestEncloser(origin, name))
	var records []dns.RR
	if qtype == dns.TypeANY {
		records = allRecordsAtName(origin, wildcard, false)
	} else {
		records = findRecordsInOrigin(origin, wildcard, qtype, false)
		if len(records) == 0 && qtype != dns.TypeCNAME {
			records = findRecordsInOrigin(origin, wildcard, dns.TypeCNAME, false)
		}
	}
	return origin, wildcard, len(records) > 0
}

// Supplies denial records for a synthesized wildcard answer.
func signedWildcardProofRecords(name string, qtype uint16, includeDNSSEC bool) ([]dns.RR, error) {
	if !includeDNSSEC {
		return nil, nil
	}

	origin, _, synthesized := wildcardSourceForQuery(name, qtype)
	if !synthesized {
		return nil, nil
	}

	closest := closestEncloser(origin, name)
	nextCloser := nextCloserName(name, closest)
	var proofs []dns.RR
	if origin == "nsec3.mut.test." {
		proofs = []dns.RR{
			matchingNSEC3Proof(origin, closest),
			coveringNSEC3Proof(origin, nextCloser),
		}
	} else {
		proofs = []dns.RR{coveringNSECProof(origin, nextCloser)}
	}

	result := []dns.RR{}
	for index, proof := range proofs {
		if proof == nil {
			return nil, fmt.Errorf("missing wildcard DNSSEC proof component %d for %s (closest=%s next=%s)", index+1, name, closest, nextCloser)
		}
		result = appendUniqueRRs(result, denialRRSet(origin, proof, true)...)
	}
	return result, nil
}

// Preserves the laboratory's exact NSEC3 hash-owner reference behavior.
func signedNODATARecords(name string, includeDNSSEC bool) ([]dns.RR, error) {
	origin := zoneOriginForName(name)
	result := findSOARecords(origin, includeDNSSEC)
	if !includeDNSSEC {
		return result, nil
	}

	var proof dns.RR
	if origin == "nsec3.mut.test." {
		proof = exactNSEC3Proof(origin, name)
		if proof == nil {
			proof = matchingNSEC3Proof(origin, name)
		}
		if proof == nil {
			proof = coveringNSEC3Proof(origin, name)
		}
	} else {
		proof = exactNSECProof(origin, name)
		if proof == nil {
			proof = coveringNSECProof(origin, name)
		}
	}
	if proof == nil {
		return nil, fmt.Errorf("no authenticated NODATA proof for %s in %s", name, origin)
	}

	result = appendUniqueRRs(result, denialRRSet(origin, proof, true)...)
	return result, nil
}

func signedNXDOMAINRecords(name string, includeDNSSEC bool) ([]dns.RR, error) {
	origin := zoneOriginForName(name)
	result := findSOARecords(origin, includeDNSSEC)
	if !includeDNSSEC {
		return result, nil
	}

	closest := closestEncloser(origin, name)
	wildcard := wildcardAt(closest)

	if origin == "nsec3.mut.test." {
		nextCloser := nextCloserName(name, closest)
		proofs := []dns.RR{
			matchingNSEC3Proof(origin, closest),
			coveringNSEC3Proof(origin, nextCloser),
			coveringNSEC3Proof(origin, wildcard),
		}
		for index, proof := range proofs {
			if proof == nil {
				return nil, fmt.Errorf("missing NSEC3 NXDOMAIN proof component %d for %s (closest=%s next=%s wildcard=%s)", index+1, name, closest, nextCloser, wildcard)
			}
			result = appendUniqueRRs(result, denialRRSet(origin, proof, true)...)
		}
		return result, nil
	}

	proofs := []dns.RR{
		coveringNSECProof(origin, name),
		coveringNSECProof(origin, wildcard),
	}
	for index, proof := range proofs {
		if proof == nil {
			return nil, fmt.Errorf("missing NSEC NXDOMAIN proof component %d for %s (closest=%s wildcard=%s)", index+1, name, closest, wildcard)
		}
		result = appendUniqueRRs(result, denialRRSet(origin, proof, true)...)
	}
	return result, nil
}

func queryDO(request *dns.Msg) bool {
	opt := request.IsEdns0()

	if opt == nil {
		return false
	}

	return opt.Do()
}

func responseEDE(response *dns.Msg) (bool, uint16, string) {
	opt := response.IsEdns0()

	if opt == nil {
		return false, 0, ""
	}

	for _, option := range opt.Option {
		ede, ok := option.(*dns.EDNS0_EDE)
		if !ok {
			continue
		}

		return true, ede.InfoCode, ede.ExtraText
	}

	return false, 0, ""
}

func rrTypes(records []dns.RR) []string {
	var result []string

	for _, rr := range records {
		name := dns.TypeToString[rr.Header().Rrtype]
		if name == "" {
			name = fmt.Sprintf("TYPE%d", rr.Header().Rrtype)
		}
		result = append(result, name)
	}

	return result
}

func responseContains(response *dns.Msg) (bool, bool, bool, bool, bool, bool) {
	containsRRSIG := false
	containsDNSKEY := false
	containsDS := false
	containsNSEC := false
	containsNSEC3 := false
	containsSOA := false

	allRecords := append([]dns.RR{}, response.Answer...)
	allRecords = append(allRecords, response.Ns...)
	allRecords = append(allRecords, response.Extra...)

	for _, rr := range allRecords {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG:
			containsRRSIG = true
		case dns.TypeDNSKEY:
			containsDNSKEY = true
		case dns.TypeDS:
			containsDS = true
		case dns.TypeNSEC:
			containsNSEC = true
		case dns.TypeNSEC3:
			containsNSEC3 = true
		case dns.TypeSOA:
			containsSOA = true
		}
	}

	return containsRRSIG, containsDNSKEY, containsDS, containsNSEC, containsNSEC3, containsSOA
}

func requestUDPPayloadSize(request *dns.Msg) uint16 {
	if opt := request.IsEdns0(); opt != nil {
		if opt.UDPSize() > 0 {
			return opt.UDPSize()
		}
	}

	return 512
}

func maybeTruncateForUDP(response *dns.Msg, request *dns.Msg, network string) *dns.Msg {
	if network != "udp" {
		return response
	}

	limit := int(requestUDPPayloadSize(request))
	wire, err := response.Pack()
	if err != nil {
		return response
	}

	if len(wire) <= limit {
		return response
	}

	truncated := new(dns.Msg)
	truncated.SetReply(request)
	truncated.Authoritative = response.Authoritative
	truncated.AuthenticatedData = response.AuthenticatedData
	truncated.CheckingDisabled = response.CheckingDisabled
	truncated.RecursionAvailable = response.RecursionAvailable
	truncated.Truncated = true
	truncated.Rcode = response.Rcode

	if requestOpt := request.IsEdns0(); requestOpt != nil {
		truncated.SetEdns0(requestOpt.UDPSize(), requestOpt.Do())
	}

	return truncated
}

func messageWireMetadata(message *dns.Msg) (int, string) {
	wire, err := message.Pack()
	if err != nil {
		return 0, ""
	}
	hash := sha256.Sum256(wire)
	return len(wire), hex.EncodeToString(hash[:])
}

func optCount(records []dns.RR) int {
	count := 0
	for _, rr := range records {
		if rr.Header().Rrtype == dns.TypeOPT {
			count++
		}
	}
	return count
}

func isPrintableUTF8(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	for _, char := range string(data) {
		if char == '\n' || char == '\r' || char == '\t' {
			continue
		}
		if !unicode.IsPrint(char) {
			return false
		}
	}
	return true
}

func setEDNSOptionPayloadMetadata(info *EDNSOptionInfo, data []byte) {
	info.Length = len(data)
	info.DataHex = hex.EncodeToString(data)
	digest := sha256.Sum256(data)
	info.DataSHA256 = hex.EncodeToString(digest[:])
	info.UTF8Valid = utf8.Valid(data)
	info.PrintableUTF8 = isPrintableUTF8(data)
	if info.PrintableUTF8 {
		info.UTF8Text = string(data)
	}
}

func ednsOptionInfoFromRRs(records []dns.RR) []EDNSOptionInfo {
	var result []EDNSOptionInfo
	for _, rr := range records {
		opt, ok := rr.(*dns.OPT)
		if !ok {
			continue
		}
		for _, option := range opt.Option {
			info := EDNSOptionInfo{Code: option.Option(), Name: ednsOptionName(option.Option())}
			switch value := option.(type) {
			case *dns.EDNS0_PADDING:
				setEDNSOptionPayloadMetadata(&info, value.Padding)
			case *dns.EDNS0_LOCAL:
				setEDNSOptionPayloadMetadata(&info, value.Data)
			case *dns.EDNS0_COOKIE:
				cookieData, err := hex.DecodeString(value.Cookie)
				if err != nil {
					setEDNSOptionPayloadMetadata(&info, []byte(value.Cookie))
				} else {
					setEDNSOptionPayloadMetadata(&info, cookieData)
				}
			case *dns.EDNS0_EDE:
				data := make([]byte, 2+len([]byte(value.ExtraText)))
				binary.BigEndian.PutUint16(data, value.InfoCode)
				copy(data[2:], []byte(value.ExtraText))
				setEDNSOptionPayloadMetadata(&info, data)
			case *dns.EDNS0_NSID:
				data, err := hex.DecodeString(value.Nsid)
				if err != nil {
					data = []byte(value.Nsid)
				}
				setEDNSOptionPayloadMetadata(&info, data)
			case *dns.EDNS0_SUBNET:
				address := value.Address.To4()
				if value.Family == 2 {
					address = value.Address.To16()
				}
				addressBytes := int((value.SourceNetmask + 7) / 8)
				data := make([]byte, 4+addressBytes)
				binary.BigEndian.PutUint16(data, value.Family)
				data[2], data[3] = value.SourceNetmask, value.SourceScope
				if addressBytes > 0 && len(address) >= addressBytes {
					copy(data[4:], address[:addressBytes])
				}
				setEDNSOptionPayloadMetadata(&info, data)
			case *dns.EDNS0_DAU:
				setEDNSOptionPayloadMetadata(&info, []byte(value.AlgCode))
			case *dns.EDNS0_DHU:
				setEDNSOptionPayloadMetadata(&info, []byte(value.AlgCode))
			case *dns.EDNS0_N3U:
				setEDNSOptionPayloadMetadata(&info, []byte(value.AlgCode))
			}
			result = append(result, info)
		}
	}
	return result
}

func ednsOptionName(code uint16) string {
	switch code {
	case 3:
		return "nsid"
	case 5:
		return "dau"
	case 6:
		return "dhu"
	case 7:
		return "n3u"
	case 8:
		return "ecs"
	case 10:
		return "cookie"
	case dns.EDNS0PADDING:
		return "padding"
	case 14:
		return "key_tag"
	case dns.EDNS0EDE:
		return "ede"
	case 65001:
		return "private_use_65001"
	default:
		return fmt.Sprintf("option_%d", code)
	}
}

func decodeHexLength(value string) int {
	if value == "" {
		return 0
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return 0
	}
	return len(decoded)
}

type TKEYDetails struct {
	Present     bool
	Count       int
	Mode        uint16
	Error       uint16
	Algorithm   string
	KeyLength   int
	OtherLength int
	Section     string
	Owner       string
	Class       string
	TTL         uint32
	Inception   uint32
	Expiration  uint32
}

type KEYDetails struct {
	Present   bool
	Count     int
	Section   string
	Owner     string
	Algorithm uint8
}

func rrSection(message *dns.Msg, target dns.RR) string {
	for _, rr := range message.Answer {
		if rr == target {
			return "answer"
		}
	}
	for _, rr := range message.Ns {
		if rr == target {
			return "authority"
		}
	}
	for _, rr := range message.Extra {
		if rr == target {
			return "additional"
		}
	}
	return ""
}

func tkeyDetails(message *dns.Msg) TKEYDetails {
	details := TKEYDetails{}
	for _, rr := range messageRecords(message) {
		tkey, ok := rr.(*dns.TKEY)
		if !ok {
			continue
		}
		details.Count++
		if details.Present {
			continue
		}
		details.Present = true
		details.Mode = tkey.Mode
		details.Error = tkey.Error
		details.Algorithm = tkey.Algorithm
		details.KeyLength = decodeHexLength(tkey.Key)
		details.OtherLength = decodeHexLength(tkey.OtherData)
		details.Section = rrSection(message, rr)
		details.Owner = tkey.Hdr.Name
		details.Class = dns.ClassToString[tkey.Hdr.Class]
		details.TTL = tkey.Hdr.Ttl
		details.Inception = tkey.Inception
		details.Expiration = tkey.Expiration
	}
	return details
}

func keyDetails(message *dns.Msg) KEYDetails {
	details := KEYDetails{}
	for _, rr := range messageRecords(message) {
		key, ok := rr.(*dns.KEY)
		if !ok {
			continue
		}
		details.Count++
		if details.Present {
			continue
		}
		details.Present = true
		details.Section = rrSection(message, rr)
		details.Owner = key.Hdr.Name
		details.Algorithm = key.Algorithm
	}
	return details
}

func rcodeMetadata(message *dns.Msg) (string, int, int, int) {
	numeric := message.Rcode
	base := numeric & 0x0f
	extended := numeric >> 4
	if numeric == 16 && message.IsEdns0() != nil {
		return "BADVERS", numeric, base, extended
	}
	if text, ok := dns.RcodeToString[numeric]; ok && text != "" {
		return text, numeric, base, extended
	}
	return fmt.Sprintf("RCODE%d", numeric), numeric, base, extended
}

func messageRecords(message *dns.Msg) []dns.RR {
	result := append([]dns.RR{}, message.Answer...)
	result = append(result, message.Ns...)
	result = append(result, message.Extra...)
	return result
}

func tkeySection(message *dns.Msg) string {
	for _, rr := range message.Answer {
		if _, ok := rr.(*dns.TKEY); ok {
			return "answer"
		}
	}
	for _, rr := range message.Ns {
		if _, ok := rr.(*dns.TKEY); ok {
			return "authority"
		}
	}
	for _, rr := range message.Extra {
		if _, ok := rr.(*dns.TKEY); ok {
			return "additional"
		}
	}
	return ""
}

func requestKEYInAdditional(message *dns.Msg) *dns.KEY {
	for _, rr := range message.Extra {
		if key, ok := rr.(*dns.KEY); ok {
			return key
		}
	}
	return nil
}

func tkeyErrorResponse(question dns.Question, requestTKEY *dns.TKEY, errorCode uint16) *dns.TKEY {
	algorithm := "hmac-sha256."
	mode := uint16(0)
	if requestTKEY != nil {
		if requestTKEY.Algorithm != "" {
			algorithm = requestTKEY.Algorithm
		}
		mode = requestTKEY.Mode
	}
	return &dns.TKEY{
		Hdr:       dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTKEY, Class: dns.ClassANY, Ttl: 0},
		Algorithm: algorithm,
		Mode:      mode,
		Error:     errorCode,
	}
}

func handleTKEYRequest(response *dns.Msg, request *dns.Msg, question dns.Question) {
	response.Authoritative = true
	if question.Qclass != dns.ClassANY {
		response.SetRcode(request, dns.RcodeFormatError)
		fmt.Printf("Response: FORMERR - TKEY QCLASS must be ANY, got %s\n", dns.ClassToString[question.Qclass])
		return
	}

	details := tkeyDetails(request)
	if details.Count != 1 {
		response.SetRcode(request, dns.RcodeFormatError)
		fmt.Printf("Response: FORMERR - expected exactly one TKEY RR, got %d\n", details.Count)
		return
	}
	if details.Section != "additional" {
		response.SetRcode(request, dns.RcodeFormatError)
		fmt.Printf("Response: FORMERR - TKEY RR must be in Additional, got %s\n", details.Section)
		return
	}

	var requestTKEY *dns.TKEY
	for _, rr := range messageRecords(request) {
		if value, ok := rr.(*dns.TKEY); ok {
			requestTKEY = value
			break
		}
	}
	if requestTKEY == nil {
		response.SetRcode(request, dns.RcodeFormatError)
		return
	}

	if requestTKEY.Mode < 1 || requestTKEY.Mode > 5 {
		response.SetRcode(request, dns.RcodeSuccess)
		response.Answer = append(response.Answer, tkeyErrorResponse(question, requestTKEY, 19))
		fmt.Printf("Response: NOERROR + TKEY BADMODE for mode %d\n", requestTKEY.Mode)
		return
	}

	key := requestKEYInAdditional(request)
	switch requestTKEY.Mode {
	case 1:
		if key == nil {
			response.SetRcode(request, dns.RcodeFormatError)
			fmt.Println("Response: FORMERR - server-assignment mode without KEY RR")
			return
		}
		response.SetRcode(request, dns.RcodeNotAuth)
		fmt.Println("Response: NOTAUTH - server-assignment probe is unauthenticated")
	case 2:
		if key == nil {
			response.SetRcode(request, dns.RcodeFormatError)
			fmt.Println("Response: FORMERR - TKEY DH mode without DH KEY RR")
			return
		}
		if key.Algorithm != 2 {
			response.SetRcode(request, dns.RcodeSuccess)
			response.Answer = append(response.Answer, tkeyErrorResponse(question, requestTKEY, 17))
			fmt.Printf("Response: NOERROR + TKEY BADKEY for KEY algorithm %d\n", key.Algorithm)
			return
		}
		response.SetRcode(request, dns.RcodeNotImplemented)
		fmt.Println("Response: NOTIMP - controlled server does not complete DH state establishment")
	case 3:
		if !equalDNSName(requestTKEY.Algorithm, "gss-tsig.") {
			response.SetRcode(request, dns.RcodeSuccess)
			response.Answer = append(response.Answer, tkeyErrorResponse(question, requestTKEY, 21))
			fmt.Printf("Response: NOERROR + TKEY BADALG for GSS mode algorithm %s\n", requestTKEY.Algorithm)
			return
		}
		if requestTKEY.Error != 0 {
			response.SetRcode(request, dns.RcodeFormatError)
			fmt.Printf("Response: FORMERR - query TKEY Error field must be zero, got %d\n", requestTKEY.Error)
			return
		}
		response.SetRcode(request, dns.RcodeNotImplemented)
		fmt.Println("Response: NOTIMP - controlled server does not implement GSS-API state establishment")
	case 4:
		if key == nil {
			response.SetRcode(request, dns.RcodeFormatError)
			fmt.Println("Response: FORMERR - resolver-assignment mode without KEY RR")
			return
		}
		response.SetRcode(request, dns.RcodeNotAuth)
		fmt.Println("Response: NOTAUTH - resolver-assignment probe is unauthenticated")
	case 5:
		response.SetRcode(request, dns.RcodeNotAuth)
		fmt.Println("Response: NOTAUTH - key deletion probe is unauthenticated")
	}
}

func handleDNSRequest(
	writer dns.ResponseWriter,
	request *dns.Msg,
) {
	response := new(dns.Msg)
	response.SetReply(request)

	network := "unknown"

	if writer.RemoteAddr() != nil {
		switch writer.RemoteAddr().(type) {
		case *net.UDPAddr:
			network = "udp"
		case *net.TCPAddr:
			network = "tcp"
		}
	}

	if len(request.Question) != 1 {
		response.SetRcode(request, dns.RcodeFormatError)
		response.Authoritative = false
		fmt.Printf("Response: FORMERR - expected one question, got %d\n", len(request.Question))
		if err := writer.WriteMsg(response); err != nil {
			log.Printf("failed to send DNS response: %v", err)
		}
		return
	}

	for _, question := range request.Question {
		fmt.Println("--------------------------------------------------")
		fmt.Printf("Transport: %s\n", network)
		fmt.Printf("QNAME:     %s\n", question.Name)
		fmt.Printf("QTYPE:     %s\n", dns.TypeToString[question.Qtype])
		fmt.Printf("RD:        %t\n", request.RecursionDesired)
		fmt.Printf("AD:        %t\n", request.AuthenticatedData)
		fmt.Printf("CD:        %t\n", request.CheckingDisabled)

		opt := request.IsEdns0()

		if opt == nil {
			fmt.Println("EDNS:      false")
			fmt.Println("DO:        false")
		} else {
			fmt.Println("EDNS:      true")
			fmt.Printf("EDNS Ver:  %d\n", opt.Version())
			fmt.Printf("UDP Size:  %d\n", opt.UDPSize())
			fmt.Printf("DO:        %t\n", opt.Do())
		}

		switch {

		case opt != nil && opt.Version() != 0:
			response.SetRcode(request, 16)
			response.Authoritative = true
			response.SetEdns0(opt.UDPSize(), false)
			if responseOpt := response.IsEdns0(); responseOpt != nil {
				responseOpt.SetVersion(0)
			}
			fmt.Printf("Response: BADVERS for EDNS version %d\n", opt.Version())

		case question.Qtype == dns.TypeTKEY:
			handleTKEYRequest(response, request, question)

		case isWithinMutTest(question.Name):

			doRequested := queryDO(request)

			records := findRecords(
				question.Name,
				question.Qtype,
				doRequested,
			)

			if len(records) == 0 {
				response.Authoritative = true

				if nameExists(question.Name) {
					response.Rcode = dns.RcodeSuccess
					denial, denialErr := signedNODATARecords(question.Name, doRequested)
					if denialErr != nil {
						response.SetRcode(request, dns.RcodeServerFailure)
						fmt.Printf("Response: SERVFAIL - %v\n", denialErr)
						break
					}
					response.Ns = append(response.Ns, denial...)
					fmt.Printf(
						"Response: NOERROR/NODATA, exact_owner=%t, authority_records=%d, DO=%t\n",
						exactNameExists(question.Name),
						len(response.Ns),
						doRequested,
					)
				} else {
					denial, denialErr := signedNXDOMAINRecords(question.Name, doRequested)
					if denialErr != nil {
						response.SetRcode(request, dns.RcodeServerFailure)
						fmt.Printf("Response: SERVFAIL - %v\n", denialErr)
						break
					}
					response.SetRcode(request, dns.RcodeNameError)
					response.Ns = append(response.Ns, denial...)
					fmt.Printf(
						"Response: NXDOMAIN with minimal signed denial, authority_records=%d, DO=%t\n",
						len(response.Ns),
						doRequested,
					)
				}

				break
			}

			response.Answer = append(
				response.Answer,
				records...,
			)

			wildcardProof, wildcardProofErr := signedWildcardProofRecords(
				question.Name,
				question.Qtype,
				doRequested,
			)
			if wildcardProofErr != nil {
				response.Answer = nil
				response.Ns = nil
				response.SetRcode(request, dns.RcodeServerFailure)
				fmt.Printf("Response: SERVFAIL - %v\n", wildcardProofErr)
				break
			}
			response.Ns = append(response.Ns, wildcardProof...)

			response.Authoritative = true

			fmt.Printf(
				"Response: NOERROR, records=%d, wildcard_proof_records=%d, DO=%t\n",
				len(records),
				len(wildcardProof),
				doRequested,
			)

		default:
			response.SetRcode(request, dns.RcodeRefused)
			response.Authoritative = false
			fmt.Println("Response: REFUSED - name outside controlled zones")
		}
	}

	response = maybeTruncateForUDP(response, request, network)

	if len(request.Question) > 0 {
		question := request.Question[0]

		ednsPresent := false
		ednsVersion := -1
		udpPayloadSize := uint16(0)
		doRequested := false
		ednsZFlags := uint16(0)
		ednsExtendedRcode := uint8(0)
		ednsOwnerName := ""

		if opt := request.IsEdns0(); opt != nil {
			ednsPresent = true
			ednsVersion = int(opt.Version())
			udpPayloadSize = opt.UDPSize()
			doRequested = opt.Do()
			ednsZFlags = uint16(opt.Hdr.Ttl & 0x7fff)
			ednsExtendedRcode = uint8((opt.Hdr.Ttl >> 24) & 0xff)
			ednsOwnerName = opt.Hdr.Name
		}

		source := ""
		destination := ""

		if writer.RemoteAddr() != nil {
			source = writer.RemoteAddr().String()
		}

		if writer.LocalAddr() != nil {
			destination = writer.LocalAddr().String()
		}

		qtypeName := dns.TypeToString[question.Qtype]
		if qtypeName == "" {
			qtypeName = fmt.Sprintf("TYPE%d", question.Qtype)
		}

		qclassName := dns.ClassToString[question.Qclass]
		if qclassName == "" {
			qclassName = fmt.Sprintf("CLASS%d", question.Qclass)
		}
		opcodeName := dns.OpcodeToString[request.Opcode]
		if opcodeName == "" {
			opcodeName = fmt.Sprintf("OPCODE%d", request.Opcode)
		}
		requestRcodeName := dns.RcodeToString[request.Rcode]
		if requestRcodeName == "" {
			requestRcodeName = fmt.Sprintf("RCODE%d", request.Rcode)
		}

		edePresent, edeInfoCode, edeText := responseEDE(response)

		requestWireSize, requestWireSHA256 := messageWireMetadata(request)
		requestTKEY := tkeyDetails(request)
		requestKEY := keyDetails(request)
		responseTKEY := tkeyDetails(response)
		responseRcode, responseRcodeNumeric, responseRcodeBase, responseRcodeExtended := rcodeMetadata(response)

		responseSizeBytes, responseWireSHA256 := messageWireMetadata(response)
		containsRRSIG, containsDNSKEY, containsDS, containsNSEC, containsNSEC3, containsSOA := responseContains(response)

		writeAuthoritativeLog(AuthoritativeLogEvent{
			Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
			Direction:   "q_upstream",
			Transport:   network,
			Source:      source,
			Destination: destination,
			MessageID:   request.Id,

			QName:         question.Name,
			QType:         qtypeName,
			QTypeNumeric:  question.Qtype,
			QClass:        qclassName,
			QClassNumeric: question.Qclass,

			RD:                     request.RecursionDesired,
			AD:                     request.AuthenticatedData,
			CD:                     request.CheckingDisabled,
			QR:                     request.Response,
			AA:                     request.Authoritative,
			TC:                     request.Truncated,
			RA:                     request.RecursionAvailable,
			Z:                      request.Zero,
			Opcode:                 request.Opcode,
			OpcodeName:             opcodeName,
			RequestRcode:           request.Rcode,
			RequestRcodeName:       requestRcodeName,
			RequestQuestionCount:   len(request.Question),
			RequestAnswerCount:     len(request.Answer),
			RequestAuthorityCount:  len(request.Ns),
			RequestAdditionalCount: len(request.Extra),

			RequestWireSize:          requestWireSize,
			RequestWireSHA256:        requestWireSHA256,
			RequestOPTCount:          optCount(request.Extra),
			RequestEDNSOptions:       ednsOptionInfoFromRRs(request.Extra),
			RequestAdditionalRRTypes: rrTypes(request.Extra),

			RequestTKEYPresent:     requestTKEY.Present,
			RequestTKEYCount:       requestTKEY.Count,
			RequestTKEYMode:        requestTKEY.Mode,
			RequestTKEYError:       requestTKEY.Error,
			RequestTKEYAlgorithm:   requestTKEY.Algorithm,
			RequestTKEYKeyLength:   requestTKEY.KeyLength,
			RequestTKEYOtherLength: requestTKEY.OtherLength,
			RequestTKEYSection:     requestTKEY.Section,
			RequestTKEYOwner:       requestTKEY.Owner,
			RequestTKEYClass:       requestTKEY.Class,
			RequestTKEYTTL:         requestTKEY.TTL,
			RequestTKEYInception:   requestTKEY.Inception,
			RequestTKEYExpiration:  requestTKEY.Expiration,
			RequestKEYPresent:      requestKEY.Present,
			RequestKEYCount:        requestKEY.Count,
			RequestKEYSection:      requestKEY.Section,
			RequestKEYOwner:        requestKEY.Owner,
			RequestKEYAlgorithm:    requestKEY.Algorithm,

			EDNSPresent:       ednsPresent,
			EDNSVersion:       ednsVersion,
			UDPPayloadSize:    udpPayloadSize,
			DO:                doRequested,
			EDNSZFlags:        ednsZFlags,
			EDNSExtendedRcode: ednsExtendedRcode,
			EDNSOwnerName:     ednsOwnerName,

			ResponseMessageID:     response.Id,
			ResponseRcode:         responseRcode,
			ResponseRcodeNumeric:  responseRcodeNumeric,
			ResponseRcodeBase:     responseRcodeBase,
			ResponseRcodeExtended: responseRcodeExtended,

			ResponseAA: response.Authoritative,
			ResponseAD: response.AuthenticatedData,
			ResponseCD: response.CheckingDisabled,
			ResponseRD: response.RecursionDesired,
			ResponseRA: response.RecursionAvailable,
			ResponseTC: response.Truncated,

			ResponseSizeBytes:  responseSizeBytes,
			ResponseWireSHA256: responseWireSHA256,

			ResponseAnswerCount:     len(response.Answer),
			ResponseAuthorityCount:  len(response.Ns),
			ResponseAdditionalCount: len(response.Extra),

			ResponseAnswerRRTypes:     rrTypes(response.Answer),
			ResponseAuthorityRRTypes:  rrTypes(response.Ns),
			ResponseAdditionalRRTypes: rrTypes(response.Extra),

			ResponseContainsRRSIG:  containsRRSIG,
			ResponseContainsDNSKEY: containsDNSKEY,
			ResponseContainsDS:     containsDS,
			ResponseContainsNSEC:   containsNSEC,
			ResponseContainsNSEC3:  containsNSEC3,
			ResponseContainsSOA:    containsSOA,

			ResponseEDEPresent:  edePresent,
			ResponseEDEInfoCode: edeInfoCode,
			ResponseEDEText:     edeText,

			ResponseTKEYPresent:     responseTKEY.Present,
			ResponseTKEYCount:       responseTKEY.Count,
			ResponseTKEYMode:        responseTKEY.Mode,
			ResponseTKEYError:       responseTKEY.Error,
			ResponseTKEYAlgorithm:   responseTKEY.Algorithm,
			ResponseTKEYKeyLength:   responseTKEY.KeyLength,
			ResponseTKEYOtherLength: responseTKEY.OtherLength,
			ResponseTKEYSection:     responseTKEY.Section,
		})
	}

	if err := writer.WriteMsg(response); err != nil {
		log.Printf(
			"failed to send DNS response: %v",
			err,
		)
	}
}

func startServer(
	network string,
) *dns.Server {
	server := &dns.Server{
		Addr:    listenAddress,
		Net:     network,
		Handler: dns.HandlerFunc(handleDNSRequest),
	}

	go func() {
		log.Printf(
			"starting DNS server on %s/%s",
			listenAddress,
			network,
		)

		if err := server.ListenAndServe(); err != nil {
			log.Fatalf(
				"%s server failed: %v",
				network,
				err,
			)
		}
	}()

	return server
}

func main() {
	if err := loadSignedZone(parentZoneFilePath, "mut.test."); err != nil {
		log.Fatalf("could not load parent signed zone: %v", err)
	}

	if err := loadSignedZone(childZoneFilePath, "child.mut.test."); err != nil {
		log.Fatalf("could not load child signed zone: %v", err)
	}

	if err := loadSignedZone(nsec3ZoneFilePath, "nsec3.mut.test."); err != nil {
		log.Fatalf("could not load nsec3 signed zone: %v", err)
	}

	fmt.Println("Minimal DNS Test Server")
	fmt.Println("Listening on UDP and TCP port 53")

	startServer("udp")
	startServer("tcp")

	select {}
}
