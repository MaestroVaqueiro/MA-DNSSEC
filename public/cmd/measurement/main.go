package main

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const largeRunThreshold = 100

type profile struct {
	Description    string     `json:"description"`
	ControlledZone string     `json:"controlled_zone"`
	Cases          []testCase `json:"cases"`
}

type testCase struct {
	Number                     int         `json:"number"`
	CaseID                     string      `json:"case_id"`
	Group                      string      `json:"group"`
	Purpose                    string      `json:"purpose"`
	RemoteAdaptation           string      `json:"remote_adaptation,omitempty"`
	QNameTemplate              string      `json:"qname_template"`
	QNameStrategy              string      `json:"qname_strategy"`
	QType                      string      `json:"qtype"`
	QClass                     string      `json:"qclass"`
	RD                         bool        `json:"rd"`
	AD                         bool        `json:"ad"`
	CD                         bool        `json:"cd"`
	EDNS                       ednsConfig  `json:"edns"`
	TKEY                       *tkeyConfig `json:"tkey,omitempty"`
	AuthoritativeMatchExpected bool        `json:"authoritative_match_expected"`
}

type ednsConfig struct {
	Present bool         `json:"present"`
	DO      bool         `json:"do"`
	UDPSize uint16       `json:"udp_size"`
	Options []ednsOption `json:"options"`
}

type ednsOption struct {
	Code    uint16 `json:"code"`
	DataHex string `json:"data_hex"`
}

type tkeyConfig struct {
	IncludeRR  bool   `json:"include_rr"`
	Section    string `json:"section"`
	Algorithm  string `json:"algorithm"`
	Mode       uint16 `json:"mode"`
	KeyDataHex string `json:"key_data_hex"`
}

type resolver struct {
	ID                    string
	IP                    string
	AddressFamily         string
	AuthoritativeObserved bool
	ProviderDNSSECLabel   bool
}

type plannedProbe struct {
	RunID    string
	Resolver resolver
	Case     testCase
	QName    string
}

type responseSummary struct {
	Received        bool
	Rcode           string
	TC              bool
	RA              bool
	AD              bool
	CD              bool
	EDNS            bool
	DO              bool
	UDPSize         uint16
	SizeBytes       int
	AnswerCount     int
	AuthorityCount  int
	AdditionalCount int
	AnswerTypes     string
	OptionCodes     string
	TKEYCount       int
	TKEYMode        uint16
	TKEYAlgorithm   string
	TKEYKeySize     uint16
}

type measurementResult struct {
	Plan           plannedProbe
	TimestampUTC   string
	UDP            responseSummary
	UDPTimeMS      int64
	UDPErr         string
	TCPRetry       bool
	TCP            responseSummary
	TCPTimeMS      int64
	TCPErr         string
	FinalTransport string
	Final          responseSummary
	TotalTimeMS    int64
}

var resultHeader = []string{
	"run_id", "resolver_id", "ip", "address_family", "preflight_authoritative_observed", "provider_dnssec_label",
	"case_number", "case_id", "case_group", "qname", "qname_strategy", "qtype", "qclass",
	"request_rd", "request_ad", "request_cd", "request_edns", "request_do", "request_udp_size", "request_option_codes",
	"probe_timestamp_utc", "udp_response_received", "udp_rcode", "udp_tc", "udp_ra", "udp_ad", "udp_cd",
	"udp_response_edns", "udp_response_do", "udp_response_udp_size", "udp_response_size_bytes", "udp_query_time_ms", "udp_error",
	"tcp_retry_sent", "tcp_response_received", "tcp_rcode", "tcp_response_size_bytes", "tcp_query_time_ms", "tcp_error",
	"final_transport", "final_rcode", "final_tc", "final_ra", "final_ad", "final_cd", "final_response_edns", "final_response_do",
	"final_response_udp_size", "final_response_size_bytes", "answer_count", "authority_count", "additional_count", "answer_types",
	"response_option_codes", "response_tkey_count", "response_tkey_mode", "response_tkey_algorithm", "response_tkey_key_size", "total_query_time_ms",
}

func main() {
	configPath := flag.String("config", "config/measurement_cases.json", "23-case measurement profile")
	resolverPath := flag.String("resolvers", "ListofResolver/eligible_resolvers.csv", "eligible resolver CSV")
	outputDir := flag.String("output", "results", "base result directory")
	only := flag.String("only", "", "select one resolver ID or IP")
	resolverIDs := flag.String("resolver-ids", "", "comma-separated resolver IDs for a non-contiguous pilot selection")
	startAt := flag.String("start-at", "", "start at this resolver ID")
	limit := flag.Int("limit", 0, "maximum selected resolvers; zero means all")
	caseFilter := flag.String("cases", "", "comma-separated case IDs; empty means all 23")
	tkeyPair := flag.Bool("tkey-pair", false, "paired TKEY RR comparison for cases 21 and 22; two opposite-order pairs per resolver")
	runIDFlag := flag.String("run-id", "", "unique run ID; generated when empty")
	timeout := flag.Duration("timeout", 3*time.Second, "timeout for each UDP or TCP transaction")
	delay := flag.Duration("delay", 250*time.Millisecond, "pause between planned probes")
	staticCacheGap := flag.Duration("static-cache-gap", 65*time.Second, "minimum gap before repeating the same static QNAME and QTYPE at one resolver")
	allowLarge := flag.Bool("allow-large-run", false, "explicitly permit more than 100 resolvers")
	execute := flag.Bool("execute", false, "send the measurement queries")
	flag.Parse()

	if *limit < 0 || *timeout <= 0 || *delay < 0 || *staticCacheGap < 0 {
		fatal(errors.New("limit, timeout, delay, or static-cache-gap is invalid"))
	}
	selectionModes := 0
	for _, value := range []string{*only, *resolverIDs, *startAt} {
		if strings.TrimSpace(value) != "" {
			selectionModes++
		}
	}
	if selectionModes > 1 {
		fatal(errors.New("only, resolver-ids, and start-at cannot be combined"))
	}

	p, err := loadProfile(*configPath)
	if err != nil {
		fatal(err)
	}
	cases, err := selectCases(p.Cases, *caseFilter)
	if err != nil {
		fatal(err)
	}
	if *tkeyPair {
		if err := validateTKEYPairCases(cases); err != nil {
			fatal(err)
		}
	}
	resolvers, err := loadResolvers(*resolverPath)
	if err != nil {
		fatal(err)
	}
	resolvers, err = selectResolvers(resolvers, *only, *resolverIDs, *startAt, *limit)
	if err != nil {
		fatal(err)
	}

	plannedCount := len(resolvers) * len(cases)
	if *tkeyPair {
		plannedCount *= 2
	}
	if !*execute {
		fmt.Printf("Loaded %d eligible resolvers; selected %d resolvers and %d cases (%d planned probes). No DNS queries sent.\n", lenMustLoadResolvers(*resolverPath), len(resolvers), len(cases), plannedCount)
		return
	}
	if len(resolvers) > largeRunThreshold && !*allowLarge {
		fatal(fmt.Errorf("selected %d resolvers; use -allow-large-run only after the pilot has been reviewed", len(resolvers)))
	}

	runID := strings.TrimSpace(*runIDFlag)
	if runID == "" {
		runID = time.Now().UTC().Format("20060102T150405Z")
	}
	if err := validateRunID(runID); err != nil {
		fatal(err)
	}
	runDir := filepath.Join(*outputDir, runID)
	if _, err := os.Stat(runDir); err == nil {
		fatal(fmt.Errorf("run directory already exists: %s", runDir))
	} else if !os.IsNotExist(err) {
		fatal(err)
	}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		fatal(err)
	}

	plans, err := planProbes(runID, resolvers, cases)
	if *tkeyPair {
		plans, err = planPairedTKEYProbes(runID, resolvers, cases)
	}
	if err != nil {
		fatal(err)
	}
	if err := writeManifest(filepath.Join(runDir, "measurement_manifest.csv"), plans); err != nil {
		fatal(err)
	}
	writer, err := newResultWriter(filepath.Join(runDir, "measurement_results.csv"))
	if err != nil {
		fatal(err)
	}

	lastStatic := map[string]time.Time{}
	for i, plan := range plans {
		if plan.Case.QNameStrategy == "static_context" && *staticCacheGap > 0 {
			key := plan.Resolver.IP + "|" + strings.ToLower(plan.QName) + "|" + strings.ToUpper(plan.Case.QType)
			if previous, ok := lastStatic[key]; ok {
				if wait := *staticCacheGap - time.Since(previous); wait > 0 {
					time.Sleep(wait)
				}
			}
			lastStatic[key] = time.Now()
		}
		result := executeProbe(plan, *timeout)
		if err := writer.Write(result); err != nil {
			writer.Close()
			fatal(err)
		}
		fmt.Printf("[%d/%d] %s %s %s: response=%t rcode=%s transport=%s\n", i+1, len(plans), plan.Resolver.ID, plan.Case.CaseID, plan.Resolver.IP, result.Final.Received, result.Final.Rcode, result.FinalTransport)
		if i+1 < len(plans) && *delay > 0 {
			time.Sleep(*delay)
		}
	}
	if err := writer.Close(); err != nil {
		fatal(err)
	}
	fmt.Printf("Finished measurement: %d probes for %d resolvers and %d cases. Results: %s\n", len(plans), len(resolvers), len(cases), filepath.Join(runDir, "measurement_results.csv"))
}

func loadProfile(path string) (profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return profile{}, fmt.Errorf("read profile: %w", err)
	}
	var p profile
	if err := json.Unmarshal(b, &p); err != nil {
		return profile{}, fmt.Errorf("parse profile: %w", err)
	}
	if len(p.Cases) != 23 {
		return profile{}, fmt.Errorf("profile has %d cases; expected 23", len(p.Cases))
	}
	seenNumber, seenID := map[int]bool{}, map[string]bool{}
	for _, c := range p.Cases {
		if c.Number < 1 || seenNumber[c.Number] {
			return profile{}, fmt.Errorf("invalid or duplicate case number %d", c.Number)
		}
		if c.CaseID == "" || seenID[c.CaseID] {
			return profile{}, fmt.Errorf("invalid or duplicate case ID %q", c.CaseID)
		}
		seenNumber[c.Number], seenID[c.CaseID] = true, true
		if _, ok := dns.StringToType[strings.ToUpper(c.QType)]; !ok {
			return profile{}, fmt.Errorf("case %s has unknown QTYPE %q", c.CaseID, c.QType)
		}
		if _, ok := dns.StringToClass[strings.ToUpper(c.QClass)]; !ok {
			return profile{}, fmt.Errorf("case %s has unknown QCLASS %q", c.CaseID, c.QClass)
		}
		if c.QNameStrategy != "unique" && c.QNameStrategy != "static_context" {
			return profile{}, fmt.Errorf("case %s has invalid qname strategy", c.CaseID)
		}
		if c.QNameStrategy == "unique" && !strings.Contains(c.QNameTemplate, "{token}") {
			return profile{}, fmt.Errorf("case %s lacks token placeholder", c.CaseID)
		}
		if !c.EDNS.Present && (c.EDNS.DO || c.EDNS.UDPSize != 0 || len(c.EDNS.Options) != 0) {
			return profile{}, fmt.Errorf("case %s has EDNS fields while EDNS is absent", c.CaseID)
		}
		for _, option := range c.EDNS.Options {
			if _, err := hex.DecodeString(option.DataHex); err != nil {
				return profile{}, fmt.Errorf("case %s has invalid EDNS option data", c.CaseID)
			}
		}
	}
	sort.Slice(p.Cases, func(i, j int) bool { return p.Cases[i].Number < p.Cases[j].Number })
	return p, nil
}

func loadResolvers(path string) ([]resolver, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open resolvers: %w", err)
	}
	defer f.Close()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read resolvers: %w", err)
	}
	if len(records) == 0 {
		return nil, errors.New("resolver CSV is empty")
	}
	columns := map[string]int{}
	for i, name := range records[0] {
		columns[strings.TrimSpace(name)] = i
	}
	required := []string{"resolver_id", "ip", "address_family", "authoritative_observed", "provider_dnssec_label"}
	for _, name := range required {
		if _, ok := columns[name]; !ok {
			return nil, fmt.Errorf("resolver column %q is missing", name)
		}
	}
	result := make([]resolver, 0, len(records)-1)
	for row, record := range records[1:] {
		observed, err := strconv.ParseBool(record[columns["authoritative_observed"]])
		if err != nil {
			return nil, fmt.Errorf("row %d: invalid authoritative flag", row+2)
		}
		provider, err := strconv.ParseBool(record[columns["provider_dnssec_label"]])
		if err != nil {
			return nil, fmt.Errorf("row %d: invalid provider flag", row+2)
		}
		ip := net.ParseIP(strings.TrimSpace(record[columns["ip"]]))
		if ip == nil {
			return nil, fmt.Errorf("row %d: invalid IP", row+2)
		}
		result = append(result, resolver{ID: record[columns["resolver_id"]], IP: ip.String(), AddressFamily: record[columns["address_family"]], AuthoritativeObserved: observed, ProviderDNSSECLabel: provider})
	}
	return result, nil
}

func lenMustLoadResolvers(path string) int {
	items, err := loadResolvers(path)
	if err != nil {
		fatal(err)
	}
	return len(items)
}

func selectResolvers(items []resolver, only, resolverIDs, startAt string, limit int) ([]resolver, error) {
	only, resolverIDs, startAt = strings.TrimSpace(only), strings.TrimSpace(resolverIDs), strings.TrimSpace(startAt)
	start := 0
	if only != "" {
		parsed := net.ParseIP(only)
		for _, item := range items {
			if strings.EqualFold(item.ID, only) || parsed != nil && item.IP == parsed.String() {
				return []resolver{item}, nil
			}
		}
		return nil, fmt.Errorf("resolver %q not found", only)
	}
	if resolverIDs != "" {
		byID := make(map[string]resolver, len(items))
		for _, item := range items {
			byID[strings.ToUpper(item.ID)] = item
		}
		seen := map[string]bool{}
		selected := make([]resolver, 0)
		for _, rawID := range strings.Split(resolverIDs, ",") {
			id := strings.ToUpper(strings.TrimSpace(rawID))
			if id == "" {
				continue
			}
			if seen[id] {
				return nil, fmt.Errorf("duplicate resolver ID %q", id)
			}
			item, ok := byID[id]
			if !ok {
				return nil, fmt.Errorf("resolver ID %q not found", id)
			}
			seen[id] = true
			selected = append(selected, item)
		}
		if len(selected) == 0 {
			return nil, errors.New("resolver-ids did not select any resolver")
		}
		if limit > 0 && len(selected) > limit {
			selected = selected[:limit]
		}
		return selected, nil
	}
	if startAt != "" {
		found := false
		for i, item := range items {
			if strings.EqualFold(item.ID, startAt) {
				start, found = i, true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("start resolver %q not found", startAt)
		}
	}
	selected := items[start:]
	if limit > 0 && len(selected) > limit {
		selected = selected[:limit]
	}
	return selected, nil
}

func selectCases(all []testCase, filter string) ([]testCase, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return all, nil
	}
	wanted := map[string]bool{}
	for _, id := range strings.Split(filter, ",") {
		id = strings.TrimSpace(id)
		if id != "" {
			wanted[id] = true
		}
	}
	var selected []testCase
	for _, c := range all {
		if wanted[c.CaseID] {
			selected = append(selected, c)
			delete(wanted, c.CaseID)
		}
	}
	if len(wanted) > 0 {
		ids := make([]string, 0, len(wanted))
		for id := range wanted {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return nil, fmt.Errorf("unknown cases: %s", strings.Join(ids, ","))
	}
	if len(selected) == 0 {
		return nil, errors.New("no cases selected")
	}
	return selected, nil
}

func planProbes(runID string, resolvers []resolver, cases []testCase) ([]plannedProbe, error) {
	plans := make([]plannedProbe, 0, len(resolvers)*len(cases))
	for _, c := range cases {
		for _, r := range resolvers {
			token := probeToken(runID, r.ID, c.Number)
			qname := dns.Fqdn(strings.ReplaceAll(c.QNameTemplate, "{token}", token))
			if _, ok := dns.IsDomainName(qname); !ok {
				return nil, fmt.Errorf("case %s produces invalid QNAME %q", c.CaseID, qname)
			}
			plans = append(plans, plannedProbe{RunID: runID, Resolver: r, Case: c, QName: qname})
		}
	}
	return plans, nil
}

func validateTKEYPairCases(cases []testCase) error {
	if len(cases) != 2 || cases[0].CaseID != "tkey_context_no_rr_rd1" || cases[1].CaseID != "tkey_rr_gss_rd1" {
		return errors.New("-tkey-pair requires exactly -cases tkey_context_no_rr_rd1,tkey_rr_gss_rd1")
	}
	a, b := cases[0], cases[1]
	if a.QNameTemplate != b.QNameTemplate || a.QType != b.QType || a.QClass != b.QClass || a.RD != b.RD || a.AD != b.AD || a.CD != b.CD || a.EDNS.Present != b.EDNS.Present || a.TKEY != nil || b.TKEY == nil || !b.TKEY.IncludeRR {
		return errors.New("TKEY pair cases differ in fields other than the Additional TKEY RR")
	}
	return nil
}

func planPairedTKEYProbes(runID string, resolvers []resolver, cases []testCase) ([]plannedProbe, error) {
	if err := validateTKEYPairCases(cases); err != nil {
		return nil, err
	}
	plans := make([]plannedProbe, 0, len(resolvers)*4)
	for _, r := range resolvers {
		for round := 1; round <= 2; round++ {
			sum := sha256.Sum256([]byte(runID + "|" + r.ID + "|tkey-pair|" + strconv.Itoa(round)))
			token := fmt.Sprintf("m-%s-p%d-%x", strings.ToLower(r.ID), round, sum[:6])
			qname := dns.Fqdn(strings.ReplaceAll(cases[0].QNameTemplate, "{token}", token))
			if _, ok := dns.IsDomainName(qname); !ok {
				return nil, fmt.Errorf("TKEY pair produces invalid QNAME %q", qname)
			}
			order := cases
			if round == 2 {
				order = []testCase{cases[1], cases[0]}
			}
			for _, c := range order {
				plans = append(plans, plannedProbe{RunID: runID, Resolver: r, Case: c, QName: qname})
			}
		}
	}
	return plans, nil
}

func probeToken(runID, resolverID string, caseNumber int) string {
	sum := sha256.Sum256([]byte(runID + "|" + resolverID + "|" + strconv.Itoa(caseNumber)))
	return fmt.Sprintf("m-%s-c%02d-%x", strings.ToLower(resolverID), caseNumber, sum[:6])
}

func buildMessage(plan plannedProbe) (*dns.Msg, error) {
	qtype := dns.StringToType[strings.ToUpper(plan.Case.QType)]
	qclass := dns.StringToClass[strings.ToUpper(plan.Case.QClass)]
	message := new(dns.Msg)
	message.SetQuestion(plan.QName, qtype)
	message.Question[0].Qclass = qclass
	message.RecursionDesired = plan.Case.RD
	message.AuthenticatedData = plan.Case.AD
	message.CheckingDisabled = plan.Case.CD
	if plan.Case.EDNS.Present {
		message.SetEdns0(plan.Case.EDNS.UDPSize, plan.Case.EDNS.DO)
		opt := message.IsEdns0()
		for _, configured := range plan.Case.EDNS.Options {
			data, err := hex.DecodeString(configured.DataHex)
			if err != nil {
				return nil, err
			}
			opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{Code: configured.Code, Data: data})
		}
	}
	if plan.Case.TKEY != nil && plan.Case.TKEY.IncludeRR {
		key, err := hex.DecodeString(plan.Case.TKEY.KeyDataHex)
		if err != nil {
			return nil, err
		}
		rr := &dns.TKEY{Hdr: dns.RR_Header{Name: plan.QName, Rrtype: dns.TypeTKEY, Class: dns.ClassANY, Ttl: 0}, Algorithm: dns.Fqdn(plan.Case.TKEY.Algorithm), Mode: plan.Case.TKEY.Mode, KeySize: uint16(len(key)), Key: hex.EncodeToString(key)}
		if strings.ToLower(plan.Case.TKEY.Section) != "additional" {
			return nil, errors.New("only additional TKEY is supported")
		}
		message.Extra = append(message.Extra, rr)
	}
	return message, nil
}

func executeProbe(plan plannedProbe, timeout time.Duration) measurementResult {
	result := measurementResult{Plan: plan, TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano)}
	message, err := buildMessage(plan)
	if err != nil {
		result.UDPErr = err.Error()
		return result
	}
	started := time.Now()
	udpResponse, udpRTT, udpErr := (&dns.Client{Net: "udp", Timeout: timeout}).Exchange(message, net.JoinHostPort(plan.Resolver.IP, "53"))
	if udpRTT <= 0 {
		udpRTT = time.Since(started)
	}
	result.UDPTimeMS = udpRTT.Milliseconds()
	if udpErr != nil {
		result.UDPErr = udpErr.Error()
	} else {
		result.UDP = summarizeResponse(udpResponse)
	}
	result.FinalTransport, result.Final = "udp", result.UDP
	if udpResponse != nil && udpResponse.Truncated {
		result.TCPRetry = true
		tcpStarted := time.Now()
		tcpResponse, tcpRTT, tcpErr := (&dns.Client{Net: "tcp", Timeout: timeout}).Exchange(message, net.JoinHostPort(plan.Resolver.IP, "53"))
		if tcpRTT <= 0 {
			tcpRTT = time.Since(tcpStarted)
		}
		result.TCPTimeMS = tcpRTT.Milliseconds()
		if tcpErr != nil {
			result.TCPErr = tcpErr.Error()
		} else {
			result.TCP = summarizeResponse(tcpResponse)
			result.FinalTransport, result.Final = "tcp", result.TCP
		}
	}
	result.TotalTimeMS = time.Since(started).Milliseconds()
	return result
}

func summarizeResponse(message *dns.Msg) responseSummary {
	if message == nil {
		return responseSummary{}
	}
	s := responseSummary{Received: true, Rcode: dns.RcodeToString[message.Rcode], TC: message.Truncated, RA: message.RecursionAvailable, AD: message.AuthenticatedData, CD: message.CheckingDisabled, SizeBytes: message.Len(), AnswerCount: len(message.Answer), AuthorityCount: len(message.Ns), AdditionalCount: len(message.Extra)}
	if s.Rcode == "" {
		s.Rcode = strconv.Itoa(message.Rcode)
	}
	answerTypes := map[string]bool{}
	for _, rr := range message.Answer {
		answerTypes[dns.TypeToString[rr.Header().Rrtype]] = true
		captureTKEY(&s, rr)
	}
	for _, rr := range message.Ns {
		captureTKEY(&s, rr)
	}
	for _, rr := range message.Extra {
		captureTKEY(&s, rr)
	}
	s.AnswerTypes = sortedKeys(answerTypes)
	if opt := message.IsEdns0(); opt != nil {
		s.EDNS, s.DO, s.UDPSize = true, opt.Do(), opt.UDPSize()
		codes := map[string]bool{}
		for _, option := range opt.Option {
			codes[strconv.Itoa(int(option.Option()))] = true
		}
		s.OptionCodes = sortedKeys(codes)
	}
	return s
}

func captureTKEY(summary *responseSummary, rr dns.RR) {
	tkey, ok := rr.(*dns.TKEY)
	if !ok {
		return
	}
	summary.TKEYCount++
	if summary.TKEYCount == 1 {
		summary.TKEYMode, summary.TKEYAlgorithm, summary.TKEYKeySize = tkey.Mode, tkey.Algorithm, tkey.KeySize
	}
}

func sortedKeys(values map[string]bool) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if key != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return strings.Join(keys, "|")
}

func requestOptionCodes(c testCase) string {
	values := map[string]bool{}
	for _, option := range c.EDNS.Options {
		values[strconv.Itoa(int(option.Code))] = true
	}
	return sortedKeys(values)
}

func writeManifest(path string, plans []plannedProbe) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	header := []string{"run_id", "resolver_id", "ip", "case_number", "case_id", "case_group", "purpose", "remote_adaptation", "qname", "qname_strategy", "qtype", "qclass", "request_rd", "request_ad", "request_cd", "request_edns", "request_do", "request_udp_size", "request_option_codes", "authoritative_match_expected"}
	if err := w.Write(header); err != nil {
		f.Close()
		return err
	}
	for _, p := range plans {
		record := []string{p.RunID, p.Resolver.ID, p.Resolver.IP, strconv.Itoa(p.Case.Number), p.Case.CaseID, p.Case.Group, p.Case.Purpose, p.Case.RemoteAdaptation, p.QName, p.Case.QNameStrategy, p.Case.QType, p.Case.QClass, strconv.FormatBool(p.Case.RD), strconv.FormatBool(p.Case.AD), strconv.FormatBool(p.Case.CD), strconv.FormatBool(p.Case.EDNS.Present), strconv.FormatBool(p.Case.EDNS.DO), strconv.Itoa(int(p.Case.EDNS.UDPSize)), requestOptionCodes(p.Case), strconv.FormatBool(p.Case.AuthoritativeMatchExpected)}
		if err := w.Write(record); err != nil {
			f.Close()
			return err
		}
	}
	w.Flush()
	writeErr, closeErr := w.Error(), f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

type resultWriter struct {
	path   string
	file   *os.File
	writer *csv.Writer
}

func newResultWriter(path string) (*resultWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := csv.NewWriter(f)
	if err := w.Write(resultHeader); err != nil {
		f.Close()
		return nil, err
	}
	w.Flush()
	return &resultWriter{path: path, file: f, writer: w}, w.Error()
}

func (w *resultWriter) Write(r measurementResult) error {
	p, c, u, t, f := r.Plan, r.Plan.Case, r.UDP, r.TCP, r.Final
	record := []string{
		p.RunID, p.Resolver.ID, p.Resolver.IP, p.Resolver.AddressFamily, strconv.FormatBool(p.Resolver.AuthoritativeObserved), strconv.FormatBool(p.Resolver.ProviderDNSSECLabel),
		strconv.Itoa(c.Number), c.CaseID, c.Group, p.QName, c.QNameStrategy, c.QType, c.QClass, strconv.FormatBool(c.RD), strconv.FormatBool(c.AD), strconv.FormatBool(c.CD), strconv.FormatBool(c.EDNS.Present), strconv.FormatBool(c.EDNS.DO), strconv.Itoa(int(c.EDNS.UDPSize)), requestOptionCodes(c),
		r.TimestampUTC, strconv.FormatBool(u.Received), u.Rcode, strconv.FormatBool(u.TC), strconv.FormatBool(u.RA), strconv.FormatBool(u.AD), strconv.FormatBool(u.CD), strconv.FormatBool(u.EDNS), strconv.FormatBool(u.DO), strconv.Itoa(int(u.UDPSize)), strconv.Itoa(u.SizeBytes), strconv.FormatInt(r.UDPTimeMS, 10), r.UDPErr,
		strconv.FormatBool(r.TCPRetry), strconv.FormatBool(t.Received), t.Rcode, strconv.Itoa(t.SizeBytes), strconv.FormatInt(r.TCPTimeMS, 10), r.TCPErr,
		r.FinalTransport, f.Rcode, strconv.FormatBool(f.TC), strconv.FormatBool(f.RA), strconv.FormatBool(f.AD), strconv.FormatBool(f.CD), strconv.FormatBool(f.EDNS), strconv.FormatBool(f.DO), strconv.Itoa(int(f.UDPSize)), strconv.Itoa(f.SizeBytes), strconv.Itoa(f.AnswerCount), strconv.Itoa(f.AuthorityCount), strconv.Itoa(f.AdditionalCount), f.AnswerTypes, f.OptionCodes, strconv.Itoa(f.TKEYCount), strconv.Itoa(int(f.TKEYMode)), f.TKEYAlgorithm, strconv.Itoa(int(f.TKEYKeySize)), strconv.FormatInt(r.TotalTimeMS, 10),
	}
	if len(record) != len(resultHeader) {
		return fmt.Errorf("internal result column mismatch: %d != %d", len(record), len(resultHeader))
	}
	if err := w.writer.Write(record); err != nil {
		return err
	}
	w.writer.Flush()
	return w.writer.Error()
}

func (w *resultWriter) Close() error {
	w.writer.Flush()
	writeErr, closeErr := w.writer.Error(), w.file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func validateRunID(value string) error {
	if value == "" || value == "." || value == ".." || strings.ContainsAny(value, `/\\`) {
		return fmt.Errorf("invalid run ID %q", value)
	}
	return nil
}

func fatal(err error) { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
