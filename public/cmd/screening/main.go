package main

import (
	"bufio"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultZone    = "test.s.inet-studies.net"
	defaultTimeout = 3 * time.Second
	defaultDelay   = 1 * time.Second
)

var resultHeader = []string{
	"run_id", "resolver_id", "ip", "address_family", "qname",
	"probe_timestamp_utc", "probe_sent", "response_received", "rcode", "ra", "ad", "cd", "tc",
	"response_edns", "response_do", "response_udp_size", "response_size_bytes", "transport",
	"query_time_ms", "response_consistent", "client_preflight_passed", "pre_excluded",
	"exclusion_reason", "error",
}

type candidate struct {
	ID string
	IP string
}

type result struct {
	RunID                 string
	Candidate             candidate
	QName                 string
	ProbeTimestampUTC     string
	ProbeSent             bool
	ResponseReceived      bool
	Rcode                 string
	RA                    bool
	AD                    bool
	CD                    bool
	TC                    bool
	ResponseEDNS          bool
	ResponseDO            bool
	ResponseUDPSize       uint16
	ResponseSizeBytes     int
	Transport             string
	QueryTimeMS           int64
	ResponseConsistent    bool
	ClientPreflightPassed bool
	PreExcluded           bool
	ExclusionReason       string
	Error                 string
}

type csvResultWriter struct {
	path   string
	file   *os.File
	writer *csv.Writer
}

func main() {
	inputDir := flag.String("input", "ListofResolver", "directory containing all.txt")
	outputDir := flag.String("output", "results", "base directory for timestamped result directories")
	exclusionFile := flag.String("exclude", "", "optional CSV file with ip and reason columns; empty means no pre-exclusions")
	zone := flag.String("zone", defaultZone, "authoritative preflight zone")
	timeout := flag.Duration("timeout", defaultTimeout, "timeout for the single UDP query")
	delay := flag.Duration("delay", defaultDelay, "pause between candidates")
	runIDFlag := flag.String("run-id", "", "optional unique run ID; generated automatically when empty")
	only := flag.String("only", "", "run exactly one candidate selected by resolver ID or IP address")
	startAt := flag.String("start-at", "", "run the candidate range beginning with this resolver ID")
	limit := flag.Int("limit", 0, "maximum number of selected candidates; zero means no limit")
	execute := flag.Bool("execute", false, "send the client-side preflight queries")
	flag.Parse()
	if *limit < 0 {
		fatal(errors.New("limit must not be negative"))
	}

	candidates, err := loadCandidates(*inputDir)
	if err != nil {
		fatal(err)
	}
	selectedCandidates, err := selectCandidates(candidates, *only, *startAt)
	if err != nil {
		fatal(err)
	}
	if *limit > 0 && len(selectedCandidates) > *limit {
		selectedCandidates = selectedCandidates[:*limit]
	}
	exclusions := make(map[string]string)
	if strings.TrimSpace(*exclusionFile) != "" {
		exclusions, err = loadExclusions(*exclusionFile)
		if err != nil {
			fatal(err)
		}
	}
	excludedCount := countExcluded(selectedCandidates, exclusions)

	if !*execute {
		return
	}
	if *timeout <= 0 {
		fatal(errors.New("timeout must be greater than zero"))
	}
	if *delay < 0 {
		fatal(errors.New("delay must not be negative"))
	}

	zoneName := dns.Fqdn(strings.TrimSpace(*zone))
	if zoneName == "." {
		fatal(errors.New("zone must not be empty"))
	}
	runID := strings.TrimSpace(*runIDFlag)
	if runID == "" {
		runID, err = newRunID()
		if err != nil {
			fatal(fmt.Errorf("create run ID: %w", err))
		}
	}
	if err := validateRunID(runID); err != nil {
		fatal(err)
	}
	runDir := filepath.Join(*outputDir, runID)
	if _, err := os.Stat(runDir); err == nil {
		fatal(fmt.Errorf("run directory already exists: %s", runDir))
	} else if !os.IsNotExist(err) {
		fatal(fmt.Errorf("check run directory: %w", err))
	}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		fatal(fmt.Errorf("create run directory: %w", err))
	}

	planned, err := planRun(runID, selectedCandidates, exclusions, zoneName)
	if err != nil {
		fatal(err)
	}
	manifestPath := filepath.Join(runDir, "probe_manifest.csv")
	if err := writeManifest(manifestPath, planned); err != nil {
		fatal(err)
	}
	allPath := filepath.Join(runDir, "client_preflight_results.csv")
	resultWriter, err := newCSVResultWriter(allPath)
	if err != nil {
		fatal(err)
	}

	results := make([]result, 0, len(planned))
	probesSent := 0
	for i, item := range planned {
		if item.PreExcluded {
			results = append(results, item)
			if err := resultWriter.Write(item); err != nil {
				resultWriter.Close()
				fatal(err)
			}
			fmt.Printf("[%d/%d] %s %s: pre-excluded (%s)\n", i+1, len(planned), item.Candidate.ID, item.Candidate.IP, item.ExclusionReason)
			continue
		}

		item = runClientPreflight(item, *timeout)
		probesSent++
		results = append(results, item)
		if err := resultWriter.Write(item); err != nil {
			resultWriter.Close()
			fatal(err)
		}
		fmt.Printf("[%d/%d] %s %s: response=%t rcode=%s ra=%t client_preflight_passed=%t\n",
			i+1, len(planned), item.Candidate.ID, item.Candidate.IP, item.ResponseReceived, item.Rcode, item.RA, item.ClientPreflightPassed)
		if i+1 < len(planned) && *delay > 0 {
			time.Sleep(*delay)
		}
	}
	if err := resultWriter.Close(); err != nil {
		fatal(err)
	}

	passedPath := filepath.Join(runDir, "client_preflight_passed.csv")
	if err := writeFilteredResults(passedPath, results); err != nil {
		fatal(err)
	}
	passedCount := 0
	for _, item := range results {
		if item.ClientPreflightPassed {
			passedCount++
		}
	}
	fmt.Printf("Finished client preflight: %d probes sent, %d passed, %d pre-excluded. Results: %s\n",
		probesSent, passedCount, excludedCount, allPath)
}

func loadCandidates(inputDir string) ([]candidate, error) {
	ips, err := readIPList(filepath.Join(inputDir, "all.txt"))
	if err != nil {
		return nil, err
	}
	candidates := make([]candidate, 0, len(ips))
	seen := make(map[string]bool, len(ips))
	for _, ip := range ips {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		candidates = append(candidates, candidate{
			ID: fmt.Sprintf("R%03d", len(candidates)+1),
			IP: ip,
		})
	}
	return candidates, nil
}

func readIPList(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	ips := make([]string, 0)
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := net.ParseIP(line)
		if ip == nil {
			return nil, fmt.Errorf("%s:%d: invalid IP address %q", path, lineNumber, line)
		}
		ips = append(ips, ip.String())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ips, nil
}

func loadExclusions(path string) (map[string]string, error) {
	exclusions := make(map[string]string)
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return exclusions, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	for i, record := range records {
		if i == 0 && len(record) >= 2 && strings.EqualFold(strings.TrimSpace(record[0]), "ip") {
			continue
		}
		if len(record) != 2 {
			return nil, fmt.Errorf("%s row %d: expected ip,reason", path, i+1)
		}
		ip := net.ParseIP(strings.TrimSpace(record[0]))
		if ip == nil {
			return nil, fmt.Errorf("%s row %d: invalid IP address %q", path, i+1, record[0])
		}
		reason := strings.TrimSpace(record[1])
		if reason == "" {
			return nil, fmt.Errorf("%s row %d: exclusion reason is empty", path, i+1)
		}
		exclusions[ip.String()] = reason
	}
	return exclusions, nil
}

func countExcluded(candidates []candidate, exclusions map[string]string) int {
	count := 0
	for _, candidate := range candidates {
		if _, exists := exclusions[candidate.IP]; exists {
			count++
		}
	}
	return count
}

func selectCandidates(candidates []candidate, selector, startAt string) ([]candidate, error) {
	selector = strings.TrimSpace(selector)
	startAt = strings.TrimSpace(startAt)
	if selector != "" && startAt != "" {
		return nil, errors.New("only and start-at cannot be used together")
	}
	if startAt != "" {
		for i, item := range candidates {
			if strings.EqualFold(item.ID, startAt) {
				return candidates[i:], nil
			}
		}
		return nil, fmt.Errorf("start candidate %q not found", startAt)
	}
	if selector == "" {
		return candidates, nil
	}
	parsedIP := net.ParseIP(selector)
	for _, item := range candidates {
		idMatches := strings.EqualFold(item.ID, selector)
		ipMatches := parsedIP != nil && item.IP == parsedIP.String()
		if idMatches || ipMatches {
			return []candidate{item}, nil
		}
	}
	return nil, fmt.Errorf("candidate %q not found", selector)
}

func planRun(runID string, candidates []candidate, exclusions map[string]string, zone string) ([]result, error) {
	planned := make([]result, 0, len(candidates))
	for _, candidate := range candidates {
		item := result{RunID: runID, Candidate: candidate, Transport: "udp"}
		if reason, excluded := exclusions[candidate.IP]; excluded {
			item.PreExcluded = true
			item.ExclusionReason = reason
			planned = append(planned, item)
			continue
		}
		qname, err := verificationQName(runID, candidate.ID, zone)
		if err != nil {
			return nil, fmt.Errorf("create qname for %s: %w", candidate.ID, err)
		}
		item.QName = qname
		planned = append(planned, item)
	}
	return planned, nil
}

func newRunID() (string, error) {
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(randomBytes), nil
}

func validateRunID(runID string) error {
	if runID == "" || runID == "." || runID == ".." || strings.ContainsAny(runID, `/\\`) {
		return fmt.Errorf("invalid run ID %q", runID)
	}
	return nil
}

func verificationQName(runID, resolverID, zone string) (string, error) {
	randomBytes := make([]byte, 6)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	runLabel := strings.ToLower(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return '-'
	}, runID))
	if len(runLabel) > 20 {
		runLabel = runLabel[:20]
	}
	label := fmt.Sprintf("verify-%s-%s-%s", strings.ToLower(resolverID), runLabel, hex.EncodeToString(randomBytes))
	if len(label) > 63 {
		return "", errors.New("generated verification label exceeds 63 octets")
	}
	return dns.Fqdn(label + "." + strings.TrimSuffix(zone, ".")), nil
}

func runClientPreflight(item result, timeout time.Duration) result {
	message := new(dns.Msg)
	message.SetQuestion(item.QName, dns.TypeA)
	message.RecursionDesired = true

	item.ProbeTimestampUTC = time.Now().UTC().Format(time.RFC3339Nano)
	item.ProbeSent = true
	client := &dns.Client{Net: "udp", Timeout: timeout}
	started := time.Now()
	response, rtt, err := client.Exchange(message, net.JoinHostPort(item.Candidate.IP, "53"))
	elapsed := rtt
	if elapsed <= 0 {
		elapsed = time.Since(started)
	}
	item.QueryTimeMS = elapsed.Milliseconds()
	if err != nil {
		item.Error = err.Error()
		item.ExclusionReason = "no_usable_response_from_measurement_vantage_point"
		return item
	}
	return evaluateClientResponse(item, response)
}

func evaluateClientResponse(item result, response *dns.Msg) result {
	item.ResponseReceived = true
	item.Rcode = dns.RcodeToString[response.Rcode]
	if item.Rcode == "" {
		item.Rcode = strconv.Itoa(response.Rcode)
	}
	item.RA = response.RecursionAvailable
	item.AD = response.AuthenticatedData
	item.CD = response.CheckingDisabled
	item.TC = response.Truncated
	item.ResponseSizeBytes = response.Len()
	if opt := response.IsEdns0(); opt != nil {
		item.ResponseEDNS = true
		item.ResponseDO = opt.Do()
		item.ResponseUDPSize = opt.UDPSize()
	}
	item.ResponseConsistent = response.Response && response.Opcode == dns.OpcodeQuery &&
		len(response.Question) == 1 && strings.EqualFold(response.Question[0].Name, item.QName) &&
		response.Question[0].Qtype == dns.TypeA && response.Question[0].Qclass == dns.ClassINET &&
		response.Rcode == dns.RcodeNameError
	item.ClientPreflightPassed = item.ResponseReceived && item.RA && item.ResponseConsistent
	if !item.RA {
		item.ExclusionReason = "recursion_available_flag_not_set"
	} else if !item.ResponseConsistent {
		item.ExclusionReason = "response_not_consistent_with_expected_nxdomain"
	}
	return item
}

func addressFamily(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed != nil && parsed.To4() != nil {
		return "IPv4"
	}
	return "IPv6"
}

func writeManifest(path string, planned []result) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	writer := csv.NewWriter(file)
	if err := writer.Write([]string{"run_id", "resolver_id", "ip", "address_family", "qname", "pre_excluded", "exclusion_reason"}); err != nil {
		file.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	for _, item := range planned {
		record := []string{item.RunID, item.Candidate.ID, item.Candidate.IP, addressFamily(item.Candidate.IP),
			item.QName, strconv.FormatBool(item.PreExcluded), item.ExclusionReason}
		if err := writer.Write(record); err != nil {
			file.Close()
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	writer.Flush()
	writeErr := writer.Error()
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write %s: %w", path, writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close %s: %w", path, closeErr)
	}
	return nil
}

func newCSVResultWriter(path string) (*csvResultWriter, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", path, err)
	}
	writer := csv.NewWriter(file)
	if err := writer.Write(resultHeader); err != nil {
		file.Close()
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		file.Close()
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return &csvResultWriter{path: path, file: file, writer: writer}, nil
}

func (w *csvResultWriter) Write(item result) error {
	if err := w.writer.Write(resultRecord(item)); err != nil {
		return fmt.Errorf("write %s: %w", w.path, err)
	}
	w.writer.Flush()
	if err := w.writer.Error(); err != nil {
		return fmt.Errorf("write %s: %w", w.path, err)
	}
	return nil
}

func (w *csvResultWriter) Close() error {
	w.writer.Flush()
	writeErr := w.writer.Error()
	closeErr := w.file.Close()
	if writeErr != nil {
		return fmt.Errorf("write %s: %w", w.path, writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close %s: %w", w.path, closeErr)
	}
	return nil
}

func writeFilteredResults(path string, results []result) error {
	writer, err := newCSVResultWriter(path)
	if err != nil {
		return err
	}
	for _, item := range results {
		if item.ClientPreflightPassed {
			if err := writer.Write(item); err != nil {
				writer.Close()
				return err
			}
		}
	}
	return writer.Close()
}

func resultRecord(item result) []string {
	return []string{
		item.RunID, item.Candidate.ID, item.Candidate.IP, addressFamily(item.Candidate.IP), item.QName,
		item.ProbeTimestampUTC, strconv.FormatBool(item.ProbeSent), strconv.FormatBool(item.ResponseReceived), item.Rcode,
		strconv.FormatBool(item.RA), strconv.FormatBool(item.AD), strconv.FormatBool(item.CD), strconv.FormatBool(item.TC),
		strconv.FormatBool(item.ResponseEDNS), strconv.FormatBool(item.ResponseDO), strconv.FormatUint(uint64(item.ResponseUDPSize), 10),
		strconv.Itoa(item.ResponseSizeBytes), item.Transport, strconv.FormatInt(item.QueryTimeMS, 10),
		strconv.FormatBool(item.ResponseConsistent), strconv.FormatBool(item.ClientPreflightPassed), strconv.FormatBool(item.PreExcluded),
		item.ExclusionReason, item.Error,
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
