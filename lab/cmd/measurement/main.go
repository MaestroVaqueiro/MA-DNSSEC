package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/miekg/dns"
)

const authoritativeLogPath = "/tmp/dns_mutation_authoritative.jsonl"
const nsec3SignedZonePath = "/home/vboxuser/dnssec-testzone/db.nsec3.mut.test.signed"

type ExperimentConfig struct {
	RunID       string
	TimeoutMS   int `json:"timeout_ms"`
	Repetitions int `json:"repetitions"`
	DrainMS     int `json:"drain_ms"`

	RejectWireEquivalentDuplicates bool `json:"reject_wire_equivalent_duplicates"`

	ProfileType    string   `json:"profile_type"`
	MutationFamily string   `json:"mutation_family"`
	Resolvers      []string `json:"resolvers"`

	Defaults CaseDefaults `json:"defaults"`
	Cases    []V6Case     `json:"cases"`

	Experiments []Experiment `json:"-"`
}

type CaseDefaults struct {
	Transport     string     `json:"transport"`
	Flags         CaseFlags  `json:"flags"`
	EDNS          EDNSConfig `json:"edns"`
	CacheStrategy string     `json:"cache_strategy"`
}

type V6Case struct {
	CaseID               string         `json:"case_id"`
	Family               string         `json:"family"`
	Priority             int            `json:"priority"`
	QName                string         `json:"qname"`
	QType                string         `json:"qtype"`
	QClass               string         `json:"qclass"`
	ResearchDimension    string         `json:"research_dimension"`
	ComparisonGroup      string         `json:"comparison_group"`
	TestTier             string         `json:"test_tier"`
	ReferenceCaseID      string         `json:"reference_case_id"`
	ChangedProperties    []string       `json:"changed_properties"`
	Motivation           string         `json:"motivation"`
	QueryValidity        string         `json:"query_validity,omitempty"`
	ExpectedProcessing   string         `json:"expected_processing,omitempty"`
	ExpectedHeaderRcodes []string       `json:"expected_header_rcodes,omitempty"`
	ExpectedTKEYErrors   []uint16       `json:"expected_tkey_errors,omitempty"`
	ExpectedObservations map[string]any `json:"expected_observations"`
	Variants             []V6Variant    `json:"variants"`
}

type V6Variant struct {
	QName                   string         `json:"qname,omitempty"`
	QType                   string         `json:"qtype,omitempty"`
	QClass                  string         `json:"qclass,omitempty"`
	VariantID               string         `json:"variant_id"`
	Description             string         `json:"description"`
	QueryValidity           string         `json:"query_validity,omitempty"`
	ExpectedProcessing      string         `json:"expected_processing,omitempty"`
	ExpectedHeaderRcodes    []string       `json:"expected_header_rcodes,omitempty"`
	ExpectedTKEYErrors      []uint16       `json:"expected_tkey_errors,omitempty"`
	Transport               string         `json:"transport"`
	Flags                   CaseFlags      `json:"flags"`
	EDNS                    EDNSConfig     `json:"edns"`
	CacheStrategy           string         `json:"cache_strategy"`
	ExpectedObservations    map[string]any `json:"expected_observations"`
	TKEY                    *TKEYConfig    `json:"tkey"`
	RawWire                 *RawWireConfig `json:"raw_wire,omitempty"`
	RepetitionQNameTemplate string         `json:"repetition_qname_template,omitempty"`
}

type CaseFlags struct {
	QR     *bool `json:"qr,omitempty"`
	AA     *bool `json:"aa,omitempty"`
	TC     *bool `json:"tc,omitempty"`
	RD     *bool `json:"rd"`
	RA     *bool `json:"ra,omitempty"`
	Z      *bool `json:"z,omitempty"`
	CD     *bool `json:"cd"`
	AD     *bool `json:"ad"`
	Opcode *int  `json:"opcode,omitempty"`
	Rcode  *int  `json:"rcode,omitempty"`
}

type EDNSConfig struct {
	Present       *bool              `json:"present"`
	Version       *uint8             `json:"version"`
	UDPSize       *uint16            `json:"udp_size"`
	DO            *bool              `json:"do"`
	ZFlags        *uint16            `json:"z_flags,omitempty"`
	ExtendedRcode *uint8             `json:"extended_rcode,omitempty"`
	OwnerName     string             `json:"owner_name,omitempty"`
	OPTCount      int                `json:"opt_count,omitempty"`
	Options       []EDNSOptionConfig `json:"options"`
}

type RawWireConfig struct {
	Hex         string `json:"hex"`
	Description string `json:"description,omitempty"`
}

type EDNSOptionConfig struct {
	Code    uint16 `json:"code"`
	Name    string `json:"name"`
	DataHex string `json:"data_hex"`
	Length  int    `json:"length"`
}

type TKEYConfig struct {
	IncludeRR    bool       `json:"include_rr"`
	Section      string     `json:"section"`
	OwnerName    string     `json:"owner_name,omitempty"`
	RRClass      string     `json:"rr_class,omitempty"`
	TTL          uint32     `json:"ttl,omitempty"`
	Count        int        `json:"count,omitempty"`
	Algorithm    string     `json:"algorithm"`
	Mode         uint16     `json:"mode"`
	Inception    uint32     `json:"inception"`
	Expiration   uint32     `json:"expiration"`
	Error        uint16     `json:"error"`
	KeyDataHex   string     `json:"key_data_hex"`
	OtherDataHex string     `json:"other_data_hex"`
	KeyRR        *KEYConfig `json:"key_rr,omitempty"`
}

type KEYConfig struct {
	IncludeRR       bool   `json:"include_rr"`
	Section         string `json:"section,omitempty"`
	OwnerName       string `json:"owner_name,omitempty"`
	RRClass         string `json:"rr_class,omitempty"`
	TTL             uint32 `json:"ttl,omitempty"`
	Flags           uint16 `json:"flags"`
	Protocol        uint8  `json:"protocol"`
	Algorithm       uint8  `json:"algorithm"`
	PublicKeyBase64 string `json:"public_key_base64"`
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

type QNameMetrics struct {
	TextLength     int  `json:"text_length"`
	WireLength     int  `json:"wire_length"`
	LabelCount     int  `json:"label_count"`
	MaxLabelLength int  `json:"max_label_length"`
	HasUppercase   bool `json:"has_uppercase"`
}

func measureQName(name string) QNameMetrics {
	fqdn := dns.Fqdn(name)
	trimmed := strings.TrimSuffix(fqdn, ".")
	metrics := QNameMetrics{
		TextLength:   len(trimmed),
		WireLength:   1,
		HasUppercase: trimmed != strings.ToLower(trimmed),
	}
	if trimmed == "" {
		return metrics
	}
	labels := strings.Split(trimmed, ".")
	metrics.LabelCount = len(labels)
	for _, label := range labels {
		length := len([]byte(label))
		metrics.WireLength += 1 + length
		if length > metrics.MaxLabelLength {
			metrics.MaxLabelLength = length
		}
	}
	return metrics
}

type Experiment struct {
	ExperimentID         string             `json:"experiment_id"`
	MutationFamily       string             `json:"mutation_family"`
	MutationName         string             `json:"mutation_name"`
	Resolver             string             `json:"resolver"`
	Target               string             `json:"target"`
	QName                string             `json:"qname"`
	QType                string             `json:"qtype"`
	QClass               string             `json:"qclass"`
	Transport            string             `json:"transport"`
	TCPFallback          bool               `json:"tcp_fallback"`
	EDNS                 bool               `json:"edns"`
	DO                   bool               `json:"do"`
	AD                   bool               `json:"ad"`
	CD                   bool               `json:"cd"`
	RD                   *bool              `json:"rd"`
	QR                   bool               `json:"qr"`
	AA                   bool               `json:"aa"`
	TC                   bool               `json:"tc"`
	RA                   bool               `json:"ra"`
	Z                    bool               `json:"z"`
	Opcode               int                `json:"opcode"`
	RequestRcode         int                `json:"request_rcode"`
	UDPPayloadSize       uint16             `json:"udp_payload_size"`
	EDNSVersion          uint8              `json:"edns_version"`
	EDNSZFlags           uint16             `json:"edns_z_flags"`
	EDNSExtendedRcode    uint8              `json:"edns_extended_rcode"`
	EDNSOwnerName        string             `json:"edns_owner_name,omitempty"`
	OPTCount             int                `json:"opt_count"`
	EDNSOptions          []EDNSOptionConfig `json:"edns_options"`
	RawWire              *RawWireConfig     `json:"raw_wire,omitempty"`
	CacheStrategy        string             `json:"cache_strategy"`
	ExpectedValidity     string             `json:"expected_validity"`
	ExpectedProcessing   string             `json:"expected_processing,omitempty"`
	ExpectedHeaderRcodes []string           `json:"expected_header_rcodes,omitempty"`
	ExpectedTKEYErrors   []uint16           `json:"expected_tkey_errors,omitempty"`

	CaseID                  string         `json:"case_id,omitempty"`
	Family                  string         `json:"family,omitempty"`
	Priority                int            `json:"priority,omitempty"`
	ResearchDimension       string         `json:"research_dimension,omitempty"`
	ComparisonGroup         string         `json:"comparison_group,omitempty"`
	TestTier                string         `json:"test_tier,omitempty"`
	ReferenceCaseID         string         `json:"reference_case_id,omitempty"`
	ChangedProperties       []string       `json:"changed_properties,omitempty"`
	VariantID               string         `json:"variant_id,omitempty"`
	VariantDescription      string         `json:"variant_description,omitempty"`
	ExpectedObservations    map[string]any `json:"expected_observations,omitempty"`
	TKEY                    *TKEYConfig    `json:"tkey,omitempty"`
	RepetitionQNameTemplate string         `json:"repetition_qname_template,omitempty"`
}

type ClientResultEvent struct {
	RunID          string `json:"run_id"`
	ExperimentID   string `json:"experiment_id"`
	MutationFamily string `json:"mutation_family"`
	MutationName   string `json:"mutation_name"`
	Resolver       string `json:"resolver"`
	Target         string `json:"target"`
	Repetition     int    `json:"repetition"`

	CaseID               string         `json:"case_id,omitempty"`
	Family               string         `json:"family,omitempty"`
	Priority             int            `json:"priority,omitempty"`
	ResearchDimension    string         `json:"research_dimension,omitempty"`
	ComparisonGroup      string         `json:"comparison_group,omitempty"`
	TestTier             string         `json:"test_tier"`
	ReferenceCaseID      string         `json:"reference_case_id"`
	ChangedProperties    []string       `json:"changed_properties"`
	VariantID            string         `json:"variant_id,omitempty"`
	VariantDescription   string         `json:"variant_description,omitempty"`
	ExpectedValidity     string         `json:"expected_validity,omitempty"`
	ExpectedProcessing   string         `json:"expected_processing,omitempty"`
	ExpectedHeaderRcodes []string       `json:"expected_header_rcodes,omitempty"`
	ExpectedTKEYErrors   []uint16       `json:"expected_tkey_errors,omitempty"`
	ExpectedObservations map[string]any `json:"expected_observations,omitempty"`

	CacheStrategy       string `json:"cache_strategy"`
	CacheFlushAttempted bool   `json:"cache_flush_attempted"`
	CacheFlushSuccess   bool   `json:"cache_flush_success"`
	CacheFlushError     string `json:"cache_flush_error,omitempty"`

	AttributionMethod                   string `json:"attribution_method"`
	AuthoritativeLogOffsetBefore        int64  `json:"authoritative_log_offset_before"`
	ExperimentWindowStart               string `json:"experiment_window_start"`
	ExperimentClientResponseTime        string `json:"experiment_client_response_time"`
	ExperimentWindowEnd                 string `json:"experiment_window_end"`
	DrainMS                             int    `json:"drain_ms"`
	AnnotatedAuthoritativeEvents        int    `json:"annotated_authoritative_events"`
	AnnotatedPrimaryAuthoritativeEvents int    `json:"annotated_primary_authoritative_events"`
	LocalHandlingWithoutPrimaryUpstream bool   `json:"local_handling_without_primary_upstream"`
	LocalHandlingType                   string `json:"local_handling_type,omitempty"`

	Timestamp     string `json:"timestamp"`
	Transport     string `json:"transport"`
	QName         string `json:"qname"`
	QType         string `json:"qtype"`
	QTypeNumeric  uint16 `json:"qtype_numeric"`
	QClass        string `json:"qclass"`
	QClassNumeric uint16 `json:"qclass_numeric"`

	QNameTextLength     int  `json:"qname_text_length"`
	QNameWireLength     int  `json:"qname_wire_length"`
	QNameLabelCount     int  `json:"qname_label_count"`
	QNameMaxLabelLength int  `json:"qname_max_label_length"`
	QNameHasUppercase   bool `json:"qname_has_uppercase"`

	ClientDO                bool             `json:"client_do"`
	ClientAD                bool             `json:"client_ad"`
	ClientCD                bool             `json:"client_cd"`
	ClientRD                bool             `json:"client_rd"`
	ClientQR                bool             `json:"client_qr"`
	ClientAA                bool             `json:"client_aa"`
	ClientTC                bool             `json:"client_tc"`
	ClientRA                bool             `json:"client_ra"`
	ClientZ                 bool             `json:"client_z"`
	ClientOpcode            int              `json:"client_opcode"`
	ClientRequestRcode      int              `json:"client_request_rcode"`
	ClientMessageID         uint16           `json:"client_message_id"`
	ClientUDPPayloadSize    *uint16          `json:"client_udp_payload_size"`
	EffectiveUDPLimit       uint16           `json:"effective_udp_limit"`
	ClientEDNS              bool             `json:"client_edns"`
	ClientEDNSVersion       *uint8           `json:"client_edns_version"`
	ClientEDNSZFlags        *uint16          `json:"client_edns_z_flags"`
	ClientEDNSExtendedRcode *uint8           `json:"client_edns_extended_rcode"`
	ClientEDNSOwnerName     string           `json:"client_edns_owner_name,omitempty"`
	QueryOPTCount           int              `json:"query_opt_count"`
	QueryEDNSOptions        []EDNSOptionInfo `json:"query_edns_options"`
	QueryWireSize           int              `json:"query_wire_size"`
	QueryWireSHA256         string           `json:"query_wire_sha256,omitempty"`
	QueryWireHex            string           `json:"query_wire_hex"`
	QueryRawWire            bool             `json:"query_raw_wire"`
	QueryRawWireDescription string           `json:"query_raw_wire_description,omitempty"`
	QueryQuestionCount      int              `json:"query_question_count"`
	QueryAnswerCount        int              `json:"query_answer_count"`
	QueryAuthorityCount     int              `json:"query_authority_count"`
	QueryAdditionalCount    int              `json:"query_additional_count"`
	QueryAnswerRRTypes      []string         `json:"query_answer_rrtypes"`
	QueryAuthorityRRTypes   []string         `json:"query_authority_rrtypes"`
	QueryAdditionalRRTypes  []string         `json:"query_additional_rrtypes"`

	QueryTKEYPresent     bool   `json:"query_tkey_present"`
	QueryTKEYCount       int    `json:"query_tkey_count"`
	QueryTKEYMode        uint16 `json:"query_tkey_mode"`
	QueryTKEYError       uint16 `json:"query_tkey_error"`
	QueryTKEYAlgorithm   string `json:"query_tkey_algorithm"`
	QueryTKEYSection     string `json:"query_tkey_section"`
	QueryTKEYOwner       string `json:"query_tkey_owner"`
	QueryTKEYClass       string `json:"query_tkey_class"`
	QueryTKEYTTL         uint32 `json:"query_tkey_ttl"`
	QueryTKEYInception   uint32 `json:"query_tkey_inception"`
	QueryTKEYExpiration  uint32 `json:"query_tkey_expiration"`
	QueryTKEYKeyLength   int    `json:"query_tkey_key_length"`
	QueryTKEYOtherLength int    `json:"query_tkey_other_length"`
	QueryKEYPresent      bool   `json:"query_key_rr_present"`
	QueryKEYCount        int    `json:"query_key_rr_count"`
	QueryKEYSection      string `json:"query_key_rr_section,omitempty"`
	QueryKEYOwner        string `json:"query_key_rr_owner,omitempty"`
	QueryKEYAlgorithm    uint8  `json:"query_key_rr_algorithm,omitempty"`

	Timeout   bool    `json:"timeout"`
	ErrorKind string  `json:"error_kind,omitempty"`
	Error     string  `json:"error,omitempty"`
	RTTMS     float64 `json:"rtt_ms"`

	ResponseReceived              bool   `json:"response_received"`
	ResponseDecodeSuccess         bool   `json:"response_decode_success"`
	ResponseDecodeError           string `json:"response_decode_error,omitempty"`
	ResponseMessageID             uint16 `json:"response_message_id"`
	ResponseIDMatchesClient       bool   `json:"response_id_matches_client"`
	ResponseRcode                 string `json:"response_rcode"`
	ResponseRcodeNumeric          int    `json:"response_rcode_numeric"`
	ResponseRcodeBase             int    `json:"response_rcode_base"`
	ResponseRcodeExtended         int    `json:"response_rcode_extended"`
	ResponseAD                    bool   `json:"response_ad"`
	ResponseCD                    bool   `json:"response_cd"`
	ResponseTC                    bool   `json:"response_tc"`
	ResponseRA                    bool   `json:"response_ra"`
	ResponseQR                    bool   `json:"response_qr"`
	ResponseAA                    bool   `json:"response_aa"`
	ResponseRD                    bool   `json:"response_rd"`
	ResponseZ                     bool   `json:"response_z"`
	ResponseOpcode                int    `json:"response_opcode"`
	ResponseSize                  int    `json:"response_size"`
	ResponseWireSize              int    `json:"response_wire_size"`
	ResponseWireSHA256            string `json:"response_wire_sha256,omitempty"`
	ResponseWireHex               string `json:"response_wire_hex,omitempty"`
	ResponseHeaderQuestionCount   int    `json:"response_header_question_count"`
	ResponseHeaderAnswerCount     int    `json:"response_header_answer_count"`
	ResponseHeaderAuthorityCount  int    `json:"response_header_authority_count"`
	ResponseHeaderAdditionalCount int    `json:"response_header_additional_count"`

	ResponseOPTCount    int              `json:"response_opt_count"`
	ResponseEDNSVersion *uint8           `json:"response_edns_version"`
	ResponseEDNSOptions []EDNSOptionInfo `json:"response_edns_options"`

	AnswerCount     int `json:"answer_count"`
	AuthorityCount  int `json:"authority_count"`
	AdditionalCount int `json:"additional_count"`

	ContainsRRSIG  bool `json:"contains_rrsig"`
	ContainsDNSKEY bool `json:"contains_dnskey"`
	ContainsDS     bool `json:"contains_ds"`
	ContainsNSEC   bool `json:"contains_nsec"`
	ContainsNSEC3  bool `json:"contains_nsec3"`
	ContainsSOA    bool `json:"contains_soa"`

	ResponseEDEPresent  bool   `json:"response_ede_present"`
	ResponseEDEInfoCode uint16 `json:"response_ede_info_code,omitempty"`
	ResponseEDEText     string `json:"response_ede_text,omitempty"`

	ResponseTKEYPresent     bool   `json:"response_tkey_present"`
	ResponseTKEYCount       int    `json:"response_tkey_count"`
	ResponseTKEYMode        uint16 `json:"response_tkey_mode"`
	ResponseTKEYError       uint16 `json:"response_tkey_error"`
	ResponseTKEYAlgorithm   string `json:"response_tkey_algorithm"`
	ResponseTKEYSection     string `json:"response_tkey_section"`
	ResponseTKEYOwner       string `json:"response_tkey_owner"`
	ResponseTKEYClass       string `json:"response_tkey_class"`
	ResponseTKEYTTL         uint32 `json:"response_tkey_ttl"`
	ResponseTKEYInception   uint32 `json:"response_tkey_inception"`
	ResponseTKEYExpiration  uint32 `json:"response_tkey_expiration"`
	ResponseTKEYKeyLength   int    `json:"response_tkey_key_length"`
	ResponseTKEYOtherLength int    `json:"response_tkey_other_length"`

	ClientTCPFallbackAttempted    bool     `json:"client_tcp_fallback_attempted"`
	ClientTCPFallbackSuccess      bool     `json:"client_tcp_fallback_success"`
	ClientTCPFallbackError        string   `json:"client_tcp_fallback_error,omitempty"`
	TCPFallbackAttempted          bool     `json:"tcp_fallback_attempted"`
	TCPFallbackSuccess            bool     `json:"tcp_fallback_success"`
	TCPFallbackError              string   `json:"tcp_fallback_error,omitempty"`
	FallbackResponseRcode         string   `json:"fallback_response_rcode,omitempty"`
	FallbackResponseRcodeNumeric  int      `json:"fallback_response_rcode_numeric,omitempty"`
	FallbackResponseRcodeBase     int      `json:"fallback_response_rcode_base,omitempty"`
	FallbackResponseRcodeExtended int      `json:"fallback_response_rcode_extended,omitempty"`
	FallbackResponseSize          int      `json:"fallback_response_size,omitempty"`
	FallbackAnswerCount           int      `json:"fallback_answer_count,omitempty"`
	FallbackAnswerRRTypes         []string `json:"fallback_answer_rrtypes,omitempty"`

	AnswerRRTypes     []string `json:"answer_rrtypes"`
	AuthorityRRTypes  []string `json:"authority_rrtypes"`
	AdditionalRRTypes []string `json:"additional_rrtypes"`
}

func main() {
	validateOnly := len(os.Args) == 3 && os.Args[1] == "--validate"
	executeWithRunID := len(os.Args) == 4 && os.Args[1] == "--run-id"
	if len(os.Args) != 2 && !validateOnly && !executeWithRunID {
		log.Fatalf("usage: measurement client --validate <config.json> | [--run-id <name>] <config.json>")
	}

	configPath := os.Args[len(os.Args)-1]
	runID := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
	if executeWithRunID {
		runID = os.Args[2]
	}
	if runID == "" || runID == "." || runID == ".." || strings.ContainsAny(runID, `/\`) {
		log.Fatalf("invalid run ID %q", runID)
	}

	config, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	config.RunID = runID

	if err := expandProfileExperiments(config); err != nil {
		log.Fatalf("failed to expand profile: %v", err)
	}

	duplicateGroups := wireEquivalentDuplicateGroups(config.Experiments)
	if len(duplicateGroups) > 0 {
		for _, ids := range duplicateGroups {
			log.Printf("wire-equivalent experiments: %s", strings.Join(ids, ", "))
		}
		if config.RejectWireEquivalentDuplicates {
			log.Fatalf("profile contains %d wire-equivalent duplicate groups", len(duplicateGroups))
		}
		log.Printf("warning: profile contains %d wire-equivalent duplicate groups", len(duplicateGroups))
	}

	if config.TimeoutMS <= 0 {
		config.TimeoutMS = 3000
	}

	if config.Repetitions <= 0 {
		config.Repetitions = 1
	}

	for _, experiment := range config.Experiments {
		if err := validateExperiment(experiment); err != nil {
			log.Fatalf("invalid experiment %s: %v", experiment.ExperimentID, err)
		}
	}
	if validateOnly {
		log.Printf("profile valid: experiments=%d", len(config.Experiments))
		return
	}

	if config.DrainMS <= 0 {
		config.DrainMS = 200
	}

	resultDir := filepath.Join("results", config.RunID)
	if err := os.MkdirAll(resultDir, 0755); err != nil {
		log.Fatalf("failed to create result directory: %v", err)
	}

	resultPath := filepath.Join(resultDir, "client_events.jsonl")
	annotatedAuthoritativePath := filepath.Join(resultDir, "authoritative_events_annotated.jsonl")

	for _, path := range []string{resultPath, annotatedAuthoritativePath} {
		if err := os.WriteFile(path, nil, 0644); err != nil {
			log.Fatalf("failed to reset latest-only result file %s: %v", path, err)
		}
	}

	log.Printf("run_id=%s", config.RunID)
	log.Printf("experiments=%d", len(config.Experiments))
	log.Printf("result_path=%s", resultPath)
	log.Printf("annotated_authoritative_path=%s", annotatedAuthoritativePath)

	for _, experiment := range config.Experiments {
		if err := validateExperiment(experiment); err != nil {
			log.Fatalf("invalid experiment %s: %v", experiment.ExperimentID, err)
		}

		for repetition := 1; repetition <= config.Repetitions; repetition++ {
			repetitionExperiment := experiment
			if experiment.RepetitionQNameTemplate != "" {
				repetitionQName := strings.ReplaceAll(
					experiment.RepetitionQNameTemplate,
					"{repetition}",
					strconv.Itoa(repetition),
				)
				resolvedQName, err := resolveProfileQName(repetitionQName)
				if err != nil {
					log.Fatalf("invalid repetition qname for %s repetition=%d: %v", experiment.ExperimentID, repetition, err)
				}
				repetitionExperiment.QName = resolvedQName
			}
			log.Printf(
				"running %s repetition=%d resolver=%s qname=%s qtype=%s do=%t cd=%t",
				experiment.ExperimentID,
				repetition,
				experiment.Resolver,
				repetitionExperiment.QName,
				repetitionExperiment.QType,
				repetitionExperiment.DO,
				repetitionExperiment.CD,
			)

			cacheFlushAttempted := false
			cacheFlushSuccess := false
			cacheFlushError := ""

			shouldFlush := false

			switch experiment.CacheStrategy {
			case "flush":
				shouldFlush = true

			case "flush_once":
				shouldFlush = repetition == 1

			case "none", "":
				shouldFlush = false

			default:
				log.Printf(
					"unknown cache_strategy=%s for experiment=%s",
					experiment.CacheStrategy,
					experiment.ExperimentID,
				)
			}

			if shouldFlush {
				cacheFlushAttempted = true

				if err := flushResolverCache(experiment.Resolver); err != nil {
					cacheFlushError = err.Error()

					log.Printf(
						"cache flush failed for resolver=%s experiment=%s: %v",
						experiment.Resolver,
						experiment.ExperimentID,
						err,
					)
				} else {
					cacheFlushSuccess = true
				}
			}

			authoritativeOffset := currentFileOffset(authoritativeLogPath)
			experimentWindowStart := time.Now().UTC()

			event := runExperiment(
				config.RunID,
				repetitionExperiment,
				repetition,
				time.Duration(config.TimeoutMS)*time.Millisecond,
			)

			clientResponseTime := time.Now().UTC()

			if config.DrainMS > 0 {
				time.Sleep(time.Duration(config.DrainMS) * time.Millisecond)
			}

			experimentWindowEnd := time.Now().UTC()

			event.CacheStrategy = experiment.CacheStrategy
			event.CacheFlushAttempted = cacheFlushAttempted
			event.CacheFlushSuccess = cacheFlushSuccess
			event.CacheFlushError = cacheFlushError
			event.AttributionMethod = "authoritative_log_offset_with_drain_window"
			event.AuthoritativeLogOffsetBefore = authoritativeOffset
			event.ExperimentWindowStart = experimentWindowStart.Format(time.RFC3339Nano)
			event.ExperimentClientResponseTime = clientResponseTime.Format(time.RFC3339Nano)
			event.ExperimentWindowEnd = experimentWindowEnd.Format(time.RFC3339Nano)
			event.DrainMS = config.DrainMS

			annotatedCount, primaryAnnotatedCount, err := appendAnnotatedAuthoritativeEvents(
				authoritativeLogPath,
				authoritativeOffset,
				annotatedAuthoritativePath,
				config.RunID,
				repetitionExperiment,
				repetition,
				experimentWindowStart,
				clientResponseTime,
				experimentWindowEnd,
				config.DrainMS,
			)

			event.AnnotatedAuthoritativeEvents = annotatedCount
			event.AnnotatedPrimaryAuthoritativeEvents = primaryAnnotatedCount
			if primaryAnnotatedCount == 0 {
				event.LocalHandlingWithoutPrimaryUpstream = true
				event.LocalHandlingType = classifyLocalHandling(event)
			}

			if err := appendJSONL(resultPath, event); err != nil {
				log.Fatalf("failed to write result: %v", err)
			}
			if err != nil {
				log.Printf(
					"failed to annotate authoritative events for experiment=%s repetition=%d: %v",
					experiment.ExperimentID,
					repetition,
					err,
				)
			} else if annotatedCount > 0 {
				log.Printf(
					"annotated_authoritative_events=%d experiment=%s repetition=%d",
					annotatedCount,
					experiment.ExperimentID,
					repetition,
				)
			}
		}
	}

	log.Println("done")
}

func loadConfig(path string) (*ExperimentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config ExperimentConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func resolverTarget(resolver string) (string, error) {
	switch resolver {
	case "bind":
		return "127.0.0.1:53", nil
	case "unbound":
		return "127.0.0.1:5353", nil
	case "powerdns":
		return "127.0.0.1:5354", nil
	default:
		return "", fmt.Errorf("unknown resolver: %s", resolver)
	}
}

func expandProfileExperiments(config *ExperimentConfig) error {
	if config.ProfileType != "case_based_target" {
		return fmt.Errorf("unsupported profile_type: %s", config.ProfileType)
	}
	return expandCaseBasedExperiments(config)
}

func expandCaseBasedExperiments(config *ExperimentConfig) error {
	if len(config.Resolvers) == 0 {
		return fmt.Errorf("case-based profile missing resolvers")
	}
	if len(config.Cases) == 0 {
		return fmt.Errorf("case-based profile missing cases")
	}

	counter := 1

	for _, resolver := range config.Resolvers {
		target, err := resolverTarget(resolver)
		if err != nil {
			return err
		}

		for _, queryCase := range config.Cases {
			if queryCase.CaseID == "" {
				return fmt.Errorf("case missing case_id")
			}
			if queryCase.QName == "" {
				return fmt.Errorf("case %s missing qname", queryCase.CaseID)
			}
			if queryCase.QType == "" {
				return fmt.Errorf("case %s missing qtype", queryCase.CaseID)
			}
			if len(queryCase.Variants) == 0 {
				return fmt.Errorf("case %s missing variants", queryCase.CaseID)
			}

			for _, variant := range queryCase.Variants {
				if variant.VariantID == "" {
					return fmt.Errorf("case %s has variant without variant_id", queryCase.CaseID)
				}

				qname, err := resolveProfileQName(firstNonEmpty(variant.QName, queryCase.QName))
				if err != nil {
					return fmt.Errorf("case %s variant %s: %w", queryCase.CaseID, variant.VariantID, err)
				}
				qclass := firstNonEmpty(variant.QClass, queryCase.QClass, "IN")
				qtype := firstNonEmpty(variant.QType, queryCase.QType)
				transport := firstNonEmpty(variant.Transport, config.Defaults.Transport, "udp")
				rd := boolPtr(valueOrDefaultBool(variant.Flags.RD, config.Defaults.Flags.RD, true))
				cd := valueOrDefaultBool(variant.Flags.CD, config.Defaults.Flags.CD, false)
				ad := valueOrDefaultBool(variant.Flags.AD, config.Defaults.Flags.AD, false)
				qr := valueOrDefaultBool(variant.Flags.QR, config.Defaults.Flags.QR, false)
				aa := valueOrDefaultBool(variant.Flags.AA, config.Defaults.Flags.AA, false)
				tc := valueOrDefaultBool(variant.Flags.TC, config.Defaults.Flags.TC, false)
				ra := valueOrDefaultBool(variant.Flags.RA, config.Defaults.Flags.RA, false)
				z := valueOrDefaultBool(variant.Flags.Z, config.Defaults.Flags.Z, false)
				opcode := valueOrDefaultInt(variant.Flags.Opcode, config.Defaults.Flags.Opcode, dns.OpcodeQuery)
				requestRcode := valueOrDefaultInt(variant.Flags.Rcode, config.Defaults.Flags.Rcode, dns.RcodeSuccess)

				ednsPresent := valueOrDefaultBool(variant.EDNS.Present, config.Defaults.EDNS.Present, true)
				ednsVersion := valueOrDefaultUint8(variant.EDNS.Version, config.Defaults.EDNS.Version, 0)
				udpPayloadSize := valueOrDefaultUint16(variant.EDNS.UDPSize, config.Defaults.EDNS.UDPSize, 1232)
				do := valueOrDefaultBool(variant.EDNS.DO, config.Defaults.EDNS.DO, true)
				ednsZFlags := valueOrDefaultUint16(variant.EDNS.ZFlags, config.Defaults.EDNS.ZFlags, 0)
				ednsExtendedRcode := valueOrDefaultUint8(variant.EDNS.ExtendedRcode, config.Defaults.EDNS.ExtendedRcode, 0)
				ednsOwnerName := firstNonEmpty(variant.EDNS.OwnerName, config.Defaults.EDNS.OwnerName, ".")
				optCount := variant.EDNS.OPTCount
				if optCount == 0 {
					optCount = config.Defaults.EDNS.OPTCount
				}
				if optCount == 0 && ednsPresent {
					optCount = 1
				}
				if !ednsPresent {
					do = false
					udpPayloadSize = 0
					ednsZFlags = 0
					ednsExtendedRcode = 0
					ednsOwnerName = ""
					optCount = 0
				}

				ednsOptions := variant.EDNS.Options
				if ednsOptions == nil {
					ednsOptions = config.Defaults.EDNS.Options
				}
				if !ednsPresent {
					ednsOptions = nil
				}

				cacheStrategy := firstNonEmpty(variant.CacheStrategy, config.Defaults.CacheStrategy, "flush")

				experimentID := fmt.Sprintf(
					"v6%03d_%s_%s_%s",
					counter,
					sanitizeID(resolver),
					sanitizeID(queryCase.CaseID),
					sanitizeID(variant.VariantID),
				)

				mutationName := fmt.Sprintf(
					"%s_%s_%s",
					resolver,
					queryCase.CaseID,
					variant.VariantID,
				)

				expectedObservations := mergeExpectedObservations(
					queryCase.ExpectedObservations,
					variant.ExpectedObservations,
				)
				queryValidity := firstNonEmpty(variant.QueryValidity, queryCase.QueryValidity, "valid")
				expectedProcessing := firstNonEmpty(variant.ExpectedProcessing, queryCase.ExpectedProcessing)
				expectedHeaderRcodes := variant.ExpectedHeaderRcodes
				if len(expectedHeaderRcodes) == 0 {
					expectedHeaderRcodes = queryCase.ExpectedHeaderRcodes
				}
				expectedTKEYErrors := variant.ExpectedTKEYErrors
				if len(expectedTKEYErrors) == 0 {
					expectedTKEYErrors = queryCase.ExpectedTKEYErrors
				}

				experiment := Experiment{
					ExperimentID:   experimentID,
					MutationFamily: firstNonEmpty(config.MutationFamily, queryCase.Family, "query_mutation_v6"),
					MutationName:   mutationName,
					Resolver:       resolver,
					Target:         target,
					QName:          qname,
					QType:          qtype,
					QClass:         qclass,
					Transport:      transport,
					TCPFallback: expectedBool(expectedObservations, "tcp_fallback_relevant") ||
						expectedBool(expectedObservations, "client_truncation_relevant") ||
						strings.Contains(strings.ToLower(queryCase.ResearchDimension), "truncation") ||
						strings.Contains(strings.ToLower(variant.VariantID), "tcp_fallback"),
					EDNS:                    ednsPresent,
					DO:                      do,
					AD:                      ad,
					CD:                      cd,
					RD:                      rd,
					QR:                      qr,
					AA:                      aa,
					TC:                      tc,
					RA:                      ra,
					Z:                       z,
					Opcode:                  opcode,
					RequestRcode:            requestRcode,
					UDPPayloadSize:          udpPayloadSize,
					EDNSVersion:             ednsVersion,
					EDNSZFlags:              ednsZFlags,
					EDNSExtendedRcode:       ednsExtendedRcode,
					EDNSOwnerName:           ednsOwnerName,
					OPTCount:                optCount,
					EDNSOptions:             ednsOptions,
					RawWire:                 variant.RawWire,
					CacheStrategy:           cacheStrategy,
					ExpectedValidity:        queryValidity,
					ExpectedProcessing:      expectedProcessing,
					ExpectedHeaderRcodes:    expectedHeaderRcodes,
					ExpectedTKEYErrors:      expectedTKEYErrors,
					CaseID:                  queryCase.CaseID,
					Family:                  queryCase.Family,
					Priority:                queryCase.Priority,
					ResearchDimension:       queryCase.ResearchDimension,
					ComparisonGroup:         queryCase.ComparisonGroup,
					TestTier:                queryCase.TestTier,
					ReferenceCaseID:         queryCase.ReferenceCaseID,
					ChangedProperties:       queryCase.ChangedProperties,
					VariantID:               variant.VariantID,
					VariantDescription:      variant.Description,
					ExpectedObservations:    expectedObservations,
					TKEY:                    variant.TKEY,
					RepetitionQNameTemplate: variant.RepetitionQNameTemplate,
				}

				config.Experiments = append(config.Experiments, experiment)
				counter++
			}
		}
	}

	return nil
}

func boolPtr(v bool) *bool {
	return &v
}

func valueOrDefaultBool(value *bool, fallback *bool, def bool) bool {
	if value != nil {
		return *value
	}
	if fallback != nil {
		return *fallback
	}
	return def
}

func valueOrDefaultUint8(value *uint8, fallback *uint8, def uint8) uint8 {
	if value != nil {
		return *value
	}
	if fallback != nil {
		return *fallback
	}
	return def
}

func valueOrDefaultUint16(value *uint16, fallback *uint16, def uint16) uint16 {
	if value != nil {
		return *value
	}
	if fallback != nil {
		return *fallback
	}
	return def
}

func valueOrDefaultInt(value *int, fallback *int, def int) int {
	if value != nil {
		return *value
	}
	if fallback != nil {
		return *fallback
	}
	return def
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func sanitizeID(value string) string {
	value = strings.ToLower(value)
	var builder strings.Builder
	lastUnderscore := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			builder.WriteRune('_')
			lastUnderscore = true
		}
	}
	result := strings.Trim(builder.String(), "_")
	if result == "" {
		return "x"
	}
	return result
}

func mergeExpectedObservations(base map[string]any, override map[string]any) map[string]any {
	result := map[string]any{}
	for k, v := range base {
		result[k] = v
	}
	for k, v := range override {
		result[k] = v
	}
	return result
}

func expectedBool(values map[string]any, key string) bool {
	value, ok := values[key]
	if !ok {
		return false
	}
	boolValue, ok := value.(bool)
	return ok && boolValue
}

func parseNumericMnemonic(value string, prefix string) (uint16, bool) {
	upper := strings.ToUpper(strings.TrimSpace(value))
	if !strings.HasPrefix(upper, prefix) {
		return 0, false
	}
	numeric, err := strconv.ParseUint(strings.TrimPrefix(upper, prefix), 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(numeric), true
}

func parseQType(value string) (uint16, bool) {
	upper := strings.ToUpper(strings.TrimSpace(value))
	if numeric, ok := parseNumericMnemonic(upper, "TYPE"); ok {
		return numeric, true
	}
	numeric, ok := dns.StringToType[upper]
	return numeric, ok
}

func parseQClass(value string) (uint16, bool) {
	upper := strings.ToUpper(strings.TrimSpace(value))
	if numeric, ok := parseNumericMnemonic(upper, "CLASS"); ok {
		return numeric, true
	}
	numeric, ok := dns.StringToClass[upper]
	return numeric, ok
}

func validateExperiment(experiment Experiment) error {
	if experiment.ExperimentID == "" {
		return fmt.Errorf("missing experiment_id")
	}

	if experiment.Target == "" {
		return fmt.Errorf("missing target")
	}

	if experiment.QName == "" {
		return fmt.Errorf("missing qname")
	}

	if !strings.HasSuffix(experiment.QName, ".") {
		return fmt.Errorf("qname must be absolute and end with dot")
	}
	if experiment.RepetitionQNameTemplate != "" {
		if experiment.RawWire != nil {
			return fmt.Errorf("repetition_qname_template is not supported for raw-wire queries")
		}
		if !strings.Contains(experiment.RepetitionQNameTemplate, "{repetition}") {
			return fmt.Errorf("repetition_qname_template must contain {repetition}")
		}
	}

	if experiment.RawWire == nil {
		qnameMetrics := measureQName(experiment.QName)
		if qnameMetrics.MaxLabelLength > 63 {
			return fmt.Errorf("qname label exceeds 63 octets")
		}
		if qnameMetrics.WireLength > 255 {
			return fmt.Errorf("qname exceeds 255 wire-format octets")
		}
	} else {
		rawHex := strings.ReplaceAll(strings.TrimSpace(experiment.RawWire.Hex), " ", "")
		if rawHex == "" {
			return fmt.Errorf("raw_wire.hex must not be empty")
		}
		if _, err := hex.DecodeString(rawHex); err != nil {
			return fmt.Errorf("invalid raw_wire.hex: %w", err)
		}
	}

	if _, ok := parseQType(experiment.QType); !ok {
		return fmt.Errorf("unknown qtype: %s", experiment.QType)
	}

	if _, ok := parseQClass(experiment.QClass); !ok {
		return fmt.Errorf("unknown qclass: %s", experiment.QClass)
	}
	if experiment.Opcode < 0 || experiment.Opcode > 15 {
		return fmt.Errorf("opcode must be between 0 and 15")
	}
	if experiment.RequestRcode < 0 || experiment.RequestRcode > 15 {
		return fmt.Errorf("request rcode must be between 0 and 15")
	}

	if !experiment.EDNS {
		if experiment.DO || experiment.UDPPayloadSize != 0 || experiment.EDNSVersion != 0 || experiment.EDNSZFlags != 0 || experiment.EDNSExtendedRcode != 0 || experiment.EDNSOwnerName != "" || experiment.OPTCount != 0 || len(experiment.EDNSOptions) != 0 {
			return fmt.Errorf("EDNS-disabled experiment must not carry OPT metadata")
		}
	} else if experiment.OPTCount < 1 {
		return fmt.Errorf("EDNS-enabled experiment must contain at least one OPT RR")
	}

	if experiment.TKEY != nil && experiment.TKEY.IncludeRR {
		switch strings.ToLower(firstNonEmpty(experiment.TKEY.Section, "additional")) {
		case "answer", "authority", "additional":
		default:
			return fmt.Errorf("unsupported TKEY section: %s", experiment.TKEY.Section)
		}
		if experiment.TKEY.Count < 0 {
			return fmt.Errorf("TKEY count must not be negative")
		}
		if experiment.TKEY.RRClass != "" {
			if _, ok := dns.StringToClass[strings.ToUpper(experiment.TKEY.RRClass)]; !ok {
				return fmt.Errorf("unknown TKEY RR class: %s", experiment.TKEY.RRClass)
			}
		}
		if experiment.TKEY.KeyRR != nil && experiment.TKEY.KeyRR.IncludeRR {
			switch strings.ToLower(firstNonEmpty(experiment.TKEY.KeyRR.Section, "additional")) {
			case "answer", "authority", "additional":
			default:
				return fmt.Errorf("unsupported KEY RR section: %s", experiment.TKEY.KeyRR.Section)
			}
		}
	}

	if experiment.Transport != "udp" && experiment.Transport != "tcp" {
		return fmt.Errorf("transport must be udp or tcp")
	}

	return nil
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

func packedMessageMetadata(message *dns.Msg) (int, string, error) {
	wire, err := message.Pack()
	if err != nil {
		return 0, "", err
	}
	digest := sha256.Sum256(wire)
	return len(wire), hex.EncodeToString(digest[:]), nil
}

func rawWireMetadata(wire []byte) (int, string) {
	digest := sha256.Sum256(wire)
	return len(wire), hex.EncodeToString(digest[:])
}

func rawHeaderSectionCounts(wire []byte) (int, int, int, int) {
	if len(wire) < 12 {
		return 0, 0, 0, 0
	}
	return int(binary.BigEndian.Uint16(wire[4:6])), int(binary.BigEndian.Uint16(wire[6:8])), int(binary.BigEndian.Uint16(wire[8:10])), int(binary.BigEndian.Uint16(wire[10:12]))
}

func exchangeRawDNS(wire []byte, target string, transport string, timeout time.Duration) (*dns.Msg, []byte, time.Duration, error) {
	connection, err := net.DialTimeout(transport, target, timeout)
	if err != nil {
		return nil, nil, 0, err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, 0, err
	}

	start := time.Now()
	var responseWire []byte
	if transport == "tcp" {
		if len(wire) > 65535 {
			return nil, nil, 0, fmt.Errorf("raw DNS message exceeds TCP framing limit")
		}
		framed := make([]byte, 2+len(wire))
		binary.BigEndian.PutUint16(framed[:2], uint16(len(wire)))
		copy(framed[2:], wire)
		if _, err := connection.Write(framed); err != nil {
			return nil, nil, time.Since(start), err
		}
		lengthBytes := make([]byte, 2)
		if _, err := io.ReadFull(connection, lengthBytes); err != nil {
			return nil, nil, time.Since(start), err
		}
		responseWire = make([]byte, int(binary.BigEndian.Uint16(lengthBytes)))
		count, err := io.ReadFull(connection, responseWire)
		responseWire = responseWire[:count]
		if err != nil {
			return nil, responseWire, time.Since(start), err
		}
	} else {
		if _, err := connection.Write(wire); err != nil {
			return nil, nil, time.Since(start), err
		}
		responseWire = make([]byte, 65535)
		count, err := connection.Read(responseWire)
		if err != nil {
			return nil, nil, time.Since(start), err
		}
		responseWire = responseWire[:count]
	}

	rtt := time.Since(start)
	response := new(dns.Msg)
	if err := response.Unpack(responseWire); err != nil {
		return nil, responseWire, rtt, fmt.Errorf("received %d response bytes but could not decode DNS message: %w", len(responseWire), err)
	}
	return response, responseWire, rtt, nil
}

func rawMessageID(wire []byte) uint16 {
	if len(wire) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(wire[:2])
}

func rcodeName(rcode int) string {
	if name, ok := dns.RcodeToString[rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE%d", rcode)
}

func populateRawResponseEvidence(event *ClientResultEvent, responseWire []byte) {
	if len(responseWire) == 0 {
		return
	}
	event.ResponseReceived = true
	event.ResponseWireSize = len(responseWire)
	event.ResponseSize = len(responseWire)
	_, event.ResponseWireSHA256 = rawWireMetadata(responseWire)

	if len(responseWire) < 12 {
		return
	}

	event.ResponseMessageID = binary.BigEndian.Uint16(responseWire[0:2])
	event.ResponseIDMatchesClient = event.ResponseMessageID == event.ClientMessageID
	flags := binary.BigEndian.Uint16(responseWire[2:4])
	event.ResponseQR = flags&(1<<15) != 0
	event.ResponseOpcode = int((flags >> 11) & 0x0f)
	event.ResponseAA = flags&(1<<10) != 0
	event.ResponseTC = flags&(1<<9) != 0
	event.ResponseRD = flags&(1<<8) != 0
	event.ResponseRA = flags&(1<<7) != 0
	event.ResponseZ = flags&(1<<6) != 0
	event.ResponseAD = flags&(1<<5) != 0
	event.ResponseCD = flags&(1<<4) != 0
	rcode := int(flags & 0x0f)
	event.ResponseRcode = rcodeName(rcode)
	event.ResponseRcodeNumeric = rcode
	event.ResponseRcodeBase = rcode
	event.ResponseHeaderQuestionCount = int(binary.BigEndian.Uint16(responseWire[4:6]))
	event.ResponseHeaderAnswerCount = int(binary.BigEndian.Uint16(responseWire[6:8]))
	event.ResponseHeaderAuthorityCount = int(binary.BigEndian.Uint16(responseWire[8:10]))
	event.ResponseHeaderAdditionalCount = int(binary.BigEndian.Uint16(responseWire[10:12]))
}

func runExperiment(
	runID string,
	experiment Experiment,
	repetition int,
	timeout time.Duration,
) ClientResultEvent {
	qtype, _ := parseQType(experiment.QType)
	qclass, _ := parseQClass(experiment.QClass)

	message := new(dns.Msg)
	message.SetQuestion(experiment.QName, qtype)
	message.Question[0].Qclass = qclass

	rd := true
	if experiment.RD != nil {
		rd = *experiment.RD
	}

	message.RecursionDesired = rd
	message.AuthenticatedData = experiment.AD
	message.CheckingDisabled = experiment.CD
	message.Response = experiment.QR
	message.Authoritative = experiment.AA
	message.Truncated = experiment.TC
	message.RecursionAvailable = experiment.RA
	message.Zero = experiment.Z
	message.Opcode = experiment.Opcode
	message.Rcode = experiment.RequestRcode

	var clientUDPPayloadSize *uint16
	var clientEDNSVersion *uint8
	var clientEDNSZFlags *uint16
	var clientEDNSExtendedRcode *uint8
	clientEDNSOwnerName := ""
	effectiveUDPLimit := uint16(512)

	if experiment.TKEY != nil && experiment.TKEY.IncludeRR {
		count := experiment.TKEY.Count
		if count == 0 {
			count = 1
		}
		for index := 0; index < count; index++ {
			tkeyRR, err := buildTKEYRR(experiment)
			if err != nil {
				return queryConstructionErrorEvent(runID, experiment, repetition, err)
			}
			if err := appendRRToMessageSection(message, experiment.TKEY.Section, tkeyRR); err != nil {
				return queryConstructionErrorEvent(runID, experiment, repetition, err)
			}
		}
		if experiment.TKEY.KeyRR != nil && experiment.TKEY.KeyRR.IncludeRR {
			keyRR, err := buildKEYRR(experiment)
			if err != nil {
				return queryConstructionErrorEvent(runID, experiment, repetition, err)
			}
			if err := appendRRToMessageSection(message, experiment.TKEY.KeyRR.Section, keyRR); err != nil {
				return queryConstructionErrorEvent(runID, experiment, repetition, err)
			}
		}
	}

	if experiment.EDNS {
		udpPayloadSize := experiment.UDPPayloadSize

		clientUDPPayloadSize = &udpPayloadSize
		clientEDNSVersion = &experiment.EDNSVersion
		clientEDNSZFlags = &experiment.EDNSZFlags
		clientEDNSExtendedRcode = &experiment.EDNSExtendedRcode
		clientEDNSOwnerName = firstNonEmpty(experiment.EDNSOwnerName, ".")
		effectiveUDPLimit = udpPayloadSize

		for index := 0; index < experiment.OPTCount; index++ {
			opt, err := buildOPT(udpPayloadSize, experiment.EDNSVersion, experiment.DO, experiment.EDNSZFlags, experiment.EDNSExtendedRcode, experiment.EDNSOwnerName, experiment.EDNSOptions)
			if err != nil {
				return queryConstructionErrorEvent(runID, experiment, repetition, err)
			}
			message.Extra = append(message.Extra, opt)
		}
	}

	var queryWire []byte
	var queryWireSize int
	var queryWireSHA256 string
	if experiment.RawWire != nil {
		queryWire, _ = hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(experiment.RawWire.Hex), " ", ""))
		queryWireSize, queryWireSHA256 = rawWireMetadata(queryWire)
	} else {
		var packErr error
		queryWire, packErr = message.Pack()
		if packErr != nil {
			return queryConstructionErrorEvent(runID, experiment, repetition, fmt.Errorf("failed to pack query: %w", packErr))
		}
		queryWireSize, queryWireSHA256 = rawWireMetadata(queryWire)
	}
	effectiveQName, effectiveQType, effectiveQClass := effectiveExperimentQuestion(experiment)
	qnameMetrics := measureQName(effectiveQName)
	queryOPTCount := optCount(message.Extra)
	queryEDNSOptions := ednsOptionInfoFromRRs(message.Extra)
	queryTKEY := tkeyDetailsFromRRs(messageRecords(message), message)
	queryKEY := keyDetailsFromRRs(messageRecords(message), message)
	queryQuestionCount := len(message.Question)
	queryAnswerCount := len(message.Answer)
	queryAuthorityCount := len(message.Ns)
	queryAdditionalCount := len(message.Extra)
	queryAnswerRRTypes := rrTypes(message.Answer)
	queryAuthorityRRTypes := rrTypes(message.Ns)
	queryAdditionalRRTypes := rrTypes(message.Extra)
	if experiment.RawWire != nil {
		queryQuestionCount, queryAnswerCount, queryAuthorityCount, queryAdditionalCount = rawHeaderSectionCounts(queryWire)
		decoded := new(dns.Msg)
		if decoded.Unpack(queryWire) == nil {
			queryAnswerRRTypes = rrTypes(decoded.Answer)
			queryAuthorityRRTypes = rrTypes(decoded.Ns)
			queryAdditionalRRTypes = rrTypes(decoded.Extra)
		}
	}

	var response *dns.Msg
	var responseWire []byte
	var rtt time.Duration
	var err error
	response, responseWire, rtt, err = exchangeRawDNS(queryWire, experiment.Target, experiment.Transport, timeout)

	event := ClientResultEvent{
		RunID:          runID,
		ExperimentID:   experiment.ExperimentID,
		MutationFamily: experiment.MutationFamily,
		MutationName:   experiment.MutationName,
		Resolver:       experiment.Resolver,
		Target:         experiment.Target,
		Repetition:     repetition,

		CaseID:               experiment.CaseID,
		Family:               experiment.Family,
		Priority:             experiment.Priority,
		ResearchDimension:    experiment.ResearchDimension,
		ComparisonGroup:      experiment.ComparisonGroup,
		TestTier:             experiment.TestTier,
		ReferenceCaseID:      experiment.ReferenceCaseID,
		ChangedProperties:    experiment.ChangedProperties,
		VariantID:            experiment.VariantID,
		VariantDescription:   experiment.VariantDescription,
		ExpectedValidity:     experiment.ExpectedValidity,
		ExpectedProcessing:   experiment.ExpectedProcessing,
		ExpectedHeaderRcodes: experiment.ExpectedHeaderRcodes,
		ExpectedTKEYErrors:   experiment.ExpectedTKEYErrors,
		ExpectedObservations: experiment.ExpectedObservations,

		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		Transport:     experiment.Transport,
		QName:         effectiveQName,
		QType:         effectiveQType,
		QTypeNumeric:  qtype,
		QClass:        effectiveQClass,
		QClassNumeric: qclass,

		QNameTextLength:     qnameMetrics.TextLength,
		QNameWireLength:     qnameMetrics.WireLength,
		QNameLabelCount:     qnameMetrics.LabelCount,
		QNameMaxLabelLength: qnameMetrics.MaxLabelLength,
		QNameHasUppercase:   qnameMetrics.HasUppercase,

		ClientDO:                experiment.DO,
		ClientAD:                experiment.AD,
		ClientCD:                experiment.CD,
		ClientRD:                rd,
		ClientQR:                experiment.QR,
		ClientAA:                experiment.AA,
		ClientTC:                experiment.TC,
		ClientRA:                experiment.RA,
		ClientZ:                 experiment.Z,
		ClientOpcode:            experiment.Opcode,
		ClientRequestRcode:      experiment.RequestRcode,
		ClientMessageID:         rawMessageID(queryWire),
		ClientEDNS:              experiment.EDNS,
		ClientUDPPayloadSize:    clientUDPPayloadSize,
		EffectiveUDPLimit:       effectiveUDPLimit,
		ClientEDNSVersion:       clientEDNSVersion,
		ClientEDNSZFlags:        clientEDNSZFlags,
		ClientEDNSExtendedRcode: clientEDNSExtendedRcode,
		ClientEDNSOwnerName:     clientEDNSOwnerName,
		QueryOPTCount:           queryOPTCount,
		QueryEDNSOptions:        queryEDNSOptions,
		QueryWireSize:           queryWireSize,
		QueryWireSHA256:         queryWireSHA256,
		QueryWireHex:            hex.EncodeToString(queryWire),
		QueryRawWire:            experiment.RawWire != nil,
		QueryQuestionCount:      queryQuestionCount,
		QueryAnswerCount:        queryAnswerCount,
		QueryAuthorityCount:     queryAuthorityCount,
		QueryAdditionalCount:    queryAdditionalCount,
		QueryAnswerRRTypes:      queryAnswerRRTypes,
		QueryAuthorityRRTypes:   queryAuthorityRRTypes,
		QueryAdditionalRRTypes:  queryAdditionalRRTypes,

		QueryTKEYPresent:     queryTKEY.Present,
		QueryTKEYCount:       queryTKEY.Count,
		QueryTKEYMode:        queryTKEY.Mode,
		QueryTKEYError:       queryTKEY.Error,
		QueryTKEYAlgorithm:   queryTKEY.Algorithm,
		QueryTKEYSection:     queryTKEY.Section,
		QueryTKEYOwner:       queryTKEY.Owner,
		QueryTKEYClass:       queryTKEY.Class,
		QueryTKEYTTL:         queryTKEY.TTL,
		QueryTKEYInception:   queryTKEY.Inception,
		QueryTKEYExpiration:  queryTKEY.Expiration,
		QueryTKEYKeyLength:   queryTKEY.KeyLength,
		QueryTKEYOtherLength: queryTKEY.OtherLength,
		QueryKEYPresent:      queryKEY.Present,
		QueryKEYCount:        queryKEY.Count,
		QueryKEYSection:      queryKEY.Section,
		QueryKEYOwner:        queryKEY.Owner,
		QueryKEYAlgorithm:    queryKEY.Algorithm,

		RTTMS: float64(rtt.Microseconds()) / 1000.0,
	}
	if experiment.RawWire != nil {
		event.QueryRawWireDescription = experiment.RawWire.Description
	}
	populateRawResponseEvidence(&event, responseWire)

	if err != nil {
		var netErr net.Error
		event.Timeout = errors.As(err, &netErr) && netErr.Timeout()
		if event.ResponseReceived {
			event.ErrorKind = "response_decode_error"
			event.ResponseDecodeError = err.Error()
			event.ResponseWireHex = hex.EncodeToString(responseWire)
		} else if event.Timeout {
			event.ErrorKind = "timeout"
		} else {
			event.ErrorKind = "transport_error"
		}
		event.Error = err.Error()
		return event
	}

	if response == nil {
		event.ErrorKind = "nil_response"
		event.Error = "nil response"
		return event
	}
	event.ResponseDecodeSuccess = true

	event.ResponseRcode, event.ResponseRcodeNumeric, event.ResponseRcodeBase, event.ResponseRcodeExtended = responseRcodeMetadata(response)
	event.ResponseMessageID = response.Id
	event.ResponseIDMatchesClient = response.Id == event.ClientMessageID
	event.ResponseQR = response.Response
	event.ResponseAA = response.Authoritative
	event.ResponseRD = response.RecursionDesired
	event.ResponseZ = response.Zero
	event.ResponseOpcode = response.Opcode
	event.ResponseAD = response.AuthenticatedData
	event.ResponseCD = response.CheckingDisabled
	event.ResponseTC = response.Truncated
	event.ResponseRA = response.RecursionAvailable
	if event.ResponseWireSize == 0 {
		event.ResponseSize = response.Len()
		event.ResponseWireSize = response.Len()
	}

	if opt := response.IsEdns0(); opt != nil {
		version := ednsVersion(opt)
		event.ResponseEDNSVersion = &version
		event.ResponseEDNSOptions = ednsOptionInfoFromRRs(response.Extra)
	}
	event.ResponseOPTCount = optCount(response.Extra)

	if opt := response.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			ede, ok := option.(*dns.EDNS0_EDE)
			if !ok {
				continue
			}

			event.ResponseEDEPresent = true
			event.ResponseEDEInfoCode = ede.InfoCode
			event.ResponseEDEText = ede.ExtraText
			break
		}
	}

	event.AnswerCount = len(response.Answer)
	event.AuthorityCount = len(response.Ns)
	event.AdditionalCount = len(response.Extra)

	event.AnswerRRTypes = rrTypes(response.Answer)
	event.AuthorityRRTypes = rrTypes(response.Ns)
	event.AdditionalRRTypes = rrTypes(response.Extra)

	responseTKEY := tkeyDetailsFromRRs(messageRecords(response), response)
	event.ResponseTKEYPresent = responseTKEY.Present
	event.ResponseTKEYCount = responseTKEY.Count
	event.ResponseTKEYMode = responseTKEY.Mode
	event.ResponseTKEYError = responseTKEY.Error
	event.ResponseTKEYAlgorithm = responseTKEY.Algorithm
	event.ResponseTKEYSection = responseTKEY.Section
	event.ResponseTKEYOwner = responseTKEY.Owner
	event.ResponseTKEYClass = responseTKEY.Class
	event.ResponseTKEYTTL = responseTKEY.TTL
	event.ResponseTKEYInception = responseTKEY.Inception
	event.ResponseTKEYExpiration = responseTKEY.Expiration
	event.ResponseTKEYKeyLength = responseTKEY.KeyLength
	event.ResponseTKEYOtherLength = responseTKEY.OtherLength

	if response.Truncated && experiment.TCPFallback {
		event.ClientTCPFallbackAttempted = true
		event.TCPFallbackAttempted = true

		tcpClient := &dns.Client{
			Net:     "tcp",
			Timeout: timeout,
		}

		fallbackResponse, _, fallbackErr := tcpClient.Exchange(
			message,
			experiment.Target,
		)

		if fallbackErr != nil {
			event.ClientTCPFallbackError = fallbackErr.Error()
			event.TCPFallbackError = fallbackErr.Error()
		} else if fallbackResponse == nil {
			event.ClientTCPFallbackError = "nil fallback response"
			event.TCPFallbackError = "nil fallback response"
		} else {
			event.ClientTCPFallbackSuccess = true
			event.TCPFallbackSuccess = true
			event.FallbackResponseRcode, event.FallbackResponseRcodeNumeric, event.FallbackResponseRcodeBase, event.FallbackResponseRcodeExtended = responseRcodeMetadata(fallbackResponse)
			event.FallbackResponseSize = fallbackResponse.Len()
			event.FallbackAnswerCount = len(fallbackResponse.Answer)
			event.FallbackAnswerRRTypes = rrTypes(fallbackResponse.Answer)
		}
	}

	allRecords := messageRecords(response)

	for _, rr := range allRecords {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG:
			event.ContainsRRSIG = true
		case dns.TypeDNSKEY:
			event.ContainsDNSKEY = true
		case dns.TypeDS:
			event.ContainsDS = true
		case dns.TypeNSEC:
			event.ContainsNSEC = true
		case dns.TypeNSEC3:
			event.ContainsNSEC3 = true
		case dns.TypeSOA:
			event.ContainsSOA = true
		}
	}

	return event
}

func buildOPT(udpPayloadSize uint16, version uint8, do bool, zFlags uint16, extendedRcode uint8, ownerName string, options []EDNSOptionConfig) (*dns.OPT, error) {
	owner := firstNonEmpty(ownerName, ".")
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(owner),
			Rrtype: dns.TypeOPT,
			Class:  udpPayloadSize,
			Ttl:    uint32(extendedRcode)<<24 | uint32(version)<<16 | uint32(zFlags),
		},
	}

	if do {
		opt.Hdr.Ttl |= 1 << 15
	}

	for _, optionConfig := range options {
		option, err := buildEDNSOption(optionConfig)
		if err != nil {
			return nil, err
		}
		opt.Option = append(opt.Option, option)
	}

	return opt, nil
}

func buildEDNSOption(config EDNSOptionConfig) (dns.EDNS0, error) {
	name := strings.ToLower(config.Name)

	if config.Code == dns.EDNS0PADDING || name == "padding" {
		length := config.Length
		if length < 0 {
			return nil, fmt.Errorf("negative EDNS padding length")
		}
		return &dns.EDNS0_PADDING{Padding: make([]byte, length)}, nil
	}

	var data []byte
	if config.DataHex != "" {
		decoded, err := hex.DecodeString(config.DataHex)
		if err != nil {
			return nil, fmt.Errorf("invalid EDNS option data_hex for code=%d: %w", config.Code, err)
		}
		data = decoded
	} else if config.Length > 0 {
		data = make([]byte, config.Length)
	}

	return &dns.EDNS0_LOCAL{Code: config.Code, Data: data}, nil
}

func buildTKEYRR(experiment Experiment) (dns.RR, error) {
	if experiment.TKEY == nil {
		return nil, fmt.Errorf("missing tkey config")
	}

	config := experiment.TKEY
	algorithm := config.Algorithm
	if algorithm == "" {
		algorithm = "hmac-sha256."
	}

	keyData, err := decodeOptionalHex(config.KeyDataHex)
	if err != nil {
		return nil, fmt.Errorf("invalid TKEY key_data_hex: %w", err)
	}

	otherData, err := decodeOptionalHex(config.OtherDataHex)
	if err != nil {
		return nil, fmt.Errorf("invalid TKEY other_data_hex: %w", err)
	}

	var rrClass uint16 = dns.ClassANY
	if config.RRClass != "" {
		rrClass = dns.StringToClass[strings.ToUpper(config.RRClass)]
	}
	owner := firstNonEmpty(config.OwnerName, experiment.QName)

	return &dns.TKEY{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(owner),
			Rrtype: dns.TypeTKEY,
			Class:  rrClass,
			Ttl:    config.TTL,
		},
		Algorithm:  dns.Fqdn(algorithm),
		Inception:  config.Inception,
		Expiration: config.Expiration,
		Mode:       config.Mode,
		Error:      config.Error,
		KeySize:    uint16(len(keyData)),
		Key:        hex.EncodeToString(keyData),
		OtherLen:   uint16(len(otherData)),
		OtherData:  hex.EncodeToString(otherData),
	}, nil
}

func buildKEYRR(experiment Experiment) (dns.RR, error) {
	if experiment.TKEY == nil || experiment.TKEY.KeyRR == nil {
		return nil, fmt.Errorf("missing KEY RR config")
	}
	config := experiment.TKEY.KeyRR
	var rrClass uint16 = dns.ClassANY
	if config.RRClass != "" {
		rrClass = dns.StringToClass[strings.ToUpper(config.RRClass)]
	}
	owner := firstNonEmpty(config.OwnerName, experiment.QName)
	publicKey := config.PublicKeyBase64
	if publicKey == "" {
		publicKey = base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	}
	return &dns.KEY{DNSKEY: dns.DNSKEY{
		Hdr:   dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeKEY, Class: rrClass, Ttl: config.TTL},
		Flags: config.Flags, Protocol: config.Protocol, Algorithm: config.Algorithm, PublicKey: publicKey,
	}}, nil
}

func queryConstructionErrorEvent(runID string, experiment Experiment, repetition int, err error) ClientResultEvent {
	return ClientResultEvent{
		RunID: runID, ExperimentID: experiment.ExperimentID,
		MutationFamily: experiment.MutationFamily, MutationName: experiment.MutationName,
		Resolver: experiment.Resolver, Target: experiment.Target, Repetition: repetition,
		CaseID: experiment.CaseID, Family: experiment.Family, Priority: experiment.Priority,
		ResearchDimension: experiment.ResearchDimension, ComparisonGroup: experiment.ComparisonGroup,
		TestTier: experiment.TestTier, ReferenceCaseID: experiment.ReferenceCaseID,
		ChangedProperties: experiment.ChangedProperties,
		Error:             err.Error(), Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func appendRRToMessageSection(message *dns.Msg, section string, rr dns.RR) error {
	switch strings.ToLower(strings.TrimSpace(section)) {
	case "", "additional", "extra":
		message.Extra = append(message.Extra, rr)
	case "answer":
		message.Answer = append(message.Answer, rr)
	case "authority", "ns":
		message.Ns = append(message.Ns, rr)
	default:
		return fmt.Errorf("unsupported TKEY section %q; use additional, answer, or authority", section)
	}
	return nil
}

func responseRcodeMetadata(message *dns.Msg) (string, int, int, int) {
	if message == nil {
		return "", 0, 0, 0
	}
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

type wireExperimentFingerprint struct {
	Resolver     string             `json:"resolver"`
	QName        string             `json:"qname"`
	QType        string             `json:"qtype"`
	QClass       string             `json:"qclass"`
	Transport    string             `json:"transport"`
	RD           bool               `json:"rd"`
	CD           bool               `json:"cd"`
	AD           bool               `json:"ad"`
	QR           bool               `json:"qr"`
	AA           bool               `json:"aa"`
	TC           bool               `json:"tc"`
	RA           bool               `json:"ra"`
	Z            bool               `json:"z"`
	Opcode       int                `json:"opcode"`
	Rcode        int                `json:"rcode"`
	EDNS         bool               `json:"edns"`
	DO           bool               `json:"do"`
	UDPPayload   uint16             `json:"udp_payload"`
	EDNSVersion  uint8              `json:"edns_version"`
	EDNSZFlags   uint16             `json:"edns_z_flags"`
	EDNSExtRcode uint8              `json:"edns_extended_rcode"`
	EDNSOwner    string             `json:"edns_owner"`
	OPTCount     int                `json:"opt_count"`
	EDNSOptions  []EDNSOptionConfig `json:"edns_options"`
	TKEY         *TKEYConfig        `json:"tkey,omitempty"`
	RawWire      *RawWireConfig     `json:"raw_wire,omitempty"`
}

func wireEquivalentDuplicateGroups(experiments []Experiment) [][]string {
	groups := map[string][]string{}
	for _, experiment := range experiments {
		rd := true
		if experiment.RD != nil {
			rd = *experiment.RD
		}
		fingerprint := wireExperimentFingerprint{
			Resolver:     experiment.Resolver,
			QName:        dns.Fqdn(experiment.QName),
			QType:        strings.ToUpper(experiment.QType),
			QClass:       strings.ToUpper(experiment.QClass),
			Transport:    strings.ToLower(experiment.Transport),
			RD:           rd,
			CD:           experiment.CD,
			AD:           experiment.AD,
			QR:           experiment.QR,
			AA:           experiment.AA,
			TC:           experiment.TC,
			RA:           experiment.RA,
			Z:            experiment.Z,
			Opcode:       experiment.Opcode,
			Rcode:        experiment.RequestRcode,
			EDNS:         experiment.EDNS,
			DO:           experiment.DO,
			UDPPayload:   experiment.UDPPayloadSize,
			EDNSVersion:  experiment.EDNSVersion,
			EDNSZFlags:   experiment.EDNSZFlags,
			EDNSExtRcode: experiment.EDNSExtendedRcode,
			EDNSOwner:    experiment.EDNSOwnerName,
			OPTCount:     experiment.OPTCount,
			EDNSOptions:  experiment.EDNSOptions,
			TKEY:         experiment.TKEY,
			RawWire:      experiment.RawWire,
		}
		encoded, err := json.Marshal(fingerprint)
		if err != nil {
			continue
		}
		key := string(encoded)
		groups[key] = append(groups[key], experiment.ExperimentID)
	}
	var duplicates [][]string
	for _, ids := range groups {
		if len(ids) > 1 {
			duplicates = append(duplicates, ids)
		}
	}
	return duplicates
}

func decodeOptionalHex(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	return hex.DecodeString(value)
}

func ednsVersion(opt *dns.OPT) uint8 {
	return uint8((opt.Hdr.Ttl >> 16) & 0xff)
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

func ednsOptionInfoFromRRs(records []dns.RR) []EDNSOptionInfo {
	var result []EDNSOptionInfo
	for _, rr := range records {
		opt, ok := rr.(*dns.OPT)
		if !ok {
			continue
		}
		for _, option := range opt.Option {
			result = append(result, ednsOptionInfo(option))
		}
	}
	return result
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

func ednsOptionInfo(option dns.EDNS0) EDNSOptionInfo {
	info := EDNSOptionInfo{
		Code: option.Option(),
		Name: ednsOptionName(option.Option()),
	}

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
	default:
		info.Length = 0
	}

	return info
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

type TKEYDetails struct {
	Present     bool
	Count       int
	Mode        uint16
	Error       uint16
	Algorithm   string
	Section     string
	Owner       string
	Class       string
	TTL         uint32
	Inception   uint32
	Expiration  uint32
	KeyLength   int
	OtherLength int
}

type KEYDetails struct {
	Present   bool
	Count     int
	Section   string
	Owner     string
	Algorithm uint8
}

func tkeyDetailsFromRRs(records []dns.RR, message *dns.Msg) TKEYDetails {
	details := TKEYDetails{Section: tkeySection(message)}
	for _, rr := range records {
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
		details.Owner = tkey.Hdr.Name
		details.Class = dns.ClassToString[tkey.Hdr.Class]
		details.TTL = tkey.Hdr.Ttl
		details.Inception = tkey.Inception
		details.Expiration = tkey.Expiration
		details.KeyLength = decodedHexLength(tkey.Key)
		details.OtherLength = decodedHexLength(tkey.OtherData)
	}
	return details
}

func keyDetailsFromRRs(records []dns.RR, message *dns.Msg) KEYDetails {
	details := KEYDetails{}
	for _, rr := range records {
		key, ok := rr.(*dns.KEY)
		if !ok {
			continue
		}
		details.Count++
		if details.Present {
			continue
		}
		details.Present = true
		details.Owner = key.Hdr.Name
		details.Algorithm = key.Algorithm
		details.Section = rrSection(message, rr)
	}
	return details
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

func decodedHexLength(value string) int {
	if value == "" {
		return 0
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return 0
	}
	return len(decoded)
}

func resolveProfileQName(value string) (string, error) {
	if value != "@first_nsec3_owner@" {
		return value, nil
	}
	file, err := os.Open(nsec3SignedZonePath)
	if err != nil {
		return "", fmt.Errorf("open NSEC3 signed zone for dynamic owner: %w", err)
	}
	defer file.Close()
	parser := dns.NewZoneParser(file, "nsec3.mut.test.", nsec3SignedZonePath)
	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		if rr.Header().Rrtype == dns.TypeNSEC3 {
			return dns.Fqdn(rr.Header().Name), nil
		}
	}
	if err := parser.Err(); err != nil {
		return "", fmt.Errorf("parse NSEC3 signed zone: %w", err)
	}
	return "", fmt.Errorf("no NSEC3 RR owner found in %s", nsec3SignedZonePath)
}

func classifyLocalHandling(event ClientResultEvent) string {
	if event.ResponseReceived && !event.ResponseDecodeSuccess {
		return "local_response_undecodable"
	}
	if event.ResponseRcode == "" && event.Error != "" {
		if event.Timeout {
			return "no_response_timeout"
		}
		return "transport_or_client_error"
	}

	switch event.ResponseRcode {
	case "REFUSED":
		return "locally_refused"
	case "FORMERR":
		return "locally_formerr"
	case "SERVFAIL":
		return "locally_servfail"
	case "NOTIMP":
		return "locally_notimp"
	case "NOERROR":
		return "locally_answered_or_cached"
	default:
		if event.ResponseRcode != "" {
			return "locally_" + strings.ToLower(event.ResponseRcode)
		}
		return "no_primary_upstream_observed"
	}
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

func appendJSONL(path string, value any) error {
	file, err := os.OpenFile(
		path,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(value)
}

func currentFileOffset(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}

	return info.Size()
}

func appendAnnotatedAuthoritativeEvents(
	rawPath string,
	offset int64,
	outputPath string,
	runID string,
	experiment Experiment,
	repetition int,
	experimentWindowStart time.Time,
	clientResponseTime time.Time,
	experimentWindowEnd time.Time,
	drainMS int,
) (int, int, error) {
	file, err := os.Open(rawPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	defer file.Close()

	if _, err := file.Seek(offset, 0); err != nil {
		return 0, 0, err
	}

	newData, err := io.ReadAll(file)
	if err != nil {
		return 0, 0, err
	}

	lines := strings.Split(string(newData), "\n")
	count := 0
	primaryCount := 0
	seenPrimary := false
	previousPrimaryTC := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return count, primaryCount, fmt.Errorf("failed to parse authoritative event: %w line=%s", err, line)
		}

		event["run_id"] = runID
		event["experiment_id"] = experiment.ExperimentID
		event["mutation_family"] = experiment.MutationFamily
		event["mutation_name"] = experiment.MutationName
		event["case_id"] = experiment.CaseID
		event["family"] = experiment.Family
		event["priority"] = experiment.Priority
		event["research_dimension"] = experiment.ResearchDimension
		event["comparison_group"] = experiment.ComparisonGroup
		event["test_tier"] = experiment.TestTier
		event["reference_case_id"] = experiment.ReferenceCaseID
		event["changed_properties"] = experiment.ChangedProperties
		event["variant_id"] = experiment.VariantID
		event["variant_description"] = experiment.VariantDescription
		event["resolver"] = experiment.Resolver
		event["target"] = experiment.Target
		event["repetition"] = repetition
		event["attribution_method"] = "authoritative_log_offset_with_drain_window"
		event["authoritative_log_offset_before"] = offset
		event["experiment_window_start"] = experimentWindowStart.Format(time.RFC3339Nano)
		event["experiment_client_response_time"] = clientResponseTime.Format(time.RFC3339Nano)
		event["experiment_window_end"] = experimentWindowEnd.Format(time.RFC3339Nano)
		event["drain_ms"] = drainMS

		effectiveQName, effectiveQType, effectiveQClass := effectiveExperimentQuestion(experiment)
		event["client_configured_qname"] = experiment.QName
		event["client_configured_qtype"] = strings.ToUpper(experiment.QType)
		event["client_configured_qclass"] = strings.ToUpper(experiment.QClass)
		event["client_qname"] = effectiveQName
		clientQNameMetrics := measureQName(effectiveQName)
		event["client_qname_text_length"] = clientQNameMetrics.TextLength
		event["client_qname_wire_length"] = clientQNameMetrics.WireLength
		event["client_qname_label_count"] = clientQNameMetrics.LabelCount
		event["client_qname_max_label_length"] = clientQNameMetrics.MaxLabelLength
		event["client_qname_has_uppercase"] = clientQNameMetrics.HasUppercase
		event["client_qtype"] = effectiveQType
		if clientQTypeNumeric, ok := parseQType(effectiveQType); ok {
			event["client_qtype_numeric"] = clientQTypeNumeric
		}
		event["client_qclass"] = effectiveQClass
		if clientQClassNumeric, ok := parseQClass(effectiveQClass); ok {
			event["client_qclass_numeric"] = clientQClassNumeric
		}
		event["client_transport"] = experiment.Transport
		event["client_edns"] = experiment.EDNS
		event["client_do"] = experiment.DO
		event["client_cd"] = experiment.CD
		event["client_edns_version"] = nil
		if experiment.EDNS {
			event["client_edns_version"] = experiment.EDNSVersion
		}
		event["client_edns_options"] = optionInfoFromConfig(experiment.EDNSOptions)
		event["client_configured_tkey_present"] = experiment.TKEY != nil && experiment.TKEY.IncludeRR
		if experiment.TKEY != nil {
			event["client_configured_tkey_mode"] = experiment.TKEY.Mode
			event["client_configured_tkey_algorithm"] = experiment.TKEY.Algorithm
			event["client_configured_tkey_section"] = firstNonEmpty(experiment.TKEY.Section, "additional")
			event["client_configured_tkey_count"] = experiment.TKEY.Count
			event["client_configured_tkey_owner"] = firstNonEmpty(experiment.TKEY.OwnerName, experiment.QName)
			event["client_configured_tkey_rr_class"] = firstNonEmpty(experiment.TKEY.RRClass, "ANY")
			event["client_configured_tkey_ttl"] = experiment.TKEY.TTL
			event["client_configured_tkey_inception"] = experiment.TKEY.Inception
			event["client_configured_tkey_expiration"] = experiment.TKEY.Expiration
			event["client_configured_tkey_error"] = experiment.TKEY.Error
			event["client_configured_tkey_key_length"] = len(experiment.TKEY.KeyDataHex) / 2
			event["client_configured_tkey_other_length"] = len(experiment.TKEY.OtherDataHex) / 2
			if experiment.TKEY.KeyRR != nil {
				event["client_configured_key_rr_present"] = experiment.TKEY.KeyRR.IncludeRR
				event["client_configured_key_rr_section"] = firstNonEmpty(experiment.TKEY.KeyRR.Section, "additional")
				event["client_configured_key_rr_algorithm"] = experiment.TKEY.KeyRR.Algorithm
			}
		}
		event["expected_validity"] = experiment.ExpectedValidity
		event["expected_processing"] = experiment.ExpectedProcessing
		event["expected_header_rcodes"] = experiment.ExpectedHeaderRcodes
		event["expected_tkey_errors"] = experiment.ExpectedTKEYErrors

		clientRD := true
		if experiment.RD != nil {
			clientRD = *experiment.RD
		}
		event["client_rd"] = clientRD

		effectiveUDPLimit := uint16(512)
		var clientUDPPayloadSize any = nil

		if experiment.EDNS {
			udpPayloadSize := experiment.UDPPayloadSize
			if udpPayloadSize == 0 {
				udpPayloadSize = 1232
			}

			clientUDPPayloadSize = udpPayloadSize
			effectiveUDPLimit = udpPayloadSize
		}

		event["client_udp_payload_size"] = clientUDPPayloadSize
		event["effective_udp_limit"] = effectiveUDPLimit

		role := annotatedAuthoritativeRole(event, experiment, &seenPrimary, &previousPrimaryTC)
		event["upstream_role"] = role
		if strings.HasPrefix(role, "primary_") {
			primaryCount++
		}

		if err := appendJSONL(outputPath, event); err != nil {
			return count, primaryCount, err
		}

		count++
	}

	return count, primaryCount, nil
}

func optionInfoFromConfig(options []EDNSOptionConfig) []EDNSOptionInfo {
	var result []EDNSOptionInfo
	for _, config := range options {
		option, err := buildEDNSOption(config)
		if err != nil {
			result = append(result, EDNSOptionInfo{
				Code:   config.Code,
				Name:   firstNonEmpty(config.Name, ednsOptionName(config.Code)),
				Length: config.Length,
			})
			continue
		}
		info := ednsOptionInfo(option)
		info.Name = firstNonEmpty(config.Name, info.Name)
		result = append(result, info)
	}
	return result
}

func effectiveExperimentQuestion(experiment Experiment) (string, string, string) {
	qname := dns.Fqdn(experiment.QName)
	qtype := strings.ToUpper(experiment.QType)
	qclass := strings.ToUpper(experiment.QClass)
	if experiment.RawWire == nil {
		return qname, qtype, qclass
	}

	rawHex := strings.ReplaceAll(strings.TrimSpace(experiment.RawWire.Hex), " ", "")
	wire, err := hex.DecodeString(rawHex)
	if err != nil {
		return qname, qtype, qclass
	}
	rawQName, rawQType, rawQClass, ok := rawWireQuestion(wire)
	if !ok {
		return qname, qtype, qclass
	}

	qname = dns.Fqdn(rawQName)
	if name, ok := dns.TypeToString[rawQType]; ok {
		qtype = name
	} else {
		qtype = fmt.Sprintf("TYPE%d", rawQType)
	}
	if name, ok := dns.ClassToString[rawQClass]; ok {
		qclass = name
	} else {
		qclass = fmt.Sprintf("CLASS%d", rawQClass)
	}
	return qname, qtype, qclass
}

// Reads the first uncompressed question without applying the 255-octet QNAME limit.
func rawWireQuestion(wire []byte) (string, uint16, uint16, bool) {
	if len(wire) < 12 || binary.BigEndian.Uint16(wire[4:6]) == 0 {
		return "", 0, 0, false
	}

	offset := 12
	labels := make([]string, 0, 8)
	for {
		if offset >= len(wire) {
			return "", 0, 0, false
		}
		length := int(wire[offset])
		offset++
		if length == 0 {
			break
		}
		if length > 63 || offset+length > len(wire) {
			return "", 0, 0, false
		}
		labels = append(labels, string(wire[offset:offset+length]))
		offset += length
	}
	if offset+4 > len(wire) {
		return "", 0, 0, false
	}

	qname := "."
	if len(labels) > 0 {
		qname = strings.Join(labels, ".") + "."
	}
	return qname, binary.BigEndian.Uint16(wire[offset : offset+2]), binary.BigEndian.Uint16(wire[offset+2 : offset+4]), true
}

func eventUint16(event map[string]any, key string) (uint16, bool) {
	value, exists := event[key]
	if !exists || value == nil {
		return 0, false
	}
	switch typed := value.(type) {
	case float64:
		if typed < 0 || typed > 65535 || typed != float64(uint16(typed)) {
			return 0, false
		}
		return uint16(typed), true
	case json.Number:
		parsed, err := strconv.ParseUint(string(typed), 10, 16)
		return uint16(parsed), err == nil
	case uint16:
		return typed, true
	case int:
		if typed < 0 || typed > 65535 {
			return 0, false
		}
		return uint16(typed), true
	default:
		return 0, false
	}
}

func isPrimaryAuthoritativeEvent(event map[string]any, experiment Experiment) bool {
	qname, _ := event["qname"].(string)
	qtype, _ := event["qtype"].(string)
	effectiveQName, effectiveQType, _ := effectiveExperimentQuestion(experiment)
	effectiveQTypeNumeric, parseOK := parseQType(effectiveQType)
	qtypeMatches := strings.EqualFold(qtype, effectiveQType)
	if observedNumeric, ok := eventUint16(event, "qtype_numeric"); ok && parseOK {
		qtypeMatches = observedNumeric == effectiveQTypeNumeric
	}

	return strings.EqualFold(qname, effectiveQName) &&
		qtypeMatches
}

func annotatedAuthoritativeRole(event map[string]any, experiment Experiment, seenPrimary, previousPrimaryTC *bool) string {
	qname, _ := event["qname"].(string)
	qtype, _ := event["qtype"].(string)
	transport, _ := event["transport"].(string)
	responseTC, _ := event["response_tc"].(bool)

	if isPrimaryAuthoritativeEvent(event, experiment) {
		role := "primary_retransmission"
		if !*seenPrimary {
			role = "primary_query"
		} else if *previousPrimaryTC && strings.EqualFold(transport, "tcp") {
			role = "primary_tcp_fallback"
		}
		*seenPrimary = true
		*previousPrimaryTC = strings.EqualFold(transport, "udp") && responseTC
		return role
	}

	qnameLower := strings.ToLower(qname)
	effectiveQName, effectiveQType, _ := effectiveExperimentQuestion(experiment)
	clientQNameLower := strings.ToLower(effectiveQName)
	qtypeUpper := strings.ToUpper(qtype)
	clientQTypeUpper := strings.ToUpper(effectiveQType)
	if strings.HasPrefix(qnameLower, "_ta-") {
		return "trust_anchor_signal"
	}
	if qtypeUpper == "A" && qnameLower == clientQNameLower && clientQTypeUpper != "A" {
		return "same_name_A_followup"
	}
	if qtypeUpper == "DNSKEY" || qtypeUpper == "DS" {
		return "auxiliary_dnssec"
	}
	if (qtypeUpper == "A" || qtypeUpper == "AAAA") && qnameLower != clientQNameLower {
		return "synthesized_address_lookup"
	}
	if qtypeUpper == "NS" && qnameLower != clientQNameLower {
		return "auxiliary_delegation"
	}
	return "unclassified_other"
}

// Uses both suffix and apex targets for PowerDNS cache clearing.
func flushResolverCache(resolver string) error {
	switch resolver {
	case "bind":
		return runCommand("sudo", "rndc", "flush")

	case "unbound":
		return runCommand("sudo", "unbound-control", "flush_zone", "mut.test.")

	case "powerdns":
		for _, target := range []string{"mut.test$", "mut.test."} {
			if err := runCommand("sudo", "rec_control", "wipe-cache", target); err != nil {
				return err
			}
		}
		return nil

	default:
		return fmt.Errorf("unknown resolver for cache flush: %s", resolver)
	}
}
func runCommand(name string, args ...string) error {
	command := exec.Command(name, args...)

	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w output=%s", name, strings.Join(args, " "), err, string(output))
	}

	return nil
}
