package tunnelcert

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultCAAQueryTimeout = 5 * time.Second
	maxCAAQueries          = 12
)

type CAAQueryer interface {
	ExchangeContext(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)
}

type DNSCAAInspectorConfig struct {
	Server  string
	Queryer CAAQueryer
	Timeout time.Duration
}

type DNSCAAInspector struct {
	server  string
	queryer CAAQueryer
	timeout time.Duration
}

func NewDNSCAAInspector(config DNSCAAInspectorConfig) (*DNSCAAInspector, error) {
	if config.Server == "" {
		return nil, fmt.Errorf("%w: CAA resolver address is required", ErrInvalid)
	}
	host, port, err := net.SplitHostPort(config.Server)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("%w: CAA resolver address is invalid", ErrInvalid)
	}
	timeout := config.Timeout
	if timeout <= 0 || timeout > time.Minute {
		timeout = defaultCAAQueryTimeout
	}
	queryer := config.Queryer
	if queryer == nil {
		queryer = &dns.Client{Timeout: timeout}
	}
	return &DNSCAAInspector{server: config.Server, queryer: queryer, timeout: timeout}, nil
}

func (i *DNSCAAInspector) Check(ctx context.Context, hostname, issuer string) (CAAResult, error) {
	ctx = certificateContext(ctx)
	if i == nil || i.queryer == nil || strings.TrimSpace(issuer) == "" {
		return CAAResult{}, ErrCAAUnavailable
	}
	host, wildcard, err := normalizeHostname(hostname)
	if err != nil {
		return CAAResult{}, err
	}
	issuer = strings.ToLower(strings.TrimSpace(issuer))
	if strings.ContainsAny(issuer, "\r\n\x00; ") {
		return CAAResult{}, fmt.Errorf("%w: CAA issuer is invalid", ErrInvalid)
	}
	base := strings.TrimPrefix(host, "*.")
	for query := 0; query < maxCAAQueries && base != ""; query++ {
		queryCtx, cancel := context.WithTimeout(ctx, i.timeout)
		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn(base), dns.TypeCAA)
		response, _, exchangeErr := i.queryer.ExchangeContext(queryCtx, message, i.server)
		cancel()
		if exchangeErr != nil {
			if errors.Is(exchangeErr, context.Canceled) || errors.Is(exchangeErr, context.DeadlineExceeded) {
				return CAAResult{}, exchangeErr
			}
			return CAAResult{}, fmt.Errorf("%w: CAA lookup failed", ErrCAAUnavailable)
		}
		if response == nil {
			return CAAResult{}, ErrCAAUnavailable
		}
		if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
			return CAAResult{}, ErrCAAUnavailable
		}
		records := caaRecords(response)
		if len(records) > 0 {
			allowed, failureCode := caaAllowed(records, issuer, wildcard)
			if allowed {
				return CAAResult{State: "ready", Issuer: issuer}, nil
			}
			if failureCode == "" {
				failureCode = "caa_issuer_not_authorized"
			}
			return CAAResult{State: "blocked", Issuer: issuer, FailureCode: failureCode}, nil
		}
		base = parentDNSName(base)
	}
	return CAAResult{State: "not_applicable", Issuer: issuer}, nil
}

func caaRecords(message *dns.Msg) []*dns.CAA {
	if message == nil {
		return nil
	}
	result := make([]*dns.CAA, 0, len(message.Answer))
	for _, answer := range message.Answer {
		if record, ok := answer.(*dns.CAA); ok && record != nil {
			result = append(result, record)
		}
	}
	return result
}

func caaAllowed(records []*dns.CAA, issuer string, wildcard bool) (bool, string) {
	var issue, issueWild bool
	for _, record := range records {
		if record == nil {
			continue
		}
		tag := strings.ToLower(strings.TrimSpace(record.Tag))
		if record.Flag&0x80 != 0 && tag != "issue" && tag != "issuewild" && tag != "iodef" {
			return false, "caa_unsupported_critical_tag"
		}
		switch tag {
		case "issue":
			issue = true
		case "issuewild":
			issueWild = true
		}
	}
	wantTag := ""
	if wildcard {
		switch {
		case issueWild:
			wantTag = "issuewild"
		case issue:
			wantTag = "issue"
		}
	} else if issue {
		wantTag = "issue"
	}
	if wantTag == "" {
		// A CAA RRset containing only iodef or other non-authorization
		// properties does not restrict issuance. This is also the correct
		// wildcard behavior when issuewild is absent and issue is absent.
		return true, ""
	}
	for _, record := range records {
		if record == nil {
			continue
		}
		if strings.ToLower(strings.TrimSpace(record.Tag)) != wantTag {
			continue
		}
		value := strings.TrimSpace(strings.SplitN(record.Value, ";", 2)[0])
		if value == "" || value == "." {
			return false, "caa_issuance_forbidden"
		}
		if strings.EqualFold(value, issuer) {
			return true, ""
		}
	}
	return false, "caa_issuer_not_authorized"
}

func parentDNSName(host string) string {
	index := strings.IndexByte(host, '.')
	if index < 0 || index+1 >= len(host) {
		return ""
	}
	return host[index+1:]
}

var _ CAAInspector = (*DNSCAAInspector)(nil)
