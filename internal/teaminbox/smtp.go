package teaminbox

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/smtp"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var smtpHostname = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

type SMTPConfig struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	Password       string `json:"password,omitempty"`
	FromAddress    string `json:"from_address"`
	TLSMode        string `json:"tls_mode"`
	Generation     uint64 `json:"generation"`
	PasswordStored bool   `json:"password_stored"`
}

type SMTPReceiptSender struct {
	config   SMTPConfig
	resolver *net.Resolver
	dialer   net.Dialer
}

func NewSMTPReceiptSender(config SMTPConfig) (*SMTPReceiptSender, error) {
	if !smtpHostname.MatchString(config.Host) || net.ParseIP(config.Host) != nil || config.Port != 465 && config.Port != 587 ||
		config.TLSMode != "implicit" && config.TLSMode != "starttls" || config.Username == "" || config.Password == "" ||
		len(config.Username) > 320 || len(config.Password) > 4096 || strings.ContainsAny(config.Username, "\r\n\x00") || !validMailbox(config.FromAddress) {
		return nil, ErrInvalid
	}
	return &SMTPReceiptSender{config: config, resolver: net.DefaultResolver, dialer: net.Dialer{Timeout: 10 * time.Second}}, nil
}

func validMailbox(value string) bool {
	if value == "" || len(value) > 320 || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Address == value
}

func publicSMTPAddress(ctx context.Context, resolver *net.Resolver, host string, port int) (string, error) {
	addresses, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	return firstPublicSMTPAddress(addresses, port)
}

func firstPublicSMTPAddress(addresses []netip.Addr, port int) (string, error) {
	for _, address := range addresses {
		if address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() {
			return net.JoinHostPort(address.String(), strconv.Itoa(port)), nil
		}
	}
	return "", errors.New("SMTP hostname has no public address")
}

func (s *SMTPReceiptSender) SendReceipt(ctx context.Context, message ReceiptMessage) (string, error) {
	if message.IdempotencyKey == "" || !safeID.MatchString(message.IdempotencyKey) || !validMailbox(message.To) || strings.ContainsAny(message.Subject, "\r\n\x00") || strings.Contains(message.Text, "\x00") {
		return "", ErrInvalid
	}
	address, err := publicSMTPAddress(ctx, s.resolver, s.config.Host, s.config.Port)
	if err != nil {
		return "", err
	}
	connection, err := s.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	deadline := time.Now().Add(30 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err = connection.SetDeadline(deadline); err != nil {
		return "", err
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopCancel()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.config.Host}
	if s.config.TLSMode == "implicit" {
		tlsConnection := tls.Client(connection, tlsConfig)
		if err = tlsConnection.HandshakeContext(ctx); err != nil {
			return "", err
		}
		connection = tlsConnection
	}
	client, err := smtp.NewClient(connection, s.config.Host)
	if err != nil {
		return "", err
	}
	defer client.Close()
	if s.config.TLSMode == "starttls" {
		if err = client.StartTLS(tlsConfig); err != nil {
			return "", err
		}
	}
	if err = client.Auth(smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)); err != nil {
		return "", err
	}
	if err = client.Mail(s.config.FromAddress); err != nil {
		return "", err
	}
	if err = client.Rcpt(message.To); err != nil {
		return "", err
	}
	body, err := client.Data()
	if err != nil {
		return "", err
	}
	payload := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMessage-ID: <%s@paperboat>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n", s.config.FromAddress, message.To, strings.ReplaceAll(message.Subject, "\r", ""), message.IdempotencyKey, message.Text)
	if _, err = body.Write([]byte(payload)); err != nil {
		body.Close()
		return "", err
	}
	if err = body.Close(); err != nil {
		return "", err
	}
	if err = client.Quit(); err != nil {
		return "", err
	}
	return "smtp:" + message.IdempotencyKey, nil
}
