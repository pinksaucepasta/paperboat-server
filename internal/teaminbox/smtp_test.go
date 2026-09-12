package teaminbox

import (
	"errors"
	"net/netip"
	"testing"
)

func TestSMTPReceiptSenderRequiresEncryptedPublicHostConfiguration(t *testing.T) {
	valid := SMTPConfig{Host: "smtp.example.com", Port: 587, Username: "team-user", Password: "secret", FromAddress: "receipts@example.com", TLSMode: "starttls"}
	if _, err := NewSMTPReceiptSender(valid); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*SMTPConfig){
		func(c *SMTPConfig) { c.Host = "127.0.0.1" },
		func(c *SMTPConfig) { c.Host = "localhost" },
		func(c *SMTPConfig) { c.Port = 25 },
		func(c *SMTPConfig) { c.TLSMode = "plaintext" },
		func(c *SMTPConfig) { c.FromAddress = "sender@example.com\r\nBcc: victim@example.com" },
	} {
		config := valid
		change(&config)
		if _, err := NewSMTPReceiptSender(config); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsafe SMTP config accepted: %+v err=%v", config, err)
		}
	}
}

func TestPublicSMTPAddressRejectsPrivateResolution(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.2", "169.254.1.2", "::1", "fd00::1"} {
		if _, err := firstPublicSMTPAddress([]netip.Addr{netip.MustParseAddr(raw)}, 587); err == nil {
			t.Fatalf("private SMTP address accepted: %s", raw)
		}
	}
}
