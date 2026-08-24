package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SMTPConfig is how the control plane reaches a mail server.
//
// It is process configuration rather than tenant data: which relay a control plane may speak to is
// the installation operator's decision, exactly like which address it listens on. What each tenant
// decides is the recipients, per alert rule.
type SMTPConfig struct {
	// Host is the mail server's name. The TLS certificate is verified against it.
	Host string

	// Port selects the mechanism: 465 speaks TLS from the first byte, anything else — 587 in
	// practice — opens plain and upgrades with STARTTLS. Plaintext SMTP is not offered at all,
	// because an alert email legitimately carries hostnames and failure text.
	Port int

	// From is the envelope and header sender.
	From string

	// Username and Password authenticate, both empty for an open relay on a trusted network.
	Username string
	Password string
}

// Configured reports whether mail can be sent at all.
func (c SMTPConfig) Configured() bool { return c.Host != "" && c.From != "" }

// smtpDeadline bounds one delivery end to end.
//
// The same reasoning as Webhook's ten seconds, with a little more room because SMTP is a
// multi-round-trip conversation: a control plane whose event path is held open by an unresponsive
// mail server is a worse outcome than a missed mail.
const smtpDeadline = 15 * time.Second

// SMTP delivers one event as mail to a fixed set of recipients.
//
// Constructed per delivery, like the tenant webhook, because the recipients come from the alert rule
// that matched — there is no meaningful "the" mail sink, only "this rule's recipients".
type SMTP struct {
	// cfg is the relay configuration.
	cfg SMTPConfig

	// to are the recipients.
	to []string
}

// NewSMTP returns a sink that mails one rule's recipients.
func NewSMTP(cfg SMTPConfig, to []string) *SMTP {
	return &SMTP{cfg: cfg, to: to}
}

// Name identifies the sink in logs and in the UI.
func (s *SMTP) Name() string { return "smtp:" + s.cfg.Host }

// Deliver sends one event as a mail.
//
// The whole conversation runs under one deadline, applied to the connection itself rather than only
// to dialling: a relay that accepts the connection and then stalls mid-DATA would otherwise hold the
// event path open indefinitely, which is the failure mode the Sink contract names.
func (s *SMTP) Deliver(ctx context.Context, ev Event) error {
	if !s.cfg.Configured() {
		return errors.New("notify: no SMTP relay is configured")
	}
	if len(s.to) == 0 {
		return errors.New("notify: no recipients")
	}

	deadline := time.Now().Add(smtpDeadline)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	dialer := net.Dialer{Deadline: deadline}
	var (
		conn net.Conn
		err  error
	)
	if s.cfg.Port == 465 {
		conn, err = tls.DialWithDialer(&dialer, "tcp", addr, &tls.Config{
			ServerName: s.cfg.Host,
			MinVersion: tls.VersionTLS12,
		})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("notify: dialling %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("notify: bounding the connection: %w", err)
	}

	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return fmt.Errorf("notify: greeting %s: %w", s.cfg.Host, err)
	}
	defer func() { _ = client.Close() }()

	if s.cfg.Port != 465 {
		// STARTTLS or nothing. Continuing in plaintext on a relay that does not offer it would mail
		// hostnames and failure text across the network in the clear, silently, for ever.
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("notify: %s does not offer STARTTLS; refusing to send in plaintext", addr)
		}
		if err := client.StartTLS(&tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("notify: starting TLS with %s: %w", addr, err)
		}
	}
	if s.cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)); err != nil {
			return fmt.Errorf("notify: authenticating to %s: %w", addr, err)
		}
	}

	if err := client.Mail(s.cfg.From); err != nil {
		return fmt.Errorf("notify: MAIL FROM: %w", err)
	}
	for _, rcpt := range s.to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("notify: RCPT TO %s: %w", rcpt, err)
		}
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("notify: DATA: %w", err)
	}
	if _, err := writer.Write(renderMail(s.cfg.From, s.to, ev)); err != nil {
		return fmt.Errorf("notify: writing the message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("notify: finishing the message: %w", err)
	}
	return client.Quit()
}

// renderMail builds the message.
//
// The subject is the event's summary, not "Farrier notification": "web-01: 3 security updates
// pending, 14 days old" is a mail somebody opens, and a generic subject is a folder rule within a
// week. The rendering matters more than it sounds — it is the entire user interface of this sink.
func renderMail(from string, to []string, ev Event) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", sanitizeHeader(ev.Summary))
	fmt.Fprintf(&b, "Date: %s\r\n", ev.At.Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")

	fmt.Fprintf(&b, "%s\r\n\r\n", ev.Summary)
	fmt.Fprintf(&b, "Event:  %s\r\n", ev.Kind)
	if ev.Hostname != "" || ev.HostID != "" {
		fmt.Fprintf(&b, "Host:   %s (%s)\r\n", ev.Hostname, ev.HostID)
	}
	fmt.Fprintf(&b, "At:     %s\r\n", ev.At.Format(time.RFC3339))
	// Sorted, because Go's map iteration is randomised and two mails about the same incident with
	// their fields in different orders defeat every threading rule an operator writes.
	keys := make([]string, 0, len(ev.Detail))
	for key := range ev.Detail {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(&b, "%s: %v\r\n", key, ev.Detail[key])
	}
	b.WriteString("\r\nSent by Farrier. The rule that matched is editable under Alerts in the UI.\r\n")
	return []byte(b.String())
}

// sanitizeHeader strips the line breaks that would let a summary inject mail headers.
//
// Summaries are built from hostnames and error text, and error text is whatever a helper printed.
// The rest of the header is fixed here, so this one substitution is the whole injection surface.
func sanitizeHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.ReplaceAll(s, "\n", " ")
}
