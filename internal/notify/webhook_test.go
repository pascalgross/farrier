package notify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestGuaranteeAWebhookMustBeHTTPS is the same rule the SMTP sink already enforces for the same data.
//
// An event carries hostnames, job summaries and the principal of whoever queued the work. smtp.go
// refuses a relay that does not offer STARTTLS, in those words and for that reason; the webhook posted
// the identical payload to an http:// URL in cleartext, and nobody had decided that.
//
// Both directions are asserted. A validator that refused everything would satisfy the first half alone,
// and the sink would then be a feature nobody could configure.
func TestGuaranteeAWebhookMustBeHTTPS(t *testing.T) {
	for _, refused := range []string{
		"http://hooks.example.org/hostseal",
		"http://169.254.169.254/latest/meta-data/",
		"ftp://example.org/",
		"file:///etc/passwd",
		"//example.org/no-scheme",
		"https://",
		"not a url at all",
	} {
		if err := ValidateWebhookURL(refused); err == nil {
			t.Errorf("%q was accepted as a webhook URL", refused)
		} else if !errors.Is(err, ErrWebhookURL) {
			t.Errorf("%q was refused with %v, which does not wrap ErrWebhookURL", refused, err)
		}
	}

	for _, accepted := range []string{
		"https://hooks.example.org/hostseal",
		"https://hooks.example.org:8443/hostseal?token=abc",
		"https://10.0.0.5:8080/hook",
	} {
		if err := ValidateWebhookURL(accepted); err != nil {
			t.Errorf("%q is a webhook an operator may legitimately configure and was refused: %v",
				accepted, err)
		}
	}
}

// TestGuaranteeAStoredPlaintextWebhookIsRefusedAtDelivery covers the rows written before the rule.
//
// Validating at configuration time tells an operator who is about to make the mistake. It does nothing
// about a tenant row that already holds an http:// URL, and that row is the one that would still be
// posting a fleet's hostnames in the clear — so the sink checks again rather than trusting that
// everything reached it through the API that now refuses.
func TestGuaranteeAStoredPlaintextWebhookIsRefusedAtDelivery(t *testing.T) {
	reached := false
	endpoint := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))
	defer endpoint.Close()

	err := NewWebhook("tenant-webhook", endpoint.URL).Deliver(context.Background(), Event{
		Kind: KindHostEnrolled, Hostname: "web-01", Summary: "web-01 joined the fleet",
	})
	if err == nil {
		t.Fatal("a plaintext webhook stored before this rule existed was delivered to")
	}
	if !errors.Is(err, ErrWebhookURL) {
		t.Errorf("the refusal is %v, which does not wrap ErrWebhookURL and so cannot be told apart "+
			"from an endpoint that is merely down", err)
	}
	if reached {
		t.Error("the event reached the plaintext endpoint despite the refusal")
	}
}

// TestGuaranteeAWebhookDoesNotFollowARedirect closes the second destination nobody configured.
//
// The sink reads only the status code, so a POST that followed a 302 would deliver a fleet's event to an
// address the operator never chose and report success. It is also how a permitted URL reaches a refused
// one — an https endpoint redirecting to the metadata service — which is why refusing the hop matters
// beyond the surprise of it.
func TestGuaranteeAWebhookDoesNotFollowARedirect(t *testing.T) {
	final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the redirect was followed to an endpoint nobody configured")
		w.WriteHeader(http.StatusOK)
	}))
	defer final.Close()

	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer redirector.Close()

	sink := NewWebhook("tenant-webhook", redirector.URL)
	trustTestServers(sink, redirector, final)

	err := sink.Deliver(context.Background(), Event{
		Kind: KindHostEnrolled, Hostname: "web-01", Summary: "web-01 joined the fleet",
	})
	if err == nil {
		t.Fatal("a redirected delivery reported success")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Errorf("the failure does not say a redirect was refused: %v", err)
	}
}

// TestGuaranteeAWebhookWillNotDialALinkLocalAddress is the destination half, checked at the socket.
//
// 169.254.169.254 is the cloud metadata service on every major provider, and it answers to any name
// that resolves to it — so the guard is on the address the kernel is about to connect to rather than on
// the string somebody configured, and a name that resolves there is refused exactly as the literal is.
//
// It is scoped to link-local on purpose. Loopback and RFC1918 stay reachable, because a self-hosted
// control plane posting to a chat relay on its own private network is the ordinary deployment.
func TestGuaranteeAWebhookWillNotDialALinkLocalAddress(t *testing.T) {
	sink := NewWebhook("tenant-webhook", "https://169.254.169.254/latest/meta-data/")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := sink.Deliver(ctx, Event{
		Kind: KindHostEnrolled, Hostname: "web-01", Summary: "web-01 joined the fleet",
	})
	if err == nil {
		t.Fatal("a delivery to the metadata address succeeded")
	}
	if !strings.Contains(err.Error(), "link-local") {
		t.Errorf("the failure does not name the reason, so an operator cannot tell it from an "+
			"unreachable endpoint: %v", err)
	}
}

// trustTestServers points a sink's transport at the certificates httptest generated.
//
// The sink's own transport is kept — its dial guard and its timeouts are what the tests above are
// about — and only the root pool is replaced, so a test cannot accidentally pass because it built a
// client without the thing under test.
func trustTestServers(sink *Webhook, servers ...*httptest.Server) {
	pool := x509.NewCertPool()
	for _, s := range servers {
		pool.AddCert(s.Certificate())
	}
	transport, ok := sink.client.Transport.(*http.Transport)
	if !ok {
		panic("the webhook sink no longer carries an *http.Transport; this helper needs updating")
	}
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}
