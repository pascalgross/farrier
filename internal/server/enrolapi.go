package server

import (
	"log/slog"
	"net/http"
	"strings"
)

// CACertificatePath is where the agent CA certificate is downloadable.
//
// Named as a constant because the interface builds a link to it and a test asserts the same path: two
// spellings of one route is a download button that answers 404 on the day somebody renames it.
const CACertificatePath = "/api/v1/ca.crt"

// handleCACertificate serves the agent CA certificate, to anybody who asks.
//
// It is the one unauthenticated route under /api/v1, and that is a decision rather than an oversight.
// The certificate is a public document — it is handed to every enrolling agent in the enrolment
// response, before that agent has any credential at all, and its whole purpose is to be distributed to
// machines that do not yet exist. Withholding it here would not withhold it.
//
// What it buys is the second step of enrolment being a single command on the host rather than a
// download in a browser and a copy over scp. That is the difference between an operator following the
// instructions and an operator improvising, and improvising is where a host ends up trusting the
// system roots instead.
//
// Nothing else about the control plane leaks through it. A CA certificate names the authority and its
// validity window; it says nothing about which hosts exist, which tenants do, or what any of them run.
func (s *Server) handleCACertificate(w http.ResponseWriter, _ *http.Request) {
	pem := s.cfg.Authority.CertificatePEM()

	// application/x-pem-file, and a filename that matches where the instructions install it. A browser
	// that guessed text/plain would show it in a tab, and the operator would then be copying a document
	// out of a viewport rather than saving the bytes.
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="farrier-ca.crt"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(pem); err != nil {
		// Logged and not answered: the header is already written, so there is nothing left to say to
		// the client. A truncated download is visible as a certificate that does not parse.
		slog.Error("could not write the CA certificate", "error", err)
	}
}

// enrolmentView is what the interface needs to render the three enrolment steps.
//
// It is one response rather than three, because the steps are one document: an operator following them
// out of order, or with an agent URL from one control plane and a CA from another, is exactly the
// failure the page exists to prevent.
type enrolmentView struct {
	// AgentURL is the base URL to pass to `farrier enroll --server`.
	AgentURL string `json:"agentUrl"`

	// AgentURLIsAGuess reports that nobody configured the address and this is the browser's own.
	//
	// The interface says so rather than hiding it. The documented Traefik deployment serves this page
	// on a hostname that refuses the agent API by design, so a guess is wrong there in a way that is
	// invisible until an agent has been installed and cannot enrol.
	AgentURLIsAGuess bool `json:"agentUrlIsAGuess"`

	// CACertificatePath is where the CA certificate can be fetched.
	CACertificatePath string `json:"caCertificatePath"`

	// APTURL is the repository the agent package is installed from.
	APTURL string `json:"aptUrl"`
}

// APTRepositoryURL is where the agent package comes from.
//
// A constant rather than configuration: it is written into
// /etc/apt/sources.list.d/farrier.sources on every host that ever installs the agent and can never be
// migrated afterwards, which is the same reason release.yml refuses to publish without it being set.
// An installation serving its own mirror edits the commands it copies; nothing about this page is the
// place to make that a setting.
const APTRepositoryURL = "https://farrier.tools/apt"

// handleEnrolmentInstructions returns what an operator needs to enrol a host.
//
// Behind requireOperator, unlike the CA download beside it, because the agent URL is a statement about
// this installation's topology rather than a public document — and because the page that renders it is
// behind a credential anyway.
func (s *Server) handleEnrolmentInstructions(w http.ResponseWriter, r *http.Request, _ operator) {
	view := enrolmentView{
		AgentURL:          strings.TrimRight(s.cfg.AgentURL, "/"),
		CACertificatePath: CACertificatePath,
		APTURL:            APTRepositoryURL,
	}
	if view.AgentURL == "" {
		// The browser's own address, marked as the guess it is. It is right for the ordinary
		// single-hostname deployment and wrong for the two-hostname one, and the interface has no way
		// to tell which it is in — so it says so instead of choosing.
		view.AgentURL = "https://" + r.Host
		view.AgentURLIsAGuess = true
	}
	writeJSON(w, http.StatusOK, view)
}
