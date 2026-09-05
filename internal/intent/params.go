package intent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// maxParamsBytes bounds the encoded parameter object a job may carry.
//
// It exists because the decoders below are the first thing a job's untrusted bytes reach, and an
// unbounded decode is a denial-of-service primitive available to anyone who can reach the endpoint.
// No legitimate intent's parameters come close: the largest is a unit name and a short message.
const maxParamsBytes = 8 << 10

// unitPattern is the only shape a systemd unit name may take when it arrives from the network.
//
// It is written here, once, rather than at each call site, because the value of a constrained
// parameter comes entirely from the constraint being unavoidable. The alternation is limited to the
// three unit types HostSeal ever acts on; .mount, .swap and .device are excluded because acting on them
// is not something this product does, and an allowlist that includes unused entries is not an
// allowlist.
var unitPattern = regexp.MustCompile(`^[a-zA-Z0-9@._-]+\.(service|socket|timer)$`)

// messagePattern bounds the character set of the wall message a reboot may carry.
//
// The set is far narrower than the message could safely be, and that is on purpose. Every external
// invocation is execve with a fixed argv slice, so quoting is not the risk; the risk is that a future
// maintainer moves one of these values somewhere a shell, a log parser or a terminal does interpret it.
// A parameter that cannot express a metacharacter cannot be the thing that goes wrong on that day.
//
// What it deliberately does not bound is POSITION, and that distinction cost a real defect: a hyphen is
// legitimate inside a message ("pre-flight check") and dangerous as its first character, because the
// message reaches shutdown(8) as a positional argument and an argument parser reads a leading hyphen as
// an option. The character set cannot express that rule, so it is checked separately below rather than
// asserted here.
var messagePattern = regexp.MustCompile(`^[A-Za-z0-9 .,:_-]{0,200}$`)

// ErrUnknownField is returned when a parameter object carries a field the intent does not define.
//
// Strict decoding is a security property rather than tidiness: a control plane that could attach
// unrecognised fields to a job would have a channel for smuggling values past a validator into
// whatever later code decided to be helpful about them.
var ErrUnknownField = errors.New("unknown parameter field")

// Params is the decoded, validated parameter set of one job.
//
// The interface is sealed by an unexported method so that no package outside internal/intent can
// introduce a parameter type. Everything downstream — the agent's dispatcher, the root helpers, the
// signing renderer — therefore knows that any Params value it holds came from one of the decoders in
// this file and has already been through that decoder's validator.
type Params interface {
	// Intent reports the catalogue member these parameters belong to.
	Intent() Name

	// Describe renders the parameters as one human-readable line.
	//
	// It exists for hostseal sign, which must show an operator what they are about to authorise
	// without contacting the server. That rendering has to come from the same typed value the agent
	// will act on; a description supplied alongside the job would let a compromised control plane
	// display one operation and have another signed.
	Describe() string

	// sealed prevents implementations outside this package.
	sealed()
}

// NoParams is the parameter set of an intent that takes no parameters.
//
// It exists as a concrete type rather than a nil Params so that every intent has a decoder that
// actively rejects anything other than an empty object. "Takes no parameters" and "does not check its
// parameters" look identical at the call site and are not the same thing.
type NoParams struct {
	intent Name
}

// Intent reports the catalogue member these parameters belong to.
func (p NoParams) Intent() Name { return p.intent }

// Describe renders the parameters as one human-readable line.
func (p NoParams) Describe() string { return string(p.intent) }

// sealed prevents implementations outside this package.
func (p NoParams) sealed() {}

// UnitParams names a single systemd unit to act on.
//
// The unit is a validated name and never a path. Accepting a path would mean the agent could be
// pointed at a unit file outside the system's own unit directories, which is a way to reach code that
// no policy list of unit names would catch.
type UnitParams struct {
	intent Name

	// Unit is a systemd unit name matching unitPattern.
	Unit string `json:"unit"`
}

// Intent reports the catalogue member these parameters belong to.
func (p UnitParams) Intent() Name { return p.intent }

// Describe renders the parameters as one human-readable line.
func (p UnitParams) Describe() string { return fmt.Sprintf("%s %s", p.intent, p.Unit) }

// sealed prevents implementations outside this package.
func (p UnitParams) sealed() {}

// ApplyParams carries the options of an update-application intent.
//
// RebootIfRequired is a request, not an instruction: the root helper still consults
// /etc/hostseal/policy.toml and will decline to reboot a host whose policy forbids it or whose
// maintenance window has closed. It exists so an operator can express "and finish the job" in one
// authorisation rather than having to sign a second one at an hour nobody wants to be awake for.
//
// It is expressible on packages.applyAll and on nothing else. packages.applySecurity is the routine
// tier — signed by the control plane's own online key, with no human present — and docs/SECURITY.md §3
// says a signature by that key must not authorise a reboot. Sharing one decoder between the two made
// that sentence false: the flag reaches the same helper, which acts on it without asking which intent
// carried it, so the control plane could reboot a host with a key it holds itself. The two decoders
// are separate now, and the field is simply unknown to the routine member rather than accepted and
// ignored — an accepted-and-ignored field is one flipped condition away from being honoured again.
type ApplyParams struct {
	intent Name

	// RebootIfRequired asks the helper to reboot afterwards if the update left the host needing it.
	RebootIfRequired bool `json:"rebootIfRequired"`
}

// Intent reports the catalogue member these parameters belong to.
func (p ApplyParams) Intent() Name { return p.intent }

// Describe renders the parameters as one human-readable line.
func (p ApplyParams) Describe() string {
	if p.RebootIfRequired {
		return string(p.intent) + " (reboot if required)"
	}
	return string(p.intent)
}

// sealed prevents implementations outside this package.
func (p ApplyParams) sealed() {}

// RebootParams carries the options of a host reboot.
//
// The delay exists so that a signed batch can be staggered across a group without the operator
// signing one job per host at one-minute offsets, which is the sort of ceremony cost that pushes
// people towards keeping a key on the control plane instead.
type RebootParams struct {
	intent Name

	// DelaySeconds is how long the host waits before rebooting, from 0 to 3600.
	DelaySeconds int `json:"delaySeconds"`

	// Message is an optional wall message, constrained by messagePattern.
	Message string `json:"message"`
}

// Intent reports the catalogue member these parameters belong to.
func (p RebootParams) Intent() Name { return p.intent }

// Describe renders the parameters as one human-readable line.
func (p RebootParams) Describe() string {
	var b strings.Builder
	b.WriteString(string(p.intent))
	if p.DelaySeconds > 0 {
		fmt.Fprintf(&b, " in %ds", p.DelaySeconds)
	}
	if p.Message != "" {
		fmt.Fprintf(&b, " (%q)", p.Message)
	}
	return b.String()
}

// sealed prevents implementations outside this package.
func (p RebootParams) sealed() {}

// strictUnmarshal decodes JSON into dst, rejecting unknown fields, trailing data and over-size input.
//
// It is factored out because every decoder below needs exactly the same three refusals, and a decoder
// that forgot one of them would not fail any test that did not specifically look for it. Nothing here
// is clever; the point is that it is in one place and every intent goes through it.
func strictUnmarshal(raw []byte, dst any) error {
	if len(raw) > maxParamsBytes {
		return fmt.Errorf("parameters too large: %d bytes, limit %d", len(raw), maxParamsBytes)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return fmt.Errorf("%w: %w", ErrUnknownField, err)
		}
		return err
	}
	if dec.More() {
		return errors.New("trailing data after parameter object")
	}
	return nil
}

// validateUnit checks a systemd unit name arriving from the network.
//
// The pattern alone is not quite enough, which is why this is a function rather than a bare
// MatchString call. A name beginning with a hyphen would be read as an option by any tool that ever
// receives it without a -- terminator, and ".." is meaningful to every path-resolving layer between
// here and systemd. Both are rejected here so that no downstream caller has to remember to.
func validateUnit(unit string) error {
	switch {
	case unit == "":
		return errors.New("unit is required")
	case len(unit) > 255:
		return fmt.Errorf("unit name too long: %d bytes, limit 255", len(unit))
	case strings.HasPrefix(unit, "-"):
		return errors.New("unit name may not begin with a hyphen")
	case strings.HasPrefix(unit, "."):
		return errors.New("unit name may not begin with a dot")
	case strings.Contains(unit, ".."):
		return errors.New("unit name may not contain '..'")
	case !unitPattern.MatchString(unit):
		return fmt.Errorf("unit name %q does not match %s", unit, unitPattern)
	}
	return nil
}

// decodeEmpty builds a decoder for an intent that takes no parameters.
//
// It returns a closure rather than a shared function value so that the resulting Params carries its
// own intent name. That name is what lets the agent assert, after decoding, that the parameters it
// holds belong to the intent it looked up — a check that catches a whole class of dispatcher bug for
// the cost of one comparison.
func decodeEmpty(n Name) func([]byte) (Params, error) {
	return func(raw []byte) (Params, error) {
		var empty struct{}
		if err := strictUnmarshal(raw, &empty); err != nil {
			return nil, err
		}
		return NoParams{intent: n}, nil
	}
}

// decodeUnit builds a decoder for an intent that acts on one systemd unit.
func decodeUnit(n Name) func([]byte) (Params, error) {
	return func(raw []byte) (Params, error) {
		var wire struct {
			Unit string `json:"unit"`
		}
		if err := strictUnmarshal(raw, &wire); err != nil {
			return nil, err
		}
		if err := validateUnit(wire.Unit); err != nil {
			return nil, err
		}
		return UnitParams{intent: n, Unit: wire.Unit}, nil
	}
}

// decodeApplyAll decodes the destructive update intent, the one that may carry a follow-up reboot.
//
// Not shared with the routine member, deliberately. See ApplyParams and decodeApplySecurity.
func decodeApplyAll(raw []byte) (Params, error) {
	var wire struct {
		RebootIfRequired bool `json:"rebootIfRequired"`
	}
	if err := strictUnmarshal(raw, &wire); err != nil {
		return nil, err
	}
	return ApplyParams{intent: PackagesApplyAll, RebootIfRequired: wire.RebootIfRequired}, nil
}

// decodeApplySecurity decodes the routine update intent, which takes no parameters at all.
//
// The refusal below is the mechanism behind docs/SECURITY.md §3's "a signature by the online key must
// not authorise a reboot". This intent is signed by the control plane for itself, so any parameter it
// accepts is a parameter an attacker owning the control plane can set. A reboot is destructive work and
// needs a key the control plane does not hold; there is no version of it that is safe to reach from
// here, which is why the field is refused rather than clamped.
//
// The error says which intent to use instead. An operator who wanted "patch and reboot" is asking for
// something reasonable, and the answer is two authorisations rather than none.
func decodeApplySecurity(raw []byte) (Params, error) {
	var wire struct{}
	if err := strictUnmarshal(raw, &wire); err != nil {
		if errors.Is(err, ErrUnknownField) {
			return nil, fmt.Errorf("%w. %s takes no parameters: a reboot is destructive work and needs "+
				"an offline signature from a key in the host's own %s, which is what %s is for. "+
				"See docs/SECURITY.md §3",
				err, PackagesApplySecurity, "trusted-signers", HostReboot)
		}
		return nil, err
	}
	return ApplyParams{intent: PackagesApplySecurity}, nil
}

// decodeReboot builds a decoder for the host reboot intent.
func decodeReboot(n Name) func([]byte) (Params, error) {
	return func(raw []byte) (Params, error) {
		var wire struct {
			DelaySeconds int    `json:"delaySeconds"`
			Message      string `json:"message"`
		}
		if err := strictUnmarshal(raw, &wire); err != nil {
			return nil, err
		}
		if wire.DelaySeconds < 0 || wire.DelaySeconds > 3600 {
			return nil, fmt.Errorf("delaySeconds %d out of range 0..3600", wire.DelaySeconds)
		}
		// Position before character set, so that the operator who typed something dangerous is told
		// which rule they broke and why, rather than being shown a regular expression.
		//
		// The three that matter are not hypothetical: shutdown(8) reads "-h" as poweroff and it
		// OVERRIDES "-r", so the host does not come back; "-k" sends the wall message and reboots
		// nothing, which is a reboot job that reports success and did not happen; and "-c" cancels a
		// shutdown already pending. The helper also passes "--" before its positional arguments, and
		// both defences are kept because this one bounds what any future call site can receive.
		if strings.HasPrefix(wire.Message, "-") {
			return nil, fmt.Errorf("message must not begin with a hyphen: it reaches shutdown(8) as a "+
				"positional argument, where a leading hyphen is read as an option — %q would power the "+
				"host off instead of rebooting it", wire.Message)
		}
		if !messagePattern.MatchString(wire.Message) {
			return nil, fmt.Errorf("message does not match %s", messagePattern)
		}
		return RebootParams{intent: n, DelaySeconds: wire.DelaySeconds, Message: wire.Message}, nil
	}
}
