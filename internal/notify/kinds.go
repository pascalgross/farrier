package notify

// Kind is one member of the closed event vocabulary.
//
// Closed and named, the way intents are, rather than a string that grows per caller: an event kind
// ends up in operators' webhook filters, in the alert rules' condition table and in the UI's icons,
// and a kind that one handler spells "job.fail" and another "job.failed" is two dashboards that each
// miss half the events. Adding a member means editing this file and the expected set in
// notify_test.go in the same commit — which is the point.
type Kind string

// The complete event vocabulary.
const (
	// KindHostEnrolled reports a machine joining the fleet.
	KindHostEnrolled Kind = "host.enrolled"

	// KindHostSilent reports a host that has stopped heartbeating for longer than a rule allows.
	//
	// It is the one signal that separates "quiet fleet" from "dead agent", which is why it comes from
	// the alert evaluator rather than from a request handler: silence is precisely the case where no
	// request will ever arrive to notice it.
	KindHostSilent Kind = "host.silent"

	// KindHostRecovered reports a silent host heartbeating again.
	//
	// Every firing condition has an un-firing counterpart, because an alert that never resolves is an
	// alert operators learn to ignore.
	KindHostRecovered Kind = "host.recovered"

	// KindJobCreated reports a job queued for a host.
	KindJobCreated Kind = "job.created"

	// KindJobApproved reports an operator releasing a destructive job.
	KindJobApproved Kind = "job.approved"

	// KindJobFailed reports a host attempting a job and failing it.
	//
	// Failures only — a refusal is the system working, not an incident, and an event stream that
	// paints refused_by_policy the same colour as failed teaches operators to ignore both.
	KindJobFailed Kind = "job.failed"

	// KindJobExpired reports a job whose validity window closed before it executed.
	//
	// max_job_age_seconds dropping work silently is exactly where silence is the wrong answer: the
	// operator who queued the job believes it ran.
	KindJobExpired Kind = "job.expired"

	// KindServiceFailed reports a watched systemd unit entering the failed state.
	KindServiceFailed Kind = "service.failed"

	// KindServiceRecovered reports a previously failed unit running again.
	KindServiceRecovered Kind = "service.recovered"

	// KindUpdatesPending reports a host whose pending security updates crossed a rule's line.
	KindUpdatesPending Kind = "updates.pending"

	// KindUpdatesResolved reports that a host's security backlog dropped back under the line.
	KindUpdatesResolved Kind = "updates.resolved"

	// KindRebootOverdue reports a host that has needed a reboot for longer than a rule allows.
	KindRebootOverdue Kind = "reboot.overdue"

	// KindRebootDone reports that an overdue host no longer needs its reboot.
	KindRebootDone Kind = "reboot.done"

	// KindDeliveryFailed reports that an event could not be delivered to a tenant's webhook.
	//
	// It is the visible record of what never went out, and it exists because a webhook that is down
	// takes every other event with it silently: the inbox fills up, the endpoint receives nothing,
	// and nobody learns which of the two is true until somebody asks why the chat channel is quiet.
	//
	// It is the one kind that is never delivered outwards, only recorded. Delivering a
	// delivery-failure notice through the delivery that just failed would either fail again — and
	// emit another — or, worse, succeed on the retry and report a failure that had resolved.
	KindDeliveryFailed Kind = "delivery.failed"
)

// Kinds is the closed set, as a set, for validation and for the test that keeps it closed.
var Kinds = map[Kind]bool{
	KindHostEnrolled:     true,
	KindHostSilent:       true,
	KindHostRecovered:    true,
	KindJobCreated:       true,
	KindJobApproved:      true,
	KindJobFailed:        true,
	KindJobExpired:       true,
	KindServiceFailed:    true,
	KindServiceRecovered: true,
	KindUpdatesPending:   true,
	KindUpdatesResolved:  true,
	KindRebootOverdue:    true,
	KindRebootDone:       true,
	KindDeliveryFailed:   true,
}

// Valid reports whether a kind is one of the closed set.
//
// Checked where events enter the store, so a handler that invented a kind fails its own test rather
// than shipping a word no filter matches.
func (k Kind) Valid() bool { return Kinds[k] }
