package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pascalgross/farrier/internal/canonical"
	"github.com/pascalgross/farrier/internal/policy"
)

// fixtureBootTime is the btime every container fixture's /proc/stat carries.
//
// Start times are asserted against it rather than against "some time in the past", because the whole
// point of the arithmetic is that btime and the clock-tick divisor are combined the right way round —
// and every wrong way of combining them still produces a plausible-looking timestamp.
const fixtureBootTime = 1750000000

// Container ids used by the fixture trees, spelled out so a failing test names the container.
const (
	// fixtureNginxID is the running container in the systemd-driver tree.
	fixtureNginxID = "a1b2c3d4e5f69999999999999999999999999999999999999999999999999999"

	// fixturePausedID is the frozen container in the systemd-driver tree.
	fixturePausedID = "b0b1b2b3b4b57777777777777777777777777777777777777777777777777777"

	// fixtureRedisID is the container used by the cgroupfs, rootless and no-controller trees.
	fixtureRedisID = "c0ffee1234561111111111111111111111111111111111111111111111111111"

	// fixturePidHostID is the --pid=host container.
	fixturePidHostID = "e0e1e2e3e4e55555555555555555555555555555555555555555555555555555"

	// fixtureSocketID is the container with the Docker socket bind-mounted into it.
	fixtureSocketID = "f0f1f2f3f4f52222222222222222222222222222222222222222222222222222"
)

// containersIn runs the scan against one fixture tree.
//
// The trees are real /proc and cgroup shapes rather than minimal invented ones, for the reason the apt
// fixtures are: every trap this file exists to catch — the parenthesised comm, the multi-entry NSpid,
// the controller file that is simply not there — lives in the parts a minimal fixture would leave out.
func containersIn(t *testing.T, scenario string) ContainerReport {
	t.Helper()
	dir := filepath.Join("testdata", "containers", scenario)
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("fixture tree %s: %v", scenario, err)
	}
	return collectContainersFrom(filepath.Join(dir, "proc"), filepath.Join(dir, "cgroup"))
}

// byID indexes a report so a test can name the container it is asserting about.
func byID(report ContainerReport) map[string]Container {
	out := map[string]Container{}
	for _, c := range report.Containers {
		out[c.ID] = c
	}
	return out
}

// TestSystemdDriverContainersAreFound covers Docker's default cgroup driver on cgroup v2.
//
// It is the shape almost every host has, so it is also where the numbers are checked in full: a
// wrong memory figure here is the one an operator would notice by comparing this against
// `docker stats`, and the subtraction of inactive_file is what makes the two agree.
func TestSystemdDriverContainersAreFound(t *testing.T) {
	report := containersIn(t, "systemd-driver")

	if !report.ScanComplete {
		t.Fatalf("the scan reported itself incomplete on an ordinary host: %q", report.Note)
	}
	if report.Total != 2 || len(report.Containers) != 2 {
		t.Fatalf("found %d containers (total %d), want 2: %+v",
			len(report.Containers), report.Total, report.Containers)
	}
	if report.Containers[0].ID >= report.Containers[1].ID {
		t.Errorf("containers are not sorted by id: %q then %q",
			report.Containers[0].ID, report.Containers[1].ID)
	}
	if report.Note != "" {
		t.Errorf("a host with running containers carries a note explaining an empty list: %q", report.Note)
	}

	nginx := byID(report)[fixtureNginxID]
	if nginx.ShortID != "a1b2c3d4e5f6" {
		t.Errorf("shortId is %q, want the twelve characters docker ps prints", nginx.ShortID)
	}
	if nginx.MainPID != 4242 {
		t.Errorf("main pid is %d, want 4242 — the entry whose NSpid ends in 1", nginx.MainPID)
	}
	if nginx.Command != "nginx" {
		t.Errorf("command is %q, want the comm value", nginx.Command)
	}
	if want := time.Unix(fixtureBootTime+3600, 0).UTC(); nginx.StartedAt == nil ||
		!nginx.StartedAt.Equal(want) {
		t.Errorf("started at %v, want %v (btime plus starttime/100)", nginx.StartedAt, want)
	}
	if !nginx.Running || nginx.Paused {
		t.Errorf("running=%t paused=%t, want a running, unpaused container", nginx.Running, nginx.Paused)
	}
	// 104857600 - 20971520: memory.current less the reclaimable page cache, which is the number
	// `docker stats` shows and the only one an operator will accept.
	if nginx.MemoryBytes == nil || *nginx.MemoryBytes != 83886080 {
		t.Errorf("memory is %v, want 83886080 — memory.current less inactive_file", nginx.MemoryBytes)
	}
	if nginx.MemoryLimitBytes == nil || *nginx.MemoryLimitBytes != 536870912 {
		t.Errorf("memory limit is %v, want 536870912", nginx.MemoryLimitBytes)
	}
	if nginx.CPUSeconds == nil || *nginx.CPUSeconds != 12 {
		t.Errorf("cpu seconds is %v, want 12", nginx.CPUSeconds)
	}
	if nginx.CPUThrottledSeconds == nil || *nginx.CPUThrottledSeconds != 2 {
		t.Errorf("throttled seconds is %v, want 2", nginx.CPUThrottledSeconds)
	}
	if nginx.Pids != 7 || nginx.PidsSource != "pids.current" {
		t.Errorf("pids is %d from %q, want 7 from pids.current", nginx.Pids, nginx.PidsSource)
	}
	if nginx.OOMKills == nil || *nginx.OOMKills != 2 {
		t.Errorf("oom kills is %v, want 2", nginx.OOMKills)
	}
	if !nginx.PostureKnown || !nginx.RunsAsRoot || nginx.Privileged || nginx.SeccompDisabled ||
		nginx.DockerSocketMounted {
		t.Errorf("posture is %+v, want a known, root, unprivileged, seccomp-confined container "+
			"with no socket mounted", nginx)
	}
}

// TestAPausedContainerIsReportedAsPaused covers the one Docker state visible without the API.
//
// `docker pause` uses the cgroup freezer rather than a signal, so cgroup.events answers it exactly. A
// collector that reported a frozen container as merely running would show a green row for a workload
// that is doing nothing at all.
func TestAPausedContainerIsReportedAsPaused(t *testing.T) {
	paused := byID(containersIn(t, "systemd-driver"))[fixturePausedID]

	if !paused.Paused {
		t.Errorf("a container whose cgroup.events says frozen 1 is not reported as paused: %+v", paused)
	}
	if !paused.Running {
		t.Error("a paused container's cgroup is still populated and must still report running")
	}
	if paused.RunsAsRoot {
		t.Error("a container whose main process has uid 999 is reported as running as root")
	}
	// memory.max reads "max", so the field must be absent rather than an invented eight-exabyte quota.
	if paused.MemoryLimitBytes != nil {
		t.Errorf("an unlimited container reports a limit of %d", *paused.MemoryLimitBytes)
	}
	if paused.CPUThrottledSeconds != nil {
		t.Errorf("throttled seconds is %d on a container whose cpu controller is off; the field must "+
			"be absent, because zero would claim it was measured", *paused.CPUThrottledSeconds)
	}
	if paused.Pids != 1 || paused.PidsSource != "cgroup.procs" {
		t.Errorf("pids is %d from %q, want 1 counted from cgroup.procs", paused.Pids, paused.PidsSource)
	}
}

// TestCgroupfsDriverContainersAreFound covers Docker's other cgroup driver.
//
// It is the reason enumeration starts at /proc rather than at a path under /sys/fs/cgroup: the driver
// is a daemon setting, and a collector that only understood the default would report zero containers on
// a host that is running plenty, with no error anywhere to explain it.
func TestCgroupfsDriverContainersAreFound(t *testing.T) {
	report := containersIn(t, "cgroupfs-driver")

	if report.Total != 1 {
		t.Fatalf("found %d containers under the cgroupfs driver, want 1: %+v",
			report.Total, report.Containers)
	}
	c := report.Containers[0]
	if c.ID != fixtureRedisID || c.MainPID != 6001 || c.Command != "redis-server" {
		t.Errorf("container parsed as %+v", c)
	}
}

// TestRootlessDockerContainersAreFound covers a container under a user slice.
//
// Rootless Docker puts its containers below user@1000.service rather than below system.slice, at a
// depth nothing fixed would match. Matching the scope name at any depth is what also covers a custom
// --cgroup-parent, which is the same problem wearing a different name.
func TestRootlessDockerContainersAreFound(t *testing.T) {
	report := containersIn(t, "rootless")

	if report.Total != 1 {
		t.Fatalf("found %d rootless containers, want 1: %+v", report.Total, report.Containers)
	}
	c := report.Containers[0]
	if c.ID != fixtureRedisID || c.MainPID != 7001 {
		t.Errorf("container parsed as %+v", c)
	}
	if c.RunsAsRoot {
		t.Error("a rootless container's uid-1000 main process is reported as running as root")
	}
	if c.MemoryBytes == nil || *c.MemoryBytes != 7340032 {
		t.Errorf("memory is %v, want 7340032", c.MemoryBytes)
	}
}

// TestKubernetesPodsAreNotReportedAsDockerContainers is the exclusion that keeps the report honest.
//
// A kubepods slice holds containers the kubelet created through a CRI runtime. Dockershim-era clusters
// name those scopes exactly like Docker's, so the id shape alone is not enough to tell them apart —
// and telling an operator that a machine they manage with kubectl is one they can manage with docker is
// worse than telling them nothing.
func TestKubernetesPodsAreNotReportedAsDockerContainers(t *testing.T) {
	report := containersIn(t, "kubepods")

	if report.Total != 1 {
		t.Fatalf("reported %d containers on a host with one Docker container and three Kubernetes "+
			"ones, want 1: %+v", report.Total, report.Containers)
	}
	if report.Containers[0].ID != fixtureNginxID {
		t.Errorf("the reported container is %q, want the one outside kubepods",
			report.Containers[0].ShortID)
	}
}

// TestPidHostContainerFallsBackToTheLowestPid covers --pid=host.
//
// Such a container is in no pid namespace, so its NSpid line has a single entry and no process in the
// cgroup claims to be process 1. The lowest pid is the one the others were forked from, and it is the
// best answer available without the Docker API — the alternative, reporting no main process at all,
// would drop the command, the start time and the whole security posture for exactly the containers
// that gave up the most isolation.
func TestPidHostContainerFallsBackToTheLowestPid(t *testing.T) {
	report := containersIn(t, "pid-host")

	if report.Total != 1 {
		t.Fatalf("found %d containers, want 1: %+v", report.Total, report.Containers)
	}
	c := report.Containers[0]
	if c.ID != fixturePidHostID {
		t.Fatalf("container id is %q", c.ID)
	}
	if c.MainPID != 9299 {
		t.Errorf("main pid is %d, want the lowest pid 9299 — no NSpid entry ends in 1 here", c.MainPID)
	}
	if c.Command != "prometheus" {
		t.Errorf("command is %q; the fallback main pid must still be read from", c.Command)
	}
	if c.Pids != 2 || c.PidsSource != "cgroup.procs" {
		t.Errorf("pids is %d from %q, want 2 counted from cgroup.procs", c.Pids, c.PidsSource)
	}
}

// TestAbsentMemoryControllerIsNotMeasuredRatherThanZero is the distinction the whole report turns on.
//
// memory.current exists only where the memory controller is enabled in the parent's
// cgroup.subtree_control. Reporting zero there would put a container using two gigabytes on a
// dashboard as using none, and nothing about the row would say the number was never measured.
func TestAbsentMemoryControllerIsNotMeasuredRatherThanZero(t *testing.T) {
	report := containersIn(t, "no-memory-controller")

	if report.Total != 1 {
		t.Fatalf("found %d containers, want 1: %+v", report.Total, report.Containers)
	}
	c := report.Containers[0]
	if c.MemoryBytes != nil {
		t.Errorf("memory is reported as %d on a host with no memory controller", *c.MemoryBytes)
	}
	if c.MemoryLimitBytes != nil || c.OOMKills != nil {
		t.Errorf("limit %v and oom kills %v are claimed with no memory controller enabled",
			c.MemoryLimitBytes, c.OOMKills)
	}
	// The kernel accounts usage_usec whether or not the cpu controller is on, so this one survives.
	if c.CPUSeconds == nil || *c.CPUSeconds != 12 {
		t.Errorf("cpu seconds is %v, want 12 even with the cpu controller disabled", c.CPUSeconds)
	}
	if c.Pids != 3 || c.PidsSource != "cgroup.procs" {
		t.Errorf("pids is %d from %q, want 3 counted from cgroup.procs", c.Pids, c.PidsSource)
	}

	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("encoding the container: %v", err)
	}
	if strings.Contains(string(raw), "memoryBytes") {
		t.Errorf("an unmeasured memory figure is present on the wire: %s", raw)
	}
}

// TestAParenthesisedCommandNameDoesNotBreakTheStartTime covers a name anybody can choose.
//
// /proc/<pid>/stat puts the executable name in parentheses as its second field, and the name may
// itself contain spaces and parentheses. A parser that split the line on whitespace would read some
// other field as the start time and report a timestamp that is wrong but entirely plausible.
func TestAParenthesisedCommandNameDoesNotBreakTheStartTime(t *testing.T) {
	c := containersIn(t, "no-memory-controller").Containers[0]

	if c.Command != "weird (x) proc" {
		t.Fatalf("command is %q, want the fixture's awkward comm", c.Command)
	}
	want := time.Unix(fixtureBootTime+12345, 0).UTC()
	if c.StartedAt == nil || !c.StartedAt.Equal(want) {
		t.Errorf("started at %v, want %v", c.StartedAt, want)
	}
}

// TestTheMountedDockerSocketIsReported is the finding this collector exists to produce.
//
// "Docker socket access is root equivalence" is the sentence in docs/SECURITY.md §6 that keeps the
// agent out of the docker group. A container with the socket bind-mounted into it holds exactly that
// access, and finding it on a host is the difference between knowing and assuming.
func TestTheMountedDockerSocketIsReported(t *testing.T) {
	report := containersIn(t, "docker-socket")

	if report.Total != 1 {
		t.Fatalf("found %d containers, want 1: %+v", report.Total, report.Containers)
	}
	c := report.Containers[0]
	if c.ID != fixtureSocketID {
		t.Fatalf("container id is %q", c.ID)
	}
	if !c.PostureKnown {
		t.Fatal("the security posture is reported as unknown for a container whose status was readable")
	}
	if !c.DockerSocketMounted {
		t.Error("a container with /var/run/docker.sock mounted in does not report it")
	}
	if !c.Privileged {
		t.Error("a container holding the full effective capability set is not reported as privileged")
	}
	if !c.SeccompDisabled {
		t.Error("a container with Seccomp: 0 is not reported as unconfined")
	}
	if !c.RunsAsRoot {
		t.Error("a container whose main process has uid 0 is not reported as running as root")
	}

	// The host paths in mountinfo are inventory of somebody's filesystem layout, and the control plane
	// has no business holding them. Only the boolean travels.
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("encoding the container: %v", err)
	}
	if strings.Contains(string(raw), "/var/run") || strings.Contains(string(raw), "overlay") {
		t.Errorf("a host path from mountinfo reached the wire: %s", raw)
	}
}

// TestHidepidMakesTheScanIncomplete covers the configuration that empties this report silently.
//
// hidepid hides other users' /proc entries from an unprivileged reader, which turns a container report
// into a report about the agent itself — and produces no error at any step. "No containers are running"
// and "I could not see the containers that are" must not render the same way, which is the rule
// RebootReport.ServiceScanComplete states and the reason this flag exists.
func TestHidepidMakesTheScanIncomplete(t *testing.T) {
	report := containersIn(t, "hidepid")

	if report.ScanComplete {
		t.Error("a /proc mounted with hidepid is reported as a complete scan")
	}
	if !strings.Contains(report.Note, "hidepid") {
		t.Errorf("the note does not say why the scan is incomplete: %q", report.Note)
	}
	if report.Containers == nil {
		t.Error("the container list is nil rather than an empty list")
	}
}

// TestAPrivateCgroupNamespaceMakesTheScanIncomplete covers the agent looking at the wrong tree.
//
// A process in its own cgroup namespace sees its cgroup as the root, so /proc/self/cgroup reads
// "0::/" and every path this collector reads is relative to something that is not the host. The
// symptom is an empty list on a busy container host, which is exactly the answer nobody should trust.
func TestAPrivateCgroupNamespaceMakesTheScanIncomplete(t *testing.T) {
	report := containersIn(t, "private-cgroup-namespace")

	if report.ScanComplete {
		t.Error("an agent in a private cgroup namespace is reported as having made a complete scan")
	}
	if !strings.Contains(report.Note, "cgroup namespace") {
		t.Errorf("the note does not say why the scan is incomplete: %q", report.Note)
	}
}

// TestAHostWithNoDockerSaysSo covers the ordinary machine, which is most of them.
//
// The collector must produce a usable, non-nil report on a host that has never had Docker installed —
// collector_test.go runs every registered collector for real, and an error here would drop the section
// on every host in a fleet. An empty list plus a note is the honest answer; an empty list alone would
// leave an operator wondering whether the feature works.
func TestAHostWithNoDockerSaysSo(t *testing.T) {
	report := containersIn(t, "no-docker")

	if !report.ScanComplete {
		t.Errorf("the scan reported itself incomplete on an ordinary host: %q", report.Note)
	}
	if len(report.Containers) != 0 || report.Total != 0 {
		t.Fatalf("found containers on a host with no Docker: %+v", report.Containers)
	}
	if !strings.Contains(report.Note, "no container runtime") {
		t.Errorf("note is %q, want one saying no runtime is visible", report.Note)
	}

	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encoding the report: %v", err)
	}
	if !strings.Contains(string(raw), `"containers":[]`) {
		t.Errorf("an empty list is not an explicit [] on the wire: %s", raw)
	}
}

// TestARunningRuntimeWithNoContainersSaysSomethingElse is the third answer that arrives as [].
//
// "Nothing is installed here", "the daemon is up and nothing is running" and "I could not see" are
// three different situations, and a client that renders them identically has thrown away the only
// information an operator would have acted on.
func TestARunningRuntimeWithNoContainersSaysSomethingElse(t *testing.T) {
	report := containersIn(t, "runtime-idle")

	if !report.ScanComplete || report.Total != 0 {
		t.Fatalf("report is %+v", report)
	}
	if !strings.Contains(report.Note, "container runtime is running") {
		t.Errorf("note is %q, want one distinguishing an idle runtime from an absent one", report.Note)
	}
	if strings.Contains(report.Note, "no container runtime is visible") {
		t.Errorf("an idle daemon is reported as an absent one: %q", report.Note)
	}
}

// TestScanCountsBeforeTruncating asserts the count and the list may disagree on purpose.
//
// It is the same property TestSummariseCountsBeforeTruncating asserts for packages, and it matters for
// the same reason: a host running six hundred containers must report six hundred and say the list was
// cut short. Reporting two hundred would be a quietly wrong answer to the question that was asked.
func TestScanCountsBeforeTruncating(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	if err := os.MkdirAll(procRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range MaxContainers + 50 {
		id := fmt.Sprintf("%064x", i+1)
		pid := 1000 + i
		dir := filepath.Join(procRoot, fmt.Sprint(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		line := fmt.Sprintf("0::/system.slice/docker-%s.scope\n", id)
		if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(line), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	report := collectContainersFrom(procRoot, filepath.Join(root, "cgroup"))

	if report.Total != MaxContainers+50 {
		t.Errorf("total is %d, want %d", report.Total, MaxContainers+50)
	}
	if len(report.Containers) != MaxContainers || !report.Truncated {
		t.Errorf("list has %d entries, truncated=%v", len(report.Containers), report.Truncated)
	}
	for i := 1; i < len(report.Containers); i++ {
		if report.Containers[i-1].ID >= report.Containers[i].ID {
			t.Fatalf("the list is not sorted, so the cut is not deterministic: %q before %q",
				report.Containers[i-1].ShortID, report.Containers[i].ShortID)
		}
	}
}

// TestAnUnreadableProcIsAnIncompleteScanRatherThanAnError covers the worst case.
//
// The collector never returns an error, because an error drops the whole section and a dropped section
// tells an operator nothing at all. A /proc this agent cannot read is a fact about the host, and the
// report has a field for saying it.
func TestAnUnreadableProcIsAnIncompleteScanRatherThanAnError(t *testing.T) {
	report := collectContainersFrom(filepath.Join(t.TempDir(), "absent"), t.TempDir())

	if report.ScanComplete {
		t.Error("a missing /proc is reported as a complete scan")
	}
	if report.Containers == nil {
		t.Error("the container list is nil rather than an empty list")
	}
	if report.Note == "" {
		t.Error("no note explains the empty list")
	}
}

// TestScanCompleteSurvivesEncodingWhenFalse is the omitempty rule, checked rather than remembered.
//
// A flag whose alarming value is false must not carry omitempty, or it vanishes from the wire in
// exactly the case worth seeing. RebootReport.Conclusive states the rule; this asserts that the two
// flags in this report follow it, because the mistake is one struct tag wide and invisible in review.
func TestScanCompleteSurvivesEncodingWhenFalse(t *testing.T) {
	raw, err := json.Marshal(ContainerReport{Containers: []Container{{}}})
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	for _, field := range []string{`"scanComplete":false`, `"postureKnown":false`, `"running":false`} {
		if !strings.Contains(string(raw), field) {
			t.Errorf("%s is absent from %s", field, raw)
		}
	}
}

// TestContainerReportCarriesNoFloatingPointValues is a heartbeat-wide failure waiting to happen.
//
// docs/PROTOCOL.md §8 rejects floats outright, and the facts document is digested with the same
// encoder. A float anywhere in this section would not break this section: it would fail
// canonical.Digest and take the entire heartbeat with it, on every cycle, on every host that turned
// container reporting on. That is why the CPU figures are whole seconds.
func TestContainerReportCarriesNoFloatingPointValues(t *testing.T) {
	for _, scenario := range []string{"systemd-driver", "docker-socket", "no-memory-controller"} {
		report := containersIn(t, scenario)
		if _, err := canonical.Marshal(report); err != nil {
			t.Errorf("%s: the report does not canonicalise: %v", scenario, err)
		}
	}
}

// TestDockerContainerIDRejectsWhatIsNotOne covers the shape check directly.
//
// Anybody can create a directory under /sys/fs/cgroup/docker, and a scan that accepted whatever
// followed the prefix would put it in a fleet report as a container. The id shape is the only thing
// separating a real container from a name somebody chose.
func TestDockerContainerIDRejectsWhatIsNotOne(t *testing.T) {
	full := strings.Repeat("ab", 32)
	cases := []struct {
		path string
		want string
	}{
		{"/system.slice/docker-" + full + ".scope", full},
		{"/docker/" + full, full},
		{"/my-parent.slice/docker-" + full + ".scope", full},
		{"/docker/not-a-container-id", ""},
		{"/system.slice/docker-short.scope", ""},
		{"/system.slice/docker-" + strings.Repeat("zz", 32) + ".scope", ""},
		{"/system.slice/containerd-" + full + ".scope", ""},
		{"/kubepods.slice/kubepods-pod1.slice/docker-" + full + ".scope", ""},
		{"/system.slice/docker.service", ""},
		{"/", ""},
	}
	for _, tc := range cases {
		if got := dockerContainerID(tc.path); got != tc.want {
			t.Errorf("dockerContainerID(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestHidepidIsReadFromMountinfoNotGuessed covers the option parsing on its own.
//
// hidepid takes both numeric and named values, and only 0 and off mean "not in force". Treating
// "hidepid=invisible" as absent would report a complete scan on the one configuration that guarantees
// an incomplete one.
func TestHidepidIsReadFromMountinfoNotGuessed(t *testing.T) {
	cases := map[string]bool{
		"25 30 0:24 / /proc rw,relatime shared:5 - proc proc rw":                     false,
		"25 30 0:24 / /proc rw,relatime shared:5 - proc proc rw,hidepid=0":           false,
		"25 30 0:24 / /proc rw,relatime shared:5 - proc proc rw,hidepid=off":         false,
		"25 30 0:24 / /proc rw,relatime shared:5 - proc proc rw,hidepid=2":           true,
		"25 30 0:24 / /proc rw,relatime shared:5 - proc proc rw,hidepid=invisible":   true,
		"25 30 0:24 / /notproc rw,relatime shared:5 - proc proc rw,hidepid=2":        false,
		"25 30 0:24 / /proc rw,relatime - tmpfs tmpfs rw,hidepid=2":                  false,
		"25 30 0:24 / /proc rw,relatime shared:5 master:2 - proc proc rw,hidepid=2":  true,
		"25 30 0:24 / /proc rw,relatime - proc proc rw,gid=100,hidepid=2,mode=0700":  true,
		"25 30 0:24 / /proc rw,relatime - proc proc rw,gid=100,nohidepid=2,mode=700": false,
	}
	for line, want := range cases {
		path := filepath.Join(t.TempDir(), "mountinfo")
		if err := os.WriteFile(path, []byte(line+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := hidepidInForce(path); got != want {
			t.Errorf("hidepidInForce(%q) = %t, want %t", line, got, want)
		}
	}
}

// TestFullCapabilitySetFollowsTheKernel covers the mask a privileged container is compared against.
//
// The number of capabilities grows with kernel releases. A hard-coded mask would make every privileged
// container on a newer kernel look unprivileged, which is a silent false negative on the one field an
// operator would act on.
func TestFullCapabilitySetFollowsTheKernel(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sys", "kernel"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := fullCapabilitySet(root); got != 1<<41-1 {
		t.Errorf("with no cap_last_cap the mask is %#x, want the fallback %#x", got, uint64(1<<41-1))
	}
	if err := os.WriteFile(filepath.Join(root, "sys", "kernel", "cap_last_cap"),
		[]byte("42\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := fullCapabilitySet(root); got != 1<<43-1 {
		t.Errorf("with cap_last_cap 42 the mask is %#x, want %#x", got, uint64(1<<43-1))
	}
}

// gatedProbe is a collector that a policy can switch off, for testing the seam rather than the shipped
// collector.
//
// It records whether it ran, which is the only way to tell "withheld" from "ran and produced nothing":
// both leave the section absent from the facts document, and only one of them is what the policy asked
// for.
type gatedProbe struct {
	// permitted is what this probe tells Gather the policy says.
	permitted bool

	// ran records that Collect was called.
	ran *bool
}

// Name is the key this probe's output would appear under.
func (gatedProbe) Name() string { return "probe" }

// Collect records that it ran and returns a section.
func (g gatedProbe) Collect(context.Context) (any, error) {
	*g.ran = true
	return map[string]any{"seen": true}, nil
}

// PermittedBy reports what this probe was constructed to say.
func (g gatedProbe) PermittedBy(policy.Policy) bool { return g.permitted }

// stubPlatform is the smallest Platform that lets Gather run in a test.
//
// It exists because Gather's first act is to identify the host, and a test about the collector gate has
// no business depending on what distribution the test machine happens to be.
type stubPlatform struct{}

// Identify reports a fixed distribution.
func (stubPlatform) Identify() (Distribution, error) {
	return Distribution{ID: "debian", Family: FamilyDebian, Codename: "bookworm"}, nil
}

// UpgradablePackages reports nothing pending.
func (stubPlatform) UpgradablePackages(context.Context) ([]Package, error) { return nil, nil }

// SecurityOrigins reports no origins.
func (stubPlatform) SecurityOrigins() []string { return nil }

// RebootRequired reports a conclusive no.
func (stubPlatform) RebootRequired(context.Context) (RebootReport, error) {
	return RebootReport{Conclusive: true}, nil
}

// SubscriptionStatus reports that the concept does not exist here.
func (stubPlatform) SubscriptionStatus(context.Context) (*Subscription, error) { return nil, nil }

// TestGatherWithholdsASectionTheLocalPolicyRefuses is the whole of the policy gate.
//
// A refused section must be absent from the facts document rather than empty, and the collector must
// not run at all — a collector that read the host and then had its output dropped would have done the
// reading the policy exists to prevent. The host's policy travels in the same heartbeat, so the control
// plane can still say "this host does not report that" rather than "this host has none".
func TestGatherWithholdsASectionTheLocalPolicyRefuses(t *testing.T) {
	local := policy.Default()

	ran := false
	facts, err := Gather(context.Background(), stubPlatform{}, local, gatedProbe{ran: &ran})
	if err != nil {
		t.Fatalf("gathering: %v", err)
	}
	if ran {
		t.Error("a collector the policy refuses was run and its output discarded")
	}
	if _, present := facts.Extra["probe"]; present {
		t.Errorf("a withheld section is present in the facts document: %v", facts.Extra)
	}

	ran = false
	facts, err = Gather(context.Background(), stubPlatform{}, local, gatedProbe{permitted: true, ran: &ran})
	if err != nil {
		t.Fatalf("gathering: %v", err)
	}
	if !ran {
		t.Error("a permitted collector did not run")
	}
	if _, present := facts.Extra["probe"]; !present {
		t.Errorf("a permitted section is absent from the facts document: %v", facts.Extra)
	}
}
