package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/pascalgross/farrier/internal/intent"
)

// TestShutdownTimeNeverBringsARebootForward is the property that matters about the rounding.
//
// shutdown(8) has no seconds, and the catalogue accepts a delay in seconds because staggering a signed
// batch is what the parameter is for. Something has to give, and the direction matters: a host that
// reboots later than authorised is an inconvenience, and one that reboots earlier has been taken away
// before the person who signed for it expected. This asserts the second never happens.
func TestShutdownTimeNeverBringsARebootForward(t *testing.T) {
	for _, seconds := range []int{1, 29, 30, 59, 60, 61, 90, 119, 120, 599, 600, 3599, 3600} {
		got := shutdownTime(seconds)
		minutes, err := strconv.Atoi(strings.TrimPrefix(got, "+"))
		if err != nil {
			t.Fatalf("shutdownTime(%d) = %q, which is not a +minutes specification: %v", seconds, got, err)
		}
		if minutes*60 < seconds {
			t.Errorf("shutdownTime(%d) = %q, which is %ds — earlier than the delay that was authorised",
				seconds, got, minutes*60)
		}
		if (minutes-1)*60 >= seconds {
			t.Errorf("shutdownTime(%d) = %q, which rounds up further than it needs to", seconds, got)
		}
	}
}

// TestShutdownTimeIsNowForNoDelay asserts the ordinary case is not "+0".
//
// "+0" and "now" mean the same thing to shutdown, but "now" is what an operator reading the job result
// expects to see, and the value is quoted back to them in the output.
func TestShutdownTimeIsNowForNoDelay(t *testing.T) {
	for _, seconds := range []int{0, -1} {
		if got := shutdownTime(seconds); got != "now" {
			t.Errorf("shutdownTime(%d) = %q, want \"now\"", seconds, got)
		}
	}
}

// TestEveryDelayTheCatalogueAcceptsProducesAValidTimeSpecification joins the two validators.
//
// The catalogue bounds the delay to 0..3600 and this helper converts it; the risk is that the two stop
// agreeing — a range widened here, a conversion changed there — and the symptom would be shutdown(8)
// refusing a time specification at the one moment somebody needed the reboot to happen.
func TestEveryDelayTheCatalogueAcceptsProducesAValidTimeSpecification(t *testing.T) {
	for seconds := 0; seconds <= 3600; seconds += 7 {
		raw, err := json.Marshal(map[string]int{"delaySeconds": seconds})
		if err != nil {
			t.Fatalf("marshalling: %v", err)
		}
		_, params, err := intent.Decode(intent.HostReboot, raw)
		if err != nil {
			t.Fatalf("the catalogue rejected delaySeconds=%d: %v", seconds, err)
		}
		reboot, ok := params.(intent.RebootParams)
		if !ok {
			t.Fatalf("host.reboot decoded to %T", params)
		}
		got := shutdownTime(reboot.DelaySeconds)
		if got != "now" && !strings.HasPrefix(got, "+") {
			t.Errorf("shutdownTime(%d) = %q, which shutdown(8) does not understand", seconds, got)
		}
	}
}
