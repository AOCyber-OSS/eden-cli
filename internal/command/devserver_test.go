package command

import (
	"strings"
	"testing"
)

func TestLaunchAgentPlistDeclaresNoLaunchdSockets(t *testing.T) {
	plist := launchAgentPlist("/usr/local/bin/eden", "/Users/x/.eden/logs")
	// The daemon binds its own loopback listeners; launchd-held sockets on
	// every interface were never consumed and only widened exposure.
	if strings.Contains(plist, "<key>Sockets</key>") {
		t.Error("LaunchAgent plist declares launchd Sockets")
	}
	for _, want := range []string{"<string>/usr/local/bin/eden</string>", "<string>daemon</string>", "/Users/x/.eden/logs/daemon.log"} {
		if !strings.Contains(plist, want) {
			t.Errorf("plist missing %q", want)
		}
	}
}

func TestLaunchAgentReloadUnloadsBeforeLoading(t *testing.T) {
	// `launchctl load` on an already-loaded job fails and leaves the old
	// daemon process (and the old plist) running, so an upgrade would keep
	// the pre-fix all-interface listener until logout. Setup must unload
	// first so the new binary and plist take effect.
	got := launchAgentReloadCmds("/Users/x/Library/LaunchAgents/com.eden.dev.plist")
	if len(got) != 2 {
		t.Fatalf("got %d commands, want unload then load: %v", len(got), got)
	}
	want := [][]string{
		{"launchctl", "unload", "/Users/x/Library/LaunchAgents/com.eden.dev.plist"},
		{"launchctl", "load", "/Users/x/Library/LaunchAgents/com.eden.dev.plist"},
	}
	for i := range want {
		if strings.Join(got[i], " ") != strings.Join(want[i], " ") {
			t.Errorf("command %d = %v, want %v", i, got[i], want[i])
		}
	}
}
