package daemon

import "testing"

func TestDaemonProxyLANExposureFollowsConfig(t *testing.T) {
	def := &Daemon{Config: DefaultConfig(), State: NewState()}
	if def.newProxy(nil, 80, 443).AllowLAN {
		t.Error("default daemon config exposes the proxy on the LAN; it must be loopback only")
	}

	cfg := DefaultConfig()
	cfg.AllowLAN = true
	lan := &Daemon{Config: cfg, State: NewState()}
	if !lan.newProxy(nil, 80, 443).AllowLAN {
		t.Error("Config.AllowLAN did not reach the proxy")
	}
}
