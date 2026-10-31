package runbook

// Rules is the machine-readable description of what the system will and will
// not do. It is exposed so operators can audit the posture without reading Go.
type Rules struct {
	// Actions the system performs automatically.
	Automatic []string
	// Actions the system never performs.
	Never []string
}

// DefaultRules returns the defensive posture of this system.
func DefaultRules() Rules {
	return Rules{
		Automatic: []string{
			"read access logs and local TCP state",
			"compute aggregate signals",
			"emit alerts to configured channels",
			"write audit events",
		},
		Never: []string{
			"block or drop network traffic",
			"modify firewall rules",
			"execute shell commands",
			"contact external threat feeds",
			"persist raw client IP addresses",
		},
	}
}

// Render returns a human-readable summary, one item per line.
func (r Rules) Render() string {
	var b []byte
	b = append(b, "Automatic:\n"...)
	for _, s := range r.Automatic {
		b = append(b, "  - "...)
		b = append(b, s...)
		b = append(b, '\n')
	}
	b = append(b, "Never:\n"...)
	for _, s := range r.Never {
		b = append(b, "  - "...)
		b = append(b, s...)
		b = append(b, '\n')
	}
	return string(b)
}