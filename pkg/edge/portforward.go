package edge

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// splitHostPortColon splits "a:b:c:d" on colons that are not inside square
// brackets, so an IPv6 literal in either half survives intact.
//
//	"0.0.0.0:1080:100.64.0.4:1080" -> ["0.0.0.0", "1080", "100.64.0.4", "1080"]
//	"[::1]:1080:100.64.0.4:1080"  -> ["[::1]", "1080", "100.64.0.4", "1080"]
//	"0.0.0.0:1080:[::1]:1080"     -> ["0.0.0.0", "1080", "[::1]", "1080"]
func splitColonSegments(s string) ([]string, error) {
	var segs []string
	var cur strings.Builder
	inBracket := false
	for _, r := range s {
		switch {
		case r == '[':
			if inBracket {
				return nil, fmt.Errorf("nested '[' in %q", s)
			}
			inBracket = true
			cur.WriteRune(r)
		case r == ']':
			if !inBracket {
				return nil, fmt.Errorf("unmatched ']' in %q", s)
			}
			inBracket = false
			cur.WriteRune(r)
		case r == ':' && !inBracket:
			segs = append(segs, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if inBracket {
		return nil, fmt.Errorf("unterminated '[' in %q", s)
	}
	segs = append(segs, cur.String())
	return segs, nil
}

// ParsePortForwardSpec decodes one -L / -R entry of the form
// "BIND:PORT:TARGET:TPORT[/proto]".
//
// The bind part uses the same address grammar as ParseListenAddr (bare port,
// omitted address, bracketed IPv6), and the target is a plain "host:port"
// that is handed to net.Dial as-is. proto is "tcp" by default and "udp" for
// stateless forwarding; anything else is rejected at parse time rather than
// at dial time.
func ParsePortForwardSpec(spec string) (PortForwardSpec, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return PortForwardSpec{}, fmt.Errorf("empty port forward specification")
	}

	proto := "tcp"
	if i := strings.LastIndex(spec, "/"); i >= 0 {
		proto = strings.ToLower(spec[i+1:])
		spec = spec[:i]
	}
	switch proto {
	case "tcp", "udp":
	default:
		return PortForwardSpec{}, fmt.Errorf("invalid protocol %q (want tcp or udp)", proto)
	}

	segs, err := splitColonSegments(spec)
	if err != nil {
		return PortForwardSpec{}, fmt.Errorf("invalid port forward %q: %w", spec, err)
	}
	if len(segs) != 4 {
		return PortForwardSpec{}, fmt.Errorf(
			"invalid port forward %q: want BIND:PORT:TARGET:TPORT, got %d field(s)", spec, len(segs))
	}

	bindAddr, err := ParseListenAddr(strings.Join(segs[:2], ":"), "0.0.0.0", "0")
	if err != nil {
		return PortForwardSpec{}, fmt.Errorf("invalid port forward %q: %w", spec, err)
	}
	// ParseListenAddr normalises to "host:port"; split it back out.
	bh, bpStr, err := net.SplitHostPort(bindAddr)
	if err != nil {
		return PortForwardSpec{}, fmt.Errorf("invalid port forward %q: %w", spec, err)
	}
	bindPort, err := strconv.Atoi(bpStr)
	if err != nil || bindPort < 1 || bindPort > 65535 {
		return PortForwardSpec{}, fmt.Errorf("invalid port forward %q: bind port %q out of range 1-65535", spec, bpStr)
	}

	tport, err := strconv.Atoi(segs[3])
	if err != nil || tport < 1 || tport > 65535 {
		return PortForwardSpec{}, fmt.Errorf("invalid port forward %q: target port %q out of range 1-65535", spec, segs[3])
	}

	return PortForwardSpec{
		BindAddr: bh,
		BindPort: bindPort,
		Target:   net.JoinHostPort(segs[2], segs[3]),
		Proto:    proto,
	}, nil
}

// String renders the spec back into the canonical -L / -R form, which is what
// the flag prints when the operator asks what they actually asked for.
func (f PortForwardSpec) String() string {
	s := fmt.Sprintf("%s:%d:%s", f.BindAddr, f.BindPort, f.Target)
	if f.Proto != "tcp" {
		s += "/" + f.Proto
	}
	return s
}