package main

import (
	"net/http"
	"sync"
)

// OutputConfig describes how data is encoded in one direction
// (server→agent or agent→server) for a single URI.
type OutputConfig struct {
	Mask      bool   // XOR the encoded bytes with a derived key
	Header    string // put data in this response/request header name
	Format    string // "base64" | "base64url" | "hex" | "base32" | "raw"
	Parameter string // put data in this URL query parameter
	Cookie    string // put data in this cookie name
	Body      string // static body to send alongside header/cookie output

	Append  string // suffix to strip (from client) / add (to server) around the data
	Prepend string // prefix to strip (from client) / add (to server) around the data

	MaxDataSize int
}

// URIConfig holds the encode/decode rules for one registered URI path.
type URIConfig struct {
	ServerOutput *OutputConfig
	ClientOutput *OutputConfig
	ClientParams []map[string]interface{}
}

// ServerError is what the listener returns when it rejects a bad request.
// Using a realistic error page keeps scanners from flagging the C2 endpoint.
type ServerError struct {
	Status   int
	Response string
	Headers  map[string]string
}

// HTTPMethod groups everything the listener knows about one HTTP verb (GET or POST).
type HTTPMethod struct {
	ServerHeaders map[string]string    // headers added to every response
	EmptyResponse []byte               // body when there is no task to send
	ClientHeaders map[string]string    // headers the agent MUST include
	URI           map[string]URIConfig // path → encoding config
}

// Callback is one "persona" - one C2 host with its own user-agent,
// error page, and GET/POST config.
type Callback struct {
	Hosts     []string
	Host      string
	UserAgent string
	SrvError  *ServerError
	Get       *HTTPMethod
	Post      *HTTPMethod
}

// ListenerConfig is serialised to JSON and stored by Adaptix.
// Field names MUST match the container.put() keys in ax_config.axs.
type ListenerConfig struct {
	HostBind string `json:"host_bind"`
	PortBind int    `json:"port_bind"`

	TrustXForwardedHost    bool   `json:"trust_x_forwarded_host"`
	AdditionalTrustedHosts string `json:"additional_trusted_hosts"` // newline-separated

	BlockUserAgents string `json:"block_user_agents"` // newline-separated glob patterns
	ProfileContent  string `json:"uploaded_file"`     // base64 of the JSON profile file

	DomainRotation string `json:"domain_rotation_strategy"` // "Random"|"Round Robin"|"Failover"

	Ssl         bool   `json:"ssl"`
	SslCert     []byte `json:"ssl_cert"`
	SslKey      []byte `json:"ssl_key"`
	SslCertPath string `json:"ssl_cert_path"`
	SslKeyPath  string `json:"ssl_key_path"`

	ProxyUrl      string `json:"proxy_url"`
	ProxyUserName string `json:"proxy_user"`
	ProxyPassword string `json:"proxy_pass"`

	// Populated at Start() by parsing ProfileContent - never serialised.
	Callbacks []Callback `json:"-"`
	Addresses string     `json:"-"` // comma-joined host list from profile
}

// HTTPListener is one running listener instance.
type HTTPListener struct {
	Name   string
	Config ListenerConfig
	server *http.Server
	mu     sync.Mutex
}
