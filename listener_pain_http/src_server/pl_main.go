package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	ax "github.com/Adaptix-Framework/axc2/v2"
)

// ListenerConfig is what the operator fills in the Adaptix UI when creating a Listener
type ListenerConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	AgentCrc string `json:"agent_crc"`
	Ssl      bool   `json:"ssl"`
	CertFile string `json:"ssl_cert"`
	KeyFile  string `json:"ssl_key"`
}

// Teamserver interface - only the v2 methods the Listener actually calls
type Teamserver interface {
	TsAgentIdByUID(uid []byte) (int64, bool)
	TsAgentCreate(agentCrc string, agentUid []byte, beat []byte, ListenerName string, ExternalIP string, Async bool) (ax.AgentData, error)
	TsAgentSetTick(agentId int64, listenerName string) error
	TsAgentProcessData(agentId int64, bodyData []byte) error
	TsAgentGetHostedAll(agentId int64, maxDataSize int) ([]byte, ax.StatTasks, error)
}

// PlugicListener is the single instance returned to Adaptix from InitPlugin
type PluginListener struct{}

// HTTPListener owns one running HTTP server - one per Listener the operator creates
type HTTPListener struct {
	Name   string
	Config ListenerConfig
	server *http.Server
}

// ModuleExtender group the teamserver handle and the plugin object
type ModuleExtender struct {
	ts Teamserver
	pl *PluginListener
}

var (
	ModuleObject    *ModuleExtender
	ModuleDir       string
	ListenerDataDir string
)

// InitPlugin is the only exported symbol - Adaptix loads it from the .so
func InitPlugin(ts any, moduleDir string, listenerDir string) ax.PluginListener {
	ModuleDir = moduleDir
	ListenerDataDir = listenerDir
	ModuleObject = &ModuleExtender{
		ts: ts.(Teamserver),
		pl: &PluginListener{},
	}
	return ModuleObject.pl
}

// Create is called when the operator clicks "New Listener" in the Adaptix UI
// config is JSON from UI form, customData is non-nil on server restart (restore)
func (pl *PluginListener) Create(name, config string, customData []byte) (ax.ExtenderListener, ax.ListenerData, []byte, error) {
	var cfg ListenerConfig

	src := config
	if customData != nil {
		src = string(customData)
	}
	if err := json.Unmarshal([]byte(src), &cfg); err != nil {
		return nil, ax.ListenerData{}, nil, err
	}

	listener := &HTTPListener{Name: name, Config: cfg}

	scheme, proto := schemeProto(cfg.Ssl)
	listenerData := ax.ListenerData{
		Name:      name,
		Protocol:  proto,
		BindHost:  cfg.Host,
		BindPort:  fmt.Sprintf("%d", cfg.Port),
		AgentAddr: fmt.Sprintf("%s://%s:%d", scheme, cfg.Host, cfg.Port),
	}

	saved, _ := json.Marshal(cfg)
	return listener, listenerData, saved, nil
}

// Call handles operator->listener RPC - not needed yet
func (pl *PluginListener) Call(operator string, listenerName string, function string, args string) {}

// Edit updates the listener config at runtime
func (l *HTTPListener) Edit(config string) (ax.ListenerData, []byte, error) {
	var cfg ListenerConfig
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		return ax.ListenerData{}, nil, err
	}
	l.Config = cfg
	scheme, proto := schemeProto(cfg.Ssl)
	listenerData := ax.ListenerData{
		Name:      l.Name,
		Protocol:  proto,
		BindHost:  cfg.Host,
		BindPort:  fmt.Sprintf("%d", cfg.Port),
		AgentAddr: fmt.Sprintf("%s://%s:%d", scheme, cfg.Host, cfg.Port),
	}
	saved, _ := json.Marshal(cfg)
	return listenerData, saved, nil
}

func schemeProto(ssl bool) (string, string) {
	if ssl {
		return "https", "HTTPS"
	}
	return "http", "HTTP"
}

// Stop shuts the HTTP server down
func (l *HTTPListener) Stop() error {
	if l.server != nil {
		return l.server.Close()
	}
	return nil
}

// GetProfile return the saved config bytes so Adaptix can restore it after restart
func (l *HTTPListener) GetProfile() ([]byte, error) {
	return json.Marshal(l.Config)
}

// InternalHandler is for listener-to-listener communication - not used
func (l *HTTPListener) InternalHandler(data []byte) (int64, error) {
	return 0, nil
}

// Start is called by Adaptix after Create - this is where we sping up the HTTP server
// (body goes in pl_listener.go)
func (l *HTTPListener) Start() error {
	return l.startHTTP()
}

func main() {}
