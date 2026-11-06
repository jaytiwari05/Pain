package main

import (
	"encoding/json"
	"fmt"

	ax "github.com/Adaptix-Framework/axc2/v2"
)

// Teamserver interface - only the v2 methods the listener actually calls.
type Teamserver interface {
	TsAgentIdByUID(uid []byte) (int64, bool)
	TsAgentCreate(agentCrc string, agentUid []byte, beat []byte, listenerName string, externalIP string, async bool) (ax.AgentData, error)
	TsAgentSetTick(agentId int64, listenerName string) error
	TsAgentProcessData(agentId int64, bodyData []byte) error
	TsAgentGetHostedAll(agentId int64, maxDataSize int) ([]byte, ax.StatTasks, error)
}

// PluginListener is the single instance returned to Adaptix from InitPlugin.
type PluginListener struct{}

// ModuleExtender groups the teamserver handle and the plugin object.
type ModuleExtender struct {
	ts Teamserver
	pl *PluginListener
}

var (
	ModuleObject    *ModuleExtender
	ModuleDir       string
	ListenerDataDir string
)

// InitPlugin is the only exported symbol - Adaptix loads it from the .so.
func InitPlugin(ts any, moduleDir string, listenerDir string) ax.PluginListener {
	ModuleDir = moduleDir
	ListenerDataDir = listenerDir
	ModuleObject = &ModuleExtender{
		ts: ts.(Teamserver),
		pl: &PluginListener{},
	}
	return ModuleObject.pl
}

// Create is called when the operator clicks "New Listener" in the Adaptix UI.
// config is JSON from the UI form; customData is non-nil on server restart (restore).
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

	_, proto := schemeProto(cfg.Ssl)
	listenerData := ax.ListenerData{
		Name:      name,
		Protocol:  proto,
		BindHost:  cfg.HostBind,
		BindPort:  fmt.Sprintf("%d", cfg.PortBind),
		AgentAddr: cfg.Addresses,
	}

	saved, _ := json.Marshal(cfg)
	return listener, listenerData, saved, nil
}

// Call handles operator→listener RPC - not needed yet.
func (pl *PluginListener) Call(operator string, listenerName string, function string, args string) {
}

// Edit updates the listener config at runtime.
func (l *HTTPListener) Edit(config string) (ax.ListenerData, []byte, error) {
	var cfg ListenerConfig
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		return ax.ListenerData{}, nil, err
	}
	l.Config = cfg
	_, proto := schemeProto(cfg.Ssl)
	listenerData := ax.ListenerData{
		Name:      l.Name,
		Protocol:  proto,
		BindHost:  cfg.HostBind,
		BindPort:  fmt.Sprintf("%d", cfg.PortBind),
		AgentAddr: cfg.Addresses,
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

// Stop shuts the HTTP server down.
func (l *HTTPListener) Stop() error {
	if l.server != nil {
		return l.server.Close()
	}
	return nil
}

// GetProfile returns the saved config bytes so Adaptix can restore after restart.
func (l *HTTPListener) GetProfile() ([]byte, error) {
	return json.Marshal(l.Config)
}

// InternalHandler is for listener-to-listener communication - not used.
func (l *HTTPListener) InternalHandler(data []byte) (int64, error) {
	return 0, nil
}

// Start is called by Adaptix after Create - spins up the HTTP server.
func (l *HTTPListener) Start() error {
	return l.startHTTP()
}

func main() {}
