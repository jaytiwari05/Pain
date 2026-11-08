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
	ModuleObject *ModuleExtender
	ModuleDir    string
)

// InitPlugin is the only exported symbol - Adaptix loads it from the .so.
func InitPlugin(ts any, moduleDir string, listenerDir string) ax.PluginListener {
	ModuleDir = moduleDir
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

	listener := &SMBListener{Name: name, Config: cfg}
	listenerData := ax.ListenerData{
		Name:      name,
		Protocol:  "SMB",
		BindHost:  "",
		BindPort:  "",
		AgentAddr: cfg.Addresses,
	}

	saved, _ := json.Marshal(cfg)
	return listener, listenerData, saved, nil
}

// Call handles operator→listener RPC - not needed yet.
func (pl *PluginListener) Call(operator string, listenerName string, function string, args string) {
}

// Edit updates the listener config at runtime.
func (l *SMBListener) Edit(config string) (ax.ListenerData, []byte, error) {
	var cfg ListenerConfig
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		return ax.ListenerData{}, nil, err
	}
	l.Config = cfg
	listenerData := ax.ListenerData{
		Name:      l.Name,
		Protocol:  "SMB",
		BindHost:  "",
		BindPort:  "",
		AgentAddr: cfg.Addresses,
	}
	saved, _ := json.Marshal(cfg)
	return listenerData, saved, nil
}

// Start is a no-op for SMB - there is no port to bind.
// All data arrives through InternalHandler forwarded by parent HTTP beacons.
func (l *SMBListener) Start() error {
	fmt.Printf("[Pain SMB Listener] %s started (pipe: %s)\n", l.Name, l.Config.PipeName)
	return nil
}

// Stop is a no-op - nothing to unbind.
func (l *SMBListener) Stop() error {
	fmt.Printf("[Pain SMB Listener] %s stopped\n", l.Name)
	return nil
}

// GetProfile returns the saved config bytes so Adaptix can restore after restart.
func (l *SMBListener) GetProfile() ([]byte, error) {
	return json.Marshal(l.Config)
}

// InternalHandler receives child agent data forwarded from a parent HTTP beacon.
// Wire format expected from the parent: [36B child UUID][payload]
//   - New child (UUID not known): payload is the checkin blob → TsAgentCreate
//   - Known child: payload is task results → TsAgentProcessData
func (l *SMBListener) InternalHandler(data []byte) (int64, error) {
	return smbInternalHandler(l, data)
}

func main() {}
