package main

import (
	ax "github.com/Adaptix-Framework/axc2/v2"
)

const (
	CMD_EXIT  = 0x01
	CMD_SHELL = 0x02
	CMD_PWD   = 0x03
	CMD_LS    = 0x04

	OS_WINDOWS = 1

	TYPE_TASK = 1

	MESSAGE_INFO    = 5
	MESSAGE_ERROR   = 6
	MESSAGE_SUCCESS = 7
)

// Teamserver connectivity code

// Teamserver interface
type Teamserver interface {
	TsAgentGenID() int64
	TsTaskUpdate(agentId int64, updateData ax.TaskData)
}

// PluginAgent handles check-in and build - one per agent TYPE (not per agent instance)
type PluginAgent struct{}

// ModuleExtender groups everything the plugin needs at runtime
type ModuleExtender struct {
	ts Teamserver // call back into the teamserver
	pa *PluginAgent
}

// ModuleObject is the Single Global instance of the plugin
// InitPlugin creates it. Every method calls into it
var (
	ModuleObject   *ModuleExtender
	ModuleDir      string
	AgentWatermark string
)

// InitPlugin is the only exported symbol in the plugin
// Adaptix server loads the .so file
// This must return a PluginAgent the implements the as.PluginAgent interface
func InitPlugin(ts any, moduleDir string, watermark string) ax.PluginAgent {
	ModuleDir = moduleDir
	AgentWatermark = watermark

	ModuleObject = &ModuleExtender{
		ts: ts.(Teamserver),
		pa: &PluginAgent{},
	}

	return ModuleObject.pa
}

// AgentRestore is called when the server restarts and reloads a saved agent.
// We return the same function set as a fresh agent.
func (pa *PluginAgent) AgentRestore(agentData ax.AgentData) ax.AgentFunctions {
	return newAgentFunctions()
}

// Call handles custom UI→plugin RPC. Not needed yet.
func (pa *PluginAgent) Call(operator string, agentId int64, function string, args string) {}

// main is required for go build -buildmode-plugin but never called
func main() {}
