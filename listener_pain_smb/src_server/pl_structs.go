package main

// ListenerConfig is serialised to JSON and stored by Adaptix.
// Field names MUST match the container.put() keys in ax_config.axs.
type ListenerConfig struct {
	PipeName  string `json:"pipe_name"` // e.g. \\.\pipe\pain
	Addresses string `json:"addresses"` // shown in Adaptix UI; newline-separated host list
}

// SMBListener is one running SMB listener instance.
// Unlike the HTTP listener, it binds no port - data arrives via InternalHandler.
type SMBListener struct {
	Name   string
	Config ListenerConfig
}
