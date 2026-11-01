package models

import "time"

const SchemaVersion = 1

type Scan struct {
	ID            string    `json:"id"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
	TargetCount   int       `json:"target_count"`
	HostCount     int       `json:"host_count"`
	SchemaVersion int       `json:"schema_version"`
}

type Host struct {
	IP        string    `json:"ip"`
	MAC       string    `json:"mac,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	Reachable bool      `json:"reachable"`
	Observed  time.Time `json:"observed_at"`
}

type Service struct {
	HostIP     string        `json:"host_ip"`
	Port       int           `json:"port"`
	Protocol   string        `json:"protocol"`
	State      string        `json:"state"`
	Name       string        `json:"name,omitempty"`
	ObservedAt time.Time     `json:"observed_at"`
	Duration   time.Duration `json:"duration,omitempty"`
}
