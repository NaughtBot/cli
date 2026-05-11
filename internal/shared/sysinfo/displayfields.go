package sysinfo

import (
	payloads "github.com/naughtbot/e2ee-payloads/go"
)

// ToSourceInfo converts ProcessInfo into a payloads.SourceInfo struct suitable
// for inclusion in any CLI-originated request payload.
func (p ProcessInfo) ToSourceInfo() *payloads.SourceInfo {
	si := &payloads.SourceInfo{
		Hostname: &p.Hostname,
		LocalIp:  &p.LocalIP,
		Username: &p.Username,
		Command:  &p.Command,
	}
	if len(p.ProcessChain) > 0 {
		chain := make([]payloads.ProcessEntry, len(p.ProcessChain))
		for i, e := range p.ProcessChain {
			chain[i] = payloads.ProcessEntry{
				Pid:      int32(e.PID),
				Username: e.Username,
				Command:  e.Command,
			}
		}
		si.ProcessChain = &chain
	}
	return si
}
