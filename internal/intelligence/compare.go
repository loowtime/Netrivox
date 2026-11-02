package intelligence

import (
	"sort"
	"strconv"

	"github.com/loowtime/netrivox/pkg/models"
)

type Change struct {
	Type    string `json:"type"`
	Target  string `json:"target"`
	Details string `json:"details"`
}

func Compare(previous, current models.ScanResult) []Change {
	changes := make([]Change, 0)
	oldHosts := make(map[string]models.Host, len(previous.Hosts))
	newHosts := make(map[string]models.Host, len(current.Hosts))
	for _, host := range previous.Hosts {
		oldHosts[host.IP] = host
	}
	for _, host := range current.Hosts {
		newHosts[host.IP] = host
	}
	for ip, host := range newHosts {
		old, ok := oldHosts[ip]
		if !ok {
			changes = append(changes, Change{"host_added", ip, "host appeared"})
		} else if old.Reachable != host.Reachable {
			changes = append(changes, Change{"host_status_changed", ip, status(old.Reachable, host.Reachable)})
		}
	}
	for ip := range oldHosts {
		if _, ok := newHosts[ip]; !ok {
			changes = append(changes, Change{"host_removed", ip, "host no longer present"})
		}
	}
	serviceKey := func(service models.Service) string {
		return service.HostIP + ":" + strconv.Itoa(service.Port) + "/" + service.Protocol
	}
	oldServices := make(map[string]models.Service, len(previous.Services))
	newServices := make(map[string]models.Service, len(current.Services))
	for _, service := range previous.Services {
		oldServices[serviceKey(service)] = service
	}
	for _, service := range current.Services {
		newServices[serviceKey(service)] = service
	}
	for key, service := range newServices {
		old, ok := oldServices[key]
		if !ok && service.State == "open" {
			changes = append(changes, Change{"service_opened", key, service.Name})
		} else if ok && old.State != service.State {
			changes = append(changes, Change{"service_state_changed", key, old.State + " -> " + service.State})
		}
	}
	for key, service := range oldServices {
		if _, ok := newServices[key]; !ok && service.State == "open" {
			changes = append(changes, Change{"service_removed", key, service.Name})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Type != changes[j].Type {
			return changes[i].Type < changes[j].Type
		}
		return changes[i].Target < changes[j].Target
	})
	return changes
}

func status(old, current bool) string {
	if current {
		return "unreachable -> reachable"
	}
	return "reachable -> unreachable"
}
