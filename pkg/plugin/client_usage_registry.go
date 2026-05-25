package plugin

import "strings"

type clientUsageObserverRegistrarEndpoint struct {
	name      string
	registrar ClientUsageObserverRegistrar
}

type clientUsageObserverEndpoint struct {
	name     string
	observer ClientUsageObserver
}

type clientUsageObserverWire struct {
	registrar ClientUsageObserverRegistrar
	observer  ClientUsageObserver
}

// WireClientUsageObservers connects registered usage observers to registered
// auth plugins that publish usage events. It is safe to call after loading
// enterprise plugins; each registrar-observer pair is wired at most once.
func (r *Registry) WireClientUsageObservers() {
	for _, wire := range r.clientUsageObserverWiresToRegister() {
		wire.registrar.RegisterClientUsageObserver(wire.observer)
	}
}

func (r *Registry) clientUsageObserverWiresToRegister() []clientUsageObserverWire {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	registrars, observers := r.clientUsageObserverEndpointsLocked()
	wires := make([]clientUsageObserverWire, 0)
	for _, registrar := range registrars {
		for _, observer := range observers {
			if samePlugin(registrar.registrar, observer.observer) {
				continue
			}
			if r.hasClientUsageObserverWireLocked(registrar.name, observer.name) {
				continue
			}
			r.markClientUsageObserverWireLocked(registrar.name, observer.name)
			wires = append(wires, clientUsageObserverWire{
				registrar: registrar.registrar,
				observer:  observer.observer,
			})
		}
	}
	return wires
}

func (r *Registry) clientUsageObserverEndpointsLocked() ([]clientUsageObserverRegistrarEndpoint, []clientUsageObserverEndpoint) {
	registrars := make([]clientUsageObserverRegistrarEndpoint, 0)
	observers := make([]clientUsageObserverEndpoint, 0)
	for name, p := range r.plugins {
		if registrar, ok := p.(ClientUsageObserverRegistrar); ok {
			registrars = append(registrars, clientUsageObserverRegistrarEndpoint{name: normalizedPluginName(name), registrar: registrar})
		}
		if observer, ok := p.(ClientUsageObserver); ok {
			observers = append(observers, clientUsageObserverEndpoint{name: normalizedPluginName(name), observer: observer})
		}
	}
	return registrars, observers
}

func (r *Registry) hasClientUsageObserverWireLocked(registrarName, observerName string) bool {
	if r.clientUsageObserverWires == nil {
		return false
	}
	observers, ok := r.clientUsageObserverWires[registrarName]
	if !ok {
		return false
	}
	_, ok = observers[observerName]
	return ok
}

func (r *Registry) markClientUsageObserverWireLocked(registrarName, observerName string) {
	if r.clientUsageObserverWires == nil {
		r.clientUsageObserverWires = make(map[string]map[string]struct{})
	}
	if _, ok := r.clientUsageObserverWires[registrarName]; !ok {
		r.clientUsageObserverWires[registrarName] = make(map[string]struct{})
	}
	r.clientUsageObserverWires[registrarName][observerName] = struct{}{}
}

func samePlugin(left, right Plugin) bool {
	leftName := normalizedPluginName(left.Name())
	rightName := normalizedPluginName(right.Name())
	return leftName != "" && strings.EqualFold(leftName, rightName)
}

func normalizedPluginName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
