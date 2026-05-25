package plugin

import (
	"context"
	"testing"
)

func TestRegistryWiresClientUsageObservers(t *testing.T) {
	registry := NewRegistry()
	registrar := &recordingClientUsageRegistrar{name: "apikey"}
	observer := &recordingClientUsageObserver{name: "billing"}

	if err := registry.Register(registrar); err != nil {
		t.Fatalf("failed to register usage registrar: %v", err)
	}
	if err := registry.Register(observer); err != nil {
		t.Fatalf("failed to register usage observer: %v", err)
	}

	registry.WireClientUsageObservers()

	if len(registrar.observers) != 1 || registrar.observers[0].Name() != "billing" {
		t.Fatalf("expected billing observer to be wired, got %+v", registrar.observers)
	}
}

func TestRegistryDoesNotWireClientUsageObserverToItself(t *testing.T) {
	registry := NewRegistry()
	combined := &recordingClientUsageRegistrar{name: "billing"}

	if err := registry.Register(combined); err != nil {
		t.Fatalf("failed to register combined plugin: %v", err)
	}

	registry.WireClientUsageObservers()

	if len(combined.observers) != 0 {
		t.Fatalf("expected self observer to be skipped, got %+v", combined.observers)
	}
}

func TestRegistryWiresClientUsageObserversOnce(t *testing.T) {
	registry := NewRegistry()
	registrar := &recordingClientUsageRegistrar{name: "apikey"}
	observer := &recordingClientUsageObserver{name: "billing"}

	if err := registry.Register(registrar); err != nil {
		t.Fatalf("failed to register usage registrar: %v", err)
	}
	if err := registry.Register(observer); err != nil {
		t.Fatalf("failed to register usage observer: %v", err)
	}

	registry.WireClientUsageObservers()
	registry.WireClientUsageObservers()
	registry.WireClientUsageObservers()

	if len(registrar.observers) != 1 || registrar.observers[0].Name() != "billing" {
		t.Fatalf("expected billing observer to be wired once, got %+v", registrar.observers)
	}
}

func TestRegistryWiresNewClientUsageObserverAfterPreviousWire(t *testing.T) {
	registry := NewRegistry()
	registrar := &recordingClientUsageRegistrar{name: "apikey"}
	billing := &recordingClientUsageObserver{name: "billing"}
	audit := &recordingClientUsageObserver{name: "audit"}

	if err := registry.Register(registrar); err != nil {
		t.Fatalf("failed to register usage registrar: %v", err)
	}
	if err := registry.Register(billing); err != nil {
		t.Fatalf("failed to register billing observer: %v", err)
	}

	registry.WireClientUsageObservers()

	if err := registry.Register(audit); err != nil {
		t.Fatalf("failed to register audit observer: %v", err)
	}

	registry.WireClientUsageObservers()

	if len(registrar.observers) != 2 {
		t.Fatalf("expected existing and new observers to be wired once, got %+v", registrar.observers)
	}
	names := map[string]bool{}
	for _, observer := range registrar.observers {
		names[observer.Name()] = true
	}
	if !names["billing"] || !names["audit"] {
		t.Fatalf("expected billing and audit observers, got %+v", registrar.observers)
	}
}

type recordingClientUsageRegistrar struct {
	name      string
	observers []ClientUsageObserver
}

func (p *recordingClientUsageRegistrar) Name() string {
	return p.name
}

func (p *recordingClientUsageRegistrar) Initialize(map[string]interface{}) error {
	return nil
}

func (p *recordingClientUsageRegistrar) RegisterClientUsageObserver(observer ClientUsageObserver) {
	p.observers = append(p.observers, observer)
}

func (p *recordingClientUsageRegistrar) ObserveClientUsage(context.Context, ClientUsageEvent) {}

type recordingClientUsageObserver struct {
	name string
}

func (p *recordingClientUsageObserver) Name() string {
	return p.name
}

func (p *recordingClientUsageObserver) Initialize(map[string]interface{}) error {
	return nil
}

func (p *recordingClientUsageObserver) ObserveClientUsage(context.Context, ClientUsageEvent) {}
