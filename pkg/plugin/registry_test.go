package plugin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type registryTestPlugin struct {
	name string
}

func (p registryTestPlugin) Name() string {
	return p.name
}

func (p registryTestPlugin) Initialize(map[string]interface{}) error {
	return nil
}

type registryTestMiddlewarePlugin struct {
	registryTestPlugin
}

func (p registryTestMiddlewarePlugin) Middleware(next http.Handler) http.Handler {
	return next
}

type registryTestTypedPlugin struct {
	registryTestPlugin
	pType PluginType
}

func (p registryTestTypedPlugin) Type() PluginType {
	return p.pType
}

type registryTestLegacyTypedPlugin struct {
	registryTestPlugin
	typeName string
}

func (p registryTestLegacyTypedPlugin) Type() string {
	return p.typeName
}

type registryTestManagedPlugin struct {
	registryTestPlugin
	calls *[]string
}

func (p *registryTestManagedPlugin) Initialize(map[string]interface{}) error {
	*p.calls = append(*p.calls, "initialize:"+p.name)
	return nil
}

func (p *registryTestManagedPlugin) OnStart() error {
	*p.calls = append(*p.calls, "start:"+p.name)
	return nil
}

func (p *registryTestManagedPlugin) OnShutdown() error {
	*p.calls = append(*p.calls, "shutdown:"+p.name)
	return nil
}

func (p *registryTestManagedPlugin) Reload(map[string]interface{}) error {
	*p.calls = append(*p.calls, "reload:"+p.name)
	return nil
}

func (p *registryTestManagedPlugin) Health() error {
	*p.calls = append(*p.calls, "health:"+p.name)
	return nil
}

func (p *registryTestManagedPlugin) Status() string {
	*p.calls = append(*p.calls, "status:"+p.name)
	return "ok"
}

type registryTestTaggedMiddlewarePlugin struct {
	registryTestPlugin
	tags  map[string]string
	calls *[]string
}

func (p registryTestTaggedMiddlewarePlugin) Tags() map[string]string {
	return p.tags
}

func (p registryTestTaggedMiddlewarePlugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*p.calls = append(*p.calls, p.name)
		next.ServeHTTP(w, r)
	})
}

type registryTestNameHookPlugin struct {
	name   string
	onName func()
}

func (p *registryTestNameHookPlugin) Name() string {
	if p.onName != nil {
		p.onName()
	}
	return p.name
}

func (p *registryTestNameHookPlugin) Initialize(map[string]interface{}) error {
	return nil
}

func TestRegistryListIsDeterministicAndIncludesFactories(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterFactory("zeta", func(map[string]interface{}) (Plugin, error) {
		return registryTestPlugin{name: "zeta"}, nil
	})
	for _, name := range []string{"ratelimit", "apikey", "observability"} {
		if err := registry.Register(registryTestPlugin{name: name}); err != nil {
			t.Fatalf("failed to register plugin %s: %v", name, err)
		}
	}

	got := registry.List()
	want := []string{"apikey", "observability", "ratelimit", "zeta"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected deterministic plugin list %v, got %v", want, got)
	}
}

func TestRegistryRegisterRejectsInvalidPlugins(t *testing.T) {
	tests := []struct {
		name   string
		plugin Plugin
		want   string
	}{
		{
			name:   "nil-plugin",
			plugin: nil,
			want:   "plugin is nil",
		},
		{
			name:   "typed-nil-plugin",
			plugin: (*registryTestPlugin)(nil),
			want:   "plugin is nil",
		},
		{
			name:   "empty-name",
			plugin: registryTestPlugin{},
			want:   "plugin name is empty",
		},
		{
			name: "name-panic",
			plugin: &registryTestNameHookPlugin{onName: func() {
				panic("name boom")
			}},
			want: "plugin name panicked",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			registry := NewRegistry()
			err := registry.Register(tc.plugin)
			if err == nil {
				t.Fatal("expected invalid plugin registration to fail")
			}
			if errText := err.Error(); !strings.Contains(errText, tc.want) {
				t.Fatalf("expected error containing %q, got %q", tc.want, errText)
			}
			if got := registry.List(); len(got) != 0 {
				t.Fatalf("expected invalid plugin not to be registered, got %v", got)
			}
		})
	}
}

func TestRegistryFactoryGetDoesNotHoldRegistryLock(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterFactory("lazy", func(map[string]interface{}) (Plugin, error) {
		if err := registry.Register(registryTestPlugin{name: "sidecar"}); err != nil {
			return nil, err
		}
		return registryTestPlugin{name: "lazy"}, nil
	})

	done := make(chan error, 1)
	go func() {
		_, err := registry.Get("lazy")
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected lazy plugin load to succeed, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("factory load appears to hold the registry lock while invoking factory code")
	}

	if _, err := registry.Get("sidecar"); err != nil {
		t.Fatalf("expected factory to register sidecar plugin, got %v", err)
	}
}

func TestRegistryFactoryGetCoalescesConcurrentLoads(t *testing.T) {
	registry := NewRegistry()
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var callsMu sync.Mutex
	calls := 0

	registry.RegisterFactory("lazy", func(map[string]interface{}) (Plugin, error) {
		callsMu.Lock()
		calls++
		callsMu.Unlock()
		once.Do(func() { close(started) })
		<-release
		return registryTestPlugin{name: "lazy"}, nil
	})

	const callers = 8
	var wg sync.WaitGroup
	ready := make(chan struct{})
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ready
			p, err := registry.Get("lazy")
			if err != nil {
				errs <- err
				return
			}
			if p == nil || p.Name() != "lazy" {
				errs <- fmt.Errorf("unexpected plugin %v", p)
			}
		}()
	}
	close(ready)

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("factory did not start")
	}
	time.Sleep(25 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("expected concurrent factory get to succeed, got %v", err)
		}
	}
	callsMu.Lock()
	defer callsMu.Unlock()
	if calls != 1 {
		t.Fatalf("expected one coalesced factory call, got %d", calls)
	}
}

func TestRegistryFactoryGetRejectsInvalidFactories(t *testing.T) {
	tests := []struct {
		name    string
		factory Factory
		want    string
	}{
		{
			name:    "nil-factory",
			factory: nil,
			want:    "factory is nil",
		},
		{
			name: "factory-error",
			factory: func(map[string]interface{}) (Plugin, error) {
				return registryTestPlugin{name: "partial"}, fmt.Errorf("load failed")
			},
			want: "load failed",
		},
		{
			name: "nil-plugin",
			factory: func(map[string]interface{}) (Plugin, error) {
				return nil, nil
			},
			want: "factory returned nil plugin",
		},
		{
			name: "empty-name-plugin",
			factory: func(map[string]interface{}) (Plugin, error) {
				return registryTestPlugin{}, nil
			},
			want: "plugin name is empty",
		},
		{
			name: "name-panic-plugin",
			factory: func(map[string]interface{}) (Plugin, error) {
				return &registryTestNameHookPlugin{onName: func() {
					panic("name boom")
				}}, nil
			},
			want: "plugin name panicked",
		},
		{
			name: "panic",
			factory: func(map[string]interface{}) (Plugin, error) {
				panic("factory boom")
			},
			want: "factory panicked",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			registry := NewRegistry()
			registry.RegisterFactory(tc.name, tc.factory)

			plugin, err := registry.Get(tc.name)
			if err == nil {
				t.Fatalf("expected invalid factory error, got plugin %v", plugin)
			}
			if plugin != nil {
				t.Fatalf("expected invalid factory not to return a plugin, got %v", plugin)
			}
			if errText := err.Error(); !strings.Contains(errText, tc.want) {
				t.Fatalf("expected error containing %q, got %q", tc.want, errText)
			}
			if _, err := registry.Get(tc.name); err == nil {
				t.Fatalf("expected invalid factory to remain uncached")
			}
		})
	}
}

func TestGlobalRegisteredPluginsSnapshotIsDeterministic(t *testing.T) {
	withGlobalPlugins(t, map[string]Plugin{
		"zeta":  registryTestPlugin{name: "zeta"},
		"alpha": registryTestPlugin{name: "alpha"},
		"mid":   registryTestPlugin{name: "mid"},
	})

	got := registeredNames(globalRegisteredPluginsSnapshot())
	want := []string{"alpha", "mid", "zeta"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected deterministic global plugin snapshot %v, got %v", want, got)
	}
}

func TestRegisterAllGlobalDoesNotHoldGlobalLockDuringRegistryRegister(t *testing.T) {
	registry := NewRegistry()
	sidecarRegistered := make(chan struct{})
	var once sync.Once
	withGlobalPlugins(t, map[string]Plugin{
		"lazy": &registryTestNameHookPlugin{
			name: "lazy",
			onName: func() {
				once.Do(func() {
					RegisterGlobal(registryTestPlugin{name: "sidecar"})
					close(sidecarRegistered)
				})
			},
		},
	})

	done := make(chan struct{})
	go func() {
		registry.RegisterAllGlobal()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("global registration appears to hold the global plugin lock while registering plugins")
	}
	select {
	case <-sidecarRegistered:
	default:
		t.Fatal("expected plugin Name hook to register sidecar global plugin")
	}
	if got := registry.List(); !reflect.DeepEqual(got, []string{"lazy"}) {
		t.Fatalf("expected RegisterAllGlobal to register the initial snapshot only, got %v", got)
	}
}

func TestRegistryBulkOperationsUseDeterministicSnapshots(t *testing.T) {
	registry := NewRegistry()
	var calls []string
	for _, name := range []string{"zeta", "alpha", "middle"} {
		if err := registry.Register(&registryTestManagedPlugin{
			registryTestPlugin: registryTestPlugin{name: name},
			calls:              &calls,
		}); err != nil {
			t.Fatalf("failed to register plugin %s: %v", name, err)
		}
	}

	if err := registry.Initialize(nil); err != nil {
		t.Fatalf("failed to initialize plugins: %v", err)
	}
	if err := registry.StartAll(); err != nil {
		t.Fatalf("failed to start plugins: %v", err)
	}
	if err := registry.ReloadAll(map[string]map[string]interface{}{
		"alpha":  {},
		"middle": {},
		"zeta":   {},
	}); err != nil {
		t.Fatalf("failed to reload plugins: %v", err)
	}
	registry.HealthCheck()
	registry.PluginStatuses()
	if err := registry.ShutdownAll(); err != nil {
		t.Fatalf("failed to shutdown plugins: %v", err)
	}

	want := []string{
		"initialize:alpha", "initialize:middle", "initialize:zeta",
		"start:alpha", "start:middle", "start:zeta",
		"reload:alpha", "reload:middle", "reload:zeta",
		"health:alpha", "health:middle", "health:zeta",
		"status:alpha", "status:middle", "status:zeta",
		"shutdown:alpha", "shutdown:middle", "shutdown:zeta",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("expected deterministic bulk operation calls %v, got %v", want, calls)
	}
}

func TestRegistryGetByTypeSupportsTypedAndLegacyPlugins(t *testing.T) {
	registry := NewRegistry()
	plugins := []Plugin{
		registryTestLegacyTypedPlugin{
			registryTestPlugin: registryTestPlugin{name: "zeta-auth"},
			typeName:           string(AuthPlugin),
		},
		registryTestLegacyTypedPlugin{
			registryTestPlugin: registryTestPlugin{name: "transformer"},
			typeName:           string(TransformPlugin),
		},
		registryTestTypedPlugin{
			registryTestPlugin: registryTestPlugin{name: "apikey"},
			pType:              AuthPlugin,
		},
	}
	for _, p := range plugins {
		if err := registry.Register(p); err != nil {
			t.Fatalf("failed to register plugin %s: %v", p.Name(), err)
		}
	}

	got := pluginNames(registry.GetByType(AuthPlugin))
	want := []string{"apikey", "zeta-auth"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected deterministic auth plugin list %v, got %v", want, got)
	}
}

func pluginNames(plugins []Plugin) []string {
	names := make([]string, 0, len(plugins))
	for _, p := range plugins {
		names = append(names, p.Name())
	}
	return names
}

func registeredNames(plugins []registeredPlugin) []string {
	names := make([]string, 0, len(plugins))
	for _, p := range plugins {
		names = append(names, p.name)
	}
	return names
}

func withGlobalPlugins(t *testing.T, plugins map[string]Plugin) {
	t.Helper()

	globalPluginsMu.Lock()
	previous := globalPlugins
	globalPlugins = plugins
	globalPluginsMu.Unlock()

	t.Cleanup(func() {
		globalPluginsMu.Lock()
		globalPlugins = previous
		globalPluginsMu.Unlock()
	})
}

func TestRegistryListMiddlewarePluginsIsDeterministic(t *testing.T) {
	registry := NewRegistry()
	for _, name := range []string{"transform", "apikey", "cors"} {
		if err := registry.Register(registryTestMiddlewarePlugin{registryTestPlugin{name: name}}); err != nil {
			t.Fatalf("failed to register plugin %s: %v", name, err)
		}
	}

	got := registry.ListMiddlewarePlugins()
	want := []string{"apikey", "cors", "transform"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected deterministic middleware plugin list %v, got %v", want, got)
	}
}

func TestRegistryBuildMiddlewareChainFromTagsIsDeterministic(t *testing.T) {
	registry := NewRegistry()
	var calls []string
	for _, name := range []string{"zeta", "alpha", "middle"} {
		if err := registry.Register(registryTestTaggedMiddlewarePlugin{
			registryTestPlugin: registryTestPlugin{name: name},
			tags:               map[string]string{"security": "authentication"},
			calls:              &calls,
		}); err != nil {
			t.Fatalf("failed to register plugin %s: %v", name, err)
		}
	}

	handler, err := registry.BuildMiddlewareChainFromTags("security", "authentication", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls = append(calls, "final")
	}))
	if err != nil {
		t.Fatalf("failed to build middleware chain: %v", err)
	}
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	want := []string{"alpha", "middle", "zeta", "final"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("expected deterministic tagged middleware calls %v, got %v", want, calls)
	}
}
