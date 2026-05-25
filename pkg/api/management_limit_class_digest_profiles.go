package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
)

type limitClassDigestProfileInspection struct {
	WebhookName       string                   `json:"webhook_name"`
	WebhookURL        string                   `json:"webhook_url,omitempty"`
	ProfileName       string                   `json:"profile_name,omitempty"`
	TargetType        string                   `json:"target_type"`
	ProfileChain      []string                 `json:"profile_chain,omitempty"`
	Profile           string                   `json:"profile,omitempty"`
	AppliedProfiles   []map[string]interface{} `json:"applied_profiles"`
	EffectiveProfile  map[string]interface{}   `json:"effective_profile"`
	FieldSources      map[string]string        `json:"field_sources"`
	AvailableProfiles []string                 `json:"available_profiles"`
}

type limitClassDigestProfileDiff struct {
	From          limitClassDigestProfileInspection                `json:"from"`
	To            limitClassDigestProfileInspection                `json:"to"`
	ChangedFields map[string]limitClassDigestProfileFieldDiffEntry `json:"changed_fields"`
}

type limitClassDigestProfileFieldDiffEntry struct {
	FromValue  interface{} `json:"from_value"`
	ToValue    interface{} `json:"to_value"`
	FromSource string      `json:"from_source,omitempty"`
	ToSource   string      `json:"to_source,omitempty"`
}

type limitClassDigestProfileExplanation struct {
	Inspection  limitClassDigestProfileInspection     `json:"inspection"`
	Field       string                                `json:"field"`
	FinalValue  interface{}                           `json:"final_value"`
	FinalSource string                                `json:"final_source,omitempty"`
	Stages      []limitClassDigestProfileExplainStage `json:"stages"`
}

type limitClassDigestProfileExplainStage struct {
	Stage   string      `json:"stage"`
	Source  string      `json:"source"`
	Value   interface{} `json:"value"`
	Changed bool        `json:"changed"`
}

type limitClassDigestProfileExplanationDiff struct {
	Field         string                                             `json:"field"`
	From          limitClassDigestProfileExplanation                 `json:"from"`
	To            limitClassDigestProfileExplanation                 `json:"to"`
	FinalChanged  bool                                               `json:"final_changed"`
	ChangedStages map[string]limitClassDigestProfileExplainDiffStage `json:"changed_stages"`
}

type limitClassDigestProfileExplainDiffStage struct {
	FromValue  interface{} `json:"from_value"`
	ToValue    interface{} `json:"to_value"`
	FromSource string      `json:"from_source,omitempty"`
	ToSource   string      `json:"to_source,omitempty"`
}

type limitClassDigestProfileExplanationBundle struct {
	Inspection   limitClassDigestProfileInspection             `json:"inspection"`
	Bundles      []string                                      `json:"bundles,omitempty"`
	Fields       []string                                      `json:"fields"`
	Explanations map[string]limitClassDigestProfileExplanation `json:"explanations"`
}

type limitClassDigestProfileExplanationBundleDiff struct {
	Bundles                 []string                                          `json:"bundles,omitempty"`
	DiffProfiles            []string                                          `json:"diff_profiles,omitempty"`
	FromRole                string                                            `json:"from_role,omitempty"`
	ToRole                  string                                            `json:"to_role,omitempty"`
	Fields                  []string                                          `json:"fields"`
	From                    limitClassDigestProfileInspection                 `json:"from"`
	To                      limitClassDigestProfileInspection                 `json:"to"`
	FieldDiffs              map[string]limitClassDigestProfileExplanationDiff `json:"field_diffs"`
	ChangedFields           []string                                          `json:"changed_fields"`
	UnexpectedChangedFields []string                                          `json:"unexpected_changed_fields,omitempty"`
	AssertionFailures       []limitClassDigestProfileAssertionFailure         `json:"assertion_failures,omitempty"`
}

type limitClassDigestProfileAssertionFailure struct {
	Side     string      `json:"side"`
	Field    string      `json:"field"`
	Rule     string      `json:"rule,omitempty"`
	Expected interface{} `json:"expected"`
	Actual   interface{} `json:"actual"`
}

type limitClassDigestAssertionGroupResult struct {
	Expected interface{}
	Actual   interface{}
	Passed   bool
}

type limitClassDigestAssertionPresetInspection struct {
	PresetName       string                   `json:"preset_name"`
	PresetChain      []string                 `json:"preset_chain,omitempty"`
	AppliedPresets   []map[string]interface{} `json:"applied_presets"`
	EffectivePreset  map[string]interface{}   `json:"effective_preset"`
	RuleSources      []string                 `json:"rule_sources,omitempty"`
	GroupSources     []string                 `json:"group_sources,omitempty"`
	AvailablePresets []string                 `json:"available_presets"`
}

type limitClassDigestAssertionPresetExplanation struct {
	Inspection limitClassDigestAssertionPresetInspection `json:"inspection"`
	Kind       string                                    `json:"kind"`
	FinalValue interface{}                               `json:"final_value"`
	Stages     []limitClassDigestProfileExplainStage     `json:"stages"`
}

type limitClassDigestAssertionPresetDiff struct {
	From          limitClassDigestAssertionPresetInspection        `json:"from"`
	To            limitClassDigestAssertionPresetInspection        `json:"to"`
	ChangedFields map[string]limitClassDigestProfileFieldDiffEntry `json:"changed_fields"`
}

type limitClassDigestAssertionPresetExplanationDiff struct {
	Kind          string                                             `json:"kind"`
	From          limitClassDigestAssertionPresetExplanation         `json:"from"`
	To            limitClassDigestAssertionPresetExplanation         `json:"to"`
	FinalChanged  bool                                               `json:"final_changed"`
	ChangedStages map[string]limitClassDigestProfileExplainDiffStage `json:"changed_stages"`
}

type limitClassDigestAssertionPresetExplanationBundle struct {
	Inspection   limitClassDigestAssertionPresetInspection             `json:"inspection"`
	Kinds        []string                                              `json:"kinds"`
	Explanations map[string]limitClassDigestAssertionPresetExplanation `json:"explanations"`
}

type limitClassDigestAssertionPresetExplanationBundleDiff struct {
	Bundles                []string                                                  `json:"bundles,omitempty"`
	DiffProfiles           []string                                                  `json:"diff_profiles,omitempty"`
	Kinds                  []string                                                  `json:"kinds"`
	From                   limitClassDigestAssertionPresetInspection                 `json:"from"`
	To                     limitClassDigestAssertionPresetInspection                 `json:"to"`
	KindDiffs              map[string]limitClassDigestAssertionPresetExplanationDiff `json:"kind_diffs"`
	ChangedKinds           []string                                                  `json:"changed_kinds"`
	UnexpectedChangedKinds []string                                                  `json:"unexpected_changed_kinds,omitempty"`
	AssertionFailures      []limitClassDigestProfileAssertionFailure                 `json:"assertion_failures,omitempty"`
}

type limitClassDigestAssertionGroupPresetInspection struct {
	PresetName       string                   `json:"preset_name"`
	PresetChain      []string                 `json:"preset_chain,omitempty"`
	AppliedPresets   []map[string]interface{} `json:"applied_presets"`
	EffectivePreset  map[string]interface{}   `json:"effective_preset"`
	GroupSources     []string                 `json:"group_sources,omitempty"`
	AvailablePresets []string                 `json:"available_presets"`
}

type limitClassDigestAssertionGroupPresetExplanation struct {
	Inspection limitClassDigestAssertionGroupPresetInspection `json:"inspection"`
	Kind       string                                         `json:"kind"`
	FinalValue interface{}                                    `json:"final_value"`
	Stages     []limitClassDigestProfileExplainStage          `json:"stages"`
}

type limitClassDigestAssertionGroupPresetExplanationDiff struct {
	Kind          string                                             `json:"kind"`
	From          limitClassDigestAssertionGroupPresetExplanation    `json:"from"`
	To            limitClassDigestAssertionGroupPresetExplanation    `json:"to"`
	FinalChanged  bool                                               `json:"final_changed"`
	ChangedStages map[string]limitClassDigestProfileExplainDiffStage `json:"changed_stages"`
}

type limitClassDigestAssertionGroupPresetExplanationBundle struct {
	Bundles      []string                                                   `json:"bundles,omitempty"`
	Presets      []string                                                   `json:"presets"`
	Explanations map[string]limitClassDigestAssertionGroupPresetExplanation `json:"explanations"`
}

type limitClassDigestAssertionGroupPresetExplanationBundleDiff struct {
	Bundles        []string                                                       `json:"bundles,omitempty"`
	Presets        []string                                                       `json:"presets"`
	PresetDiffs    map[string]limitClassDigestAssertionGroupPresetExplanationDiff `json:"preset_diffs"`
	ChangedPresets []string                                                       `json:"changed_presets"`
}

func (api *ManagementAPI) getGatewayLimitClassDigestProfile(w http.ResponseWriter, r *http.Request) {
	webhookName := strings.TrimSpace(r.URL.Query().Get("webhook"))
	profileName := strings.TrimSpace(r.URL.Query().Get("profile"))
	if (webhookName == "" && profileName == "") || (webhookName != "" && profileName != "") {
		api.writeManagedError(w, managedRequiredFieldError("exactly one of webhook or profile query parameter is required"), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	inspection, ok := inspectLimitClassDigestTarget(cfg, webhookName, profileName)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "notification webhook or digest profile not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{"inspection": inspection})
}

func (api *ManagementAPI) getGatewayLimitClassDigestAssertionPreset(w http.ResponseWriter, r *http.Request) {
	presetName := strings.TrimSpace(r.URL.Query().Get("preset"))
	if presetName == "" {
		api.writeManagedError(w, managedRequiredFieldError("preset query parameter is required"), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	inspection, ok := inspectLimitClassDigestAssertionPreset(cfg, presetName)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "assertion preset not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{"inspection": inspection})
}

func (api *ManagementAPI) getGatewayLimitClassDigestAssertionGroupPreset(w http.ResponseWriter, r *http.Request) {
	presetName := strings.TrimSpace(r.URL.Query().Get("preset"))
	if presetName == "" {
		api.writeManagedError(w, managedRequiredFieldError("preset query parameter is required"), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	inspection, ok := inspectLimitClassDigestAssertionGroupPreset(cfg, presetName)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "assertion group preset not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{"inspection": inspection})
}

func (api *ManagementAPI) explainGatewayLimitClassDigestAssertionPreset(w http.ResponseWriter, r *http.Request) {
	presetName := strings.TrimSpace(r.URL.Query().Get("preset"))
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	if presetName == "" {
		api.writeManagedError(w, managedRequiredFieldError("preset query parameter is required"), http.StatusBadRequest)
		return
	}
	if kind == "" {
		api.writeManagedError(w, managedRequiredFieldError("kind query parameter is required"), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	explanation, ok := explainLimitClassDigestAssertionPreset(cfg, presetName, kind)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "assertion preset or kind not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{"explanation": explanation})
}

func (api *ManagementAPI) explainGatewayLimitClassDigestAssertionGroupPreset(w http.ResponseWriter, r *http.Request) {
	presetName := strings.TrimSpace(r.URL.Query().Get("preset"))
	if presetName == "" {
		api.writeManagedError(w, managedRequiredFieldError("preset query parameter is required"), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	explanation, ok := explainLimitClassDigestAssertionGroupPreset(cfg, presetName)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "assertion group preset not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{"explanation": explanation})
}

func (api *ManagementAPI) explainGatewayLimitClassDigestAssertionGroupPresetBundle(w http.ResponseWriter, r *http.Request) {
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	bundleNames := normalizeLimitClassDigestExplainFields(r.URL.Query()["bundle"])
	presetNames, ok := resolveLimitClassDigestAssertionGroupPresetExplainBundlePresets(cfg, bundleNames, r.URL.Query()["preset"])
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "one or more requested assertion group preset explain bundles or presets were not found", nil), http.StatusNotFound)
		return
	}
	if len(presetNames) == 0 {
		api.writeManagedError(w, managedRequiredFieldError("at least one preset or bundle query parameter is required"), http.StatusBadRequest)
		return
	}
	bundle, ok := explainLimitClassDigestAssertionGroupPresetBundle(cfg, bundleNames, presetNames)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "one or more requested assertion group presets were not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{"bundle": bundle})
}

func (api *ManagementAPI) diffGatewayLimitClassDigestAssertionGroupPresetExplanationBundle(w http.ResponseWriter, r *http.Request) {
	fromBundleNames := normalizeLimitClassDigestExplainFields(r.URL.Query()["from_bundle"])
	toBundleNames := normalizeLimitClassDigestExplainFields(r.URL.Query()["to_bundle"])
	explicitFromPresets := r.URL.Query()["from_preset"]
	explicitToPresets := r.URL.Query()["to_preset"]
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	fromPresets, ok := resolveLimitClassDigestAssertionGroupPresetExplainBundlePresets(cfg, fromBundleNames, explicitFromPresets)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "one or more requested from_bundle or from_preset entries were not found", nil), http.StatusNotFound)
		return
	}
	toPresets, ok := resolveLimitClassDigestAssertionGroupPresetExplainBundlePresets(cfg, toBundleNames, explicitToPresets)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "one or more requested to_bundle or to_preset entries were not found", nil), http.StatusNotFound)
		return
	}
	if len(fromPresets) == 0 || len(toPresets) == 0 {
		api.writeManagedError(w, managedRequiredFieldError("at least one from_bundle/from_preset and one to_bundle/to_preset query parameter are required"), http.StatusBadRequest)
		return
	}
	diff, ok := explainLimitClassDigestAssertionGroupPresetBundleDiff(cfg, fromBundleNames, fromPresets, toBundleNames, toPresets)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "one or more requested assertion group presets were not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{"diff": diff})
}

func (api *ManagementAPI) diffGatewayLimitClassDigestAssertionPreset(w http.ResponseWriter, r *http.Request) {
	fromPreset := strings.TrimSpace(r.URL.Query().Get("from_preset"))
	toPreset := strings.TrimSpace(r.URL.Query().Get("to_preset"))
	if fromPreset == "" || toPreset == "" {
		api.writeManagedError(w, managedRequiredFieldError("from_preset and to_preset query parameters are required"), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	fromInspection, ok := inspectLimitClassDigestAssertionPreset(cfg, fromPreset)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "from assertion preset not found", nil), http.StatusNotFound)
		return
	}
	toInspection, ok := inspectLimitClassDigestAssertionPreset(cfg, toPreset)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "to assertion preset not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{
		"diff": buildLimitClassDigestAssertionPresetDiff(fromInspection, toInspection),
	})
}

func (api *ManagementAPI) diffGatewayLimitClassDigestAssertionGroupPreset(w http.ResponseWriter, r *http.Request) {
	fromPreset := strings.TrimSpace(r.URL.Query().Get("from_preset"))
	toPreset := strings.TrimSpace(r.URL.Query().Get("to_preset"))
	if fromPreset == "" || toPreset == "" {
		api.writeManagedError(w, managedRequiredFieldError("from_preset and to_preset query parameters are required"), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	fromInspection, ok := inspectLimitClassDigestAssertionGroupPreset(cfg, fromPreset)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "from assertion group preset not found", nil), http.StatusNotFound)
		return
	}
	toInspection, ok := inspectLimitClassDigestAssertionGroupPreset(cfg, toPreset)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "to assertion group preset not found", nil), http.StatusNotFound)
		return
	}
	changedFields := map[string]limitClassDigestProfileFieldDiffEntry{}
	if !reflect.DeepEqual(fromInspection.EffectivePreset["groups"], toInspection.EffectivePreset["groups"]) {
		changedFields["groups"] = limitClassDigestProfileFieldDiffEntry{
			FromValue:  fromInspection.EffectivePreset["groups"],
			ToValue:    toInspection.EffectivePreset["groups"],
			FromSource: "effective",
			ToSource:   "effective",
		}
	}
	api.writeJSON(w, map[string]interface{}{
		"diff": map[string]interface{}{
			"from":           fromInspection,
			"to":             toInspection,
			"changed_fields": changedFields,
		},
	})
}

func (api *ManagementAPI) diffGatewayLimitClassDigestAssertionGroupPresetExplanation(w http.ResponseWriter, r *http.Request) {
	fromPreset := strings.TrimSpace(r.URL.Query().Get("from_preset"))
	toPreset := strings.TrimSpace(r.URL.Query().Get("to_preset"))
	if fromPreset == "" || toPreset == "" {
		api.writeManagedError(w, managedRequiredFieldError("from_preset and to_preset query parameters are required"), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	fromExplanation, ok := explainLimitClassDigestAssertionGroupPreset(cfg, fromPreset)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "from assertion group preset not found", nil), http.StatusNotFound)
		return
	}
	toExplanation, ok := explainLimitClassDigestAssertionGroupPreset(cfg, toPreset)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "to assertion group preset not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{
		"diff": buildLimitClassDigestAssertionGroupPresetExplanationDiff(fromExplanation, toExplanation),
	})
}

func (api *ManagementAPI) diffGatewayLimitClassDigestAssertionPresetExplanation(w http.ResponseWriter, r *http.Request) {
	fromPreset := strings.TrimSpace(r.URL.Query().Get("from_preset"))
	toPreset := strings.TrimSpace(r.URL.Query().Get("to_preset"))
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	if fromPreset == "" || toPreset == "" {
		api.writeManagedError(w, managedRequiredFieldError("from_preset and to_preset query parameters are required"), http.StatusBadRequest)
		return
	}
	if kind == "" {
		api.writeManagedError(w, managedRequiredFieldError("kind query parameter is required"), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	fromExplanation, ok := explainLimitClassDigestAssertionPreset(cfg, fromPreset, kind)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "from assertion preset or kind not found", nil), http.StatusNotFound)
		return
	}
	toExplanation, ok := explainLimitClassDigestAssertionPreset(cfg, toPreset, kind)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "to assertion preset or kind not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{
		"diff": buildLimitClassDigestAssertionPresetExplanationDiff(fromExplanation, toExplanation),
	})
}

func (api *ManagementAPI) explainGatewayLimitClassDigestAssertionPresetBundle(w http.ResponseWriter, r *http.Request) {
	presetName := strings.TrimSpace(r.URL.Query().Get("preset"))
	if presetName == "" {
		api.writeManagedError(w, managedRequiredFieldError("preset query parameter is required"), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	bundleNames := normalizeLimitClassDigestExplainFields(r.URL.Query()["bundle"])
	kinds, ok := resolveLimitClassDigestAssertionExplainKinds(cfg, bundleNames, r.URL.Query()["kind"])
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "one or more requested assertion explain bundles were not found", nil), http.StatusNotFound)
		return
	}
	if len(kinds) == 0 {
		api.writeManagedError(w, managedRequiredFieldError("at least one kind or bundle query parameter is required"), http.StatusBadRequest)
		return
	}
	bundle, ok := explainLimitClassDigestAssertionPresetKinds(cfg, presetName, kinds)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "assertion preset or one of the requested kinds was not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{"bundle": bundle})
}

func (api *ManagementAPI) diffGatewayLimitClassDigestAssertionPresetExplanationBundle(w http.ResponseWriter, r *http.Request) {
	fromPreset := strings.TrimSpace(r.URL.Query().Get("from_preset"))
	toPreset := strings.TrimSpace(r.URL.Query().Get("to_preset"))
	if fromPreset == "" || toPreset == "" {
		api.writeManagedError(w, managedRequiredFieldError("from_preset and to_preset query parameters are required"), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	diffProfileNames := normalizeLimitClassDigestExplainFields(r.URL.Query()["diff_profile"])
	bundleNames, kinds, allowedChangedKinds, expectedFromValues, expectedToValues, assertFromRules, assertToRules, assertFromGroups, assertToGroups, ok := resolveLimitClassDigestAssertionExplainBundleDiffInputs(cfg, diffProfileNames, r.URL.Query()["bundle"], r.URL.Query()["kind"])
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "one or more requested assertion explain bundles or diff profiles were not found", nil), http.StatusNotFound)
		return
	}
	if len(kinds) == 0 {
		api.writeManagedError(w, managedRequiredFieldError("at least one kind, bundle, or diff_profile query parameter is required"), http.StatusBadRequest)
		return
	}
	diff, ok := explainLimitClassDigestAssertionPresetKindBundleDiff(cfg, fromPreset, toPreset, diffProfileNames, bundleNames, kinds, allowedChangedKinds, expectedFromValues, expectedToValues, assertFromRules, assertToRules, assertFromGroups, assertToGroups)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "assertion preset or one of the requested kinds was not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{"diff": diff})
}

func (api *ManagementAPI) diffGatewayLimitClassDigestProfile(w http.ResponseWriter, r *http.Request) {
	fromWebhook := strings.TrimSpace(r.URL.Query().Get("from_webhook"))
	fromProfile := strings.TrimSpace(r.URL.Query().Get("from_profile"))
	toWebhook := strings.TrimSpace(r.URL.Query().Get("to_webhook"))
	toProfile := strings.TrimSpace(r.URL.Query().Get("to_profile"))
	if !hasExactlyOneLimitClassDigestTarget(fromWebhook, fromProfile) || !hasExactlyOneLimitClassDigestTarget(toWebhook, toProfile) {
		api.writeManagedError(w, managedRequiredFieldError("supply exactly one of from_webhook/from_profile and exactly one of to_webhook/to_profile"), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	fromInspection, ok := inspectLimitClassDigestTarget(cfg, fromWebhook, fromProfile)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "from webhook or digest profile not found", nil), http.StatusNotFound)
		return
	}
	toInspection, ok := inspectLimitClassDigestTarget(cfg, toWebhook, toProfile)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "to webhook or digest profile not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{
		"diff": buildLimitClassDigestProfileDiff(fromInspection, toInspection),
	})
}

func (api *ManagementAPI) explainGatewayLimitClassDigestProfile(w http.ResponseWriter, r *http.Request) {
	webhookName := strings.TrimSpace(r.URL.Query().Get("webhook"))
	profileName := strings.TrimSpace(r.URL.Query().Get("profile"))
	fieldName := strings.TrimSpace(r.URL.Query().Get("field"))
	if !hasExactlyOneLimitClassDigestTarget(webhookName, profileName) {
		api.writeManagedError(w, managedRequiredFieldError("exactly one of webhook or profile query parameter is required"), http.StatusBadRequest)
		return
	}
	if fieldName == "" {
		api.writeManagedError(w, managedRequiredFieldError("field query parameter is required"), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	explanation, ok := explainLimitClassDigestTargetField(cfg, webhookName, profileName, fieldName)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "notification webhook, digest profile, or field not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{"explanation": explanation})
}

func (api *ManagementAPI) diffGatewayLimitClassDigestProfileExplanation(w http.ResponseWriter, r *http.Request) {
	fromWebhook := strings.TrimSpace(r.URL.Query().Get("from_webhook"))
	fromProfile := strings.TrimSpace(r.URL.Query().Get("from_profile"))
	toWebhook := strings.TrimSpace(r.URL.Query().Get("to_webhook"))
	toProfile := strings.TrimSpace(r.URL.Query().Get("to_profile"))
	fieldName := strings.TrimSpace(r.URL.Query().Get("field"))
	if !hasExactlyOneLimitClassDigestTarget(fromWebhook, fromProfile) || !hasExactlyOneLimitClassDigestTarget(toWebhook, toProfile) {
		api.writeManagedError(w, managedRequiredFieldError("supply exactly one of from_webhook/from_profile and exactly one of to_webhook/to_profile"), http.StatusBadRequest)
		return
	}
	if fieldName == "" {
		api.writeManagedError(w, managedRequiredFieldError("field query parameter is required"), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	fromExplanation, ok := explainLimitClassDigestTargetField(cfg, fromWebhook, fromProfile, fieldName)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "from webhook, digest profile, or field not found", nil), http.StatusNotFound)
		return
	}
	toExplanation, ok := explainLimitClassDigestTargetField(cfg, toWebhook, toProfile, fieldName)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "to webhook, digest profile, or field not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{
		"diff": buildLimitClassDigestProfileExplanationDiff(fromExplanation, toExplanation),
	})
}

func (api *ManagementAPI) explainGatewayLimitClassDigestProfileBundle(w http.ResponseWriter, r *http.Request) {
	webhookName := strings.TrimSpace(r.URL.Query().Get("webhook"))
	profileName := strings.TrimSpace(r.URL.Query().Get("profile"))
	if !hasExactlyOneLimitClassDigestTarget(webhookName, profileName) {
		api.writeManagedError(w, managedRequiredFieldError("exactly one of webhook or profile query parameter is required"), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	bundleNames := normalizeLimitClassDigestExplainFields(r.URL.Query()["bundle"])
	fields, ok := resolveLimitClassDigestExplainFields(cfg, bundleNames, r.URL.Query()["field"])
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "one or more requested explain bundles were not found", nil), http.StatusNotFound)
		return
	}
	if len(fields) == 0 {
		api.writeManagedError(w, managedRequiredFieldError("at least one field or bundle query parameter is required"), http.StatusBadRequest)
		return
	}
	bundle, ok := explainLimitClassDigestTargetFields(cfg, webhookName, profileName, bundleNames, fields)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "notification webhook, digest profile, or one of the requested fields was not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{"bundle": bundle})
}

func (api *ManagementAPI) diffGatewayLimitClassDigestProfileExplanationBundle(w http.ResponseWriter, r *http.Request) {
	fromWebhook := strings.TrimSpace(r.URL.Query().Get("from_webhook"))
	fromProfile := strings.TrimSpace(r.URL.Query().Get("from_profile"))
	toWebhook := strings.TrimSpace(r.URL.Query().Get("to_webhook"))
	toProfile := strings.TrimSpace(r.URL.Query().Get("to_profile"))
	fromRole := strings.TrimSpace(r.URL.Query().Get("from_role"))
	toRole := strings.TrimSpace(r.URL.Query().Get("to_role"))
	if !hasExactlyOneLimitClassDigestTarget(fromWebhook, fromProfile) || !hasExactlyOneLimitClassDigestTarget(toWebhook, toProfile) {
		api.writeManagedError(w, managedRequiredFieldError("supply exactly one of from_webhook/from_profile and exactly one of to_webhook/to_profile"), http.StatusBadRequest)
		return
	}
	cfg := api.gateway.GetConfig()
	if cfg == nil {
		api.writeManagedError(w, managedConfigError("gateway config unavailable", nil), http.StatusServiceUnavailable)
		return
	}
	diffProfileNames := normalizeLimitClassDigestExplainFields(r.URL.Query()["diff_profile"])
	bundleNames, fields, allowedChangedFields, expectedFromValues, expectedToValues, assertFromRules, assertToRules, assertFromGroups, assertToGroups, expectedFromRole, expectedToRole, ok := resolveLimitClassDigestExplainBundleDiffInputs(cfg, diffProfileNames, r.URL.Query()["bundle"], r.URL.Query()["field"])
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "one or more requested explain bundles or diff profiles were not found", nil), http.StatusNotFound)
		return
	}
	if expectedFromRole != "" || expectedToRole != "" {
		if fromRole == "" || toRole == "" {
			api.writeManagedError(w, managedRequiredFieldError("from_role and to_role query parameters are required when using role-aware diff profiles"), http.StatusBadRequest)
			return
		}
		if fromRole != expectedFromRole || toRole != expectedToRole {
			api.writeManagedError(w, managedValidationError("diff profile role mismatch: expected "+expectedFromRole+" -> "+expectedToRole, nil), http.StatusBadRequest)
			return
		}
	}
	if len(fields) == 0 {
		api.writeManagedError(w, managedRequiredFieldError("at least one field or bundle query parameter is required"), http.StatusBadRequest)
		return
	}
	diff, ok := explainLimitClassDigestTargetFieldBundleDiff(cfg, fromWebhook, fromProfile, toWebhook, toProfile, fromRole, toRole, diffProfileNames, bundleNames, fields, allowedChangedFields, expectedFromValues, expectedToValues, assertFromRules, assertToRules, assertFromGroups, assertToGroups)
	if !ok {
		api.writeManagedError(w, managedError(coreerrors.CodeRouteNotFound, "notification webhook, digest profile, or one of the requested fields was not found", nil), http.StatusNotFound)
		return
	}
	api.writeJSON(w, map[string]interface{}{"diff": diff})
}

func inspectLimitClassDigestTarget(cfg *config.Config, webhookName string, profileName string) (limitClassDigestProfileInspection, bool) {
	if strings.TrimSpace(webhookName) != "" {
		return inspectLimitClassDigestProfile(cfg, webhookName)
	}
	if strings.TrimSpace(profileName) != "" {
		return inspectLimitClassDigestNamedProfile(cfg, profileName)
	}
	return limitClassDigestProfileInspection{}, false
}

func inspectLimitClassDigestAssertionPreset(cfg *config.Config, presetName string) (limitClassDigestAssertionPresetInspection, bool) {
	resolvedPreset, ok := resolveLimitClassDigestAssertionPreset(cfg.Security.LimitClassDigestAssertionPresets, presetName, map[string]bool{})
	if !ok {
		return limitClassDigestAssertionPresetInspection{}, false
	}
	appliedNames := make([]string, 0)
	visited := map[string]bool{}
	collectLimitClassDigestAssertionPresetOrder(cfg.Security.LimitClassDigestAssertionPresets, presetName, visited, &appliedNames)
	appliedPresets := make([]map[string]interface{}, 0, len(appliedNames))
	ruleSources := make([]string, 0)
	groupSources := make([]string, 0)
	for _, name := range appliedNames {
		preset := cfg.Security.LimitClassDigestAssertionPresets[name]
		appliedPresets = append(appliedPresets, map[string]interface{}{
			"name":        name,
			"presetChain": append([]string(nil), preset.PresetChain...),
			"rules":       append([]string(nil), preset.Rules...),
			"groups":      preset.Groups,
		})
		for range preset.Rules {
			ruleSources = append(ruleSources, "preset:"+name)
		}
		for range preset.Groups {
			groupSources = append(groupSources, "preset:"+name)
		}
	}
	availablePresets := make([]string, 0, len(cfg.Security.LimitClassDigestAssertionPresets))
	for name := range cfg.Security.LimitClassDigestAssertionPresets {
		availablePresets = append(availablePresets, name)
	}
	sort.Strings(availablePresets)
	return limitClassDigestAssertionPresetInspection{
		PresetName:       presetName,
		PresetChain:      append([]string(nil), cfg.Security.LimitClassDigestAssertionPresets[presetName].PresetChain...),
		AppliedPresets:   appliedPresets,
		EffectivePreset:  map[string]interface{}{"rules": resolvedPreset.Rules, "groups": resolvedPreset.Groups},
		RuleSources:      ruleSources,
		GroupSources:     groupSources,
		AvailablePresets: availablePresets,
	}, true
}

func collectLimitClassDigestAssertionGroupPresetOrder(presets map[string]config.LimitClassDigestAssertionGroupPreset, name string, visited map[string]bool, ordered *[]string) {
	resolvedName := strings.TrimSpace(name)
	if resolvedName == "" || visited[resolvedName] {
		return
	}
	preset, ok := presets[resolvedName]
	if !ok {
		return
	}
	visited[resolvedName] = true
	for _, parent := range preset.PresetChain {
		collectLimitClassDigestAssertionGroupPresetOrder(presets, parent, visited, ordered)
	}
	*ordered = append(*ordered, resolvedName)
}

func inspectLimitClassDigestAssertionGroupPreset(cfg *config.Config, presetName string) (limitClassDigestAssertionGroupPresetInspection, bool) {
	resolvedPreset, ok := resolveLimitClassDigestAssertionGroupPreset(cfg.Security.LimitClassDigestAssertionGroupPresets, presetName, map[string]bool{})
	if !ok {
		return limitClassDigestAssertionGroupPresetInspection{}, false
	}
	appliedNames := make([]string, 0)
	visited := map[string]bool{}
	collectLimitClassDigestAssertionGroupPresetOrder(cfg.Security.LimitClassDigestAssertionGroupPresets, presetName, visited, &appliedNames)
	appliedPresets := make([]map[string]interface{}, 0, len(appliedNames))
	groupSources := make([]string, 0)
	for _, name := range appliedNames {
		preset := cfg.Security.LimitClassDigestAssertionGroupPresets[name]
		appliedPresets = append(appliedPresets, map[string]interface{}{
			"name":        name,
			"presetChain": append([]string(nil), preset.PresetChain...),
			"groups":      preset.Groups,
		})
		for range preset.Groups {
			groupSources = append(groupSources, "preset:"+name)
		}
	}
	availablePresets := make([]string, 0, len(cfg.Security.LimitClassDigestAssertionGroupPresets))
	for name := range cfg.Security.LimitClassDigestAssertionGroupPresets {
		availablePresets = append(availablePresets, name)
	}
	sort.Strings(availablePresets)
	return limitClassDigestAssertionGroupPresetInspection{
		PresetName:       presetName,
		PresetChain:      append([]string(nil), cfg.Security.LimitClassDigestAssertionGroupPresets[presetName].PresetChain...),
		AppliedPresets:   appliedPresets,
		EffectivePreset:  map[string]interface{}{"groups": resolvedPreset.Groups},
		GroupSources:     groupSources,
		AvailablePresets: availablePresets,
	}, true
}

func explainLimitClassDigestAssertionGroupPreset(cfg *config.Config, presetName string) (limitClassDigestAssertionGroupPresetExplanation, bool) {
	inspection, ok := inspectLimitClassDigestAssertionGroupPreset(cfg, presetName)
	if !ok {
		return limitClassDigestAssertionGroupPresetExplanation{}, false
	}
	stages := make([]limitClassDigestProfileExplainStage, 0, len(inspection.AppliedPresets))
	var previousValue interface{}
	for _, applied := range inspection.AppliedPresets {
		name, _ := applied["name"].(string)
		value := applied["groups"]
		changed := !reflect.DeepEqual(previousValue, value)
		stages = append(stages, limitClassDigestProfileExplainStage{
			Stage:   "preset:" + name,
			Source:  "preset:" + name,
			Value:   value,
			Changed: changed,
		})
		previousValue = value
	}
	return limitClassDigestAssertionGroupPresetExplanation{
		Inspection: inspection,
		Kind:       "groups",
		FinalValue: inspection.EffectivePreset["groups"],
		Stages:     stages,
	}, true
}

func resolveLimitClassDigestAssertionGroupPresetExplainBundlePresets(cfg *config.Config, bundleNames []string, explicitPresets []string) ([]string, bool) {
	if cfg == nil {
		return nil, false
	}
	presets := make([]string, 0)
	seen := map[string]struct{}{}
	for _, bundleName := range bundleNames {
		bundle, ok := cfg.Security.LimitClassDigestAssertionGroupPresetExplainBundles[bundleName]
		if !ok {
			return nil, false
		}
		for _, presetName := range bundle.Presets {
			resolvedName := strings.TrimSpace(presetName)
			if resolvedName == "" {
				continue
			}
			if _, ok := seen[resolvedName]; ok {
				continue
			}
			seen[resolvedName] = struct{}{}
			presets = append(presets, resolvedName)
		}
	}
	for _, presetName := range normalizeLimitClassDigestExplainFields(explicitPresets) {
		resolvedName := strings.TrimSpace(presetName)
		if resolvedName == "" {
			continue
		}
		if _, ok := cfg.Security.LimitClassDigestAssertionGroupPresets[resolvedName]; !ok {
			return nil, false
		}
		if _, ok := seen[resolvedName]; ok {
			continue
		}
		seen[resolvedName] = struct{}{}
		presets = append(presets, resolvedName)
	}
	return presets, true
}

func explainLimitClassDigestAssertionGroupPresetBundle(cfg *config.Config, bundleNames []string, presetNames []string) (limitClassDigestAssertionGroupPresetExplanationBundle, bool) {
	explanations := make(map[string]limitClassDigestAssertionGroupPresetExplanation, len(presetNames))
	for _, presetName := range presetNames {
		explanation, ok := explainLimitClassDigestAssertionGroupPreset(cfg, presetName)
		if !ok {
			return limitClassDigestAssertionGroupPresetExplanationBundle{}, false
		}
		explanations[presetName] = explanation
	}
	return limitClassDigestAssertionGroupPresetExplanationBundle{
		Bundles:      append([]string(nil), bundleNames...),
		Presets:      append([]string(nil), presetNames...),
		Explanations: explanations,
	}, true
}

func explainLimitClassDigestAssertionGroupPresetBundleDiff(cfg *config.Config, fromBundleNames []string, fromPresetNames []string, toBundleNames []string, toPresetNames []string) (limitClassDigestAssertionGroupPresetExplanationBundleDiff, bool) {
	fromBundle, ok := explainLimitClassDigestAssertionGroupPresetBundle(cfg, fromBundleNames, fromPresetNames)
	if !ok {
		return limitClassDigestAssertionGroupPresetExplanationBundleDiff{}, false
	}
	toBundle, ok := explainLimitClassDigestAssertionGroupPresetBundle(cfg, toBundleNames, toPresetNames)
	if !ok {
		return limitClassDigestAssertionGroupPresetExplanationBundleDiff{}, false
	}
	seen := map[string]struct{}{}
	presets := make([]string, 0, len(fromBundle.Presets)+len(toBundle.Presets))
	for _, name := range fromBundle.Presets {
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		presets = append(presets, name)
	}
	for _, name := range toBundle.Presets {
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		presets = append(presets, name)
	}
	presetDiffs := make(map[string]limitClassDigestAssertionGroupPresetExplanationDiff, len(presets))
	changedPresets := make([]string, 0)
	for _, name := range presets {
		fromExplanation, fromOK := fromBundle.Explanations[name]
		toExplanation, toOK := toBundle.Explanations[name]
		if !fromOK {
			fromExplanation = limitClassDigestAssertionGroupPresetExplanation{Kind: "groups"}
		}
		if !toOK {
			toExplanation = limitClassDigestAssertionGroupPresetExplanation{Kind: "groups"}
		}
		diff := buildLimitClassDigestAssertionGroupPresetExplanationDiff(fromExplanation, toExplanation)
		presetDiffs[name] = diff
		if diff.FinalChanged {
			changedPresets = append(changedPresets, name)
		}
	}
	return limitClassDigestAssertionGroupPresetExplanationBundleDiff{
		Bundles:        append(append([]string(nil), fromBundleNames...), toBundleNames...),
		Presets:        presets,
		PresetDiffs:    presetDiffs,
		ChangedPresets: changedPresets,
	}, true
}

func explainLimitClassDigestAssertionPreset(cfg *config.Config, presetName string, kind string) (limitClassDigestAssertionPresetExplanation, bool) {
	inspection, ok := inspectLimitClassDigestAssertionPreset(cfg, presetName)
	if !ok {
		return limitClassDigestAssertionPresetExplanation{}, false
	}
	resolvedKind := strings.ToLower(strings.TrimSpace(kind))
	if resolvedKind != "rules" && resolvedKind != "groups" {
		return limitClassDigestAssertionPresetExplanation{}, false
	}
	stages := make([]limitClassDigestProfileExplainStage, 0, len(inspection.AppliedPresets))
	var previousValue interface{}
	for _, applied := range inspection.AppliedPresets {
		name, _ := applied["name"].(string)
		var value interface{}
		if resolvedKind == "rules" {
			value = applied["rules"]
		} else {
			value = applied["groups"]
		}
		changed := !reflect.DeepEqual(previousValue, value)
		stages = append(stages, limitClassDigestProfileExplainStage{
			Stage:   "preset:" + name,
			Source:  "preset:" + name,
			Value:   value,
			Changed: changed,
		})
		previousValue = value
	}
	finalValue := inspection.EffectivePreset[resolvedKind]
	return limitClassDigestAssertionPresetExplanation{
		Inspection: inspection,
		Kind:       resolvedKind,
		FinalValue: finalValue,
		Stages:     stages,
	}, true
}

func explainLimitClassDigestAssertionPresetKinds(cfg *config.Config, presetName string, kinds []string) (limitClassDigestAssertionPresetExplanationBundle, bool) {
	inspection, ok := inspectLimitClassDigestAssertionPreset(cfg, presetName)
	if !ok {
		return limitClassDigestAssertionPresetExplanationBundle{}, false
	}
	resolvedKinds := normalizeLimitClassDigestExplainFields(kinds)
	explanations := make(map[string]limitClassDigestAssertionPresetExplanation, len(resolvedKinds))
	for _, kind := range resolvedKinds {
		explanation, ok := explainLimitClassDigestAssertionPreset(cfg, presetName, kind)
		if !ok {
			return limitClassDigestAssertionPresetExplanationBundle{}, false
		}
		explanations[kind] = explanation
	}
	return limitClassDigestAssertionPresetExplanationBundle{
		Inspection:   inspection,
		Kinds:        resolvedKinds,
		Explanations: explanations,
	}, true
}

func explainLimitClassDigestAssertionPresetKindBundleDiff(cfg *config.Config, fromPreset string, toPreset string, diffProfileNames []string, bundleNames []string, kinds []string, allowedChangedKinds []string, expectedFromValues map[string]string, expectedToValues map[string]string, assertFromRules map[string][]string, assertToRules map[string][]string, assertFromGroups map[string][]config.LimitClassDigestAssertionGroup, assertToGroups map[string][]config.LimitClassDigestAssertionGroup) (limitClassDigestAssertionPresetExplanationBundleDiff, bool) {
	fromBundle, ok := explainLimitClassDigestAssertionPresetKinds(cfg, fromPreset, kinds)
	if !ok {
		return limitClassDigestAssertionPresetExplanationBundleDiff{}, false
	}
	toBundle, ok := explainLimitClassDigestAssertionPresetKinds(cfg, toPreset, kinds)
	if !ok {
		return limitClassDigestAssertionPresetExplanationBundleDiff{}, false
	}
	kindDiffs := make(map[string]limitClassDigestAssertionPresetExplanationDiff, len(kinds))
	changedKinds := make([]string, 0)
	allowed := map[string]struct{}{}
	for _, kind := range allowedChangedKinds {
		allowed[kind] = struct{}{}
	}
	unexpectedChangedKinds := make([]string, 0)
	assertionFailures := make([]limitClassDigestProfileAssertionFailure, 0)
	for _, kind := range kinds {
		diff := buildLimitClassDigestAssertionPresetExplanationDiff(fromBundle.Explanations[kind], toBundle.Explanations[kind])
		kindDiffs[kind] = diff
		if expected, ok := expectedFromValues[kind]; ok {
			expectedValue := parseLimitClassDigestExpectedValue(expected)
			if !reflect.DeepEqual(expectedValue, fromBundle.Explanations[kind].FinalValue) {
				assertionFailures = append(assertionFailures, limitClassDigestProfileAssertionFailure{
					Side:     "from",
					Field:    kind,
					Expected: expectedValue,
					Actual:   fromBundle.Explanations[kind].FinalValue,
				})
			}
		}
		if expected, ok := expectedToValues[kind]; ok {
			expectedValue := parseLimitClassDigestExpectedValue(expected)
			if !reflect.DeepEqual(expectedValue, toBundle.Explanations[kind].FinalValue) {
				assertionFailures = append(assertionFailures, limitClassDigestProfileAssertionFailure{
					Side:     "to",
					Field:    kind,
					Expected: expectedValue,
					Actual:   toBundle.Explanations[kind].FinalValue,
				})
			}
		}
		for _, rule := range assertFromRules[kind] {
			if expectedValue, actualValue, passed := evaluateLimitClassDigestAssertionRule(rule, fromBundle.Explanations[kind].FinalValue); !passed {
				assertionFailures = append(assertionFailures, limitClassDigestProfileAssertionFailure{
					Side: "from", Field: kind, Rule: rule, Expected: expectedValue, Actual: actualValue,
				})
			}
		}
		for _, rule := range assertToRules[kind] {
			if expectedValue, actualValue, passed := evaluateLimitClassDigestAssertionRule(rule, toBundle.Explanations[kind].FinalValue); !passed {
				assertionFailures = append(assertionFailures, limitClassDigestProfileAssertionFailure{
					Side: "to", Field: kind, Rule: rule, Expected: expectedValue, Actual: actualValue,
				})
			}
		}
		for _, group := range assertFromGroups[kind] {
			result := evaluateLimitClassDigestAssertionGroup(group, fromBundle.Explanations[kind].FinalValue)
			if !result.Passed {
				assertionFailures = append(assertionFailures, limitClassDigestProfileAssertionFailure{
					Side: "from", Field: kind, Rule: formatLimitClassDigestAssertionGroup(group), Expected: result.Expected, Actual: result.Actual,
				})
			}
		}
		for _, group := range assertToGroups[kind] {
			result := evaluateLimitClassDigestAssertionGroup(group, toBundle.Explanations[kind].FinalValue)
			if !result.Passed {
				assertionFailures = append(assertionFailures, limitClassDigestProfileAssertionFailure{
					Side: "to", Field: kind, Rule: formatLimitClassDigestAssertionGroup(group), Expected: result.Expected, Actual: result.Actual,
				})
			}
		}
		if diff.FinalChanged {
			changedKinds = append(changedKinds, kind)
			if len(allowed) > 0 {
				if _, ok := allowed[kind]; !ok {
					unexpectedChangedKinds = append(unexpectedChangedKinds, kind)
				}
			}
		}
	}
	return limitClassDigestAssertionPresetExplanationBundleDiff{
		Bundles:                append([]string(nil), bundleNames...),
		DiffProfiles:           append([]string(nil), diffProfileNames...),
		Kinds:                  append([]string(nil), kinds...),
		From:                   fromBundle.Inspection,
		To:                     toBundle.Inspection,
		KindDiffs:              kindDiffs,
		ChangedKinds:           changedKinds,
		UnexpectedChangedKinds: unexpectedChangedKinds,
		AssertionFailures:      assertionFailures,
	}, true
}

func resolveLimitClassDigestAssertionExplainKinds(cfg *config.Config, bundleNames []string, explicitKinds []string) ([]string, bool) {
	if cfg == nil {
		return nil, false
	}
	kinds := make([]string, 0)
	seen := map[string]struct{}{}
	for _, bundleName := range bundleNames {
		bundle, ok := cfg.Security.LimitClassDigestAssertionExplainBundles[bundleName]
		if !ok {
			return nil, false
		}
		for _, kind := range bundle.Kinds {
			resolvedKind := strings.ToLower(strings.TrimSpace(kind))
			if resolvedKind == "" {
				continue
			}
			if _, ok := seen[resolvedKind]; ok {
				continue
			}
			seen[resolvedKind] = struct{}{}
			kinds = append(kinds, resolvedKind)
		}
	}
	for _, kind := range normalizeLimitClassDigestExplainFields(explicitKinds) {
		resolvedKind := strings.ToLower(strings.TrimSpace(kind))
		if resolvedKind == "" {
			continue
		}
		if _, ok := seen[resolvedKind]; ok {
			continue
		}
		seen[resolvedKind] = struct{}{}
		kinds = append(kinds, resolvedKind)
	}
	return kinds, true
}

func resolveLimitClassDigestAssertionExplainBundleDiffInputs(cfg *config.Config, diffProfileNames []string, explicitBundles []string, explicitKinds []string) ([]string, []string, []string, map[string]string, map[string]string, map[string][]string, map[string][]string, map[string][]config.LimitClassDigestAssertionGroup, map[string][]config.LimitClassDigestAssertionGroup, bool) {
	bundleNames := make([]string, 0)
	seenBundles := map[string]struct{}{}
	kinds := make([]string, 0)
	seenKinds := map[string]struct{}{}
	allowedChangedKinds := make([]string, 0)
	seenAllowedKinds := map[string]struct{}{}
	expectedFromValues := map[string]string{}
	expectedToValues := map[string]string{}
	assertFromRules := map[string][]string{}
	assertToRules := map[string][]string{}
	assertFromGroups := map[string][]config.LimitClassDigestAssertionGroup{}
	assertToGroups := map[string][]config.LimitClassDigestAssertionGroup{}

	for _, profileName := range diffProfileNames {
		profile, ok := cfg.Security.LimitClassDigestAssertionExplainDiffProfiles[profileName]
		if !ok {
			return nil, nil, nil, nil, nil, nil, nil, nil, nil, false
		}
		for _, bundleName := range normalizeLimitClassDigestExplainFields(profile.Bundles) {
			if _, ok := seenBundles[bundleName]; ok {
				continue
			}
			seenBundles[bundleName] = struct{}{}
			bundleNames = append(bundleNames, bundleName)
		}
		for _, kind := range normalizeLimitClassDigestExplainFields(profile.Kinds) {
			resolvedKind := strings.ToLower(strings.TrimSpace(kind))
			if _, ok := seenKinds[resolvedKind]; ok {
				continue
			}
			seenKinds[resolvedKind] = struct{}{}
			kinds = append(kinds, resolvedKind)
		}
		for _, kind := range normalizeLimitClassDigestExplainFields(profile.AllowedChangedKinds) {
			resolvedKind := strings.ToLower(strings.TrimSpace(kind))
			if _, ok := seenAllowedKinds[resolvedKind]; ok {
				continue
			}
			seenAllowedKinds[resolvedKind] = struct{}{}
			allowedChangedKinds = append(allowedChangedKinds, resolvedKind)
		}
		for kind, expected := range profile.ExpectedFromValues {
			resolvedKind := strings.ToLower(strings.TrimSpace(kind))
			if resolvedKind == "" {
				continue
			}
			expectedFromValues[resolvedKind] = expected
		}
		for kind, expected := range profile.ExpectedToValues {
			resolvedKind := strings.ToLower(strings.TrimSpace(kind))
			if resolvedKind == "" {
				continue
			}
			expectedToValues[resolvedKind] = expected
		}
		for kind, presetNames := range profile.AssertFromGroupPresets {
			resolvedKind := strings.ToLower(strings.TrimSpace(kind))
			if resolvedKind == "" {
				continue
			}
			for _, presetName := range presetNames {
				resolvedPreset := strings.TrimSpace(presetName)
				if resolvedPreset == "" {
					continue
				}
				preset, ok := resolveLimitClassDigestAssertionGroupPreset(cfg.Security.LimitClassDigestAssertionGroupPresets, resolvedPreset, map[string]bool{})
				if !ok {
					return nil, nil, nil, nil, nil, nil, nil, nil, nil, false
				}
				assertFromGroups[resolvedKind] = append(assertFromGroups[resolvedKind], preset.Groups...)
			}
		}
		for kind, presetNames := range profile.AssertToGroupPresets {
			resolvedKind := strings.ToLower(strings.TrimSpace(kind))
			if resolvedKind == "" {
				continue
			}
			for _, presetName := range presetNames {
				resolvedPreset := strings.TrimSpace(presetName)
				if resolvedPreset == "" {
					continue
				}
				preset, ok := resolveLimitClassDigestAssertionGroupPreset(cfg.Security.LimitClassDigestAssertionGroupPresets, resolvedPreset, map[string]bool{})
				if !ok {
					return nil, nil, nil, nil, nil, nil, nil, nil, nil, false
				}
				assertToGroups[resolvedKind] = append(assertToGroups[resolvedKind], preset.Groups...)
			}
		}
		for kind, rules := range profile.AssertFromRules {
			resolvedKind := strings.ToLower(strings.TrimSpace(kind))
			if resolvedKind == "" {
				continue
			}
			for _, rule := range rules {
				trimmedRule := strings.TrimSpace(rule)
				if trimmedRule == "" {
					continue
				}
				assertFromRules[resolvedKind] = append(assertFromRules[resolvedKind], trimmedRule)
			}
		}
		for kind, rules := range profile.AssertToRules {
			resolvedKind := strings.ToLower(strings.TrimSpace(kind))
			if resolvedKind == "" {
				continue
			}
			for _, rule := range rules {
				trimmedRule := strings.TrimSpace(rule)
				if trimmedRule == "" {
					continue
				}
				assertToRules[resolvedKind] = append(assertToRules[resolvedKind], trimmedRule)
			}
		}
		for kind, groups := range profile.AssertFromGroups {
			resolvedKind := strings.ToLower(strings.TrimSpace(kind))
			if resolvedKind == "" {
				continue
			}
			assertFromGroups[resolvedKind] = append(assertFromGroups[resolvedKind], groups...)
		}
		for kind, groups := range profile.AssertToGroups {
			resolvedKind := strings.ToLower(strings.TrimSpace(kind))
			if resolvedKind == "" {
				continue
			}
			assertToGroups[resolvedKind] = append(assertToGroups[resolvedKind], groups...)
		}
	}
	for _, bundleName := range normalizeLimitClassDigestExplainFields(explicitBundles) {
		if _, ok := seenBundles[bundleName]; ok {
			continue
		}
		seenBundles[bundleName] = struct{}{}
		bundleNames = append(bundleNames, bundleName)
	}
	resolvedKinds, ok := resolveLimitClassDigestAssertionExplainKinds(cfg, bundleNames, append(kinds, explicitKinds...))
	if !ok {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, false
	}
	return bundleNames, resolvedKinds, allowedChangedKinds, expectedFromValues, expectedToValues, assertFromRules, assertToRules, assertFromGroups, assertToGroups, true
}

func resolveLimitClassDigestAssertionGroupPreset(presets map[string]config.LimitClassDigestAssertionGroupPreset, name string, visiting map[string]bool) (config.LimitClassDigestAssertionGroupPreset, bool) {
	resolvedName := strings.TrimSpace(name)
	preset, ok := presets[resolvedName]
	if !ok {
		return config.LimitClassDigestAssertionGroupPreset{}, false
	}
	if visiting[resolvedName] {
		return config.LimitClassDigestAssertionGroupPreset{}, false
	}
	visiting[resolvedName] = true
	merged := config.LimitClassDigestAssertionGroupPreset{}
	for _, parentName := range preset.PresetChain {
		parent, ok := resolveLimitClassDigestAssertionGroupPreset(presets, parentName, visiting)
		if !ok {
			return config.LimitClassDigestAssertionGroupPreset{}, false
		}
		merged.Groups = append(merged.Groups, parent.Groups...)
	}
	delete(visiting, resolvedName)
	merged.PresetChain = append(merged.PresetChain, preset.PresetChain...)
	merged.Groups = append(merged.Groups, preset.Groups...)
	return merged, true
}

func collectLimitClassDigestAssertionPresetOrder(presets map[string]config.LimitClassDigestAssertionPreset, name string, visited map[string]bool, ordered *[]string) {
	resolvedName := strings.TrimSpace(name)
	if resolvedName == "" || visited[resolvedName] {
		return
	}
	preset, ok := presets[resolvedName]
	if !ok {
		return
	}
	visited[resolvedName] = true
	for _, parent := range preset.PresetChain {
		collectLimitClassDigestAssertionPresetOrder(presets, parent, visited, ordered)
	}
	*ordered = append(*ordered, resolvedName)
}

func hasExactlyOneLimitClassDigestTarget(webhookName string, profileName string) bool {
	return (strings.TrimSpace(webhookName) == "") != (strings.TrimSpace(profileName) == "")
}

func buildLimitClassDigestProfileDiff(from, to limitClassDigestProfileInspection) limitClassDigestProfileDiff {
	changedFields := map[string]limitClassDigestProfileFieldDiffEntry{}
	keys := map[string]struct{}{}
	for key := range from.EffectiveProfile {
		keys[key] = struct{}{}
	}
	for key := range to.EffectiveProfile {
		keys[key] = struct{}{}
	}
	sortedKeys := make([]string, 0, len(keys))
	for key := range keys {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)
	for _, key := range sortedKeys {
		fromValue, fromOk := from.EffectiveProfile[key]
		toValue, toOk := to.EffectiveProfile[key]
		if fromOk && toOk && reflect.DeepEqual(fromValue, toValue) {
			continue
		}
		changedFields[key] = limitClassDigestProfileFieldDiffEntry{
			FromValue:  fromValue,
			ToValue:    toValue,
			FromSource: from.FieldSources[key],
			ToSource:   to.FieldSources[key],
		}
	}
	return limitClassDigestProfileDiff{
		From:          from,
		To:            to,
		ChangedFields: changedFields,
	}
}

func buildLimitClassDigestAssertionPresetDiff(from, to limitClassDigestAssertionPresetInspection) limitClassDigestAssertionPresetDiff {
	changedFields := map[string]limitClassDigestProfileFieldDiffEntry{}
	keys := map[string]struct{}{}
	for key := range from.EffectivePreset {
		keys[key] = struct{}{}
	}
	for key := range to.EffectivePreset {
		keys[key] = struct{}{}
	}
	sortedKeys := make([]string, 0, len(keys))
	for key := range keys {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)
	for _, key := range sortedKeys {
		fromValue, fromOk := from.EffectivePreset[key]
		toValue, toOk := to.EffectivePreset[key]
		if fromOk && toOk && reflect.DeepEqual(fromValue, toValue) {
			continue
		}
		changedFields[key] = limitClassDigestProfileFieldDiffEntry{
			FromValue:  fromValue,
			ToValue:    toValue,
			FromSource: strings.Join(from.PresetChain, " -> "),
			ToSource:   strings.Join(to.PresetChain, " -> "),
		}
	}
	return limitClassDigestAssertionPresetDiff{
		From:          from,
		To:            to,
		ChangedFields: changedFields,
	}
}

func buildLimitClassDigestAssertionPresetExplanationDiff(from, to limitClassDigestAssertionPresetExplanation) limitClassDigestAssertionPresetExplanationDiff {
	changedStages := map[string]limitClassDigestProfileExplainDiffStage{}
	stageIndex := map[string]limitClassDigestProfileExplainDiffStage{}
	stageOrder := make([]string, 0, len(from.Stages)+len(to.Stages))
	for _, stage := range from.Stages {
		stageOrder = append(stageOrder, stage.Stage)
		stageIndex[stage.Stage] = limitClassDigestProfileExplainDiffStage{
			FromValue:  stage.Value,
			FromSource: stage.Source,
		}
	}
	for _, stage := range to.Stages {
		entry, ok := stageIndex[stage.Stage]
		if !ok {
			stageOrder = append(stageOrder, stage.Stage)
		}
		entry.ToValue = stage.Value
		entry.ToSource = stage.Source
		stageIndex[stage.Stage] = entry
	}
	for _, stageName := range stageOrder {
		entry := stageIndex[stageName]
		if reflect.DeepEqual(entry.FromValue, entry.ToValue) && entry.FromSource == entry.ToSource {
			continue
		}
		changedStages[stageName] = entry
	}
	return limitClassDigestAssertionPresetExplanationDiff{
		Kind:          from.Kind,
		From:          from,
		To:            to,
		FinalChanged:  !reflect.DeepEqual(from.FinalValue, to.FinalValue),
		ChangedStages: changedStages,
	}
}

func buildLimitClassDigestAssertionGroupPresetExplanationDiff(from, to limitClassDigestAssertionGroupPresetExplanation) limitClassDigestAssertionGroupPresetExplanationDiff {
	changedStages := make(map[string]limitClassDigestProfileExplainDiffStage)
	fromStageMap := make(map[string]limitClassDigestProfileExplainStage, len(from.Stages))
	for _, stage := range from.Stages {
		fromStageMap[stage.Stage] = stage
	}
	toStageMap := make(map[string]limitClassDigestProfileExplainStage, len(to.Stages))
	for _, stage := range to.Stages {
		toStageMap[stage.Stage] = stage
	}
	seenStages := make(map[string]struct{})
	for _, stage := range from.Stages {
		seenStages[stage.Stage] = struct{}{}
	}
	for _, stage := range to.Stages {
		seenStages[stage.Stage] = struct{}{}
	}
	stageNames := make([]string, 0, len(seenStages))
	for name := range seenStages {
		stageNames = append(stageNames, name)
	}
	sort.Strings(stageNames)
	for _, stageName := range stageNames {
		fromStage := fromStageMap[stageName]
		toStage := toStageMap[stageName]
		if !reflect.DeepEqual(fromStage.Value, toStage.Value) || fromStage.Source != toStage.Source {
			changedStages[stageName] = limitClassDigestProfileExplainDiffStage{
				FromValue:  fromStage.Value,
				ToValue:    toStage.Value,
				FromSource: fromStage.Source,
				ToSource:   toStage.Source,
			}
		}
	}
	return limitClassDigestAssertionGroupPresetExplanationDiff{
		Kind:          "groups",
		From:          from,
		To:            to,
		FinalChanged:  !reflect.DeepEqual(from.FinalValue, to.FinalValue),
		ChangedStages: changedStages,
	}
}

func buildLimitClassDigestProfileExplanationDiff(from, to limitClassDigestProfileExplanation) limitClassDigestProfileExplanationDiff {
	changedStages := map[string]limitClassDigestProfileExplainDiffStage{}
	stageIndex := map[string]limitClassDigestProfileExplainDiffStage{}
	stageOrder := make([]string, 0, len(from.Stages)+len(to.Stages))
	for _, stage := range from.Stages {
		stageOrder = append(stageOrder, stage.Stage)
		stageIndex[stage.Stage] = limitClassDigestProfileExplainDiffStage{
			FromValue:  stage.Value,
			FromSource: stage.Source,
		}
	}
	for _, stage := range to.Stages {
		entry, ok := stageIndex[stage.Stage]
		if !ok {
			stageOrder = append(stageOrder, stage.Stage)
		}
		entry.ToValue = stage.Value
		entry.ToSource = stage.Source
		stageIndex[stage.Stage] = entry
	}
	for _, stageName := range stageOrder {
		entry := stageIndex[stageName]
		if reflect.DeepEqual(entry.FromValue, entry.ToValue) && entry.FromSource == entry.ToSource {
			continue
		}
		changedStages[stageName] = entry
	}
	return limitClassDigestProfileExplanationDiff{
		Field:         from.Field,
		From:          from,
		To:            to,
		FinalChanged:  !reflect.DeepEqual(from.FinalValue, to.FinalValue) || from.FinalSource != to.FinalSource,
		ChangedStages: changedStages,
	}
}

func normalizeLimitClassDigestExplainFields(values []string) []string {
	seen := map[string]struct{}{}
	fields := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			field := strings.TrimSpace(part)
			if field == "" {
				continue
			}
			if _, ok := seen[field]; ok {
				continue
			}
			seen[field] = struct{}{}
			fields = append(fields, field)
		}
	}
	return fields
}

func resolveLimitClassDigestExplainFields(cfg *config.Config, bundleNames []string, explicitFields []string) ([]string, bool) {
	fields := make([]string, 0)
	seen := map[string]struct{}{}
	for _, bundleName := range bundleNames {
		bundle, ok := cfg.Security.LimitClassDigestExplainBundles[bundleName]
		if !ok {
			return nil, false
		}
		for _, field := range bundle.Fields {
			resolvedField := strings.TrimSpace(field)
			if resolvedField == "" {
				continue
			}
			if _, ok := seen[resolvedField]; ok {
				continue
			}
			seen[resolvedField] = struct{}{}
			fields = append(fields, resolvedField)
		}
	}
	for _, field := range normalizeLimitClassDigestExplainFields(explicitFields) {
		if _, ok := seen[field]; ok {
			continue
		}
		seen[field] = struct{}{}
		fields = append(fields, field)
	}
	return fields, true
}

func resolveLimitClassDigestExplainBundleDiffInputs(cfg *config.Config, diffProfileNames []string, explicitBundles []string, explicitFields []string) ([]string, []string, []string, map[string]string, map[string]string, map[string][]string, map[string][]string, map[string][]config.LimitClassDigestAssertionGroup, map[string][]config.LimitClassDigestAssertionGroup, string, string, bool) {
	bundleNames := make([]string, 0)
	fields := make([]string, 0)
	allowedChangedFields := make([]string, 0)
	expectedFromValues := map[string]string{}
	expectedToValues := map[string]string{}
	assertFromRules := map[string][]string{}
	assertToRules := map[string][]string{}
	assertFromGroups := map[string][]config.LimitClassDigestAssertionGroup{}
	assertToGroups := map[string][]config.LimitClassDigestAssertionGroup{}
	expectedFromRole := ""
	expectedToRole := ""
	seenBundles := map[string]struct{}{}
	seenFields := map[string]struct{}{}
	seenAllowed := map[string]struct{}{}
	for _, profileName := range diffProfileNames {
		profile, ok := cfg.Security.LimitClassDigestExplainDiffProfiles[profileName]
		if !ok {
			return nil, nil, nil, nil, nil, nil, nil, nil, nil, "", "", false
		}
		if strings.TrimSpace(profile.FromRole) != "" || strings.TrimSpace(profile.ToRole) != "" {
			if expectedFromRole == "" && expectedToRole == "" {
				expectedFromRole = strings.TrimSpace(profile.FromRole)
				expectedToRole = strings.TrimSpace(profile.ToRole)
			} else if expectedFromRole != strings.TrimSpace(profile.FromRole) || expectedToRole != strings.TrimSpace(profile.ToRole) {
				return nil, nil, nil, nil, nil, nil, nil, nil, nil, "", "", false
			}
		}
		for _, bundleName := range profile.Bundles {
			resolved := strings.TrimSpace(bundleName)
			if resolved == "" {
				continue
			}
			if _, ok := seenBundles[resolved]; ok {
				continue
			}
			seenBundles[resolved] = struct{}{}
			bundleNames = append(bundleNames, resolved)
		}
		for _, field := range profile.Fields {
			resolved := strings.TrimSpace(field)
			if resolved == "" {
				continue
			}
			if _, ok := seenFields[resolved]; ok {
				continue
			}
			seenFields[resolved] = struct{}{}
			fields = append(fields, resolved)
		}
		for _, field := range profile.AllowedChangedFields {
			resolved := strings.TrimSpace(field)
			if resolved == "" {
				continue
			}
			if _, ok := seenAllowed[resolved]; ok {
				continue
			}
			seenAllowed[resolved] = struct{}{}
			allowedChangedFields = append(allowedChangedFields, resolved)
		}
		for field, expected := range profile.ExpectedFromValues {
			resolved := strings.TrimSpace(field)
			if resolved == "" {
				continue
			}
			expectedFromValues[resolved] = expected
		}
		for field, expected := range profile.ExpectedToValues {
			resolved := strings.TrimSpace(field)
			if resolved == "" {
				continue
			}
			expectedToValues[resolved] = expected
		}
		for field, presetNames := range profile.AssertFromPresets {
			resolved := strings.TrimSpace(field)
			if resolved == "" {
				continue
			}
			for _, presetName := range presetNames {
				resolvedPreset := strings.TrimSpace(presetName)
				if resolvedPreset == "" {
					continue
				}
				preset, ok := resolveLimitClassDigestAssertionPreset(cfg.Security.LimitClassDigestAssertionPresets, resolvedPreset, map[string]bool{})
				if !ok {
					return nil, nil, nil, nil, nil, nil, nil, nil, nil, "", "", false
				}
				assertFromRules[resolved] = append(assertFromRules[resolved], preset.Rules...)
				assertFromGroups[resolved] = append(assertFromGroups[resolved], preset.Groups...)
			}
		}
		for field, presetNames := range profile.AssertToPresets {
			resolved := strings.TrimSpace(field)
			if resolved == "" {
				continue
			}
			for _, presetName := range presetNames {
				resolvedPreset := strings.TrimSpace(presetName)
				if resolvedPreset == "" {
					continue
				}
				preset, ok := resolveLimitClassDigestAssertionPreset(cfg.Security.LimitClassDigestAssertionPresets, resolvedPreset, map[string]bool{})
				if !ok {
					return nil, nil, nil, nil, nil, nil, nil, nil, nil, "", "", false
				}
				assertToRules[resolved] = append(assertToRules[resolved], preset.Rules...)
				assertToGroups[resolved] = append(assertToGroups[resolved], preset.Groups...)
			}
		}
		for field, rules := range profile.AssertFromRules {
			resolved := strings.TrimSpace(field)
			if resolved == "" {
				continue
			}
			for _, rule := range rules {
				trimmedRule := strings.TrimSpace(rule)
				if trimmedRule == "" {
					continue
				}
				assertFromRules[resolved] = append(assertFromRules[resolved], trimmedRule)
			}
		}
		for field, rules := range profile.AssertToRules {
			resolved := strings.TrimSpace(field)
			if resolved == "" {
				continue
			}
			for _, rule := range rules {
				trimmedRule := strings.TrimSpace(rule)
				if trimmedRule == "" {
					continue
				}
				assertToRules[resolved] = append(assertToRules[resolved], trimmedRule)
			}
		}
		for field, groups := range profile.AssertFromGroups {
			resolved := strings.TrimSpace(field)
			if resolved == "" {
				continue
			}
			assertFromGroups[resolved] = append(assertFromGroups[resolved], groups...)
		}
		for field, groups := range profile.AssertToGroups {
			resolved := strings.TrimSpace(field)
			if resolved == "" {
				continue
			}
			assertToGroups[resolved] = append(assertToGroups[resolved], groups...)
		}
	}
	for _, bundleName := range normalizeLimitClassDigestExplainFields(explicitBundles) {
		if _, ok := seenBundles[bundleName]; ok {
			continue
		}
		seenBundles[bundleName] = struct{}{}
		bundleNames = append(bundleNames, bundleName)
	}
	resolvedFields, ok := resolveLimitClassDigestExplainFields(cfg, bundleNames, explicitFields)
	if !ok {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, "", "", false
	}
	for _, field := range resolvedFields {
		if _, ok := seenFields[field]; ok {
			continue
		}
		seenFields[field] = struct{}{}
		fields = append(fields, field)
	}
	return bundleNames, fields, allowedChangedFields, expectedFromValues, expectedToValues, assertFromRules, assertToRules, assertFromGroups, assertToGroups, expectedFromRole, expectedToRole, true
}

func resolveLimitClassDigestAssertionPreset(presets map[string]config.LimitClassDigestAssertionPreset, name string, visiting map[string]bool) (config.LimitClassDigestAssertionPreset, bool) {
	resolvedName := strings.TrimSpace(name)
	if resolvedName == "" {
		return config.LimitClassDigestAssertionPreset{}, false
	}
	if visiting[resolvedName] {
		return config.LimitClassDigestAssertionPreset{}, false
	}
	preset, ok := presets[resolvedName]
	if !ok {
		return config.LimitClassDigestAssertionPreset{}, false
	}
	visiting[resolvedName] = true
	merged := config.LimitClassDigestAssertionPreset{}
	for _, parentName := range preset.PresetChain {
		parent, ok := resolveLimitClassDigestAssertionPreset(presets, parentName, visiting)
		if !ok {
			return config.LimitClassDigestAssertionPreset{}, false
		}
		merged.Rules = append(merged.Rules, parent.Rules...)
		merged.Groups = append(merged.Groups, parent.Groups...)
	}
	delete(visiting, resolvedName)
	merged.Rules = append(merged.Rules, preset.Rules...)
	merged.Groups = append(merged.Groups, preset.Groups...)
	return merged, true
}

func explainLimitClassDigestTargetFields(cfg *config.Config, webhookName string, profileName string, bundleNames []string, fields []string) (limitClassDigestProfileExplanationBundle, bool) {
	inspection, ok := inspectLimitClassDigestTarget(cfg, webhookName, profileName)
	if !ok {
		return limitClassDigestProfileExplanationBundle{}, false
	}
	explanations := make(map[string]limitClassDigestProfileExplanation, len(fields))
	for _, field := range fields {
		explanation, ok := explainLimitClassDigestTargetField(cfg, webhookName, profileName, field)
		if !ok {
			return limitClassDigestProfileExplanationBundle{}, false
		}
		explanations[field] = explanation
	}
	return limitClassDigestProfileExplanationBundle{
		Inspection:   inspection,
		Bundles:      append([]string(nil), bundleNames...),
		Fields:       append([]string(nil), fields...),
		Explanations: explanations,
	}, true
}

func explainLimitClassDigestTargetFieldBundleDiff(cfg *config.Config, fromWebhook string, fromProfile string, toWebhook string, toProfile string, fromRole string, toRole string, diffProfileNames []string, bundleNames []string, fields []string, allowedChangedFields []string, expectedFromValues map[string]string, expectedToValues map[string]string, assertFromRules map[string][]string, assertToRules map[string][]string, assertFromGroups map[string][]config.LimitClassDigestAssertionGroup, assertToGroups map[string][]config.LimitClassDigestAssertionGroup) (limitClassDigestProfileExplanationBundleDiff, bool) {
	fromBundle, ok := explainLimitClassDigestTargetFields(cfg, fromWebhook, fromProfile, bundleNames, fields)
	if !ok {
		return limitClassDigestProfileExplanationBundleDiff{}, false
	}
	toBundle, ok := explainLimitClassDigestTargetFields(cfg, toWebhook, toProfile, bundleNames, fields)
	if !ok {
		return limitClassDigestProfileExplanationBundleDiff{}, false
	}
	fieldDiffs := make(map[string]limitClassDigestProfileExplanationDiff, len(fields))
	changedFields := make([]string, 0, len(fields))
	unexpectedChangedFields := make([]string, 0)
	assertionFailures := make([]limitClassDigestProfileAssertionFailure, 0)
	allowedChangedSet := map[string]struct{}{}
	for _, field := range allowedChangedFields {
		allowedChangedSet[field] = struct{}{}
	}
	for _, field := range fields {
		diff := buildLimitClassDigestProfileExplanationDiff(fromBundle.Explanations[field], toBundle.Explanations[field])
		fieldDiffs[field] = diff
		if expected, ok := expectedFromValues[field]; ok {
			expectedValue := parseLimitClassDigestExpectedValue(expected)
			if !reflect.DeepEqual(expectedValue, fromBundle.Explanations[field].FinalValue) {
				assertionFailures = append(assertionFailures, limitClassDigestProfileAssertionFailure{
					Side:     "from",
					Field:    field,
					Expected: expectedValue,
					Actual:   fromBundle.Explanations[field].FinalValue,
				})
			}
		}
		if expected, ok := expectedToValues[field]; ok {
			expectedValue := parseLimitClassDigestExpectedValue(expected)
			if !reflect.DeepEqual(expectedValue, toBundle.Explanations[field].FinalValue) {
				assertionFailures = append(assertionFailures, limitClassDigestProfileAssertionFailure{
					Side:     "to",
					Field:    field,
					Expected: expectedValue,
					Actual:   toBundle.Explanations[field].FinalValue,
				})
			}
		}
		for _, rule := range assertFromRules[field] {
			if expectedValue, actualValue, passed := evaluateLimitClassDigestAssertionRule(rule, fromBundle.Explanations[field].FinalValue); !passed {
				assertionFailures = append(assertionFailures, limitClassDigestProfileAssertionFailure{
					Side: "from", Field: field, Rule: rule, Expected: expectedValue, Actual: actualValue,
				})
			}
		}
		for _, rule := range assertToRules[field] {
			if expectedValue, actualValue, passed := evaluateLimitClassDigestAssertionRule(rule, toBundle.Explanations[field].FinalValue); !passed {
				assertionFailures = append(assertionFailures, limitClassDigestProfileAssertionFailure{
					Side: "to", Field: field, Rule: rule, Expected: expectedValue, Actual: actualValue,
				})
			}
		}
		for _, group := range assertFromGroups[field] {
			result := evaluateLimitClassDigestAssertionGroup(group, fromBundle.Explanations[field].FinalValue)
			if !result.Passed {
				assertionFailures = append(assertionFailures, limitClassDigestProfileAssertionFailure{
					Side: "from", Field: field, Rule: formatLimitClassDigestAssertionGroup(group), Expected: result.Expected, Actual: result.Actual,
				})
			}
		}
		for _, group := range assertToGroups[field] {
			result := evaluateLimitClassDigestAssertionGroup(group, toBundle.Explanations[field].FinalValue)
			if !result.Passed {
				assertionFailures = append(assertionFailures, limitClassDigestProfileAssertionFailure{
					Side: "to", Field: field, Rule: formatLimitClassDigestAssertionGroup(group), Expected: result.Expected, Actual: result.Actual,
				})
			}
		}
		if diff.FinalChanged || len(diff.ChangedStages) > 0 {
			changedFields = append(changedFields, field)
			if len(allowedChangedSet) > 0 {
				if _, ok := allowedChangedSet[field]; !ok {
					unexpectedChangedFields = append(unexpectedChangedFields, field)
				}
			}
		}
	}
	return limitClassDigestProfileExplanationBundleDiff{
		Bundles:                 append([]string(nil), bundleNames...),
		DiffProfiles:            append([]string(nil), diffProfileNames...),
		FromRole:                fromRole,
		ToRole:                  toRole,
		Fields:                  append([]string(nil), fields...),
		From:                    fromBundle.Inspection,
		To:                      toBundle.Inspection,
		FieldDiffs:              fieldDiffs,
		ChangedFields:           changedFields,
		UnexpectedChangedFields: unexpectedChangedFields,
		AssertionFailures:       assertionFailures,
	}, true
}

func parseLimitClassDigestExpectedValue(raw string) interface{} {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	var decoded interface{}
	if err := json.Unmarshal([]byte(trimmed), &decoded); err == nil {
		return decoded
	}
	return raw
}

func evaluateLimitClassDigestAssertionRule(rule string, actual interface{}) (interface{}, interface{}, bool) {
	switch {
	case rule == "exists":
		return "exists", actual, limitClassDigestAssertionValueExists(actual)
	case strings.HasPrefix(rule, "contains:"):
		expected := parseLimitClassDigestExpectedValue(strings.TrimPrefix(rule, "contains:"))
		return expected, actual, limitClassDigestAssertionContains(actual, expected)
	case strings.HasPrefix(rule, "not_contains:"):
		expected := parseLimitClassDigestExpectedValue(strings.TrimPrefix(rule, "not_contains:"))
		return expected, actual, !limitClassDigestAssertionContains(actual, expected)
	case strings.HasPrefix(rule, "regex:"):
		pattern := strings.TrimSpace(strings.TrimPrefix(rule, "regex:"))
		matcher, err := regexp.Compile(pattern)
		if err != nil {
			return pattern, actual, false
		}
		value, ok := actual.(string)
		return pattern, actual, ok && matcher.MatchString(value)
	case strings.HasPrefix(rule, "lte:"):
		expected := parseLimitClassDigestExpectedValue(strings.TrimPrefix(rule, "lte:"))
		expectedNumber, ok1 := toFloat64(expected)
		actualNumber, ok2 := toFloat64(actual)
		return expected, actual, ok1 && ok2 && actualNumber <= expectedNumber
	case strings.HasPrefix(rule, "gte:"):
		expected := parseLimitClassDigestExpectedValue(strings.TrimPrefix(rule, "gte:"))
		expectedNumber, ok1 := toFloat64(expected)
		actualNumber, ok2 := toFloat64(actual)
		return expected, actual, ok1 && ok2 && actualNumber >= expectedNumber
	default:
		return rule, actual, false
	}
}

func evaluateLimitClassDigestAssertionGroup(group config.LimitClassDigestAssertionGroup, actual interface{}) limitClassDigestAssertionGroupResult {
	operator := strings.ToLower(strings.TrimSpace(group.Operator))
	switch operator {
	case "allof":
		for _, rule := range group.Rules {
			if _, _, passed := evaluateLimitClassDigestAssertionRule(strings.TrimSpace(rule), actual); !passed {
				return limitClassDigestAssertionGroupResult{
					Expected: formatLimitClassDigestAssertionGroup(group),
					Actual:   actual,
					Passed:   false,
				}
			}
		}
		for _, nested := range group.Groups {
			if result := evaluateLimitClassDigestAssertionGroup(nested, actual); !result.Passed {
				return limitClassDigestAssertionGroupResult{
					Expected: formatLimitClassDigestAssertionGroup(group),
					Actual:   actual,
					Passed:   false,
				}
			}
		}
		return limitClassDigestAssertionGroupResult{Expected: formatLimitClassDigestAssertionGroup(group), Actual: actual, Passed: true}
	case "anyof":
		for _, rule := range group.Rules {
			if _, _, passed := evaluateLimitClassDigestAssertionRule(strings.TrimSpace(rule), actual); passed {
				return limitClassDigestAssertionGroupResult{Expected: formatLimitClassDigestAssertionGroup(group), Actual: actual, Passed: true}
			}
		}
		for _, nested := range group.Groups {
			if result := evaluateLimitClassDigestAssertionGroup(nested, actual); result.Passed {
				return limitClassDigestAssertionGroupResult{Expected: formatLimitClassDigestAssertionGroup(group), Actual: actual, Passed: true}
			}
		}
		return limitClassDigestAssertionGroupResult{
			Expected: formatLimitClassDigestAssertionGroup(group),
			Actual:   actual,
			Passed:   false,
		}
	case "noneof":
		for _, rule := range group.Rules {
			if _, _, passed := evaluateLimitClassDigestAssertionRule(strings.TrimSpace(rule), actual); passed {
				return limitClassDigestAssertionGroupResult{
					Expected: formatLimitClassDigestAssertionGroup(group),
					Actual:   actual,
					Passed:   false,
				}
			}
		}
		for _, nested := range group.Groups {
			if result := evaluateLimitClassDigestAssertionGroup(nested, actual); result.Passed {
				return limitClassDigestAssertionGroupResult{
					Expected: formatLimitClassDigestAssertionGroup(group),
					Actual:   actual,
					Passed:   false,
				}
			}
		}
		return limitClassDigestAssertionGroupResult{
			Expected: formatLimitClassDigestAssertionGroup(group),
			Actual:   actual,
			Passed:   true,
		}
	default:
		return limitClassDigestAssertionGroupResult{
			Expected: formatLimitClassDigestAssertionGroup(group),
			Actual:   actual,
			Passed:   false,
		}
	}
}

func formatLimitClassDigestAssertionGroup(group config.LimitClassDigestAssertionGroup) string {
	operator := strings.TrimSpace(group.Operator)
	if operator == "" {
		operator = "group"
	}
	parts := make([]string, 0, len(group.Rules)+len(group.Groups))
	parts = append(parts, group.Rules...)
	for _, nested := range group.Groups {
		parts = append(parts, formatLimitClassDigestAssertionGroup(nested))
	}
	return operator + "(" + strings.Join(parts, ",") + ")"
}

func limitClassDigestAssertionValueExists(actual interface{}) bool {
	if actual == nil {
		return false
	}
	switch value := actual.(type) {
	case string:
		return strings.TrimSpace(value) != ""
	case []interface{}:
		return len(value) > 0
	case []string:
		return len(value) > 0
	case map[string]interface{}:
		return len(value) > 0
	case map[string]string:
		return len(value) > 0
	default:
		return true
	}
}

func limitClassDigestAssertionContains(actual interface{}, expected interface{}) bool {
	switch value := actual.(type) {
	case string:
		expectedString, _ := expected.(string)
		return strings.Contains(value, expectedString)
	case []interface{}:
		for _, item := range value {
			if reflect.DeepEqual(item, expected) {
				return true
			}
		}
	case []string:
		expectedString, _ := expected.(string)
		for _, item := range value {
			if item == expectedString {
				return true
			}
		}
	}
	return false
}

func toFloat64(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case int32:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func explainLimitClassDigestTargetField(cfg *config.Config, webhookName string, profileName string, fieldName string) (limitClassDigestProfileExplanation, bool) {
	inspection, ok := inspectLimitClassDigestTarget(cfg, webhookName, profileName)
	if !ok {
		return limitClassDigestProfileExplanation{}, false
	}
	finalValue, ok := inspection.EffectiveProfile[fieldName]
	if !ok {
		return limitClassDigestProfileExplanation{}, false
	}
	var stages []limitClassDigestProfileExplainStage
	if inspection.TargetType == "webhook" {
		stages = explainWebhookLimitClassDigestFieldStages(cfg, webhookName, fieldName)
	} else {
		stages = explainNamedProfileLimitClassDigestFieldStages(cfg, profileName, fieldName)
	}
	return limitClassDigestProfileExplanation{
		Inspection:  inspection,
		Field:       fieldName,
		FinalValue:  finalValue,
		FinalSource: inspection.FieldSources[fieldName],
		Stages:      stages,
	}, true
}

func explainWebhookLimitClassDigestFieldStages(cfg *config.Config, webhookName string, fieldName string) []limitClassDigestProfileExplainStage {
	var webhook config.NotificationWebhook
	for _, candidate := range cfg.Security.NotificationWebhooks {
		if strings.TrimSpace(candidate.Name) == webhookName {
			webhook = candidate
			break
		}
	}
	currentProfile := config.LimitAlertRecipientProfile{}
	stages := make([]limitClassDigestProfileExplainStage, 0)
	var previousValue interface{}
	for _, profileName := range webhook.LimitClassDigestProfileChain {
		resolvedName := strings.TrimSpace(profileName)
		profile, ok := cfg.Security.LimitClassDigestProfiles[resolvedName]
		if !ok || resolvedName == "" {
			continue
		}
		currentProfile = mergedLimitClassDigestRecipientProfile(currentProfile, profile)
		stages = appendExplainStageIfChanged(stages, "profile_chain:"+resolvedName, "profile_chain:"+resolvedName, notificationWebhookFromLimitAlertRecipientProfile(currentProfile), cfg.Security.LimitClassDigestHiddenStrategyPolicyPresets, fieldName, &previousValue)
	}
	if profileName := strings.TrimSpace(webhook.LimitClassDigestProfile); profileName != "" {
		if profile, ok := cfg.Security.LimitClassDigestProfiles[profileName]; ok {
			currentProfile = mergedLimitClassDigestRecipientProfile(currentProfile, profile)
			stages = appendExplainStageIfChanged(stages, "profile:"+profileName, "profile:"+profileName, notificationWebhookFromLimitAlertRecipientProfile(currentProfile), cfg.Security.LimitClassDigestHiddenStrategyPolicyPresets, fieldName, &previousValue)
		}
	}
	webhookOverlay := limitAlertRecipientProfileFromNotificationWebhook(webhook)
	currentProfile = mergedLimitClassDigestRecipientProfile(currentProfile, webhookOverlay)
	stages = appendExplainStageIfChanged(stages, "webhook", "webhook", notificationWebhookFromLimitAlertRecipientProfile(currentProfile), cfg.Security.LimitClassDigestHiddenStrategyPolicyPresets, fieldName, &previousValue)
	return stages
}

func explainNamedProfileLimitClassDigestFieldStages(cfg *config.Config, profileName string, fieldName string) []limitClassDigestProfileExplainStage {
	resolvedName := strings.TrimSpace(profileName)
	profile, ok := cfg.Security.LimitClassDigestProfiles[resolvedName]
	if !ok || resolvedName == "" {
		return nil
	}
	stages := make([]limitClassDigestProfileExplainStage, 0, 1)
	var previousValue interface{}
	stages = appendExplainStageIfChanged(stages, "profile:"+resolvedName, "profile:"+resolvedName, notificationWebhookFromLimitAlertRecipientProfile(profile), cfg.Security.LimitClassDigestHiddenStrategyPolicyPresets, fieldName, &previousValue)
	return stages
}

func appendExplainStageIfChanged(stages []limitClassDigestProfileExplainStage, stage string, source string, webhook config.NotificationWebhook, presets map[string]config.LimitClassDigestHiddenStrategyPolicy, fieldName string, previousValue *interface{}) []limitClassDigestProfileExplainStage {
	resolvedWebhook := resolveNotificationWebhookHiddenStrategyPolicyPresets(webhook, presets)
	values := filteredLimitClassDigestInspectionMap(notificationWebhookInspectionMap(resolvedWebhook))
	value, ok := values[fieldName]
	if !ok {
		return stages
	}
	changed := !reflect.DeepEqual(*previousValue, value)
	if !changed {
		return stages
	}
	stages = append(stages, limitClassDigestProfileExplainStage{
		Stage:   stage,
		Source:  source,
		Value:   value,
		Changed: true,
	})
	*previousValue = value
	return stages
}

func inspectLimitClassDigestNamedProfile(cfg *config.Config, profileName string) (limitClassDigestProfileInspection, bool) {
	resolvedName := strings.TrimSpace(profileName)
	profile, ok := cfg.Security.LimitClassDigestProfiles[resolvedName]
	if !ok || resolvedName == "" {
		return limitClassDigestProfileInspection{}, false
	}
	resolvedWebhook := resolveNotificationWebhookHiddenStrategyPolicyPresets(notificationWebhookFromLimitAlertRecipientProfile(profile), cfg.Security.LimitClassDigestHiddenStrategyPolicyPresets)
	effectiveMap := filteredLimitClassDigestInspectionMap(notificationWebhookInspectionMap(resolvedWebhook))
	fieldSources := map[string]string{}
	for key := range effectiveMap {
		fieldSources[key] = "profile:" + resolvedName
	}
	assignLimitClassDigestPolicyFieldSource(fieldSources, effectiveMap, map[string]interface{}{},
		"limitClassDigestTruncatedReasonBucketExactSeverityPolicy",
		map[string]string{
			"limitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset":      "profile:" + resolvedName,
			"limitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain": "profile:" + resolvedName,
		},
		[]string{"limitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset", "limitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain"},
	)
	assignLimitClassDigestPolicyFieldSource(fieldSources, effectiveMap, map[string]interface{}{},
		"limitClassDigestTruncatedReasonBucketMinSeverityPolicy",
		map[string]string{
			"limitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset":      "profile:" + resolvedName,
			"limitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain": "profile:" + resolvedName,
		},
		[]string{"limitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset", "limitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain"},
	)
	assignLimitClassDigestPolicyFieldSource(fieldSources, effectiveMap, map[string]interface{}{},
		"limitClassDigestTruncatedReasonBucketMaxReasonsPolicy",
		map[string]string{
			"limitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset":      "profile:" + resolvedName,
			"limitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain": "profile:" + resolvedName,
		},
		[]string{"limitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset", "limitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain"},
	)

	availableProfiles := make([]string, 0, len(cfg.Security.LimitClassDigestProfiles))
	for name := range cfg.Security.LimitClassDigestProfiles {
		availableProfiles = append(availableProfiles, name)
	}
	sort.Strings(availableProfiles)
	return limitClassDigestProfileInspection{
		ProfileName:       resolvedName,
		TargetType:        "profile",
		AppliedProfiles:   []map[string]interface{}{{"name": resolvedName, "source": "profile"}},
		EffectiveProfile:  effectiveMap,
		FieldSources:      fieldSources,
		AvailableProfiles: availableProfiles,
	}, true
}

func inspectLimitClassDigestProfile(cfg *config.Config, webhookName string) (limitClassDigestProfileInspection, bool) {
	var webhook config.NotificationWebhook
	found := false
	for _, candidate := range cfg.Security.NotificationWebhooks {
		if strings.TrimSpace(candidate.Name) == webhookName {
			webhook = candidate
			found = true
			break
		}
	}
	if !found {
		return limitClassDigestProfileInspection{}, false
	}

	_, profileSources, appliedProfiles := resolvedLimitClassDigestProfileStack(webhook, cfg.Security.LimitClassDigestProfiles)
	resolvedWebhook := effectiveNotificationWebhookLimitClassDigestProfile(webhook, cfg.Security.LimitClassDigestProfiles)
	resolvedWebhook = resolveNotificationWebhookHiddenStrategyPolicyPresets(resolvedWebhook, cfg.Security.LimitClassDigestHiddenStrategyPolicyPresets)

	effectiveMap := filteredLimitClassDigestInspectionMap(notificationWebhookInspectionMap(resolvedWebhook))
	originalMap := filteredLimitClassDigestInspectionMap(notificationWebhookInspectionMap(webhook))
	fieldSources := map[string]string{}
	for key, value := range effectiveMap {
		if originalValue, ok := originalMap[key]; ok && reflect.DeepEqual(originalValue, value) {
			fieldSources[key] = "webhook"
			continue
		}
		if source, ok := profileSources[key]; ok {
			fieldSources[key] = source
		}
	}
	assignLimitClassDigestPolicyFieldSource(fieldSources, effectiveMap, originalMap,
		"limitClassDigestTruncatedReasonBucketExactSeverityPolicy",
		profileSources,
		[]string{"limitClassDigestTruncatedReasonBucketExactSeverityPolicyPreset", "limitClassDigestTruncatedReasonBucketExactSeverityPolicyPresetChain"},
	)
	assignLimitClassDigestPolicyFieldSource(fieldSources, effectiveMap, originalMap,
		"limitClassDigestTruncatedReasonBucketMinSeverityPolicy",
		profileSources,
		[]string{"limitClassDigestTruncatedReasonBucketMinSeverityPolicyPreset", "limitClassDigestTruncatedReasonBucketMinSeverityPolicyPresetChain"},
	)
	assignLimitClassDigestPolicyFieldSource(fieldSources, effectiveMap, originalMap,
		"limitClassDigestTruncatedReasonBucketMaxReasonsPolicy",
		profileSources,
		[]string{"limitClassDigestTruncatedReasonBucketMaxReasonsPolicyPreset", "limitClassDigestTruncatedReasonBucketMaxReasonsPolicyPresetChain"},
	)

	availableProfiles := make([]string, 0, len(cfg.Security.LimitClassDigestProfiles))
	for name := range cfg.Security.LimitClassDigestProfiles {
		availableProfiles = append(availableProfiles, name)
	}
	sort.Strings(availableProfiles)

	return limitClassDigestProfileInspection{
		TargetType:        "webhook",
		WebhookName:       strings.TrimSpace(webhook.Name),
		WebhookURL:        strings.TrimSpace(webhook.URL),
		ProfileChain:      append([]string(nil), webhook.LimitClassDigestProfileChain...),
		Profile:           strings.TrimSpace(webhook.LimitClassDigestProfile),
		AppliedProfiles:   appliedProfiles,
		EffectiveProfile:  effectiveMap,
		FieldSources:      fieldSources,
		AvailableProfiles: availableProfiles,
	}, true
}

func resolvedLimitClassDigestProfileStack(webhook config.NotificationWebhook, profiles map[string]config.LimitAlertRecipientProfile) (config.LimitAlertRecipientProfile, map[string]string, []map[string]interface{}) {
	merged := config.LimitAlertRecipientProfile{}
	fieldSources := map[string]string{}
	applied := []map[string]interface{}{}
	for _, profileName := range webhook.LimitClassDigestProfileChain {
		resolvedName := strings.TrimSpace(profileName)
		profile, ok := profiles[resolvedName]
		if !ok || resolvedName == "" {
			continue
		}
		beforeMap := filteredLimitClassDigestInspectionMap(notificationWebhookInspectionMap(notificationWebhookFromLimitAlertRecipientProfile(merged)))
		merged = mergedLimitClassDigestRecipientProfile(merged, profile)
		afterMap := filteredLimitClassDigestInspectionMap(notificationWebhookInspectionMap(notificationWebhookFromLimitAlertRecipientProfile(merged)))
		updateLimitClassDigestInspectionSources(fieldSources, beforeMap, afterMap, "profile_chain:"+resolvedName)
		applied = append(applied, map[string]interface{}{"name": resolvedName, "source": "profile_chain"})
	}
	if profileName := strings.TrimSpace(webhook.LimitClassDigestProfile); profileName != "" {
		if profile, ok := profiles[profileName]; ok {
			beforeMap := filteredLimitClassDigestInspectionMap(notificationWebhookInspectionMap(notificationWebhookFromLimitAlertRecipientProfile(merged)))
			merged = mergedLimitClassDigestRecipientProfile(merged, profile)
			afterMap := filteredLimitClassDigestInspectionMap(notificationWebhookInspectionMap(notificationWebhookFromLimitAlertRecipientProfile(merged)))
			updateLimitClassDigestInspectionSources(fieldSources, beforeMap, afterMap, "profile:"+profileName)
			applied = append(applied, map[string]interface{}{"name": profileName, "source": "profile"})
		}
	}
	return merged, fieldSources, applied
}

func notificationWebhookInspectionMap(webhook config.NotificationWebhook) map[string]interface{} {
	bytes, err := json.Marshal(webhook)
	if err != nil {
		return map[string]interface{}{}
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return map[string]interface{}{}
	}
	return decoded
}

func filteredLimitClassDigestInspectionMap(values map[string]interface{}) map[string]interface{} {
	filtered := map[string]interface{}{}
	for key, value := range values {
		if strings.HasPrefix(key, "limitClassDigest") ||
			strings.HasPrefix(key, "limitClassSnooze") ||
			strings.HasPrefix(key, "minLimitAlert") ||
			key == "limitAlertTypes" ||
			key == "limitAlertKeyTypes" ||
			key == "limitAlertBucketClasses" ||
			key == "limitAlertBucketIDRegex" ||
			key == "limitAlertCooldown" {
			filtered[key] = value
		}
	}
	return filtered
}

func updateLimitClassDigestInspectionSources(target map[string]string, before, after map[string]interface{}, label string) {
	for key, value := range after {
		if reflect.DeepEqual(before[key], value) {
			continue
		}
		target[key] = label
	}
}

func assignLimitClassDigestPolicyFieldSource(fieldSources map[string]string, effectiveMap, originalMap map[string]interface{}, policyField string, profileSources map[string]string, fallbackFields []string) {
	if _, ok := effectiveMap[policyField]; !ok {
		return
	}
	if originalValue, ok := originalMap[policyField]; ok && reflect.DeepEqual(originalValue, effectiveMap[policyField]) {
		fieldSources[policyField] = "webhook"
		return
	}
	if _, ok := fieldSources[policyField]; ok {
		return
	}
	for _, field := range fallbackFields {
		if source, ok := profileSources[field]; ok {
			fieldSources[policyField] = source
			return
		}
	}
}
