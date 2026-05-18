package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bhangun/iket/pkg/config"
	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/bhangun/iket/pkg/core/gateway"
	"github.com/gorilla/mux"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (api *ManagementAPI) createBackup(w http.ResponseWriter, r *http.Request) {
	backupID, filePath, size, err := createConfigBackup(api.gateway.GetConfig())
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to create backup", err), http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "Backup created successfully",
		Data: map[string]interface{}{
			"backup_id":  backupID,
			"filename":   filepath.Base(filePath),
			"size_bytes": size,
			"created_at": time.Now(),
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) listBackups(w http.ResponseWriter, r *http.Request) {
	backups, err := listConfigBackups()
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to list backups", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"backups": backups,
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) restoreBackup(w http.ResponseWriter, r *http.Request) {
	if err := restoreConfigBackup(api.gateway, mux.Vars(r)["id"]); err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	api.lastReload = time.Now()

	response := APIResponse{
		Success: true,
		Message: "Backup restored successfully",
		Data: map[string]interface{}{
			"restart_required": true,
		},
	}
	api.writeJSON(w, response)
}

func (api *ManagementAPI) listRevisions(w http.ResponseWriter, r *http.Request) {
	revisions, err := listConfigRevisions()
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to list revisions", err), http.StatusInternalServerError)
		return
	}
	api.writeJSON(w, map[string]interface{}{
		"revisions": revisions,
	})
}

func (api *ManagementAPI) getRevision(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigRevision(mux.Vars(r)["id"])
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	serviceCount := 0
	routeCount := 0
	if record.Config != nil {
		for _, svcCfg := range record.Config.Services {
			serviceCount += len(svcCfg.Services)
			for _, svc := range svcCfg.Services {
				routeCount += len(svc.Routes)
			}
		}
	}
	api.writeJSON(w, map[string]interface{}{
		"id":            record.ID,
		"action":        record.Action,
		"label":         record.Label,
		"note":          record.Note,
		"change_ref":    record.ChangeRef,
		"created_at":    record.CreatedAt,
		"summary":       record.Summary,
		"service_count": serviceCount,
		"route_count":   routeCount,
		"config":        record.Config,
	})
}

func (api *ManagementAPI) diffRevisions(w http.ResponseWriter, r *http.Request) {
	fromID := strings.TrimSpace(r.URL.Query().Get("from"))
	toID := strings.TrimSpace(r.URL.Query().Get("to"))
	if fromID == "" || toID == "" {
		api.writeManagedError(w, managedRequiredFieldError("from and to query parameters are required"), http.StatusBadRequest)
		return
	}

	fromCfg, fromMeta, err := api.resolveRevisionConfig(fromID)
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	toCfg, toMeta, err := api.resolveRevisionConfig(toID)
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}

	api.writeJSON(w, map[string]interface{}{
		"from": map[string]interface{}{
			"id":         fromID,
			"source":     fromMeta["source"],
			"action":     fromMeta["action"],
			"label":      fromMeta["label"],
			"note":       fromMeta["note"],
			"change_ref": fromMeta["change_ref"],
			"created_at": fromMeta["created_at"],
		},
		"to": map[string]interface{}{
			"id":         toID,
			"source":     toMeta["source"],
			"action":     toMeta["action"],
			"label":      toMeta["label"],
			"note":       toMeta["note"],
			"change_ref": toMeta["change_ref"],
			"created_at": toMeta["created_at"],
		},
		"config_summary":  configChangeSummary(fromCfg, toCfg),
		"service_summary": serviceChangeSummary(fromCfg, toCfg),
	})
}

func (api *ManagementAPI) restoreRevision(w http.ResponseWriter, r *http.Request) {
	record, err := loadConfigRevision(mux.Vars(r)["id"])
	if err != nil {
		api.writeManagedError(w, err, http.StatusNotFound)
		return
	}
	if record.Config == nil {
		api.writeManagedError(w, managedError(coreerrors.CodeRevisionConfigMissing, "Revision has no stored configuration", nil), http.StatusInternalServerError)
		return
	}
	summary := map[string]interface{}{
		"restored_from_revision": record.ID,
		"original_action":        record.Action,
	}
	label, note, changeRef := revisionMetadataFromRequest(r)
	if err := api.applyManagedConfigChange(record.Config, "restore_revision", label, note, changeRef, summary); err != nil {
		api.writeManagedError(w, managedConfigError("Failed to restore revision", err), http.StatusInternalServerError)
		return
	}
	api.writeJSON(w, APIResponse{
		Success: true,
		Message: "Revision restored successfully",
		Data: map[string]interface{}{
			"revision_id": record.ID,
			"summary":     summary,
		},
	})
}

type configRevisionRecord struct {
	ID        string                 `json:"id"`
	Action    string                 `json:"action"`
	Label     string                 `json:"label,omitempty"`
	Note      string                 `json:"note,omitempty"`
	ChangeRef string                 `json:"change_ref,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
	Summary   map[string]interface{} `json:"summary,omitempty"`
	Config    *config.Config         `json:"config"`
}

func createConfigBackup(cfg *config.Config) (string, string, int64, error) {
	if err := os.MkdirAll(backupsDir(), 0755); err != nil {
		return "", "", 0, err
	}
	id := fmt.Sprintf("backup-%s", time.Now().Format("20060102-150405"))
	path := filepath.Join(backupsDir(), id+".json")
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", "", 0, err
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", "", 0, err
	}
	return id, path, int64(len(data)), nil
}

func listConfigBackups() ([]map[string]interface{}, error) {
	if err := os.MkdirAll(backupsDir(), 0755); err != nil {
		return nil, err
	}
	files, err := os.ReadDir(backupsDir())
	if err != nil {
		return nil, err
	}
	backups := make([]map[string]interface{}, 0)
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}
		info, err := file.Info()
		if err != nil {
			continue
		}
		backups = append(backups, map[string]interface{}{
			"id":         strings.TrimSuffix(file.Name(), ".json"),
			"filename":   file.Name(),
			"size_bytes": info.Size(),
			"created_at": info.ModTime(),
		})
	}
	return backups, nil
}

func restoreConfigBackup(gw *gateway.Gateway, id string) error {
	path := filepath.Join(backupsDir(), id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return coreerrors.New(coreerrors.CodeBackupNotFound, "Backup not found")
		}
		return err
	}
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	return gw.UpdateConfig(&cfg)
}

func saveConfigRevision(action, label, note, changeRef string, summary map[string]interface{}, cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("configuration not available")
	}
	if err := os.MkdirAll(revisionsDir(), 0755); err != nil {
		return "", err
	}
	id := fmt.Sprintf("rev-%s", time.Now().UTC().Format("20060102-150405.000000000"))
	cloned, err := cloneConfig(cfg)
	if err != nil {
		return "", err
	}
	record := configRevisionRecord{
		ID:        id,
		Action:    action,
		Label:     strings.TrimSpace(label),
		Note:      strings.TrimSpace(note),
		ChangeRef: strings.TrimSpace(changeRef),
		CreatedAt: time.Now().UTC(),
		Summary:   summary,
		Config:    cloned,
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(revisionsDir(), id+".json"), data, 0644); err != nil {
		return "", err
	}
	return id, nil
}

func listConfigRevisions() ([]map[string]interface{}, error) {
	if err := os.MkdirAll(revisionsDir(), 0755); err != nil {
		return nil, err
	}
	files, err := os.ReadDir(revisionsDir())
	if err != nil {
		return nil, err
	}
	revisions := make([]map[string]interface{}, 0)
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(revisionsDir(), file.Name()))
		if err != nil {
			continue
		}
		var record configRevisionRecord
		if err := json.Unmarshal(data, &record); err != nil {
			continue
		}
		serviceCount := 0
		routeCount := 0
		if record.Config != nil {
			for _, svcCfg := range record.Config.Services {
				serviceCount += len(svcCfg.Services)
				for _, svc := range svcCfg.Services {
					routeCount += len(svc.Routes)
				}
			}
		}
		revisions = append(revisions, map[string]interface{}{
			"id":            record.ID,
			"action":        record.Action,
			"label":         record.Label,
			"note":          record.Note,
			"change_ref":    record.ChangeRef,
			"created_at":    record.CreatedAt,
			"summary":       record.Summary,
			"service_count": serviceCount,
			"route_count":   routeCount,
		})
	}
	sort.SliceStable(revisions, func(i, j int) bool {
		return fmt.Sprint(revisions[i]["id"]) > fmt.Sprint(revisions[j]["id"])
	})
	return revisions, nil
}

func loadConfigRevision(id string) (*configRevisionRecord, error) {
	data, err := os.ReadFile(filepath.Join(revisionsDir(), id+".json"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, coreerrors.New(coreerrors.CodeRevisionNotFound, "Revision not found")
		}
		return nil, err
	}
	var record configRevisionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func (api *ManagementAPI) resolveRevisionConfig(id string) (*config.Config, map[string]interface{}, error) {
	if strings.EqualFold(id, "current") {
		cfg, err := cloneConfig(api.gateway.GetConfig())
		if err != nil {
			return nil, nil, err
		}
		return cfg, map[string]interface{}{
			"source":     "current",
			"action":     "live_config",
			"label":      "",
			"note":       "",
			"change_ref": "",
			"created_at": time.Now().UTC(),
		}, nil
	}
	record, err := loadConfigRevision(id)
	if err != nil {
		return nil, nil, err
	}
	if record.Config == nil {
		return nil, nil, coreerrors.New(coreerrors.CodeRevisionConfigMissing, "Revision has no stored configuration")
	}
	return record.Config, map[string]interface{}{
		"source":     "revision",
		"action":     record.Action,
		"label":      record.Label,
		"note":       record.Note,
		"change_ref": record.ChangeRef,
		"created_at": record.CreatedAt,
	}, nil
}
