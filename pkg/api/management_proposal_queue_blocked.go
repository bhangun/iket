package api

import (
	"net/http"
	"sort"
	"strings"
)

func (api *ManagementAPI) getBlockedProposalQueueReport(w http.ResponseWriter, r *http.Request) {
	proposals, err := listConfigProposals()
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to list proposals", err), http.StatusInternalServerError)
		return
	}

	filterEnv := strings.TrimSpace(r.URL.Query().Get("environment"))
	filterStatus := strings.TrimSpace(r.URL.Query().Get("status"))
	type blockerSummary struct {
		Reason      string   `json:"reason"`
		Count       int      `json:"count"`
		ProposalIDs []string `json:"proposal_ids"`
	}

	index := map[string]*blockerSummary{}
	blockedProposalIDs := make([]string, 0)
	byAction := map[string]int{}

	for _, proposal := range proposals {
		id, _ := proposal["id"].(string)
		if strings.TrimSpace(id) == "" {
			continue
		}
		record, err := loadConfigProposal(id)
		if err != nil {
			continue
		}
		if filterEnv != "" && record.Environment != filterEnv {
			continue
		}
		if filterStatus != "" && record.Status != filterStatus {
			continue
		}
		readiness, err := api.buildProposalReadiness(record)
		if err != nil {
			continue
		}
		if ready, _ := readiness["ready_for_apply"].(bool); ready {
			continue
		}
		blockers, _ := readiness["blockers"].([]string)
		if len(blockers) == 0 {
			continue
		}
		blockedProposalIDs = append(blockedProposalIDs, record.ID)
		actionKey := strings.TrimSpace(record.Action)
		if actionKey == "" {
			actionKey = "unknown"
		}
		byAction[actionKey]++
		for _, blocker := range blockers {
			summary := index[blocker]
			if summary == nil {
				summary = &blockerSummary{Reason: blocker}
				index[blocker] = summary
			}
			summary.Count++
			summary.ProposalIDs = append(summary.ProposalIDs, record.ID)
		}
	}

	summaries := make([]blockerSummary, 0, len(index))
	for _, summary := range index {
		summaries = append(summaries, *summary)
	}
	sort.SliceStable(summaries, func(i, j int) bool {
		if summaries[i].Count != summaries[j].Count {
			return summaries[i].Count > summaries[j].Count
		}
		return summaries[i].Reason < summaries[j].Reason
	})

	api.writeJSON(w, map[string]interface{}{
		"blocked_proposal_count": len(blockedProposalIDs),
		"blocked_proposal_ids":   blockedProposalIDs,
		"blockers":               summaries,
		"by_action":              byAction,
		"filters": map[string]interface{}{
			"environment": filterEnv,
			"status":      filterStatus,
		},
	})
}
