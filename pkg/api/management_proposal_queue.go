package api

import (
	"net/http"
)

func (api *ManagementAPI) listProposals(w http.ResponseWriter, r *http.Request) {
	proposals, err := listConfigProposals()
	if err != nil {
		api.writeManagedError(w, managedConfigError("Failed to list proposals", err), http.StatusInternalServerError)
		return
	}
	for _, proposal := range proposals {
		id, _ := proposal["id"].(string)
		if id == "" {
			continue
		}
		record, err := loadConfigProposal(id)
		if err != nil {
			continue
		}
		proposal["approval_count"] = proposalApprovalCount(api.gateway.GetConfig(), record)
		proposal["required_approvals"] = requiredProposalApprovers(api.gateway.GetConfig(), record)
	}
	api.writeJSON(w, map[string]interface{}{
		"proposals": proposals,
	})
}

func (api *ManagementAPI) getProposalQueue(w http.ResponseWriter, r *http.Request) {
	response, statusCode, err := api.buildProposalQueueSnapshot(r)
	if err != nil {
		api.writeManagedError(w, err, statusCode)
		return
	}
	api.writeJSON(w, response)
}
