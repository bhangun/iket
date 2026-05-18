package api

import (
	"net/http"
	"strings"
)

func proposalMetadataFromRequest(r *http.Request, record *configProposalRecord) (string, string, string) {
	label, note, changeRef := revisionMetadataFromRequest(r)
	if record == nil {
		return label, note, changeRef
	}
	return firstNonEmpty(label, record.Label), firstNonEmpty(note, record.Note), firstNonEmpty(changeRef, record.ChangeRef)
}

func proposalReviewMetadataFromRequest(r *http.Request, record *configProposalRecord) (string, string) {
	if r == nil {
		if record == nil {
			return "", ""
		}
		return strings.TrimSpace(record.ReviewedBy), strings.TrimSpace(record.ReviewNote)
	}
	reviewer := strings.TrimSpace(r.URL.Query().Get("reviewer"))
	reviewNote := strings.TrimSpace(r.URL.Query().Get("review_note"))
	if record == nil {
		return reviewer, reviewNote
	}
	return firstNonEmpty(reviewer, record.ReviewedBy), firstNonEmpty(reviewNote, record.ReviewNote)
}
