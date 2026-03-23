package models

type RevokeCredentialRequest struct {
	CredentialID string `json:"credential_id"`
	SubjectID    string `json:"subject_id"`
	Proof        string `json:"proof"`
}
