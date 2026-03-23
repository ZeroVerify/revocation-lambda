package domain

type CredentialStatus string

const (
	StatusActive  CredentialStatus = "ACTIVE"
	StatusRevoked CredentialStatus = "REVOKED"
)

type BitIndexStatus string

const (
	BitClaimed BitIndexStatus = "CLAIMED"
	BitRevoked BitIndexStatus = "REVOKED"
)

type CredentialRecord struct {
	SubjectID       string
	CredentialID    string
	RevocationIndex int
	Status          CredentialStatus
}
