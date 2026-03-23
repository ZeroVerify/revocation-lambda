package domain

import "errors"

var (
	ErrCredentialNotFound      = errors.New("credential not found")
	ErrCredentialAlreadyRevoked = errors.New("credential already revoked")
	ErrProofInvalid            = errors.New("proof verification failed")
)
