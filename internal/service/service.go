package service

import (
	"context"
	"fmt"

	verifier "github.com/zeroverify/verifier-go"

	"github.com/zeroverify/revocation-lambda/internal/adapters/dynamodb"
	"github.com/zeroverify/revocation-lambda/internal/domain"
)

type RevocationService struct {
	creds   *dynamodb.CredentialStore
	bits    *dynamodb.BitIndexStore
	fetcher *verifier.Fetcher
}

func New(
	creds *dynamodb.CredentialStore,
	bits *dynamodb.BitIndexStore,
	fetcher *verifier.Fetcher,
) *RevocationService {
	return &RevocationService{
		creds:   creds,
		bits:    bits,
		fetcher: fetcher,
	}
}

func (s *RevocationService) RevokeCredential(ctx context.Context, subjectID, credentialID string, proofJSON []byte) error {
	record, err := s.creds.FindByKey(ctx, subjectID, credentialID)
	if err != nil {
		return err
	}

	if record.Status == domain.StatusRevoked {
		return domain.ErrCredentialAlreadyRevoked
	}

	if err := s.verifyProof(ctx, credentialID, proofJSON); err != nil {
		return err
	}

	if err := s.creds.MarkRevoked(ctx, record); err != nil {
		return err
	}

	if err := s.bits.MarkRevoked(ctx, record.RevocationIndex); err != nil {
		return fmt.Errorf("marking revocation bit: %w", err)
	}

	return nil
}

func (s *RevocationService) verifyProof(ctx context.Context, credentialID string, proofJSON []byte) error {
	vkJSON, err := s.fetcher.VerificationKey(ctx, "credential_revocation")
	if err != nil {
		return fmt.Errorf("fetching verification key: %w", err)
	}

	pubKeyHex, err := s.fetcher.BabyJubJubPublicKey(ctx)
	if err != nil {
		return fmt.Errorf("fetching issuer public key: %w", err)
	}

	ax, ay, err := verifier.DecompressBabyJubJubKey(pubKeyHex)
	if err != nil {
		return fmt.Errorf("decompressing issuer public key: %w", err)
	}

	credIDFE := verifier.FieldElement(credentialID).String()
	signals := []string{credIDFE, ax, ay}

	result, err := verifier.VerifyProof(proofJSON, vkJSON, signals)
	if err != nil {
		return fmt.Errorf("verifying proof: %w", err)
	}

	if !result.Valid {
		return domain.ErrProofInvalid
	}

	return nil
}
