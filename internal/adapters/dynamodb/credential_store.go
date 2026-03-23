package dynamodb

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/zeroverify/revocation-lambda/internal/domain"
)

type CredentialStore struct {
	readClient  *dynamodb.Client
	writeClient *dynamodb.Client
	tableName   string
}

func NewCredentialStore(localCfg, primaryCfg aws.Config, tableName string) *CredentialStore {
	return &CredentialStore{
		readClient:  dynamodb.NewFromConfig(localCfg),
		writeClient: dynamodb.NewFromConfig(primaryCfg),
		tableName:   tableName,
	}
}

type credentialItem struct {
	SubjectID       string `dynamodbav:"subject_id"`
	CredentialID    string `dynamodbav:"credential_id"`
	RevocationIndex int    `dynamodbav:"revocation_index"`
	Status          string `dynamodbav:"status"`
}

func (s *CredentialStore) FindByKey(ctx context.Context, subjectID, credentialID string) (*domain.CredentialRecord, error) {
	out, err := s.readClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]dbtypes.AttributeValue{
			"subject_id":    &dbtypes.AttributeValueMemberS{Value: subjectID},
			"credential_id": &dbtypes.AttributeValueMemberS{Value: credentialID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("getting credential %q: %w", credentialID, err)
	}

	if out.Item == nil {
		return nil, domain.ErrCredentialNotFound
	}

	var ci credentialItem
	if err := attributevalue.UnmarshalMap(out.Item, &ci); err != nil {
		return nil, fmt.Errorf("unmarshalling credential item: %w", err)
	}

	return &domain.CredentialRecord{
		SubjectID:       ci.SubjectID,
		CredentialID:    ci.CredentialID,
		RevocationIndex: ci.RevocationIndex,
		Status:          domain.CredentialStatus(ci.Status),
	}, nil
}

func (s *CredentialStore) MarkRevoked(ctx context.Context, record *domain.CredentialRecord) error {
	_, err := s.writeClient.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]dbtypes.AttributeValue{
			"subject_id":    &dbtypes.AttributeValueMemberS{Value: record.SubjectID},
			"credential_id": &dbtypes.AttributeValueMemberS{Value: record.CredentialID},
		},
		ConditionExpression: aws.String("#st = :active"),
		UpdateExpression:    aws.String("SET #st = :revoked"),
		ExpressionAttributeNames: map[string]string{
			"#st": "status",
		},
		ExpressionAttributeValues: map[string]dbtypes.AttributeValue{
			":active":  &dbtypes.AttributeValueMemberS{Value: string(domain.StatusActive)},
			":revoked": &dbtypes.AttributeValueMemberS{Value: string(domain.StatusRevoked)},
		},
	})
	if err != nil {
		var ccfe *dbtypes.ConditionalCheckFailedException
		if errors.As(err, &ccfe) {
			return domain.ErrCredentialAlreadyRevoked
		}
		return fmt.Errorf("revoking credential %q: %w", record.CredentialID, err)
	}

	return nil
}

