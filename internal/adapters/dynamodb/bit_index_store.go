package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/zeroverify/revocation-lambda/internal/domain"
)

type BitIndexStore struct {
	readClient  *dynamodb.Client
	writeClient *dynamodb.Client
	tableName   string
}

func NewBitIndexStore(localCfg, primaryCfg aws.Config, tableName string) *BitIndexStore {
	return &BitIndexStore{
		readClient:  dynamodb.NewFromConfig(localCfg),
		writeClient: dynamodb.NewFromConfig(primaryCfg),
		tableName:   tableName,
	}
}

func (s *BitIndexStore) MarkRevoked(ctx context.Context, bitIndex int) error {
	_, err := s.writeClient.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"bit_index": &types.AttributeValueMemberN{Value: strconv.Itoa(bitIndex)},
		},
		ConditionExpression: aws.String("#st = :claimed"),
		UpdateExpression:    aws.String("SET #st = :revoked"),
		ExpressionAttributeNames: map[string]string{
			"#st": "status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":claimed": &types.AttributeValueMemberS{Value: string(domain.BitClaimed)},
			":revoked": &types.AttributeValueMemberS{Value: string(domain.BitRevoked)},
		},
	})
	if err != nil {
		var ccfe *types.ConditionalCheckFailedException
		if errors.As(err, &ccfe) {
			return domain.ErrCredentialAlreadyRevoked
		}
		return fmt.Errorf("marking bit index %d revoked: %w", bitIndex, err)
	}

	return nil
}
