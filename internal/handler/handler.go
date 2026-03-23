package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	verifier "github.com/zeroverify/verifier-go"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const credentialsTable = "zeroverify-credentials"

type Handler struct {
	db      *dynamodb.Client
	fetcher *verifier.Fetcher
}

type RequestBody struct {
	SubjectID    string          `json:"subjectId"`
	CredentialID string          `json:"credentialId"`
	ProofJSON    json.RawMessage `json:"proofJson"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

var (
	dbClient *dynamodb.Client
	fetcher  *verifier.Fetcher
)

func init() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("failed to load AWS config: %v", err)
	}
	dbClient = dynamodb.NewFromConfig(cfg)
	fetcher = verifier.NewFetcher().Build()
}

func NewHandler() *Handler {
	return &Handler{db: dbClient, fetcher: fetcher}
}

func (h *Handler) Handle(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	if req.RequestContext.HTTP.Method != http.MethodPost || req.RequestContext.HTTP.Path != "/api/v1/credentials/revoke" {
		return errResponse(http.StatusNotFound, "not_found", "endpoint not found"), nil
	}

	var body RequestBody
	if err := json.Unmarshal([]byte(req.Body), &body); err != nil {
		return errResponse(http.StatusBadRequest, "invalid_request", "invalid JSON body"), nil
	}

	if body.SubjectID == "" || body.CredentialID == "" || len(body.ProofJSON) == 0 {
		return errResponse(http.StatusBadRequest, "invalid_request", "missing required fields"), nil
	}

	vkJSON, err := h.fetcher.VerificationKey(ctx, "credential_revocation")
	if err != nil {
		log.Printf("fetching verification key: %v", err)
		return errResponse(http.StatusInternalServerError, "internal_error", "could not fetch verification key"), nil
	}

	pubKeyHex, err := h.fetcher.BabyJubJubPublicKey(ctx)
	if err != nil {
		log.Printf("fetching issuer public key: %v", err)
		return errResponse(http.StatusInternalServerError, "internal_error", "could not fetch issuer public key"), nil
	}

	verifyResult, err := verifier.Verify(verifier.VerifyRequest{
		ProofJSON:        body.ProofJSON,
		VerificationKey:  vkJSON,
		BabyJubJubPubKey: pubKeyHex,
		Circuit:          verifier.RevocationCircuit,
		Inputs: verifier.CircuitInputs{
			CredentialID: body.CredentialID,
		},
	})
	if err != nil {
		log.Printf("verify error: %v", err)
		return errResponse(http.StatusInternalServerError, "internal_error", "verification failed"), nil
	}

	if !verifyResult.Valid {
		return errResponse(http.StatusBadRequest, verifyResult.Reason, "proof invalid"), nil
	}

	_, err = h.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(credentialsTable),
		Key: map[string]types.AttributeValue{
			"subject_id":    &types.AttributeValueMemberS{Value: body.SubjectID},
			"credential_id": &types.AttributeValueMemberS{Value: body.CredentialID},
		},
		UpdateExpression:    aws.String("SET #status = :revoked"),
		ConditionExpression: aws.String("#status = :active"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":revoked": &types.AttributeValueMemberS{Value: "REVOKED"},
			":active":  &types.AttributeValueMemberS{Value: "ACTIVE"},
		},
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return errResponse(http.StatusConflict, "already_revoked", "credential is not active"), nil
		}
		log.Printf("dynamo error: %v", err)
		return errResponse(http.StatusInternalServerError, "internal_error", "db update failed"), nil
	}

	return jsonResponse(http.StatusAccepted, map[string]string{
		"status": "credential revoked",
	}), nil
}

func jsonResponse(status int, body any) events.APIGatewayV2HTTPResponse {
	b, _ := json.Marshal(body)
	return events.APIGatewayV2HTTPResponse{
		StatusCode: status,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(b),
	}
}

func errResponse(status int, code, msg string) events.APIGatewayV2HTTPResponse {
	return jsonResponse(status, errorResponse{
		Error:   code,
		Message: msg,
	})
}
