package handler

import (
	"context"
	// added (below)
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	verifier "github.com/zeroverify/verifier-go"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const credentialsTable = "zeroverify-credentials"

type Handler struct {
	db *dynamodb.Client
}

type RequestBody struct {
	SubjectID          string            `json:"subjectId"`
	CredentialID       string            `json:"credentialId"`
	ProofJSON          json.RawMessage   `json:"proofJson"`
	ExpectedChallenge  string            `json:"expectedChallenge"`
	Challenge          string            `json:"challenge"`
	ExpiresAt          int64             `json:"expiresAt"`
	RevocationIndex    int               `json:"revocationIndex"`
	BitstringB64       string            `json:"bitstring"`
	VerificationKeyB64 string            `json:"verificationKey"`
	BabyJubJubPubKey   string            `json:"babyJubJubPubKey"`
	Fields             map[string]string `json:"fields"`
	Signatures         map[string]string `json:"signatures"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

var dbClient *dynamodb.Client

func init() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("failed to load AWS config: %v", err)
	}
	dbClient = dynamodb.NewFromConfig(cfg)
}

func NewHandler() *Handler {
	return &Handler{db: dbClient}
}

func (h *Handler) Handle(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {

	// only handle revoke endpoint
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

	bitstring, err := base64.StdEncoding.DecodeString(body.BitstringB64)
	if err != nil {
		return errResponse(http.StatusBadRequest, "invalid_request", "invalid bitstring"), nil
	}

	verificationKey, err := base64.StdEncoding.DecodeString(body.VerificationKeyB64)
	if err != nil {
		return errResponse(http.StatusBadRequest, "invalid_request", "invalid verification key"), nil
	}

	verifyReq := verifier.VerifyRequest{
		ProofJSON:         body.ProofJSON,
		ExpectedChallenge: body.ExpectedChallenge,
		VerificationKey:   verificationKey,
		Bitstring:         bitstring,
		BabyJubJubPubKey:  body.BabyJubJubPubKey,
		Inputs: verifier.CircuitInputs{
			Fields:          body.Fields,
			Signatures:      body.Signatures,
			Challenge:       body.Challenge,
			ExpiresAt:       body.ExpiresAt,
			RevocationIndex: body.RevocationIndex,
		},
	}

	verifyResult, err := verifier.Verify(verifyReq)
	if err != nil {
		log.Printf("verify error: %v", err)
		return errResponse(http.StatusInternalServerError, "internal_error", "verification failed"), nil
	}

	if !verifyResult.Valid {
		return errResponse(http.StatusBadRequest, verifyResult.Reason, "proof invalid"), nil
	}

	// update DynamoDB (ACTIVE -> REVOKED)
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
		ExpressionAttributeValues: mustMarshalValues(map[string]string{
			":revoked": "REVOKED",
			":active":  "ACTIVE",
		}),
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return errResponse(http.StatusBadRequest, "already_revoked", "credential not ACTIVE"), nil
		}

		log.Printf("dynamo error: %v", err)
		return errResponse(http.StatusInternalServerError, "internal_error", "db update failed"), nil
	}

	return jsonResponse(http.StatusAccepted, map[string]string{
		"status": "credential revoked",
	}), nil
}

func mustMarshalValues(values map[string]string) map[string]types.AttributeValue {
	out := make(map[string]types.AttributeValue)
	for k, v := range values {
		av, err := attributevalue.Marshal(v)
		if err != nil {
			panic(err)
		}
		out[k] = av
	}
	return out
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
