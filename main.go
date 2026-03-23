package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

type RequestBody struct {
	CredentialID string `json:"credentialId"`
	Proof        string `json:"proof"`
}

func handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	var body RequestBody

	err := json.Unmarshal([]byte(request.Body), &body)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusBadRequest,
			Body:       "Invalid request",
		}, nil
	}

	// TEMP proof check
	if body.Proof != "valid" {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusBadRequest,
			Body:       "Invalid proof",
		}, nil
	}

	// simulate revocation
	println("Revoked credential:", body.CredentialID)

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusAccepted,
		Body:       "Credential revoked",
	}, nil
}

func main() {
	lambda.Start(handler)
}