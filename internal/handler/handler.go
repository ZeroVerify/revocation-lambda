package handler

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) Handle(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// NOTE: using API Gateway request (NOT DynamoDB) because revocation = API endpoint
	// also keeping it super simple (no fake proof logic like last time LOL)

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       `{"message": "Hello, World!"}`, // just a basic response for now
	}, nil
}
