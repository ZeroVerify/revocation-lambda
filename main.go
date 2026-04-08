package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/zeroverify/revocation-lambda/internal/handler"
)

func main() {
	h := handler.NewHandler()
	lambda.Start(h.Handle)
}
