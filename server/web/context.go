package web

import (
	"context"

	"github.com/theredrad/certauthz/core/common"
)

type contextKey int

const (
	clientKey contextKey = iota
)

// setClient sets the client in the context
func setClient(ctx context.Context, client common.Client) context.Context {
	return context.WithValue(ctx, clientKey, client)
}

// ClientFromContext reads the client from the context
func ClientFromContext(ctx context.Context) common.Client {
	val := ctx.Value(clientKey)
	client, _ := val.(common.Client)
	return client
}
