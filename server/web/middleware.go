package web

import (
	"net/http"
)

// Middlware is a signature to wrap a HTTP handler
type Middlware func(http.HandlerFunc) http.HandlerFunc

// WrapMiddlewares wraps the handler with a list of middlewares
func WrapMiddlewares(middlewares []Middlware, handler http.HandlerFunc) http.HandlerFunc {
	for i := len(middlewares) - 1; i >= 0; i-- {
		if middlewares[i] != nil {
			handler = middlewares[i](handler)
		}
	}
	return handler
}
