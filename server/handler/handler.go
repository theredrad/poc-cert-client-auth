package handler

import (
	"fmt"
	"net/http"

	"github.com/theredrad/certauthz/server/web"
)

type Handler struct{}

func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) {
	// get the client from context
	client := web.ClientFromContext(r.Context())
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Welcome %s, you are authorized to %s", client.Name, client.Scopes.String())))
}
