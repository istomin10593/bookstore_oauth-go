package oauth

import (
	"net/http"
	"strings"

	"github.com/istomin10593/bookstore_oauth-go/oauth/errors"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-User-Id"

	paramAccessToken = "access_token"
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}

	return request.Header.Get(headerXPublic) == "true"
}

func AuthenticateRequest(request *http.Request) *errors.RestErr {
	if request == nil {
		return nil
	}

	accessToken := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))

	if accessToken == "" {
		return nil
	}
}
