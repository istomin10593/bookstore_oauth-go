package oauth

import (
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/mercadolibre/golang-restclient/rest"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	fmt.Println("about to start oauth tests")

	rest.StartMockupServer()

	os.Exit(m.Run())
}

func TestOauthConstants(t *testing.T) {
	assert.EqualValues(t, "X-Public", headerXPublic)
	assert.EqualValues(t, "X-Client-Id", headerXClientId)
	assert.EqualValues(t, "X-Caller-Id", headerXCallerId)
	assert.EqualValues(t, "access_token", paramAccessToken)
}

func TestIsPublicNilRequest(t *testing.T) {
	assert.True(t, IsPublic(nil))
}

func TestIsPublicNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	assert.False(t, IsPublic(&request))

	request.Header.Add("X-Public", "true")
	assert.True(t, IsPublic(&request))
}

func TestGetCallerNilRequest(t *testing.T) {
	assert.EqualValues(t, 0, GetCallerId(nil))
}

func TestGetCallerInvalidCallerFormat(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add("X-Caller-Id", "notInt")

	assert.EqualValues(t, 0, GetCallerId(&request))
}

func TestGetCallerNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	assert.EqualValues(t, 0, GetCallerId(&request))

	request.Header.Add("X-Caller-Id", "1")
	assert.EqualValues(t, 1, GetCallerId(&request))
}

func TestGetClientNilRequest(t *testing.T) {
	assert.EqualValues(t, 0, GetClientId(nil))
}

func TestGetClientInvalidClientFormat(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add("X-Client-Id", "notInt")

	assert.EqualValues(t, 0, GetClientId(&request))
}

func TestGetClientNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	assert.EqualValues(t, 0, GetClientId(&request))

	request.Header.Add("X-Client-Id", "1")
	assert.EqualValues(t, 1, GetClientId(&request))
}

func TestGetAccessTokenInvalidRestclientResponce(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/AbC123",
		ReqBody:      ``,
		RespHTTPCode: -1,
		RespBody:     `{}`,
	})

	accessToken, err := getAccessToken("AbC123")
	assert.Nil(t, accessToken)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusInternalServerError, err.Status())
	assert.EqualValues(t, "invalid restclient response when trying to get access token", err.Message())
}

func TestGetAccessTokenErrorInterface(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/AbC123",
		ReqBody:      ``,
		RespHTTPCode: http.StatusNotFound,
		RespBody:     `{"message": "invalid logic credentials", "status": "404", "error": "not_found"}`,
	})

	accessToken, err := getAccessToken("AbC123")
	assert.Nil(t, accessToken)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusInternalServerError, err.Status())
	assert.EqualValues(t, "invalid error interface when trying to get access token", err.Message())
}

func TestGetAccessTokenInvalidLoginCredentials(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/AbC123",
		ReqBody:      ``,
		RespHTTPCode: http.StatusNotFound,
		RespBody:     `{"message": "invalid logic credentials", "status": 404, "error": "not_found", "causes": []}`,
	})

	accessToken, err := getAccessToken("AbC123")
	assert.Nil(t, accessToken)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusNotFound, err.Status())
	assert.EqualValues(t, "invalid logic credentials", err.Message())
}

func TestGetAccessTokenInvalidJSONResponse(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/AbC123",
		ReqBody:      ``,
		RespHTTPCode: http.StatusOK,
		RespBody:     `{"access_token": "AbC123", "user_id": 1, "client_id": "1", "expires": 1}`,
	})

	accessToken, err := getAccessToken("AbC123")
	assert.Nil(t, accessToken)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusInternalServerError, err.Status())
	assert.EqualValues(t, "error when trying to unmarshal users login response", err.Message())
}

func TestGetAccessTokenNoError(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/AbC123",
		ReqBody:      ``,
		RespHTTPCode: http.StatusOK,
		RespBody:     `{"access_token": "AbC123", "user_id": 1, "client_id": 2, "expires": 3}`,
	})

	accessToken, err := getAccessToken("AbC123")
	assert.Nil(t, err)
	assert.NotNil(t, accessToken)
	assert.EqualValues(t, "AbC123", accessToken.AccessToken)
	assert.EqualValues(t, 1, accessToken.UserId)
	assert.EqualValues(t, 2, accessToken.ClientId)
	assert.EqualValues(t, 3, accessToken.Expires)
}
