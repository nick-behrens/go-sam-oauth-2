package main

import (
	"context"
	"encoding/json"
	"fmt"
	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/pkg/errors"
	"log"
	"net/http"
	samoauth2 "sam_oauth2/pkg"
)

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(jwtmiddleware.ContextKey{}).(*oidc.IDToken)

	payload, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
})

func main() {
	keycloakIssuerString := "https://keycloak.staging.snpd.io/auth/realms/snapdocs"
	auth0IssuerString := "https://login.staging.snpd.io/"

	samValidator, err := samoauth2.NewValidator(samoauth2.Config{
		IssuerUrls: []string{keycloakIssuerString, auth0IssuerString},
		Audience:   "https://tara.snpd.io",
	})
	if err != nil {
		log.Fatalf("There was an error with creating the validator. %v", err)
	}

	// Set up the middleware.
	middleware := jwtmiddleware.New(func(ctx context.Context, s string) (interface{}, error) {
		return samValidator.ValidateToken(ctx, s)
	}, jwtmiddleware.WithErrorHandler(errorHandler))

	http.ListenAndServe("0.0.0.0:3000", middleware.CheckJWT(handler))
}

// errorHandler is the default error handler from github.com/auth0/go-jwt-middleware/v2 but with an added
// tweak of setting the www-authenticate header upon a failed request to give more details about the failure.
//   spec: <https://datatracker.ietf.org/doc/html/rfc6750#section-3>
func errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")

	switch {
	case errors.Is(err, jwtmiddleware.ErrJWTMissing):
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"JWT is missing."}`))
	case errors.Is(err, jwtmiddleware.ErrJWTInvalid):
		authenticateHeader := fmt.Sprintf("error=invalid_token, error_description=%s", errors.Unwrap(err))
		w.Header().Set("WWW-Authenticate", authenticateHeader)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"JWT is invalid."}`))
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"Something went wrong while checking the JWT."}`))
	}
}