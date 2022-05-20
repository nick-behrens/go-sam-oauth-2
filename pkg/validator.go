package sam_oauth2

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2/jwt"
	"log"
	"net/url"
)

type StandardClaims struct {
	Issuer    string   `json:"iss,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	Expiry    int64    `json:"exp,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	ID        string   `json:"jti,omitempty"`
	AppMetadata string `json:"https://api.snapdocs.com/app_metadata"`
}

type AppMetadataClaim struct {
	Vault string `json:"vault"`
}

type Config struct {
	IssuerUrls []string
	Audience string
	ClientID string
	ClientSecret string
}

// SAMValidator can validate tokens issued by SAM.
type SAMValidator struct {
	validIssuers map[string]*oidc.IDTokenVerifier
	providers map[string]*oidc.Provider
}

func NewValidator(config Config) (*SAMValidator, error) {
	providers := make(map[string]*oidc.Provider)
	verifiers := make(map[string]*oidc.IDTokenVerifier)

	for _, issuerUrl := range config.IssuerUrls {
		provider, err := oidc.NewProvider(context.TODO(), issuerUrl)
		if err != nil {
			log.Fatalf("failed to set up the provider: %v", err)
		}

		verifier := provider.Verifier(&oidc.Config{
			ClientID: config.Audience,
		})

		providers[issuerUrl] = provider
		verifiers[issuerUrl] = verifier
	}

	return &SAMValidator{
		validIssuers: verifiers,
		providers:    providers,
	}, nil
}

func (v *SAMValidator) GetTokenURL(issuerUrl string) (*url.URL, error) {
	if samProvider, found := v.providers[issuerUrl]; found {
		tokenUrl, err := url.Parse(samProvider.Endpoint().TokenURL)
		if err != nil {
			return nil, errors.Errorf("Unable to parse the token url, %v", err)
		}

		return tokenUrl, nil
	} else {
		return nil, errors.Errorf("Issuer (%s) is not configured", issuerUrl)
	}
}

func (v *SAMValidator) ValidateToken(ctx context.Context, token string) (*oidc.IDToken, error) {
	// Parse the token outside the normal validation chain.
	jwtToken, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("could not parse the token: %w", err)
	}

	// Grab the issuer.
	claimDest := []interface{}{&jwt.Claims{}}
	if err = jwtToken.UnsafeClaimsWithoutVerification(claimDest...); err != nil {
		return nil, fmt.Errorf("could not get token claims: %w", err)
	}

	// If we haven't configured the issuer in the token, error.
	//	Else use the configured validator to check the token.
	if samValidator, found := v.validIssuers[claimDest[0].(*jwt.Claims).Issuer]; found {
		return samValidator.Verify(ctx, token)
	} else {
		return nil, fmt.Errorf("invalid issuer (%s) for the token", claimDest[0].(*jwt.Claims).Issuer)
	}
}
