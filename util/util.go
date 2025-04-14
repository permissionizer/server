package util

import (
	"server/types"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type UnsignedIDTokenClaims struct {
	jwt.RegisteredClaims
	types.TokenRequestor
}

func GenerateUnsignedIDToken(audience string, repository string, ref string, workflowRef string) string {
	// To protect against clock drift, set the issuance time 60 seconds in the past.
	now := time.Now().Add(-60 * time.Second)
	expiresAt := now.Add(10 * time.Minute)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, UnsignedIDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			Issuer:    repository,
			Audience:  []string{audience},
		},
		TokenRequestor: types.TokenRequestor{
			Repository:  repository,
			Ref:         ref,
			WorkflowRef: workflowRef,
			RunId:       "0",
		},
	})

	tokenString, err := token.SigningString()
	if err != nil {
		panic(err)
	}
	return tokenString
}

func Ptr[T any](v T) *T {
	return &v
}
