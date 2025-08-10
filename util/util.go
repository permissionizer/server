package util

import (
	"fmt"
	"reflect"
	"server/types"
	"strings"
	"time"

	"github.com/google/go-github/v71/github"

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

func ParseRepository(repository string) (string, string) {
	parts := strings.SplitN(repository, "/", 2)
	// test
	return parts[0], parts[1]
}

func MapToInstallationPermissions(permissions map[string]string) (*github.InstallationPermissions, error) {
	installationPermissions := &github.InstallationPermissions{}
	permissionsReflectElem := reflect.ValueOf(installationPermissions).Elem()
	invalidPermissions := []string{}

	for permission, access := range permissions {
		setter := findPermission(permissionsReflectElem, permission)
		if setter != nil {
			setter.Set(reflect.ValueOf(&access))
		} else {
			invalidPermissions = append(invalidPermissions, permission)
		}
	}
	if len(invalidPermissions) > 0 {
		return nil, fmt.Errorf("invalid permissions: %v", invalidPermissions)
	}

	return installationPermissions, nil
}

func findPermission(permissionsValue reflect.Value, permission string) *reflect.Value {
	normalizedKey := strings.ReplaceAll(strings.ToLower(permission), "-", "_")
	for i := 0; i < permissionsValue.NumField(); i++ {
		field := permissionsValue.Type().Field(i)
		jsonTag := field.Tag.Get("json")
		githubPermission := strings.SplitN(jsonTag, ",", 2)[0]
		if githubPermission == normalizedKey {
			fieldValue := permissionsValue.Field(i)
			if fieldValue.CanSet() {
				return &fieldValue
			}
		}
	}
	return nil
}

func Ptr[T any](v T) *T {
	return &v
}
