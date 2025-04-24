package permissionizer

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"server/types"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/google/go-github/v71/github"
)

type PermissionizerApi struct {
	client        *github.Client
	tokenVerifier *oidc.IDTokenVerifier
	webhookSecret string
}

func NewApi(client *github.Client, audience string, webhookSecret string, skipTokenValidation bool) *PermissionizerApi {
	provider, err := oidc.NewProvider(context.Background(), "https://token.actions.githubusercontent.com")
	if err != nil {
		panic(fmt.Errorf("failed to initialize OIDC provider: %w", err))
	}

	tokenVerifier := provider.Verifier(&oidc.Config{
		ClientID:                   audience,
		SkipExpiryCheck:            skipTokenValidation,
		SkipIssuerCheck:            skipTokenValidation,
		InsecureSkipSignatureCheck: skipTokenValidation,
	})
	return &PermissionizerApi{
		client:        client,
		tokenVerifier: tokenVerifier,
		webhookSecret: webhookSecret,
	}
}

var (
	repositoryPattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$`)
)

func (a *PermissionizerApi) IssueToken(c *gin.Context) {
	var req types.IssueTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortWithProblem(c, &types.ProblemDetail{
			Title:  "Bad Request",
			Status: http.StatusBadRequest,
		})
		return
	}

	authorization := c.GetHeader("Authorization")
	if authorization == "" {
		abortWithProblem(c, &types.ProblemDetail{
			Title:  "IDToken is required",
			Status: http.StatusUnauthorized,
		})
		return
	}
	parts := strings.SplitN(authorization, " ", 2)

	if len(parts) != 2 || parts[0] != "Bearer" || strings.TrimSpace(parts[1]) == "" {
		abortWithProblem(c, &types.ProblemDetail{
			Title:  "IDToken is required",
			Status: http.StatusUnauthorized,
		})
		return
	}
	IDTokenRaw := parts[1]
	IDToken, err := a.validateIDToken(c.Request.Context(), IDTokenRaw)
	if err != nil {
		abortWithProblem(c, &types.ProblemDetail{
			Title:  "Invalid IDToken",
			Status: http.StatusUnauthorized,
		})
		return
	}
	tokenRequestor := &types.TokenRequestor{}
	IDToken.Claims(tokenRequestor)

	if !slices.Equal(req.TargetRepositories, []string{"permissionizer/server"}) {
		abortWithProblem(c, &types.ProblemDetail{
			Title:  "The repository does not allow issuing tokens",
			Status: http.StatusBadRequest,
		})
		return
	}

	targetRepository := req.TargetRepositories[0]

	if !repositoryPattern.MatchString(targetRepository) {
		abortWithProblem(c, &types.ProblemDetail{
			Title:  fmt.Sprintf("Invalid repository %s", targetRepository),
			Status: http.StatusBadRequest,
		})
		return

	}
	parts = strings.SplitN(targetRepository, "/", 2)
	org := parts[0]
	repository := parts[1]

	installation, _, err := a.client.Apps.FindRepositoryInstallation(c.Request.Context(), org, repository)
	if err != nil {
		abortWithProblem(c, &types.ProblemDetail{
			Title:  "Failed to find installation on repository",
			Detail: err.Error(),
			Status: http.StatusBadRequest,
		})
		return
	}

	installationToken, _, err := a.client.Apps.CreateInstallationToken(c.Request.Context(), *installation.ID, &github.InstallationTokenOptions{
		Repositories: []string{repository},
		Permissions:  req.Permissions,
	})
	if err != nil {
		abortWithProblem(c, &types.ProblemDetail{
			Title:  "Failed to fetch access token from GitHub API",
			Detail: err.Error(),
			Status: http.StatusBadRequest,
		})
		return
	}

	repositories := []string{}
	for _, tokenRepository := range installationToken.Repositories {
		repositories = append(repositories, tokenRepository.GetFullName())
	}

	c.IndentedJSON(http.StatusOK, types.IssueTokenResponse{
		Token:        *installationToken.Token,
		ExpiresAt:    installationToken.ExpiresAt.GetTime(),
		Permissions:  installationToken.Permissions,
		Repositories: repositories,
		IssuedBy:     tokenRequestor,
	})
}

func (a *PermissionizerApi) HandleWebhook(c *gin.Context) {
	c.Status(http.StatusNotImplemented)
}

func abortWithProblem(c *gin.Context, pd *types.ProblemDetail) {
	if pd.Status == 0 {
		panic("code must be not nil")
	}
	if pd.Title == "" {
		panic("ProblemDetail.Title must be set")
	}
	if pd.Type == "" {
		pd.Type = "about:blank"
	}
	c.AbortWithStatusJSON(pd.Status, pd)
}

func (a *PermissionizerApi) validateIDToken(ctx context.Context, IDToken string) (*oidc.IDToken, error) {
	idToken, err := a.tokenVerifier.Verify(ctx, IDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Decode claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to decode ID token claims: %w", err)
	}

	return idToken, nil
}
