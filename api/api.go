package api

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
	"net/http"
	"regexp"
	"server/policy"
	"server/types"
	"server/util"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/google/go-github/v71/github"
)

type PermissionizerApi struct {
	client        *github.Client
	tokenVerifier *oidc.IDTokenVerifier
	config        *types.PermissionizerConfig
	logger        *zap.SugaredLogger
}

func NewApi(config *types.PermissionizerConfig, logger *zap.SugaredLogger) *PermissionizerApi {
	provider, err := oidc.NewProvider(context.Background(), "https://token.actions.githubusercontent.com")
	if err != nil {
		panic(fmt.Errorf("failed to initialize OIDC provider: %w", err))
	}

	tokenVerifier := provider.Verifier(&oidc.Config{
		ClientID:                   config.ExpectedAudience,
		SkipExpiryCheck:            config.SkipTokenValidation,
		SkipIssuerCheck:            config.SkipTokenValidation,
		InsecureSkipSignatureCheck: config.SkipTokenValidation,
	})

	authenticatedClient := oauth2.NewClient(context.Background(), &jwtTokenSource{
		clientId:   config.ClientId,
		privateKey: config.PrivateKey,
	})

	client := github.NewClient(authenticatedClient)
	return &PermissionizerApi{
		client:        client,
		tokenVerifier: tokenVerifier,
		config:        config,
		logger:        logger,
	}
}

var (
	repositoryPattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$`)
)

func (a *PermissionizerApi) IssueToken(c *gin.Context) {
	request := &types.IssueTokenRequest{}
	if err := c.ShouldBindJSON(request); err != nil {
		abortWithProblem(c, err, &types.ProblemDetail{
			Type:   string(types.InvalidRequest),
			Title:  "Invalid request body",
			Status: http.StatusBadRequest,
		})
		return
	}

	authorization := strings.TrimSpace(c.GetHeader("Authorization"))
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" {
		abortWithInvalidToken(c, errors.New("missing ID token"))
		return
	}

	IDToken, err := a.validateIDToken(c.Request.Context(), parts[1])
	requestor := &types.TokenRequestor{}
	if err != nil {
		abortWithInvalidToken(c, err)
		return
	}
	if IDToken.Claims(requestor) != nil || requestor.Repository == "" || requestor.Ref == "" || requestor.WorkflowRef == "" {
		abortWithInvalidToken(c, errors.New("invalid ID token claims"))
		return
	}

	if len(request.TargetRepositories) != 1 {
		abortWithProblem(c, nil, &types.ProblemDetail{
			Type:   string(types.InvalidRequest),
			Detail: "Currently, only a single target repository is allowed",
			Status: http.StatusBadRequest,
		})
		return
	}

	targetRepository := request.TargetRepositories[0]

	if !repositoryPattern.MatchString(targetRepository) {
		abortWithProblem(c, nil, &types.ProblemDetail{
			Type:   string(types.InvalidRequest),
			Detail: fmt.Sprintf("Invalid repository '%s'", targetRepository),
			Status: http.StatusBadRequest,
		})
		return
	}

	org, repository := parseRepository(targetRepository)

	requestedPermissions, err := util.MapToInstallationPermissions(request.Permissions)
	if err != nil {
		abortWithProblem(c, err, &types.ProblemDetail{
			Type:   string(types.InvalidRequest),
			Detail: err.Error(),
			Status: http.StatusBadRequest,
		})
		return
	}

	installation, _, err := a.client.Apps.FindRepositoryInstallation(c.Request.Context(), org, repository)
	if err != nil || installation.GetPermissions().GetContents() == "none" {
		abortWithProblem(c, err, &types.ProblemDetail{
			Type:   string(types.PermissionizerNotInstalled),
			Detail: fmt.Sprintf("Repository '%s' does not have Permissioniner app installed or does not allow issuing tokens", targetRepository),
			Status: http.StatusUnauthorized,
		})
		return
	}

	permissionizerToken, _, err := a.client.Apps.CreateInstallationToken(c.Request.Context(), *installation.ID, &github.InstallationTokenOptions{
		Repositories: []string{repository},
		Permissions: &github.InstallationPermissions{
			Contents: util.Ptr("read"),
		},
	})
	if err != nil {
		abortWithProblem(c, err, &types.ProblemDetail{
			Type:   string(types.PermissionizerNotSufficientPermissions),
			Detail: fmt.Sprintf("Permissionizer App does not have sufficient permissions to issue token: %s", err),
			Status: http.StatusUnauthorized,
		})
		return
	}

	targetRepositoryPolicy, err := a.fetchRepositoryPolicy(c, permissionizerToken, org, repository)
	if err != nil {
		abortWithProblem(c, err, createProblemDetail(requestor, targetRepository, types.RepositoryMisconfigured, err.Error()))
		return
	}

	policyError := policy.MatchTargetRepositoryPolicy(requestor, targetRepositoryPolicy, requestedPermissions)
	if policyError != nil {
		abortWithProblem(c, err, createProblemDetail(requestor, targetRepository, policyError.Type, policyError.Error))
		return
	}

	// while this can be done before checking the policy itself, it's better not to leak the permissions of the app
	// if repository is not allowed to issue tokens
	err = policy.CheckInstallationPermissions(installation.GetPermissions(), requestedPermissions)
	if err != nil {
		abortWithProblem(c, err, &types.ProblemDetail{
			Type:   string(types.PermissionizerNotSufficientPermissions),
			Detail: fmt.Sprintf("Permissionizer App does not have sufficient permissions to issue token: %s", err),
			Status: http.StatusUnauthorized,
		})
		return
	}

	a.logger.Infow("Issuing a scoped token", "requestor", requestor, "request", request)

	scopedToken, _, err := a.client.Apps.CreateInstallationToken(c.Request.Context(), *installation.ID, &github.InstallationTokenOptions{
		Repositories: []string{repository},
		Permissions:  requestedPermissions,
	})
	if err != nil {
		abortWithProblem(c, err, &types.ProblemDetail{
			Type:   string(types.InternalError),
			Title:  "Failed to fetch access token from GitHub API",
			Detail: err.Error(),
			Status: http.StatusBadRequest,
		})
		return
	}

	repositories := []string{}
	for _, tokenRepository := range scopedToken.Repositories {
		repositories = append(repositories, tokenRepository.GetFullName())
	}

	c.IndentedJSON(http.StatusOK, types.IssueTokenResponse{
		Token:        *scopedToken.Token,
		ExpiresAt:    scopedToken.ExpiresAt.GetTime(),
		Permissions:  scopedToken.Permissions,
		Repositories: repositories,
		IssuedBy:     requestor,
	})
}

func (a *PermissionizerApi) fetchRepositoryPolicy(c *gin.Context, permissionizerToken *github.InstallationToken, org string, repository string) (*types.RepositoryPolicy, error) {
	client := github.NewClient(nil).WithAuthToken(*permissionizerToken.Token)

	permissionizerAccessFileContent, _, _, err := client.Repositories.GetContents(c.Request.Context(), org, repository, ".github/permissionizer.yaml", nil)
	if err != nil || permissionizerAccessFileContent == nil {
		if err == nil {
			err = errors.New("permissionizer.yaml is not a file")
		}
		return nil, err
	}

	permissionizerAccessFile, err := permissionizerAccessFileContent.GetContent()
	if err != nil {
		return nil, err
	}

	return ParsePolicy(permissionizerAccessFile, org, repository)
}

func ParsePolicy(content string, org string, repository string) (*types.RepositoryPolicy, error) {
	var repositoryPolicy types.RepositoryPolicy
	err := yaml.Unmarshal([]byte(content), &repositoryPolicy)
	if err != nil {
		return nil, err
	}

	if repositoryPolicy.Self != fmt.Sprintf("%s/%s", org, repository) {
		return nil, fmt.Errorf("mismatching 'self' clause: '%s' != '%s/%s'", repositoryPolicy.Self, org, repository)
	}
	return &repositoryPolicy, nil
}

func parseRepository(targetRepository string) (string, string) {
	parts := strings.SplitN(targetRepository, "/", 2)
	return parts[0], parts[1]
}

func (a *PermissionizerApi) HandleWebhook(c *gin.Context) {
	c.Status(http.StatusNotImplemented)
}

func createProblemDetail(requestor *types.TokenRequestor, targetRepository string, errorType types.ErrorType, errorDetails string) *types.ProblemDetail {
	detail := ""
	status := http.StatusUnauthorized
	switch errorType {
	case types.RepositoryMisconfigured:
		detail = fmt.Sprintf("The repository '%s' defines invalid access file.", targetRepository)
		if requestor.Repository == targetRepository {
			detail += fmt.Sprintf("\nAccess file '.github/permissionizer.yaml' is invalid: %s", errorDetails)
		} else {
			detail += "\nContact the repository owners to fix '.github/permissionizer.yaml' access file."
		}
	case types.RepositoryDoesNotAllowAccess:
		detail = fmt.Sprintf("The repository '%s' does not allow issuing token for '%s'.", targetRepository, requestor.Repository)
		if requestor.Repository == targetRepository {
			detail += "\nIssuing a token to the same repository requires explicit policy defined in the '.github/permissionizer.yaml' file."
		} else {
			detail += "\nContact the repository owners to define a policy allowing the access in the '.github/permissionizer.yaml' file."
		}
	case types.RepositoryDoesNotAllowAccessFromRef:
		detail = fmt.Sprintf("The repository '%s' does not allow issuing token for '%s' from the ref '%s'.", targetRepository, requestor.Repository, requestor.Ref)
		if requestor.Repository != targetRepository {
			detail += "\nContact the repository owners to define a policy allowing the access in the '.github/permissionizer.yaml' file."
		}
	case types.RepositoryDoesNotAllowAccessFromWorkflowRef:
		detail = fmt.Sprintf("The repository '%s' does not allow issuing token for '%s' from the workflow ref '%s'.", targetRepository, requestor.Repository, requestor.WorkflowRef)
		if requestor.Repository != targetRepository {
			detail += "\nContact the repository owners to define a policy allowing the access in the '.github/permissionizer.yaml' file."
		}
	case types.RepositoryDoesNotAllowPermissions:
		detail = fmt.Sprintf("The repository '%s' does not allow issuing token for '%s' with the permissions: %s", targetRepository, requestor.Repository, errorDetails)
		if requestor.Repository != targetRepository {
			detail += "\nContact the repository owners to define a policy allowing the access in the '.github/permissionizer.yaml' file."
		}
	}
	return &types.ProblemDetail{
		Type:   string(errorType),
		Detail: detail,
		Status: status,
	}
}

func abortWithProblem(c *gin.Context, err error, pd *types.ProblemDetail) {
	if err != nil {
		_ = c.Error(err)
	}
	if pd.Status == 0 {
		panic("code must be not nil")
	}
	if pd.Type == "" {
		pd.Type = "about:blank"
	}
	c.AbortWithStatusJSON(pd.Status, pd)
}

func abortWithInvalidToken(c *gin.Context, err error) {
	abortWithProblem(c, err, &types.ProblemDetail{
		Type:   string(types.InvalidIDToken),
		Detail: err.Error() + ". Use 'actions/request-token@1' to request access token.",
		Status: http.StatusUnauthorized,
	})
}

type jwtTokenSource struct {
	clientId   string
	privateKey *rsa.PrivateKey
}

func (tokenSource *jwtTokenSource) Token() (*oauth2.Token, error) {
	// To protect against clock drift, set the issuance time 60 seconds in the past.
	now := time.Now().Add(-60 * time.Second)
	expiresAt := now.Add(10 * time.Minute)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		Issuer:    tokenSource.clientId,
	})

	tokenString, err := token.SignedString(tokenSource.privateKey)
	if err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		Expiry:      expiresAt,
	}, nil
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
