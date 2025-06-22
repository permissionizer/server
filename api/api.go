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
	"io"
	"net/http"
	"regexp"
	"server/policy"
	"server/types"
	"server/util"
	"slices"
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

	if len(request.TargetRepositories) == 0 {
		abortWithProblem(c, nil, &types.ProblemDetail{
			Type:   string(types.InvalidRequest),
			Detail: "Target targetRepositories must be specified",
			Status: http.StatusBadRequest,
		})
		return
	}

	var targetOrg = ""
	var targetRepositories []string
	for _, targetRepository := range request.TargetRepositories {
		if !repositoryPattern.MatchString(targetRepository) {
			abortWithProblem(c, nil, &types.ProblemDetail{
				Type:   string(types.InvalidRequest),
				Detail: fmt.Sprintf("Invalid repository '%s'", targetRepository),
				Status: http.StatusBadRequest,
			})
			return
		}
		org, repository := util.ParseRepository(targetRepository)
		if targetOrg == "" {
			targetOrg = org
		} else if targetOrg != org {
			abortWithProblem(c, nil, &types.ProblemDetail{
				Type:   string(types.RepositoriesMustBelongToSameOrg),
				Detail: "All target repositories must belong to the same organization",
				Status: http.StatusBadRequest,
			})
			return
		}
		targetRepositories = append(targetRepositories, repository)
	}

	requestedPermissions, err := util.MapToInstallationPermissions(request.Permissions)
	if err != nil {
		abortWithProblem(c, err, &types.ProblemDetail{
			Type:   string(types.InvalidRequest),
			Detail: err.Error(),
			Status: http.StatusBadRequest,
		})
		return
	}

	var installation *github.Installation
	if len(targetRepositories) == 1 {
		targetRepository := targetRepositories[0]
		installation, _, err = a.client.Apps.FindRepositoryInstallation(c.Request.Context(), targetOrg, targetRepository)
		if err != nil || installation.GetPermissions().GetContents() == "none" {
			abortWithProblem(c, err, &types.ProblemDetail{
				Type:   string(types.PermissionizerNotInstalled),
				Detail: fmt.Sprintf("Repository '%s' does not have Permissioniner App installed or does not allow issuing tokens", targetRepository),
				Status: http.StatusUnauthorized,
			})
			return
		}
	} else {
		installation, _, err = a.client.Apps.FindOrganizationInstallation(c.Request.Context(), targetOrg)
		if err != nil || installation.GetPermissions().GetContents() == "none" {
			abortWithProblem(c, err, &types.ProblemDetail{
				Type:   string(types.PermissionizerNotInstalled),
				Detail: fmt.Sprintf("Organization '%s' does not have Permissioniner App installed or does not allow issuing tokens", targetOrg),
				Status: http.StatusUnauthorized,
			})
			return
		}
	}

	permissionizerToken, _, err := a.client.Apps.CreateInstallationToken(c.Request.Context(), *installation.ID, &github.InstallationTokenOptions{
		Repositories: targetRepositories,
		Permissions: &github.InstallationPermissions{
			Contents: util.Ptr("read"),
		},
	})
	if err != nil {
		abortWithProblem(c, err, &types.ProblemDetail{
			Type:   string(types.PermissionizerNotSufficientPermissions),
			Detail: fmt.Sprintf("Permissionizer App does not have sufficient permissions to issue a token: %s", err),
			Status: http.StatusUnauthorized,
		})
		return
	}

	for _, targetRepository := range targetRepositories {
		targetRepositoryPolicy, _, err := a.fetchRepositoryPolicy(c.Request.Context(), permissionizerToken, targetOrg, targetRepository, nil)
		if err != nil {
			abortWithErrorType(c, requestor, targetRepository, types.RepositoryMisconfigured, err, fmt.Sprintf("Access file '.github/permissionizer.yaml' is invalid: %s", err.Error()))
			return
		}

		policyError := policy.MatchTargetRepositoryPolicy(requestor, targetRepositoryPolicy, requestedPermissions)
		if policyError != nil {
			abortWithErrorType(c, requestor, targetRepository, policyError.Type, nil, policyError.Error)
			return
		}
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
		Repositories: targetRepositories,
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

	var tokenRepositories []string
	for _, tokenRepository := range scopedToken.Repositories {
		tokenRepositories = append(tokenRepositories, tokenRepository.GetFullName())
	}

	c.IndentedJSON(http.StatusOK, types.IssueTokenResponse{
		Token:        *scopedToken.Token,
		ExpiresAt:    scopedToken.ExpiresAt.GetTime(),
		Permissions:  scopedToken.Permissions,
		Repositories: tokenRepositories,
		IssuedBy:     requestor,
	})
}

func (a *PermissionizerApi) fetchRepositoryPolicy(ctx context.Context, permissionizerToken *github.InstallationToken, org string, repository string, opts *github.RepositoryContentGetOptions) (*types.RepositoryPolicy, string, error) {
	client := github.NewClient(nil).WithAuthToken(*permissionizerToken.Token)

	policyFile := ".github/permissionizer.yaml"
	permissionizerAccessFileContent, _, _, err := client.Repositories.GetContents(ctx, org, repository, policyFile, opts)
	if err != nil {
		policyFile = ".github/permissionizer.yml"
		permissionizerAccessFileContent, _, _, err = client.Repositories.GetContents(ctx, org, repository, policyFile, opts)
	}
	if err != nil {
		return nil, ".github/permissionizer.yaml", err
	}
	if permissionizerAccessFileContent == nil {
		return nil, policyFile, errors.New("permissionizer.yaml is not a file")
	}

	permissionizerAccessFile, err := permissionizerAccessFileContent.GetContent()
	if err != nil {
		return nil, policyFile, err
	}

	parsedPolicy, err := ParsePolicy(permissionizerAccessFile, org, repository)
	return parsedPolicy, policyFile, err
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

func (a *PermissionizerApi) HandleWebhook(c *gin.Context) {
	event := c.GetHeader("X-GitHub-Event")
	a.logger.Infow("Received webhook event", "event", event)
	switch event {
	case "ping":
		pingEvent := &github.PingEvent{}
		err := c.ShouldBindJSON(pingEvent)
		if err != nil && strings.Contains(err.Error(), "json: unknown field") {
			// we might receive an event with an unknown field, which is fine
			err = nil
		}
		if err != nil {
			a.logger.Error("Failed to bind ping event", err)
			abortWithProblem(c, err, &types.ProblemDetail{
				Type:   string(types.InvalidWebhook),
				Detail: "Invalid ping event",
				Status: http.StatusBadRequest,
			})
			return
		}
		a.logger.Infow("Received ping pingEvent", "event", pingEvent)
		c.Status(http.StatusAccepted)
	case "installation":
		installationEvent := &github.InstallationEvent{}
		err := c.ShouldBindJSON(installationEvent)
		if err != nil && strings.Contains(err.Error(), "json: unknown field") {
			// we might receive an event with an unknown field, which is fine
			err = nil
		}
		if err != nil {
			a.logger.Error("Failed to bind installation event", err)
			abortWithProblem(c, err, &types.ProblemDetail{
				Type:   string(types.InvalidWebhook),
				Detail: "Invalid installation event",
				Status: http.StatusBadRequest,
			})
			return
		}
		a.logger.Infow("Received installation event", "event", installationEvent)
	case "check_suite":
		checkSuiteEvent := &github.CheckSuiteEvent{}
		err := c.ShouldBindJSON(checkSuiteEvent)
		if err != nil && strings.Contains(err.Error(), "json: unknown field") {
			// we might receive an event with an unknown field, which is fine
			err = nil
		}
		if err != nil {
			a.logger.Error("Failed to bind push event", err)
			abortWithProblem(c, err, &types.ProblemDetail{
				Type:   string(types.InvalidWebhook),
				Detail: "Invalid push event",
				Status: http.StatusBadRequest,
			})
			return
		}
		go a.validateRepositoryPolicy(checkSuiteEvent)
		c.Status(http.StatusAccepted)
	default:
		bytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			a.logger.Error(err)
			c.AbortWithStatus(http.StatusInternalServerError)
		}
		a.logger.Warnw("Received unsupported event", "event", event, "body", string(bytes))
		abortWithProblem(c, nil, &types.ProblemDetail{
			Type:   string(types.InvalidWebhook),
			Detail: fmt.Sprintf("Unsupported event '%s'", event),
			Status: http.StatusBadRequest,
		})
	}
}

func (a *PermissionizerApi) validateRepositoryPolicy(checkSuiteEvent *github.CheckSuiteEvent) {
	createdAt := checkSuiteEvent.GetCheckSuite().GetCreatedAt()
	org := checkSuiteEvent.GetRepo().GetOwner().GetLogin()
	repository := checkSuiteEvent.GetRepo().GetName()
	beforeSha := checkSuiteEvent.GetCheckSuite().GetBeforeSHA()
	headSha := checkSuiteEvent.GetCheckSuite().GetHeadSHA()

	ctx := context.Background()

	permissionizerToken, _, err := a.client.Apps.CreateInstallationToken(ctx, *checkSuiteEvent.GetInstallation().ID, &github.InstallationTokenOptions{
		Repositories: []string{repository},
		Permissions: &github.InstallationPermissions{
			Contents: util.Ptr("read"),
			Checks:   util.Ptr("write"),
		},
	})
	if err != nil {
		a.logger.Errorw("Failed to create installation token for repository policy validation", "org", org, "repository", repository, "error", err)
		return
	}
	client := github.NewClient(nil).WithAuthToken(*permissionizerToken.Token)
	var files []*github.CommitFile
	if beforeSha != "0000000000000000000000000000000000000000" {
		comparison, _, err := client.Repositories.CompareCommits(ctx, org, repository, beforeSha, headSha, nil)
		if err != nil {
			a.logger.Errorw("Failed to compare commits for repository policy validation", "org", org, "repository", repository, "before", beforeSha, "head", headSha, "error", err)
			return
		}
		files = comparison.Files
	} else {
		commit, _, err := client.Repositories.GetCommit(ctx, org, repository, headSha, nil)
		if err != nil {
			a.logger.Errorw("Failed to get commit for repository policy validation", "org", org, "repository", repository, "head", headSha, "error", err)
			return
		}
		files = commit.Files
	}
	permissionizerPolicyChanged := slices.ContainsFunc(files, func(file *github.CommitFile) bool {
		return a.isPermissionizerPolicyFile(file.GetFilename())
	})

	if !permissionizerPolicyChanged {
		return
	}
	repositoryPolicy, policyFile, err := a.fetchRepositoryPolicy(ctx, permissionizerToken, org, repository, &github.RepositoryContentGetOptions{
		Ref: checkSuiteEvent.GetCheckSuite().GetAfterSHA(),
	})
	validationError := err
	if validationError == nil {
		allowedPermissions := make(map[string]string)
		for _, allow := range repositoryPolicy.Allow {
			for permission, access := range allow.Permissions {
				existingAccess := allowedPermissions[permission]
				if existingAccess == "" || existingAccess == "none" || (existingAccess == "read" && access == "write") {
					allowedPermissions[permission] = access
				}
			}
		}
		requestedPermissions, err := util.MapToInstallationPermissions(allowedPermissions)
		err = policy.CheckInstallationPermissions(checkSuiteEvent.GetInstallation().GetPermissions(), requestedPermissions)
		if err != nil {
			validationError = err
		}
	}
	if validationError != nil {
		_, _, err := client.Checks.CreateCheckRun(ctx, org, repository, github.CreateCheckRunOptions{
			Name:        policyFile,
			HeadSHA:     headSha,
			Status:      util.Ptr("completed"),
			Conclusion:  util.Ptr("failure"),
			StartedAt:   &createdAt,
			CompletedAt: &github.Timestamp{Time: time.Now()},
			DetailsURL:  util.Ptr("https://github.com/marketplace/actions/permissionizer-request-token"),
			Output: &github.CheckRunOutput{
				Title: util.Ptr("Failed to validate Permissionizer policy file"),
				Summary: util.Ptr(`
Failed to validate Permissionizer policy file ` + fmt.Sprintf("`%s`", policyFile) + `.

Please check documentation at [permissionizer/request-token](https://github.com/marketplace/actions/permissionizer-request-token) for more information.
`),
				Text: util.Ptr(fmt.Sprintf("Error: %s", validationError.Error())),
			},
		})
		if err != nil {
			a.logger.Errorw("Failed to create check run for repository policy", "org", org, "repository", repository, "error", err)
			return
		}
		a.logger.Infow("Created failed policy validation check", "org", org, "repository", repository, "error", err)
	} else {
		_, _, err := client.Checks.CreateCheckRun(ctx, org, repository, github.CreateCheckRunOptions{
			Name:        policyFile,
			HeadSHA:     headSha,
			Status:      util.Ptr("completed"),
			Conclusion:  util.Ptr("success"),
			StartedAt:   &createdAt,
			CompletedAt: &github.Timestamp{Time: time.Now()},
			DetailsURL:  util.Ptr("https://github.com/marketplace/actions/permissionizer-request-token"),
			Output: &github.CheckRunOutput{
				Title: util.Ptr("Successfully validated Permissionizer policy file"),
				Summary: util.Ptr(`
Permissionizer policy file ` + fmt.Sprintf("`%s`", policyFile) + ` has been successfully validated.

You can now issue tokens for this repository using ` + "`permissionizer/request-token@v1`" + ` GitHub Action. Please check documentation at [permissionizer/request-token](https://github.com/marketplace/actions/permissionizer-request-token) for more information.
`),
			},
		})
		if err != nil {
			a.logger.Errorw("Failed to create check run for repository policy", "org", org, "repository", repository, "error", err)
			return
		}
		a.logger.Infow("Created successful policy validation check", "org", org, "repository", repository, "error", err)
	}
}

func (a *PermissionizerApi) isPermissionizerPolicyFile(file string) bool {
	return file == ".github/permissionizer.yaml" || file == ".github/permissionizer.yml"
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

func abortWithErrorType(c *gin.Context, requestor *types.TokenRequestor, targetRepository string, errorType types.ErrorType, err error, errorDetails string) {
	detail := ""
	status := http.StatusUnauthorized
	switch errorType {
	case types.RepositoryMisconfigured:
		detail = fmt.Sprintf("The repository '%s' defines invalid access file.", targetRepository)
	case types.RepositoryDoesNotAllowAccess:
		detail = fmt.Sprintf("The repository '%s' does not allow issuing token for '%s'.", targetRepository, requestor.Repository)
	case types.RepositoryDoesNotAllowAccessFromRef:
		detail = fmt.Sprintf("The repository '%s' does not allow issuing token for '%s' from the ref '%s'.", targetRepository, requestor.Repository, requestor.Ref)
	case types.RepositoryDoesNotAllowAccessFromWorkflowRef:
		detail = fmt.Sprintf("The repository '%s' does not allow issuing token for '%s' from the workflow ref '%s'.", targetRepository, requestor.Repository, requestor.WorkflowRef)
	case types.RepositoryDoesNotAllowPermissions:
		detail = fmt.Sprintf("The repository '%s' does not allow issuing token for '%s' with the permissions: %s", targetRepository, requestor.Repository, errorDetails)
	}
	if requestor.Repository == targetRepository {
		if errorDetails != "" {
			detail += "\n" + errorDetails
		} else if err != nil {
			detail += "\n" + err.Error()
		}
	} else {
		detail += "\nContact the repository owners to define a policy allowing the access in the '.github/permissionizer.yaml' file."
	}
	abortWithProblem(c, err, &types.ProblemDetail{
		Type:   string(errorType),
		Detail: detail,
		Status: status,
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
