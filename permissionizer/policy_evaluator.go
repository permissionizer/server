package permissionizer

import (
	"fmt"
	"net/http"
	"reflect"
	"server/types"
	"server/util"
	"strings"

	"github.com/google/go-github/v71/github"
)

const policy = `
self: permissionizer/request-token
allow:
  # (required)
  # Repository requesting the token
  - repository: permissionizer/permissionizer-server
	# (required)
	# Permissions that can be requested by 'permissionizer/permissionizer-server'
	# Only permissions listed here are allowed to be requested, except 'metadata: read', which is added
	# automatically if any other permission is defined.
	# Requestor can always request less permissions or lower access than allowed
	# (e.g. 'issues: read' even if 'contents: write', 'issues: write' are allowed)
	permissions:
	  contents: read
	  issues: write
	# (optional)
	# Restricts requesting token to specific branches of the requesting repository
	# Uses GitHub format of 'ref' (e.g. 'refs/heads/main', 'refs/tags/v1.0.0', 'refs/tags/v*')
	ref: refs/heads/main
	# (optional)
	# Restricts requesting token only from a specific workflow of the requesting repository
	workflow_ref: .github/workflows/release.yaml
`

func FindMatchingPolicy(requestor types.TokenRequestor, request types.IssueTokenRequest) (types.PolicyDecision, error) {
	errors := []types.PolicyError{}

	for _, targetRepo := range request.TargetRepositories {
		perm, err := FetchPermissionizerPermissions(targetRepo)
		if err != nil {
			if err == http.ErrMissingFile {
				errors = append(errors, types.PolicyError{TargetRepository: targetRepo, PolicyIndex: -1, Type: types.PermissionizerNotInstalled})
				continue
			}
			return types.PolicyDecision{}, err
		}

		permDecision := MatchPermissions(perm, request.Permissions)
		if !permDecision.Allow {
			errors = append(errors, types.PolicyError{
				TargetRepository: targetRepo,
				PolicyIndex:      -1,
				Type:             types.PermissionizerNoSufficientPermissions,
				Errors:           map[string]string{"notAllowedPermissions": NotAllowedPermissionsString(permDecision.PermissionDecisions)},
			})
		}

		repoPolicy, err := FetchRepositoryPolicy(targetRepo)
		if err != nil {
			return types.PolicyDecision{}, err
		}
		if repoPolicy.Self != targetRepo {
			errors = append(errors, types.PolicyError{TargetRepository: targetRepo, PolicyIndex: -1, Type: types.TargetRepositoryMisconfiguredSelfClause})
			continue
		}

		policyDecision := MatchTargetRepositoryPolicy(requestor, request, targetRepo, repoPolicy)
		if !policyDecision.Allow {
			errors = append(errors, policyDecision.Errors...)
		}
	}

	return types.PolicyDecision{Allow: len(errors) == 0, Errors: errors}, nil
}

func MatchTargetRepositoryPolicy(requestor types.TokenRequestor, request types.IssueTokenRequest, targetRepo string, repoPolicy types.RepositoryPolicy) types.PolicyDecision {
	errors := []types.PolicyError{}
	for idx, policy := range repoPolicy.Allow {
		if policy.Repository != requestor.Repository {
			continue
		}
		if policy.Ref != nil && *policy.Ref != requestor.Ref {
			errors = append(errors, types.PolicyError{TargetRepository: targetRepo, PolicyIndex: idx, Type: types.TargetRepositoryDoesNotAllowFromRef})
			continue
		}
		if policy.WorkflowRef != nil && *policy.WorkflowRef != requestor.WorkflowRef {
			errors = append(errors, types.PolicyError{TargetRepository: targetRepo, PolicyIndex: idx, Type: types.TargetRepositoryDoesNotAllowFromWorkflowRef})
			continue
		}
		permDecision := MatchPermissions(policy.Permissions, request.Permissions)
		if !permDecision.Allow {
			errors = append(errors, types.PolicyError{
				TargetRepository: targetRepo,
				PolicyIndex:      idx,
				Type:             types.TargetRepositoryDoesNotAllowPermissionAccess,
				Errors:           map[string]string{"notAllowedPermissions": NotAllowedPermissionsString(permDecision.PermissionDecisions)},
			})
		}
		return types.PolicyDecision{Allow: len(errors) == 0, Errors: errors}
	}
	errors = append(errors, types.PolicyError{TargetRepository: targetRepo, PolicyIndex: -1, Type: types.TargetRepositoryDoesNotAllowAccess})
	return types.PolicyDecision{Allow: false, Errors: errors}
}

// MatchPermissions validates that all requested permissions are allowed by the given allowed permissions.
func MatchPermissions(allowed, requested *github.InstallationPermissions) types.PermissionsDecision {
	decisions := []types.PermissionDecision{}
	allowAll := true

	allowedVal := reflect.ValueOf(allowed).Elem()
	requestedVal := reflect.ValueOf(requested).Elem()
	typ := allowedVal.Type()

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		perm := field.Tag.Get("json")
		if perm == "" || perm == "-" {
			continue
		}
		perm = strings.SplitN(perm, ",", 2)[0]

		allowedAccessPtr := allowedVal.Field(i).Interface().(*string)
		requestedAccessPtr := requestedVal.Field(i).Interface().(*string)

		if requestedAccessPtr == nil {
			continue // Not requested, skip
		}

		requestedAccess := *requestedAccessPtr
		allowedAccess := "none"
		if allowedAccessPtr != nil {
			allowedAccess = *allowedAccessPtr
		}

		allow := MatchPermission(allowedAccess, requestedAccess)
		if !allow {
			allowAll = false
		}

		decisions = append(decisions, types.PermissionDecision{
			Allow:           allow,
			Permission:      perm,
			RequestedAccess: requestedAccess,
			AllowedAccess:   allowedAccess,
		})
	}

	return types.PermissionsDecision{
		Allow:               allowAll,
		PermissionDecisions: decisions,
	}
}

// MatchPermission compares requested vs allowed access levels.
func MatchPermission(allowedAccess, requestedAccess string) bool {
	switch allowedAccess {
	case "write":
		return requestedAccess == "write" || requestedAccess == "read"
	case "read":
		return requestedAccess == "read"
	default:
		return false
	}
}

func NotAllowedPermissionsString(decisions []types.PermissionDecision) string {
	notAllowed := ""
	for _, d := range decisions {
		if !d.Allow {
			notAllowed += fmt.Sprintf("'%s' (requested '%s', allowed: '%s'), ", d.Permission, d.RequestedAccess, d.AllowedAccess)
		}
	}
	if len(notAllowed) > 2 {
		return notAllowed[:len(notAllowed)-2] // trim last comma
	}
	return ""
}

func FetchPermissionizerPermissions(targetRepo string) (*github.InstallationPermissions, error) {
	// Dummy implementation
	return &github.InstallationPermissions{
		Contents: util.Ptr("write"),
		Issues:   util.Ptr("read"),
	}, nil
}

func FetchRepositoryPolicy(targetRepo string) (types.RepositoryPolicy, error) {
	// Dummy implementation
	return types.RepositoryPolicy{Self: targetRepo, Allow: []types.AllowPolicy{}}, nil
}
