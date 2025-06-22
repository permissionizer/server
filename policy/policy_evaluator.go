package policy

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"server/types"
	"server/util"
	"strings"

	"github.com/google/go-github/v71/github"
)

func MatchTargetRepositoryPolicy(requestor *types.TokenRequestor, repositoryPolicy *types.RepositoryPolicy, requestedPermissions *github.InstallationPermissions) *types.PolicyError {
	var mostMatchingPolicyError *types.PolicyError
	mostMatchingPolicyPriority := 0
	for _, policy := range repositoryPolicy.Allow {
		if policy.Repository != requestor.Repository {
			continue
		}
		policyPermissions, err := util.MapToInstallationPermissions(policy.Permissions)
		if err != nil {
			return &types.PolicyError{
				Type:  types.RepositoryMisconfigured,
				Error: fmt.Sprintf("Access file '.github/permissionizer.yaml' is invalid: %s", err.Error()),
			}
		}
		if policy.Ref != nil && !refMatch(policy, requestor.Ref) {
			if mostMatchingPolicyPriority < 1 {
				mostMatchingPolicyError = &types.PolicyError{Type: types.RepositoryDoesNotAllowAccessFromRef}
				mostMatchingPolicyPriority = 1
			}
			continue
		}
		if policy.WorkflowRef != nil && !workflowRefMatch(policy, requestor.WorkflowRef) {
			if mostMatchingPolicyPriority < 2 {
				mostMatchingPolicyError = &types.PolicyError{Type: types.RepositoryDoesNotAllowAccessFromWorkflowRef}
				mostMatchingPolicyPriority = 2
			}
			continue
		}
		err = checkPermissions(policyPermissions, requestedPermissions)
		if err != nil {
			if mostMatchingPolicyPriority < 3 {
				mostMatchingPolicyError = &types.PolicyError{
					Type:  types.RepositoryDoesNotAllowPermissions,
					Error: err.Error(),
				}
				mostMatchingPolicyPriority = 3
			}
			continue
		}
		// if no errors at this point - the access is allowed by this policy
		return nil
	}
	if mostMatchingPolicyError == nil {
		mostMatchingPolicyError = &types.PolicyError{
			Type:  types.RepositoryDoesNotAllowAccess,
			Error: "Issuing a token to the same repository requires explicit policy defined in the '.github/permissionizer.yaml' file.",
		}
	}
	return mostMatchingPolicyError
}

func refMatch(policy types.AllowPolicy, ref string) bool {
	policyRef := *policy.Ref
	if ref == policyRef {
		return true
	}

	// Check for wildcard matching (e.g., refs/tags/v*)
	matched, err := filepath.Match(policyRef, ref)
	if err == nil && matched {
		return true
	}

	if strings.HasPrefix(ref, "refs/heads/") && refMatch(policy, strings.TrimPrefix(ref, "refs/heads/")) {
		return true
	}

	if strings.HasPrefix(ref, "refs/tags/") && refMatch(policy, strings.TrimPrefix(ref, "refs/tags/")) {
		return true
	}

	return false
}

// workflowRefMatch checks if the workflowRef matches the policy's workflowRef.
// while the requestor always uses complete ref, a policy can use an incomplete workflowRef that can match it
// 1. full: org/repo/.github/workflows/release.yaml@refs/heads/main
// 2. workflow without ref: org/repo/.github/workflows/release.yaml
// 3. wildcard with ref: org/repo/.github/workflows/release-*.yaml@refs/heads/main
// 4. wildcard without ref: org/repo/.github/workflows/release-*.yaml
// 5. wildcard in both places: org/repo/.github/workflows/release-*.yaml@refs/heads/*
// 6. any of the above, without the org/repo prefix
func workflowRefMatch(policy types.AllowPolicy, workflowRef string) bool {
	policyWorkflowRef := *policy.WorkflowRef
	if workflowRef == policyWorkflowRef {
		return true
	}
	workflowParts := strings.SplitN(workflowRef, "@", 2)
	workflowFile := workflowParts[0]
	workflowFileRef := workflowParts[1]

	policyParts := strings.SplitN(policyWorkflowRef, "@", 2)
	policyWorkflowFile := policyParts[0]
	policyWorkflowFileRef := ""
	if len(policyParts) > 1 {
		policyWorkflowFileRef = policyParts[1]
	}

	// Check for wildcard matching (e.g., .github/workflows/release-*.yaml)
	matched, err := filepath.Match(policyWorkflowFile, workflowFile)
	if err == nil && matched {
		if policyWorkflowFileRef == "" {
			return true
		}
		// Check for wildcard matching (e.g., refs/heads/*)
		matchedRef, err := filepath.Match(policyWorkflowFileRef, workflowFileRef)
		if err == nil && matchedRef {
			return true
		}
	}

	// Allow a workflow within the same repository
	if strings.HasPrefix(workflowRef, policy.Repository) {
		workflowRef = workflowRef[len(policy.Repository)+1:]
		return workflowRefMatch(policy, workflowRef)
	}

	return false
}

func CheckInstallationPermissions(installationPermissions, requestedPermissions *github.InstallationPermissions) error {
	return checkPermissions(installationPermissions, requestedPermissions)
}

// checkPermissions validates that all requested permissions are allowed by the given allowed permissions.
func checkPermissions(allowed, requested *github.InstallationPermissions) error {
	decisions := []types.PermissionDecision{}
	allowAll := true

	allowedReflectElem := reflect.ValueOf(allowed).Elem()
	requestedReflectElem := reflect.ValueOf(requested).Elem()
	typ := allowedReflectElem.Type()

	for i := 0; i < typ.NumField(); i++ {
		permissionField := typ.Field(i)
		permission := permissionField.Tag.Get("json")
		if permission == "" {
			continue
		}
		permission = strings.SplitN(permission, ",", 2)[0]

		allowedAccessPtr := allowedReflectElem.Field(i).Interface().(*string)
		requestedAccessPtr := requestedReflectElem.Field(i).Interface().(*string)

		if requestedAccessPtr == nil {
			continue // Not requested, skip
		}

		requestedAccess := *requestedAccessPtr
		allowedAccess := "none"
		if allowedAccessPtr != nil {
			allowedAccess = *allowedAccessPtr
		}

		allow := checkPermission(allowedAccess, requestedAccess)
		if !allow {
			allowAll = false
		}

		decisions = append(decisions, types.PermissionDecision{
			Allow:           allow,
			Permission:      permission,
			RequestedAccess: requestedAccess,
			AllowedAccess:   allowedAccess,
		})
	}
	if !allowAll {
		return errors.New(NotAllowedPermissionsString(decisions))
	}

	return nil
}

// checkPermission compares requested vs allowed access levels.
func checkPermission(allowedAccess, requestedAccess string) bool {
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
			notAllowed += fmt.Sprintf("%s (requested '%s', allowed '%s'), ", d.Permission, d.RequestedAccess, d.AllowedAccess)
		}
	}
	if len(notAllowed) > 2 {
		return notAllowed[:len(notAllowed)-2] // trim last comma
	}
	return ""
}
