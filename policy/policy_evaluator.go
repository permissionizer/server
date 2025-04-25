package policy

import (
	"errors"
	"fmt"
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
				Type:  types.TargetRepositoryMisconfigured,
				Error: err.Error(),
			}
		}
		if policy.Ref != nil && *policy.Ref != requestor.Ref {
			if mostMatchingPolicyPriority < 1 {
				mostMatchingPolicyError = &types.PolicyError{Type: types.TargetRepositoryDoesNotAllowRef}
				mostMatchingPolicyPriority = 1
			}
			continue
		}
		if policy.WorkflowRef != nil && *policy.WorkflowRef != requestor.WorkflowRef {
			if mostMatchingPolicyPriority < 2 {
				mostMatchingPolicyError = &types.PolicyError{Type: types.TargetRepositoryDoesNotAllowWorkflowRef}
				mostMatchingPolicyPriority = 2
			}
			continue
		}
		err = checkPermissions(policyPermissions, requestedPermissions)
		if err != nil {
			if mostMatchingPolicyPriority < 3 {
				mostMatchingPolicyError = &types.PolicyError{
					Type:  types.TargetRepositoryDoesNotAllowPermission,
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
		mostMatchingPolicyError = &types.PolicyError{Type: types.TargetRepositoryDoesNotAllowAccess}
	}
	return mostMatchingPolicyError
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
