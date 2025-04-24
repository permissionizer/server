package permissionizer_test

import (
	"server/permissionizer"
	"server/types"
	"server/util"
	"testing"

	"github.com/google/go-github/v71/github"
)

func TestMatchTargetRepositoryPolicy_HappyPath_LessPermissions(t *testing.T) {
	policyDoc := types.RepositoryPolicy{
		Self: "permissionizer/request-token",
		Allow: []types.AllowPolicy{
			{
				Repository:  "permissionizer/server",
				Ref:         util.Ptr("refs/heads/main"),
				WorkflowRef: util.Ptr(".github/workflows/release.yaml"),
				Permissions: &github.InstallationPermissions{
					Contents: util.Ptr("read"),
					Issues:   util.Ptr("write"),
				},
			},
		},
	}

	requestor := types.TokenRequestor{
		Repository:  "permissionizer/server",
		Ref:         "refs/heads/main",
		WorkflowRef: ".github/workflows/release.yaml",
	}

	request := types.IssueTokenRequest{
		TargetRepositories: []string{"permissionizer/request-token"},
		Permissions: &github.InstallationPermissions{
			Contents: util.Ptr("read"), // requesting only lesser permission
		},
	}

	decision := permissionizer.MatchTargetRepositoryPolicy(requestor, request, "permissionizer/request-token", policyDoc)
	if !decision.Allow {
		t.Errorf("expected Allow=true, got errors: %+v", decision.Errors)
	}
}

func TestMatchTargetRepositoryPolicy_HappyPath_ExactPermissions(t *testing.T) {
	policyDoc := types.RepositoryPolicy{
		Self: "permissionizer/request-token",
		Allow: []types.AllowPolicy{
			{
				Repository:  "permissionizer/server",
				Ref:         util.Ptr("refs/heads/main"),
				WorkflowRef: util.Ptr(".github/workflows/release.yaml"),
				Permissions: &github.InstallationPermissions{
					Contents: util.Ptr("read"),
					Issues:   util.Ptr("write"),
				},
			},
		},
	}

	requestor := types.TokenRequestor{
		Repository:  "permissionizer/server",
		Ref:         "refs/heads/main",
		WorkflowRef: ".github/workflows/release.yaml",
	}

	request := types.IssueTokenRequest{
		TargetRepositories: []string{"permissionizer/request-token"},
		Permissions: &github.InstallationPermissions{
			Contents: util.Ptr("read"),
			Issues:   util.Ptr("write"),
		},
	}

	decision := permissionizer.MatchTargetRepositoryPolicy(requestor, request, "permissionizer/request-token", policyDoc)
	if !decision.Allow {
		t.Errorf("expected Allow=true, got errors: %+v", decision.Errors)
	}
}
