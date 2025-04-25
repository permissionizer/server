package policy_test

import (
	"server/policy"
	"server/types"
	"server/util"
	"testing"

	"github.com/google/go-github/v71/github"
)

func TestMatchTargetRepositoryPolicy_HappyPath_LessPermissions(t *testing.T) {
	repositoryPolicy := &types.RepositoryPolicy{
		Self: "permissionizer/request-token",
		Allow: []types.AllowPolicy{
			{
				Repository:  "permissionizer/server",
				Ref:         util.Ptr("refs/heads/main"),
				WorkflowRef: util.Ptr(".github/workflows/release.yaml"),
				Permissions: map[string]string{
					"contents": "read",
					"issues":   "write",
				},
			},
		},
	}

	requestor := &types.TokenRequestor{
		Repository:  "permissionizer/server",
		Ref:         "refs/heads/main",
		WorkflowRef: ".github/workflows/release.yaml",
	}

	err := policy.MatchTargetRepositoryPolicy(requestor, repositoryPolicy, &github.InstallationPermissions{
		Contents: util.Ptr("read"),
	})
	if err != nil {
		t.Errorf("expected policy to allow access, got error: %s", err)
	}
}

func TestMatchTargetRepositoryPolicy_HappyPath_ExactPermissions(t *testing.T) {
	repositoryPolicy := &types.RepositoryPolicy{
		Self: "permissionizer/request-token",
		Allow: []types.AllowPolicy{
			{
				Repository:  "permissionizer/server",
				Ref:         util.Ptr("refs/heads/main"),
				WorkflowRef: util.Ptr(".github/workflows/release.yaml"),
				Permissions: map[string]string{
					"contents": "read",
					"issues":   "write",
				},
			},
		},
	}

	requestor := &types.TokenRequestor{
		Repository:  "permissionizer/server",
		Ref:         "refs/heads/main",
		WorkflowRef: ".github/workflows/release.yaml",
	}

	err := policy.MatchTargetRepositoryPolicy(requestor, repositoryPolicy, &github.InstallationPermissions{
		Contents: util.Ptr("read"),
		Issues:   util.Ptr("write"),
	})
	if err != nil {
		t.Errorf("expected policy to allow access, got error: %s", err)
	}
}
