package policy_test

import (
	"github.com/google/go-github/v71/github"
	"github.com/onsi/gomega"
	"server/policy"
	"server/types"
	"server/util"
	"testing"
)

var (
	defaultPermissions = map[string]string{
		"contents": "read",
		"issues":   "write",
	}
)

func TestMatchRepositoryOnlyPolicy(t *testing.T) {
	gomega.RegisterTestingT(t)

	repositoryPolicy := &types.RepositoryPolicy{
		Self: "permissionizer/target-repository",
		Allow: []types.AllowPolicy{
			allowPolicy(&types.AllowPolicy{
				Repository: "permissionizer/requesting-repository",
			}),
		},
	}
	tests := []struct {
		name        string
		requestor   *types.TokenRequestor
		permissions map[string]string
		allowed     bool
	}{
		{
			name:        "allow default",
			requestor:   testRequestor(),
			permissions: defaultPermissions,
			allowed:     true,
		},
		{
			name: "allow from any branch ref",
			requestor: &types.TokenRequestor{
				Ref: "refs/heads/feature-1",
			},
			permissions: defaultPermissions,
			allowed:     true,
		},
		{
			name: "allow from any workflow ref",
			requestor: &types.TokenRequestor{
				WorkflowRef: "permissionizer/requesting-repository/.github/workflows/test.yaml@refs/heads/main",
			},
			permissions: defaultPermissions,
			allowed:     true,
		},
		{
			name: "allow from any workflow ref of any branch",
			requestor: &types.TokenRequestor{
				Ref:         "refs/heads/feature-1",
				WorkflowRef: "permissionizer/requesting-repository/.github/workflows/test.yaml@refs/heads/feature-1",
			},
			permissions: defaultPermissions,
			allowed:     true,
		},
		{
			name: "allow less permissions",
			permissions: map[string]string{
				"contents": "read",
			},
			allowed: true,
		},
		{
			name: "allow weaker permissions access",
			permissions: map[string]string{
				"contents": "read",
				"issues":   "read",
			},
			allowed: true,
		},
		{
			name: "deny more permissions",
			permissions: map[string]string{
				"contents":      "read",
				"issues":        "write",
				"pull-requests": "write",
			},
			allowed: false,
		},
		{
			name: "deny stronger permissions access",
			requestor: &types.TokenRequestor{
				Ref:         "refs/heads/feature-1",
				WorkflowRef: "permissionizer/requesting-repository/.github/workflows/test.yaml@refs/heads/feature-1",
			},
			permissions: map[string]string{
				"contents": "write",
				"issues":   "write",
			},
			allowed: false,
		},
		{
			name: "deny from different repository",
			requestor: &types.TokenRequestor{
				Repository: "permissionizer/other-repository",
			},
			permissions: defaultPermissions,
			allowed:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestor := testRequestor(tt.requestor)

			policyError := policy.MatchTargetRepositoryPolicy(requestor, repositoryPolicy, convertPermissions(tt.permissions))
			if tt.allowed {
				gomega.Expect(policyError).To(gomega.BeNil())
			} else {
				gomega.Expect(policyError).To(gomega.Not(gomega.BeNil()))
				gomega.Expect(policyError.Type).To(gomega.Not(gomega.BeNil()))
			}
		})
	}
}

func TestMatchFullRefPolicy(t *testing.T) {
	gomega.RegisterTestingT(t)
	repositoryPolicy := &types.RepositoryPolicy{
		Self: "permissionizer/target-repository",
		Allow: []types.AllowPolicy{
			allowPolicy(&types.AllowPolicy{
				Repository: "permissionizer/requesting-repository",
				Ref:        util.Ptr("refs/heads/main"),
			}),
		},
	}

	tests := []struct {
		name        string
		requestor   *types.TokenRequestor
		permissions map[string]string
		allowed     bool
	}{
		{
			name:        "allow default",
			requestor:   testRequestor(),
			permissions: defaultPermissions,
			allowed:     true,
		},
		{
			name: "allow from any workflow ref",
			requestor: &types.TokenRequestor{
				WorkflowRef: "permissionizer/requesting-repository/.github/workflows/test.yaml@refs/heads/main",
			},
			permissions: defaultPermissions,
			allowed:     true,
		},
		{
			name: "allow less permissions",
			permissions: map[string]string{
				"contents": "read",
			},
			allowed: true,
		},
		{
			name: "allow weaker permissions access",
			permissions: map[string]string{
				"contents": "read",
				"issues":   "read",
			},
			allowed: true,
		},
		{
			name: "deny from other branch ref",
			requestor: &types.TokenRequestor{
				Ref: "refs/heads/feature-1",
			},
			permissions: defaultPermissions,
			allowed:     false,
		},
		{
			name: "deny more permissions",
			requestor: &types.TokenRequestor{
				Ref:         "refs/heads/feature-1",
				WorkflowRef: "permissionizer/requesting-repository/.github/workflows/test.yaml@refs/heads/feature-1",
			},
			permissions: map[string]string{
				"contents":      "read",
				"issues":        "write",
				"pull-requests": "write",
			},
			allowed: false,
		},
		{
			name: "deny stronger permissions access",
			requestor: &types.TokenRequestor{
				Ref:         "refs/heads/feature-1",
				WorkflowRef: "permissionizer/requesting-repository/.github/workflows/test.yaml@refs/heads/feature-1",
			},
			permissions: map[string]string{
				"contents": "write",
				"issues":   "write",
			},
			allowed: false,
		},
		{
			name: "deny from different repository",
			requestor: &types.TokenRequestor{
				Repository: "permissionizer/other-repository",
			},
			permissions: defaultPermissions,
			allowed:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestor := testRequestor(tt.requestor)

			policyError := policy.MatchTargetRepositoryPolicy(requestor, repositoryPolicy, convertPermissions(tt.permissions))
			if tt.allowed {
				gomega.Expect(policyError).To(gomega.BeNil())
			} else {
				gomega.Expect(policyError).To(gomega.Not(gomega.BeNil()))
				gomega.Expect(policyError.Type).To(gomega.Not(gomega.BeNil()))
			}
		})
	}
}

func TestRefMatch(t *testing.T) {
	gomega.RegisterTestingT(t)

	tests := []struct {
		name      string
		policyRef string
		ref       string
		allowed   bool
	}{
		{
			name:      "simple ref match",
			policyRef: "main",
			ref:       "refs/heads/main",
			allowed:   true,
		},
		{
			name:      "wildcard ref match",
			policyRef: "refs/tags/v*",
			ref:       "refs/tags/v1.0.0",
			allowed:   true,
		},
		{
			name:      "wildcard simplified ref match",
			policyRef: "v*",
			ref:       "refs/tags/v1.0.0",
			allowed:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repositoryPolicy := &types.RepositoryPolicy{
				Self: "permissionizer/target-repository",
				Allow: []types.AllowPolicy{
					allowPolicy(&types.AllowPolicy{
						Ref: util.Ptr(tt.policyRef),
					}),
				},
			}
			requestor := testRequestor(&types.TokenRequestor{
				Ref: tt.ref,
			})

			policyError := policy.MatchTargetRepositoryPolicy(requestor, repositoryPolicy, convertPermissions(defaultPermissions))
			if tt.allowed {
				gomega.Expect(policyError).To(gomega.BeNil())
			} else {
				gomega.Expect(policyError).To(gomega.Not(gomega.BeNil()))
				gomega.Expect(policyError.Type).To(gomega.Not(gomega.BeNil()))
			}
		})
	}
}

func TestWorkflowRefMatch(t *testing.T) {
	gomega.RegisterTestingT(t)

	tests := []struct {
		name        string
		policy      types.AllowPolicy
		workflowRef string
		allowed     bool
	}{
		{
			name: "exact match",
			policy: types.AllowPolicy{
				WorkflowRef: util.Ptr("permissionizer/requesting-repository/.github/workflows/release.yaml@refs/heads/main"),
			},
			workflowRef: "permissionizer/requesting-repository/.github/workflows/release.yaml@refs/heads/main",
			allowed:     true,
		},
		{
			name: "workflow without ref",
			policy: types.AllowPolicy{
				WorkflowRef: util.Ptr("permissionizer/requesting-repository/.github/workflows/release.yaml"),
			},
			workflowRef: "permissionizer/requesting-repository/.github/workflows/release.yaml@refs/heads/main",
			allowed:     true,
		},
		{
			name: "wildcard in workflow file",
			policy: types.AllowPolicy{
				WorkflowRef: util.Ptr("permissionizer/requesting-repository/.github/workflows/release-*.yaml@refs/heads/main"),
			},
			workflowRef: "permissionizer/requesting-repository/.github/workflows/release-v1.yaml@refs/heads/main",
			allowed:     true,
		},
		{
			name: "wildcard in ref",
			policy: types.AllowPolicy{
				WorkflowRef: util.Ptr("permissionizer/requesting-repository/.github/workflows/release.yaml@refs/heads/*"),
			},
			workflowRef: "permissionizer/requesting-repository/.github/workflows/release.yaml@refs/heads/feature-1",
			allowed:     true,
		},
		{
			name: "wildcard in both workflow file and ref",
			policy: types.AllowPolicy{
				WorkflowRef: util.Ptr("permissionizer/requesting-repository/.github/workflows/release-*.yaml@refs/heads/*"),
			},
			workflowRef: "permissionizer/requesting-repository/.github/workflows/release-v1.yaml@refs/heads/feature-1",
			allowed:     true,
		},
		{
			name: "workflow without org/repo prefix",
			policy: types.AllowPolicy{
				WorkflowRef: util.Ptr(".github/workflows/release.yaml@refs/heads/main"),
			},
			workflowRef: "permissionizer/requesting-repository/.github/workflows/release.yaml@refs/heads/main",
			allowed:     true,
		},
		{
			name: "wildcard without org/repo prefix",
			policy: types.AllowPolicy{
				WorkflowRef: util.Ptr(".github/workflows/release-*.yaml@refs/heads/*"),
			},
			workflowRef: "permissionizer/requesting-repository/.github/workflows/release-v1.yaml@refs/heads/feature-1",
			allowed:     true,
		},
		{
			name: "no match due to different workflow file",
			policy: types.AllowPolicy{
				WorkflowRef: util.Ptr("permissionizer/requesting-repository/.github/workflows/release.yaml@refs/heads/main"),
			},
			workflowRef: "permissionizer/requesting-repository/.github/workflows/build.yaml@refs/heads/main",
			allowed:     false,
		},
		{
			name: "no match due to different ref",
			policy: types.AllowPolicy{
				WorkflowRef: util.Ptr("permissionizer/requesting-repository/.github/workflows/release.yaml@refs/heads/main"),
			},
			workflowRef: "permissionizer/requesting-repository/.github/workflows/release.yaml@refs/heads/feature-1",
			allowed:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestor := testRequestor(&types.TokenRequestor{
				WorkflowRef: tt.workflowRef,
			})

			repositoryPolicy := &types.RepositoryPolicy{
				Self:  "permissionizer/target-repository",
				Allow: []types.AllowPolicy{allowPolicy(&tt.policy)},
			}

			policyError := policy.MatchTargetRepositoryPolicy(requestor, repositoryPolicy, convertPermissions(defaultPermissions))
			if tt.allowed {
				gomega.Expect(policyError).To(gomega.BeNil())
			} else {
				gomega.Expect(policyError).To(gomega.Not(gomega.BeNil()))
				gomega.Expect(policyError.Type).To(gomega.Not(gomega.BeNil()))
			}
		})
	}
}

func TestMatchOrgWildcard(t *testing.T) {
	gomega.RegisterTestingT(t)

	repositoryPolicy := &types.RepositoryPolicy{
		Self: "permissionizer/target-repository",
		Allow: []types.AllowPolicy{
			allowPolicy(&types.AllowPolicy{
				Repository: "permissionizer/*",
			}),
		},
	}
	tests := []struct {
		name        string
		requestor   *types.TokenRequestor
		permissions map[string]string
		allowed     bool
	}{
		{
			name: "allow from the same repo",
			requestor: &types.TokenRequestor{
				Repository: "permissionizer/target-repository",
			},
			permissions: defaultPermissions,
			allowed:     true,
		},
		{
			name: "allow from another repo",
			requestor: &types.TokenRequestor{
				Repository: "permissionizer/requesting-repository",
			},
			permissions: defaultPermissions,
			allowed:     true,
		},
		{
			name: "deny from different org",
			requestor: &types.TokenRequestor{
				Repository: "org/repo",
			},
			permissions: defaultPermissions,
			allowed:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestor := testRequestor(tt.requestor)

			policyError := policy.MatchTargetRepositoryPolicy(requestor, repositoryPolicy, convertPermissions(tt.permissions))
			if tt.allowed {
				gomega.Expect(policyError).To(gomega.BeNil())
			} else {
				gomega.Expect(policyError).To(gomega.Not(gomega.BeNil()))
				gomega.Expect(policyError.Type).To(gomega.Not(gomega.BeNil()))
			}
		})
	}
}

func allowPolicy(incomplete ...*types.AllowPolicy) types.AllowPolicy {
	var value *types.AllowPolicy
	if len(incomplete) == 1 && incomplete[0] != nil {
		value = incomplete[0]
	} else {
		value = &types.AllowPolicy{}
	}
	if value.Repository == "" {
		value.Repository = "permissionizer/requesting-repository"
	}
	if value.Permissions == nil {
		value.Permissions = defaultPermissions
	}
	return *value
}

func testRequestor(incomplete ...*types.TokenRequestor) *types.TokenRequestor {
	var value *types.TokenRequestor
	if len(incomplete) == 1 && incomplete[0] != nil {
		value = incomplete[0]
	} else {
		value = &types.TokenRequestor{}
	}
	if value.Repository == "" {
		value.Repository = "permissionizer/requesting-repository"
	}
	if value.Ref == "" {
		value.Ref = "refs/heads/main"
	}
	if value.WorkflowRef == "" {
		value.WorkflowRef = "permissionizer/requesting-repository/.github/workflows/release.yaml@" + value.Ref
	}
	if value.RunId == "" {
		value.RunId = "0"
	}
	return value
}

func convertPermissions(permissions map[string]string) *github.InstallationPermissions {
	installationPermissions, err := util.MapToInstallationPermissions(permissions)
	if err != nil {
		panic(err)
	}
	return installationPermissions
}
