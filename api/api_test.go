package api_test

import (
	"github.com/onsi/gomega"
	"server/api"
	"testing"
)

func TestParsesPolicyFile(t *testing.T) {
	gomega.RegisterTestingT(t)

	policy, err := api.ParsePolicy(`
self: permissionizer/target-repository
allow:
  - repository: permissionizer/requesting-repository
    ref: refs/heads/main
    workflow_ref: permissionizer/requesting-repository/.github/workflows/permissionizer.yaml@refs/heads/main
    permissions:
      contents: read
      issues: write
`, "permissionizer", "target-repository")
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(policy.Self).To(gomega.Equal("permissionizer/target-repository"))
	gomega.Expect(policy.Allow).To(gomega.HaveLen(1))
	gomega.Expect(policy.Allow[0].Repository).To(gomega.Equal("permissionizer/requesting-repository"))
	gomega.Expect(*policy.Allow[0].Ref).To(gomega.Equal("refs/heads/main"))
	gomega.Expect(*policy.Allow[0].WorkflowRef).To(gomega.Equal("permissionizer/requesting-repository/.github/workflows/permissionizer.yaml@refs/heads/main"))
	gomega.Expect(policy.Allow[0].Permissions).To(gomega.Equal(map[string]string{
		"contents": "read",
		"issues":   "write",
	}))

}
