# Permissionizer / Server

This is a server for [Permissionizer App](TODO), a GitHub OIDC provider that issues tokens for requesting GitHub repositories if allowed by the target repository.

## Local development

1. Create a GitHub App with required permissions and install it into the repository / org
2. Add `client-id` and `private-key` of the GitHub App into `config/permissionizer-server.yaml` or use Environment variables. Adjust other settings if necessary.
3. Start the permissionizer server
   ```bash
   go run .
   ```
4. Issue a permissionizer token with (fake) GitHub OIDC token
   ```bash
   curl -d '
     {
       "target_repositories": ["permissionizer/server"],
       "permissions": {
         "contents": "read"
       }
     }' \
     -H "Authorization: Bearer $(go run . --fake-token --repository permissionizer/request-token)" \
     http://localhost:8080/v1/token
   ```

> [!NOTE]
> `--fake-token` flag allows generating an unsigned JWT token that imitates the token issued by GitHub OIDC.
> In order to use it, you must disable all token checks when starting the server `permissionizer.unsecure-skip-token-validation: true` (Not suited for production use)

## Troubleshooting

### Error types

#### Error: `target_repository_misconfigured_self_clause`

This error indicates that the target repository access policy is invalid due to mismatching `self` clause. This might
happen if the repository was renamed or forked without updating `permissionizer` policy file.

**Fix:** reach out to the repository owner asking them to update the permissionizer policy (`.github/permissionizer.yaml`)
