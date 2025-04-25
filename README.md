# Permissionizer / Server

This is a server for [Permissionizer App](TODO), a GitHub OIDC provider that issues tokens for requesting GitHub repositories if allowed by the target repository.

## Custom Deployment

1. Create a GitHub App with required permissions and install it into the repository / org
2. Add app details into `config/permissionizer-server.yaml` or use Environment variables (see `config/.env`).
3. Use docker image `ghcr.io/permissionizer/server:latest` to run the server with mounting the configuration or using environment variables.
4. When using `permissionizer/request-token` action, specify the `permissionizer-server` URL:
   ```yaml
   - name: Request permissionizer token
     id: permissionizer
     uses: permissionizer/request-token@v1
     with:
       permissionizer-server: https://permissionizer.mycompany.com
       target-repositories: permissionizer/server
       permissions: contents:read
   ```
  
## Local development

1. Create a GitHub App with required permissions and install it into the repository / org
2. Add app details into `config/dev/permissionizer-server.yaml` (see `config/permissionizer-server.yaml`)
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

