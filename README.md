# Permissionizer / Server

This is a server for [Permissionizer](https://github.com/marketplace/actions/permissionizer-request-token), a GitHub OIDC provider that issues tokens for requesting GitHub repositories if allowed by the target repository.

For detailed guidance on how to use the Permissionizer App, please refer to the [permissionizer/request-token](https://github.com/marketplace/actions/permissionizer-request-token) action documentation.

### Custom Deployment

While the process of issuing tokens is secure and requires explicit policies for
the token exchange, to maintain full control over token exchange and deployment,
organizations can create a custom Permissionizer App (public or internal) and
deploy an instance of the Permissionizer Server. This ensures that no tokens
ever leave the organization's internal network.

To deploy a custom instance of the Permissionizer Server, follow these steps:

1. **Create a GitHub App**

   Set up a GitHub App with the required permissions and install it into the
   desired repository or organization. The only required permission is
   `contents: read`, that ensures the server can read the
   `.github/permissionizer.yaml` policy file in the target repository, all other
   permissions are optional and depend on which permissions you might need to
   request for cross-repository automations.

2. **Configure the Server**

   Add the GitHub App details to the `config/permissionizer-server.yaml` file or
   use environment variables (refer to `config/.env` for supported variables).

3. **Run the Server**

   Use the official Docker image `ghcr.io/permissionizer/server:latest` to
   deploy the server. Mount the configuration file or pass the required
   environment variables.

4. **Integrate with `permissionizer/request-token`**

   When using the `permissionizer/request-token` action, specify the custom
   server URL in the `permissionizer-server` input:

   ```yaml
   - id: request-token
     uses: permissionizer/request-token@v1
     with:
       permissionizer-server: https://permissionizer.mycompany.com
       target-repository: permissionizer/server
       permissions: |
         contents: read
         issues: write
   ```
  
## Local development

1. Create a GitHub App with required permissions and install it into the repository / org
2. Add app details into `config/dev/permissionizer-server.yaml` (see `config/permissionizer-server.yaml`)
3. Start the permissionizer server
   ```bash
   go run .
   ```
4. Issue a permissionizer token with a (fake) GitHub OIDC token
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

