package app.permissionizer.server.api;

import app.permissionizer.server.TokenService;
import app.permissionizer.server.util.IdTokenValidator;
import app.permissionizer.server.exception.TokenValidationException;
import app.permissionizer.server.api.types.IssueTokenRequest;
import app.permissionizer.server.api.types.IssueTokenResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class PermissionizerServerController {

    private final IdTokenValidator idTokenValidator;
    private final TokenService tokenService;

    public PermissionizerServerController(IdTokenValidator idTokenValidator, TokenService tokenService) {
        this.idTokenValidator = idTokenValidator;
        this.tokenService = tokenService;
    }

    @PostMapping("/v1/token")
    public IssueTokenResponse token(
            @RequestBody IssueTokenRequest request,
            @RequestHeader("Authorization") String authorization
    ) {
        if (!authorization.startsWith("Bearer ")) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        var values = authorization.split(" ", 2);
        if (values.length != 2) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        var idToken = values[1];
        if (idToken.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        try {
            var claims = idTokenValidator.validateIdToken(idToken);

            var repository = claims.getStringClaim("repository");
            var ref = claims.getStringClaim("ref");
            var workflowRef = claims.getStringClaim("workflow_ref");
            var runId = claims.getStringClaim("run_id");

            return tokenService.issueScopedToken(request, repository, ref, workflowRef, runId);
        } catch (TokenValidationException e) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
    }

    @PostMapping("/v1/webhook")
    public void webhook() {
        throw new IllegalStateException("Not implemented");
    }
}
