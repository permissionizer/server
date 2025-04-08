package app.permissionizer.server.github.types;

import org.springframework.aot.hint.annotation.RegisterReflectionForBinding;

import java.util.List;
import java.util.Map;

@RegisterReflectionForBinding
public record AccessTokenRequest(
        List<String> repositories,
        Map<String, String> permissions
) {
}
