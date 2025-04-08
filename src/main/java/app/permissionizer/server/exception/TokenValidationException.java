package app.permissionizer.server.exception;

public class TokenValidationException extends RuntimeException {
    public TokenValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
