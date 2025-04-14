package app.permissionizer.server.github;

public class GithubClientException extends RuntimeException {
    private int statusCode;

    public GithubClientException(int statusCode, String message) {
        this(statusCode, message, null);
    }

    public GithubClientException(int statusCode, String message, Throwable clause) {
        super(message, clause);
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }
}
