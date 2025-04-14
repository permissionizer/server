package app.permissionizer.server.util;

public final class AllowRequestContainer<T> {

    public static <T> Builder<T> withAllowed(T allowed) {
        return new Builder<>(allowed);
    }

    private final T allowed;
    private final T requested;

    private AllowRequestContainer(T allowed, T requested) {
        this.allowed = allowed;
        this.requested = requested;
    }

    public T allowed() {
        return allowed;
    }

    public T requested() {
        return requested;
    }

    public static class Builder<T> {
        private final T allowed;

        private Builder(T allowed) {
            this.allowed = allowed;
        }

        public AllowRequestContainer<T> request(T requested) {
            return new AllowRequestContainer<>(allowed, requested);
        }
    }
}
