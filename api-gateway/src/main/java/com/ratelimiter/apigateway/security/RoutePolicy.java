package com.ratelimiter.apigateway.security;

import com.ratelimiter.apigateway.ratelimit.RateTier;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.PathContainer;
import org.springframework.stereotype.Component;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Deny-by-default allow-list of every (method, path) the gateway will forward, with the roles that may use it and
 * the rate-limit tier that applies. Anything not listed here never reaches a backend service.
 */
@Component
public class RoutePolicy {

    public enum Outcome { MATCH, METHOD_NOT_ALLOWED, NOT_FOUND }

    /** An empty role set means "public" (no token needed). */
    public record Rule(HttpMethod method, PathPattern pattern, Set<Role> roles, RateTier tier) {
        public boolean isPublic() {
            return roles.isEmpty();
        }
    }

    public record Decision(Outcome outcome, Rule rule, Set<HttpMethod> allowedMethods) {
    }

    private static final Pattern SAFE_PATH = Pattern.compile("^/[A-Za-z0-9._/-]*$");
    private static final Set<Role> ANY_ROLE = Set.of(Role.ADMIN, Role.SELLER, Role.CUSTOMER);
    private static final Set<Role> ADMIN_ONLY = Set.of(Role.ADMIN);
    private static final Set<Role> ADMIN_OR_SELLER = Set.of(Role.ADMIN, Role.SELLER);

    private final PathPatternParser parser = new PathPatternParser();
    private final List<Rule> rules = List.of(
            rule(HttpMethod.POST, "/auth/register", Set.of(), RateTier.REGISTER),
            rule(HttpMethod.POST, "/auth/login", Set.of(), RateTier.LOGIN),
            rule(HttpMethod.GET, "/auth/admin/users", ADMIN_ONLY, RateTier.READ),
            rule(HttpMethod.PUT, "/auth/admin/users/{username}/role", ADMIN_ONLY, RateTier.WRITE),
            rule(HttpMethod.GET, "/products", ANY_ROLE, RateTier.READ),
            rule(HttpMethod.GET, "/products/{id}", ANY_ROLE, RateTier.READ),
            rule(HttpMethod.POST, "/products", ADMIN_OR_SELLER, RateTier.WRITE),
            rule(HttpMethod.DELETE, "/products/{id}", ADMIN_OR_SELLER, RateTier.WRITE));

    private Rule rule(HttpMethod method, String pattern, Set<Role> roles, RateTier tier) {
        return new Rule(method, parser.parse(pattern), roles, tier);
    }

    /**
     * Only plain path characters are accepted: no percent-encoding (so no %2e%2e or %2f tricks), no dot segments,
     * no double slashes, bounded length. Backends therefore never see a path the policy interpreted differently.
     */
    public static boolean isSafePath(String rawPath) {
        if (rawPath == null || rawPath.length() > 200 || !SAFE_PATH.matcher(rawPath).matches()) {
            return false;
        }
        if (rawPath.contains("//")) {
            return false;
        }
        for (String segment : rawPath.split("/")) {
            if (segment.equals(".") || segment.equals("..")) {
                return false;
            }
        }
        return true;
    }

    public Decision decide(HttpMethod method, String rawPath) {
        PathContainer path = PathContainer.parsePath(rawPath);
        Set<HttpMethod> allowed = new LinkedHashSet<>();
        for (Rule r : rules) {
            if (r.pattern().matches(path)) {
                if (r.method().equals(method)) {
                    return new Decision(Outcome.MATCH, r, Set.of());
                }
                allowed.add(r.method());
            }
        }
        if (allowed.isEmpty()) {
            return new Decision(Outcome.NOT_FOUND, null, Set.of());
        }
        return new Decision(Outcome.METHOD_NOT_ALLOWED, null, allowed);
    }
}
