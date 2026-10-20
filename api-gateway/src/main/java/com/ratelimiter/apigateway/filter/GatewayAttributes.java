package com.ratelimiter.apigateway.filter;

/** Keys for values that one filter hands to the next through the exchange. */
public final class GatewayAttributes {

    /** The matched {@code RoutePolicy.Rule}. */
    public static final String RULE = "gateway.rule";
    /** The authenticated user ({@code AuthenticatedUser}); absent on public routes. */
    public static final String PRINCIPAL = "gateway.principal";

    private GatewayAttributes() {
    }
}
