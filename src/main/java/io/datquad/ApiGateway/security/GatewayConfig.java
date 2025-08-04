package io.datquad.ApiGateway.security;

import io.datquad.ApiGateway.filter.CookieToHeaderFilter;
import io.datquad.ApiGateway.filter.JwtAuthenticationFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class GatewayConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CookieToHeaderFilter cookieToHeaderFilter;

    public GatewayConfig(JwtAuthenticationFilter jwtAuthenticationFilter, CookieToHeaderFilter cookieToHeaderFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.cookieToHeaderFilter = cookieToHeaderFilter;
    }

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration corsConfig = new CorsConfiguration();

        corsConfig.setAllowedOrigins(Arrays.asList(
                "http://182.18.177.16",
                "http://localhost:3000",
                "http://localhost:80"
        ));

        corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        corsConfig.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "Accept",
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers",
                "X-Forwarded-For",
                "X-Forwarded-Proto",
                "X-Forwarded-Host"
        ));
        corsConfig.setExposedHeaders(Arrays.asList("Authorization", "Set-Cookie"));
        corsConfig.setAllowCredentials(true);
        corsConfig.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);

        return new CorsWebFilter(source);
    }

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                // Authentication routes (no JWT filter needed)
                .route("user_service_auth", r -> r
                        .path("/users/login", "/users/register", "/users/send-otp", "/users/verify-otp", "/users/update-password")
                        .filters(f -> f.filter(new CookieToHeaderFilter()))
                        .uri("http://dataquad-userregister-dev:8084"))

                // Protected user routes
                .route("user_service", r -> r
                        .path("/users/**")
                        .filters(f -> f.filter(new CookieToHeaderFilter())
                                .filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
                        .uri("http://dataquad-userregister-dev:8084"))

                // Protected requirements routes
                .route("requirements_service", r -> r
                        .path("/requirements/**")
                        .filters(f -> f.filter(new CookieToHeaderFilter())
                                .filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
                        .uri("http://dataquad-requirements-dev:8222"))

                // Protected candidates routes
                .route("candidates_service", r -> r
                        .path("/candidate/**")
                        .filters(f -> f.filter(new CookieToHeaderFilter())
                                .filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
                        .uri("http://dataquad-candidates-dev:8086"))

                // ✅ ✅ Protected hotlist routes
                .route("hotlist_service", r -> r
                        .path("/hotlist/**")
                        .filters(f -> f.filter(new CookieToHeaderFilter())
                                .filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
                        .uri("http://adroit-hotlist-dev:8091"))

                // Optional health check route
                .route("health_check", r -> r
                        .path("/health")
                        .filters(f -> f.setStatus(200))
                        .uri("http://httpbin.org"))

                .build();

    }
}
