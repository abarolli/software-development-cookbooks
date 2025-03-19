The following dependencies are necessary to enable Spring Security with JsonWebtoken for authorization.

```java
implementation 'org.springframework.boot:spring-boot-starter-security'
implementation 'io.jsonwebtoken:jjwt-api'
runtimeOnly 'io.jsonwebtoken:jjwt-impl'
runtimeOnly 'io.jsonwebtoken:jjwt-jackson'
```

First create the JwtService class. This is used to generate Json Web Tokens (JWTs) as well as
parse JWTs to validate user credentials.

```java
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;

@Service
public class JwtService {
    @Value("${jwt.secret}") // injected from application properties file
    private String SECRET_KEY;
    private SecretKey key;

    @PostConstruct // needed because SECRET_KEY is injected after field initialization
    public void init() {
        key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    }

    public String generateToken(String username) {
        final int oneHour = 1000 * 60 * 60;
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + oneHour))
                .signWith(key)
                .compact();
    }

    public String extractUsername(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public boolean validateToken(String token, String username) {
        return username.equals(extractUsername(token)) && !isTokenExpired(token);
    }

    public boolean isTokenExpired(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration()
                .before(new Date());
    }
}
```

Next is implementing the authentication filter.

```java
package io.onicodes.issue_tracker.security.jwt;
import java.io.IOException;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String token = authHeader.substring(7);
        try {
            String username = jwtService.extractUsername(token);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(
                        new User(username, "", List.of(new SimpleGrantedAuthority("USER"))),
                        null,
                        List.of(new SimpleGrantedAuthority("USER"))
                    );
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        } catch (ExpiredJwtException e) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token expired");
            return;
        }

        filterChain.doFilter(request, response);
    }
}

```

Extending the `OncePerRequestFilter` built-in Spring class ensures `doFilterInternal` is
called only once per request. `doFilterInternal` performs the following:

#### retrieving the token

```java
        // retrieves the Authorization http header
        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // if authHeader is null or does not start with 'Bearer ' then immediately skip JWT processing
            filterChain.doFilter(request, response);
            return;
        }
        // else, extract the token from the authHeader
        final String token = authHeader.substring(7);
```

#### creating and adding a new authentication token to the security context if the user's not yet authenticated

```java
        try {
            // parse token to extract username
            String username = jwtService.extractUsername(token);
            // verify the username exists and the user is not already authenticated in the security context
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // create a new authentication token
                UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(
                        // Principal is created from the builtin User class using the username,
                        // a blank string for the password (not needed after token's already been granted),
                        // and a hardcoded list with a single "USER" authority
                        new User(username, "", List.of(new SimpleGrantedAuthority("USER"))),
                        null, // null for password since again it's not needed here
                        List.of(new SimpleGrantedAuthority("USER")) // same list used in Principal object
                    );
                // set the new authentication token in the security context for downstream request filters
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
```

#### handling expired jwt exception

```java
         catch (ExpiredJwtException e) {
            // returns 401 unauthorized error response with "Token expired" message
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token expired");
            return;
        }
```

#### forward request to next filter in chain

```java
        // Regardless of whether the token was processed or an error occurred (outside of an early return),
        // the request is forwarded to the next filter in the chain.
        filterChain.doFilter(request, response);
```
