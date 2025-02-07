package io.security.springsecuritymaster.security.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class RestAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;
    private final Object credential;

    public RestAuthenticationToken(Collection<? extends GrantedAuthority> authorities, Object principal, Object credential) {
        super(authorities);
        this.principal = principal;
        this.credential = credential;
        setAuthenticated(true);
    }

    public RestAuthenticationToken(Object principal, Object credential) {
        super(null);
        this.principal = principal;
        this.credential = credential;
        setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
        return this.credential;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }
}
