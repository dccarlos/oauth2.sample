package edu.dccarlos.oauth2.sample.auth;

import java.text.ParseException;
import java.util.Optional;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;

public class OAuth2Authenticator implements Authenticator<String, AccessTokenPrincipal> {
    @Override
    public Optional<AccessTokenPrincipal> authenticate(String accessToken) throws AuthenticationException {
        return Optional.of(new AccessTokenPrincipal(parse(accessToken)));
    }

    private static final JWT parse(String accessToken) throws AuthenticationException {
        try {
            return JWTParser.parse(accessToken);
        } catch (ParseException e) {
            throw new AuthenticationException(e);
        }
    }
}