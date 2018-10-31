package edu.dccarlos.oauth2.sample.auth;

import java.security.Principal;
import java.text.ParseException;

import com.nimbusds.jwt.JWT;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AccessTokenPrincipal implements Principal {
    private final JWT accessToken;

    AccessTokenPrincipal(JWT accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public String getName() {
        try {
            return accessToken.getJWTClaimsSet().getStringClaim("sub");
        } catch (ParseException e) {
            log.error("There was an error parsing JWT");
            return "N/A";
        }
    }
}