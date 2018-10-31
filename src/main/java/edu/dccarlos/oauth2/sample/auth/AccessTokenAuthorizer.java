package edu.dccarlos.oauth2.sample.auth;

import io.dropwizard.auth.Authorizer;

public class AccessTokenAuthorizer implements Authorizer<AccessTokenPrincipal> {

    @Override
    public boolean authorize(AccessTokenPrincipal principal, String role) {
        return true;
    }
}