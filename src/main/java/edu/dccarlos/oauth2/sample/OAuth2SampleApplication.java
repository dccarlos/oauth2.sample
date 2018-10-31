package edu.dccarlos.oauth2.sample;

import org.eclipse.jetty.server.session.SessionHandler;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;

import edu.dccarlos.oauth2.sample.auth.AccessTokenAuthorizer;
import edu.dccarlos.oauth2.sample.auth.AccessTokenPrincipal;
import edu.dccarlos.oauth2.sample.auth.OAuth2Authenticator;
import edu.dccarlos.oauth2.sample.resources.Oauth2ResourceV1;
import edu.dccarlos.oauth2.sample.resources.SampleResourceV1;
import io.dropwizard.Application;
import io.dropwizard.assets.AssetsBundle;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.oauth.OAuthCredentialAuthFilter;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

public class OAuth2SampleApplication extends Application<OAuth2SampleConfiguration> {
    private static final String KIS_REALM = "KIS REALM";

    public static void main(final String[] args) throws Exception {
        new OAuth2SampleApplication().run(args);
    }

    @Override
    public String getName() {
        return "OAuth2Sample";
    }

    @Override
    public void initialize(final Bootstrap<OAuth2SampleConfiguration> bootstrap) {
        bootstrap.addBundle(new AssetsBundle("/static", "/", "index.html", "oauth2-sample-ui"));
    }

    @Override
    public void run(final OAuth2SampleConfiguration configuration, final Environment environment) {
        configureOAuth(environment);

        // Auth resource
        environment.jersey().register(Oauth2ResourceV1.builder().oAuth2Config(configuration.getOauth2Config()).build());

        // Sample resource
        environment.jersey().register(SampleResourceV1.class);
    }

    private void configureOAuth(final Environment environment) {
        try {
            // Session handler
            environment.servlets().setSessionHandler(new SessionHandler());

            // OAuth2 filter
            environment.jersey().register(new AuthDynamicFeature(new OAuthCredentialAuthFilter.Builder<AccessTokenPrincipal>()
                    .setAuthenticator(new OAuth2Authenticator())
                    .setAuthorizer(new AccessTokenAuthorizer())
                    .setPrefix("Bearer")
                    .setRealm(KIS_REALM)
                    .buildAuthFilter()));

            environment.jersey().register(RolesAllowedDynamicFeature.class);
            environment.jersey().register(new AuthValueFactoryProvider.Binder<>(AccessTokenPrincipal.class));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to configure JwtVerifier", e);
        }
    }
}