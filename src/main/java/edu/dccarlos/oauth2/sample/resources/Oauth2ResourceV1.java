package edu.dccarlos.oauth2.sample.resources;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiConsumer;

import javax.servlet.http.HttpSession;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.StatusType;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.glassfish.jersey.client.oauth2.ClientIdentifier;
import org.glassfish.jersey.client.oauth2.OAuth2ClientSupport;
import org.glassfish.jersey.client.oauth2.OAuth2CodeGrantFlow;
import org.glassfish.jersey.client.oauth2.TokenResult;

import com.codahale.metrics.annotation.Timed;
import com.google.common.io.BaseEncoding;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import edu.dccarlos.oauth2.sample.OAuth2SampleConfiguration.OAuth2Config;
import io.dropwizard.jersey.sessions.Session;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Path("/auth") /* Remember config in YAML: 'rootPath: /api/' */
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class Oauth2ResourceV1 {
    public static final String FLOW_KEY = "oauth2-flow-id";
    public static final String ACCESS_TOKEN_KEY = "access-token-attribute";
    public static final String TOKEN_ID_KEY = "token-id-attribute";

    private final OAuth2Config oAuth2Config;
    private final Client oktaClient;

    @Builder
    public Oauth2ResourceV1(OAuth2Config oAuth2Config) {
        Objects.requireNonNull(oAuth2Config, "OAuth2 config shouldn't be null");
        this.oAuth2Config = oAuth2Config;
        this.oktaClient = ClientBuilder.newClient();
    }

    @GET
    @Path("/login")
    @Timed
    public Response login(@Context UriInfo uriInfo, @Session HttpSession session) {
        if (session != null && session.getAttribute(ACCESS_TOKEN_KEY) != null) {
            log.warn("Existing session...");

            URI spaPath = getBaseUri(uriInfo);

            log.info("Redirecting to {}", spaPath);

            return Response.status(Response.Status.FOUND).location(spaPath).build();
        } else {

            final OAuth2CodeGrantFlow flow = createOAuth2CodeGrantFlow(oAuth2Config, getBaseUri(uriInfo));
            String oAuthLoginUri = flow.start();
            session.setAttribute(FLOW_KEY, flow);

            return Response.status(Response.Status.FOUND).location(UriBuilder.fromUri(oAuthLoginUri).build()).build();
        }
    }

    @GET
    @Path("/logout")
    public Response logout(@Session HttpSession session, @Context UriInfo uriInfo) {
        String accessToken = (String) session.getAttribute(ACCESS_TOKEN_KEY);
        String tokenId = (String) session.getAttribute(TOKEN_ID_KEY);

        if (accessToken != null) {
            log.warn("Token has been found and is going to be revoked...");

            StatusType revoked = revokeAccessToken(accessToken);
            StatusType loggedOut = logout(tokenId);

            session.removeAttribute(ACCESS_TOKEN_KEY);
            session.removeAttribute(TOKEN_ID_KEY);
            session.invalidate();

            log.warn("Access token has been revoked: {}", revoked);
            log.warn("Session has been logged out: {}", loggedOut);
        }

        URI spaPath = getBaseUri(uriInfo);

        log.info("Redirecting to {}", spaPath);

        return Response.status(Response.Status.FOUND).location(spaPath).build();
    }

    @GET
    @Path("/callback")
    @Timed
    public Response getCallback(
            @QueryParam("state") String state,
            @QueryParam("code") String code,
            @QueryParam("error_description") String errorDescription,
            @Context UriInfo uriInfo,
            @Session HttpSession session) {

        log.warn("Enterig OAuth provider callback...");

        OAuth2CodeGrantFlow flow = (OAuth2CodeGrantFlow) session.getAttribute(FLOW_KEY);

        log.info("Obtained grant flow from session: {}", (flow != null));

        if(flow != null  && code != null && state != null) {
            final TokenResult tokenResult = flow.finish(code, state);

            setIdToken(session::setAttribute, tokenResult.getAllProperties());
            setAccessTokenAndClaims(session::setAttribute, tokenResult.getAccessToken());

            URI spaPath = getBaseUri(uriInfo);

            log.info("Redirecting to {}", spaPath);

            return Response.status(Response.Status.FOUND).location(spaPath).build();
        }
        else return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    @GET
    @Path("/user")
    @Timed
    public Response user(@Session HttpSession session) {
        /*
         * Since we're executing a SPA using the authorization code flow we need
         * to pass the token to the front end. In real life this should be
         * invoked through ssl
         */
        if (session.getAttribute(ACCESS_TOKEN_KEY) != null) {
            Map<String, String> user = new HashMap<String, String>();
            user.put("name", (String) session.getAttribute("sub"));

            return Response.ok(user).header("access-token", session.getAttribute(ACCESS_TOKEN_KEY)).build();
        } else
            return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    /*
     * It should remove the same as
     * server:
     *     rootPath: /api/
     * From the perspective
     * of this API, 'host/api/' is the base but we have the SPA as resources on /
     */
    public static final URI getBaseUri(UriInfo uriInfo) {
        if (uriInfo != null) {
            String base = uriInfo.getBaseUri().toString();
            if (base.contains("api")) {
                return UriBuilder.fromUri(base.replace("api/", "").replace("api", "")).build();
            }
        }

        return (uriInfo != null ? uriInfo.getBaseUri() : null);
    }

    public static final void setAccessTokenAndClaims(BiConsumer<String, String> put, String accessToken) {
        if (put != null) {
            if (accessToken != null) {
                try {
                    // Access token
                    put.accept(ACCESS_TOKEN_KEY, accessToken);

                    // Claims
                    JWTClaimsSet claims = JWTParser.parse(accessToken).getJWTClaimsSet();
                    claims.getClaims().forEach((k, v) -> put.accept(k, v.toString()));
                } catch (Exception e) {
                    log.error("Error setting access token claims {}", e.getMessage(), e);
                }
            }
        }
    }

    public static final void setIdToken(BiConsumer<String, String> put, Map<String, String> tokenProperties) {
        if (tokenProperties != null && tokenProperties.containsKey("id_token")) {
            put.accept(TOKEN_ID_KEY, tokenProperties.get("id_token"));
        }
    }

    public static final OAuth2CodeGrantFlow createOAuth2CodeGrantFlow(OAuth2Config oAuth2Config, URI baseUri) {
        ClientIdentifier ClientIdentifier = new ClientIdentifier(oAuth2Config.getClientId(), oAuth2Config.getClientSecret());
        return OAuth2ClientSupport.authorizationCodeGrantFlowBuilder(ClientIdentifier,
                oAuth2Config.getAuthorizationUri(),
                oAuth2Config.getAccessTokenUri())
                .redirectUri(UriBuilder.fromUri(baseUri).path(oAuth2Config.getRedirectPath()).build().toString())
                .scope(oAuth2Config.getScopes())
                .build();
    }

    public StatusType revokeAccessToken(String token) {
        String clientId = oAuth2Config.getClientId();
        String clientSecret = oAuth2Config.getClientSecret();
        String base64EncodedClientInfo = BaseEncoding.base64().encode((clientId + ":" + clientSecret).getBytes());

        URI oktaTokenURI = UriBuilder.fromUri(oAuth2Config.getRevokeTokenUri()).build();

        Response response = oktaClient.target(oktaTokenURI)
                .queryParam("token", token)
                .queryParam("token_type_hint", "access_token")
                .request(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Basic " + base64EncodedClientInfo)
                .header(HttpHeaders.CACHE_CONTROL, "no-cache")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .post(Entity.form(new Form()));

        if (response.getStatus() >= 400) {
            throw new WebApplicationException("Okta sent back an error", Response.Status.BAD_GATEWAY);
        }

        return response.getStatusInfo();
    }

    public StatusType logout(String tokenId) {
        if (tokenId != null) {
            URI oktaTokenURI = UriBuilder.fromUri(oAuth2Config.getLogoutTokenUri()).build();

            Response response = oktaClient.target(oktaTokenURI)
                    .queryParam("id_token_hint", tokenId)
                    .request(MediaType.APPLICATION_JSON)
                    .get();

            if (response.getStatus() >= 400) {
                throw new WebApplicationException("Okta sent back an error", Response.Status.BAD_GATEWAY);
            }

            return response.getStatusInfo();
        } else return null;
    }
}