package edu.dccarlos.oauth2.sample.resources;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpSession;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.codahale.metrics.annotation.Timed;

import edu.dccarlos.oauth2.sample.auth.AccessTokenPrincipal;
import io.dropwizard.auth.Auth;
import io.dropwizard.jersey.sessions.Session;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Path("/v1") /* Remember config in YAML: 'rootPath: /api/' */
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class SampleResourceV1 {

    @GET
    @Path("/admin/protected")
    @Timed
    public Response getProtected(@Auth AccessTokenPrincipal user) {
        log.warn("[getProtected] is being called by user: {}", user.getName());

        Map<String, String> protectedResponse = new HashMap<>();
        protectedResponse.put("secret", UUID.randomUUID().toString());
        protectedResponse.put("name", user.getName());

        return Response.ok(protectedResponse, MediaType.APPLICATION_JSON_TYPE).build();
    }

    @GET
    @Path("/admin/unprotected")
    @Timed
    public Response getUnprotected(@Session HttpSession session) {
        log.warn("[getUnprotected] is being called by user: {}", session);

        Map<String, String> unProtectedResponse = new HashMap<>();
        unProtectedResponse.put("notSecret", UUID.randomUUID().toString());
        unProtectedResponse.put("sessionId", (session != null ? session.getId() : "NULL"));

        return Response.ok(unProtectedResponse, MediaType.APPLICATION_JSON_TYPE).build();
    }
}