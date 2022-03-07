/*
 * Copyright (c) 2021, 2022 Contributors to the Eclipse Foundation
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0, which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception, which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * Contributors:
 *   2021 : Payara Foundation and/or its affiliates

 */
package org.glassfish.soteria.test.server;

import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.ACCESS_TOKEN;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.AUTHORIZATION_CODE;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.CLIENT_ID;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.CLIENT_SECRET;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.CODE;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.ERROR_PARAM;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.EXPIRES_IN;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.GRANT_TYPE;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.GROUPS;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.IDENTITY_TOKEN;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.NONCE;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.REDIRECT_URI;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.RESPONSE_TYPE;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.SCOPE;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.STATE;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.SUBJECT_IDENTIFIER;
import static jakarta.security.enterprise.identitystore.openid.OpenIdConstant.TOKEN_TYPE;
import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;
import static java.util.UUID.randomUUID;
import static java.util.logging.Level.SEVERE;
import static java.util.stream.Collectors.joining;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObjectBuilder;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.ResponseBuilder;

/**
 * @author Gaurav Gupta
 * @author Rudy De Busscher
 */
@Path("/oidc-provider-demo")
public class OidcProvider {

    private static final Logger LOGGER = Logger.getLogger(OidcProvider.class.getName());

    public static final String CLIENT_ID_VALUE = "sample_client_id";
    public static final String CLIENT_SECRET_VALUE = "sample_client_secret";

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_TYPE = "Bearer";
    private static final String AUTH_CODE_VALUE = "sample_auth_code";
    private static final String ACCESS_TOKEN_VALUE = "sample_access_token";

    private static String nonce;

    boolean rolesInUserInfoEndpoint;
    List<String> userGroups = List.of("all");

    @PathParam("subject")
    String subject;

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String get() {
        return getSubject();
    }

    @GET
    @Path("/.well-known/openid-configuration")
    @Produces(APPLICATION_JSON)
    public Response getConfiguration() {
        String result = null;
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        try (InputStream inputStream = classLoader.getResourceAsStream("openid-configuration.json")) {
            result = new BufferedReader(new InputStreamReader(inputStream)).lines().collect(joining("\n"));
        } catch (IOException ex) {
            LOGGER.log(SEVERE, null, ex);
        }

        return Response.ok(result).header("Access-Control-Allow-Origin", "*").build();
    }

    @GET
    @Path("/auth")
    public Response authEndpoint(
            @QueryParam(CLIENT_ID) String clientId, @QueryParam(SCOPE) String scope,
            @QueryParam(RESPONSE_TYPE) String responseType, @QueryParam(NONCE) String nonce,
            @QueryParam(STATE) String state, @QueryParam(REDIRECT_URI) String redirectUri) throws URISyntaxException {

        String returnURL = redirectUri + "?&" + STATE + "=" + state + "&" + CODE + "=" + AUTH_CODE_VALUE;

        OidcProvider.nonce = nonce;
        JsonObjectBuilder jsonBuilder = Json.createObjectBuilder();
        if (!CODE.equals(responseType)) {
            jsonBuilder.add(ERROR_PARAM, "invalid_response_type");
            return Response.serverError().entity(jsonBuilder.build()).build();
        }

        if (!CLIENT_ID_VALUE.equals(clientId)) {
            jsonBuilder.add(ERROR_PARAM, "invalid_client_id");
            return Response.serverError().entity(jsonBuilder.build()).build();
        }

        return Response.seeOther(new URI(returnURL)).build();
    }

    @POST
    @Path("/token")
    @Produces(APPLICATION_JSON)
    public Response tokenEndpoint(
            @FormParam(CLIENT_ID) String clientId, @FormParam(CLIENT_SECRET) String clientSecret,
            @FormParam(GRANT_TYPE) String grantType, @FormParam(CODE) String code,
            @FormParam(REDIRECT_URI) String redirectUri) {

        ResponseBuilder builder;
        JsonObjectBuilder jsonBuilder = Json.createObjectBuilder();

        if (!CLIENT_ID_VALUE.equals(clientId)) {
            jsonBuilder.add(ERROR_PARAM, "invalid_client_id");
            builder = Response.serverError();
        } else if (!CLIENT_SECRET_VALUE.equals(clientSecret)) {
            jsonBuilder.add(ERROR_PARAM, "invalid_client_secret");
            builder = Response.serverError();
        } else if (!AUTHORIZATION_CODE.equals(grantType)) {
            jsonBuilder.add(ERROR_PARAM, "invalid_grant_type");
            builder = Response.serverError();
        } else if (!AUTH_CODE_VALUE.equals(code)) {
            jsonBuilder.add(ERROR_PARAM, "invalid_auth_code");
            builder = Response.serverError();
        } else {

            Date now = new Date();
            JWTClaimsSet.Builder jstClaimsBuilder =
                new JWTClaimsSet.Builder()
                                .issuer("http://localhost:8080/openid-server/webresources/oidc-provider-demo")
                                .subject(getSubject())
                                .audience(List.of(CLIENT_ID_VALUE))
                                .expirationTime(new Date(now.getTime() + 1000 * 60 * 10))
                                .notBeforeTime(now)
                                .issueTime(now)
                                .jwtID(randomUUID().toString())
                                .claim(NONCE, nonce);

            if (!rolesInUserInfoEndpoint) {
                jstClaimsBuilder.claim(GROUPS, userGroups);
            }
            JWTClaimsSet jwtClaims = jstClaimsBuilder.build();

            PlainJWT idToken = new PlainJWT(jwtClaims);
            jsonBuilder.add(IDENTITY_TOKEN, idToken.serialize());
            jsonBuilder.add(ACCESS_TOKEN, ACCESS_TOKEN_VALUE);
            jsonBuilder.add(TOKEN_TYPE, BEARER_TYPE);
            jsonBuilder.add(EXPIRES_IN, 1000);
            builder = Response.ok();
        }

        return builder.entity(jsonBuilder.build()).build();
    }

    @GET
    @Path("/userinfo")
    @Produces(APPLICATION_JSON)
    public Response userinfoEndpoint(@HeaderParam(AUTHORIZATION_HEADER) String authorizationHeader) {
        String accessToken = authorizationHeader.substring(BEARER_TYPE.length() + 1);

        ResponseBuilder builder;
        JsonObjectBuilder jsonBuilder = Json.createObjectBuilder();
        if (ACCESS_TOKEN_VALUE.equals(accessToken)) {
            builder = Response.ok();
            jsonBuilder.add(SUBJECT_IDENTIFIER, getSubject())
                       .add("name", "John")
                       .add("family_name", "Doe")
                       .add("given_name", "John Doe")
                       .add("profile", "https://abc.com/+johnDoe")
                       .add("picture", "https://abc.com/photo.jpg")
                       .add("email", "john.doe@acme.org")
                       .add("email_verified", true)
                       .add("gender", "male")
                       .add("locale", "en");

            if (rolesInUserInfoEndpoint) {
                JsonArrayBuilder groupsBuilder = Json.createArrayBuilder();
                userGroups.forEach(g -> {
                    groupsBuilder.add(g);
                });

                jsonBuilder.add(GROUPS, groupsBuilder);
            }
        } else {
            jsonBuilder.add(ERROR_PARAM, "invalid_access_token");
            builder = Response.serverError();
        }

        return builder.entity(jsonBuilder.build().toString()).build();
    }

    private String getSubject() {
        String subjectPrefix = "/subject-";
        return subject != null && subject.startsWith(subjectPrefix) ? subject.substring(subjectPrefix.length()) : "sample_subject";
    }

}
