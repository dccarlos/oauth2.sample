package edu.dccarlos.oauth2.sample;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import org.hibernate.validator.constraints.NotEmpty;

import io.dropwizard.Configuration;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuth2SampleConfiguration extends Configuration {
    @Valid
    @NotNull
    private OAuth2Config oauth2Config = new OAuth2Config();

    @Data
    public static final class OAuth2Config {
        @NotNull
        @NotEmpty
        public String clientId;

        @NotNull
        @NotEmpty
        public String clientSecret;

        @NotNull
        @NotEmpty
        public String authorizationUri;

        @NotNull
        @NotEmpty
        public String revokeTokenUri;

        @NotNull
        @NotEmpty
        public String logoutTokenUri;

        @NotNull
        @NotEmpty
        public String accessTokenUri;

        @NotNull
        @NotEmpty
        public String redirectPath;

        @NotNull
        @NotEmpty
        public String scopes;
    }
}