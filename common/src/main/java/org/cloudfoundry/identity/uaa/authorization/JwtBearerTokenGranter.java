/*
 * Copyright 2002-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.cloudfoundry.identity.uaa.authorization;

import org.cloudfoundry.identity.uaa.oauth.token.UaaTokenServices;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;

/**
 * Token granter for the JWT bearer grant type.
 * 
 * @author Will Tran
 * 
 */
public class JwtBearerTokenGranter extends AbstractTokenGranter {

    public JwtBearerTokenGranter(UaaTokenServices tokenServices,
            ClientDetailsService clientDetailsService,
            OAuth2RequestFactory requestFactory) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
        this.uaaTokenServices = tokenServices;
    }

    public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    public static final String TOKEN_PARAM = "assertion";

    private UaaTokenServices uaaTokenServices;

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {

        String jwtToken = tokenRequest.getRequestParameters().get(TOKEN_PARAM);

        if (jwtToken == null) {
            throw new InvalidRequestException("An jwt assertion must be supplied.");
        }

        OAuth2Authentication authentication = uaaTokenServices.loadAuthentication(jwtToken);
        if (!authentication.getOAuth2Request().getResourceIds().contains(uaaTokenServices.getTokenEndpoint())) {
            throw new InvalidClientException(
                    "The JWT MUST contain an 'aud' (audience) claim containing a value that identifies the authorization server as an intended audience.");
        }
        OAuth2Request storedOAuth2Request = getRequestFactory().createOAuth2Request(client, tokenRequest);
        return new OAuth2Authentication(storedOAuth2Request, authentication);
    }

}
