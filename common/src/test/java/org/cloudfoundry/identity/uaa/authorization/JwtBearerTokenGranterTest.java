package org.cloudfoundry.identity.uaa.authorization;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.UUID;

import org.cloudfoundry.identity.uaa.oauth.token.UaaTokenServices;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

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

@RunWith(MockitoJUnitRunner.class)
public class JwtBearerTokenGranterTest {

    private JwtBearerTokenGranter jwtBearerTokenGranter;
    @Mock
    private UaaTokenServices tokenServices;
    @Mock
    private ClientDetailsService clientDetailsService;
    @Mock
    private OAuth2RequestFactory requestFactory;

    @Before
    public void before() {
        jwtBearerTokenGranter = new JwtBearerTokenGranter(tokenServices, clientDetailsService, requestFactory);

    }

    @Test
    public void success() {
        String token = UUID.randomUUID().toString();
        testJwtBearerTokenGranter(token, "resource1", "resource1", "foo", "bar");
    }

    @Test(expected = InvalidRequestException.class)
    public void noAssertionFails() {
        String token = null;
        testJwtBearerTokenGranter(token, "resource1", "resource1", "foo", "bar");
    }

    @Test(expected = InvalidRequestException.class)
    public void clientIdNotInAudFails() {
        String token = null;
        testJwtBearerTokenGranter(token, "resource1", "resource2", "foo", "bar");
    }

    private void testJwtBearerTokenGranter(String token, String clientId, String... aud) {
        BaseClientDetails client = new BaseClientDetails();
        client.setClientId("resource1");
        Map<String, String> params = new HashMap<>();
        params.put(JwtBearerTokenGranter.TOKEN_PARAM, token);
        TokenRequest tokenRequest = new TokenRequest(params, client.getClientId(), Arrays.asList("foo.read"),
                JwtBearerTokenGranter.GRANT_TYPE);
        OAuth2Authentication auth = new OAuth2Authentication(new OAuth2Request(null, null, null, true, null,
                new HashSet<String>(Arrays.asList(aud)), null, null, null), null);
        Mockito.when(tokenServices.loadAuthentication(token)).thenReturn(auth);
        jwtBearerTokenGranter.getOAuth2Authentication(client, tokenRequest);
    }

}
