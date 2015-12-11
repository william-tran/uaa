package org.cloudfoundry.identity.uaa.integration;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.Map;

import static org.junit.Assert.assertEquals;

@OAuth2ContextConfiguration(OAuth2ContextConfiguration.Password.class)
public class JwtBearerGrantIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.withTestAccounts(serverRunning, testAccounts);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testTokenExchangeViaJwtBearerGrant() throws Exception {
        ResponseEntity<Map> responseEntity = makePasswordGrantRequest(testAccounts.getUserName(),
                testAccounts.getPassword());
        String accessToken = responseEntity.getBody().get("access_token").toString();
        assertEquals(HttpStatus.OK, makeJwtBearerGrantRequest(accessToken).getStatusCode());
        String idToken = responseEntity.getBody().get("id_token").toString();
        assertEquals(HttpStatus.OK, makeJwtBearerGrantRequest(idToken).getStatusCode());

    }

    private ResponseEntity<Map> makePasswordGrantRequest(String userName, String password) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", testAccounts.getAuthorizationHeader("app", "appclientsecret"));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("username", userName);
        params.add("password", password);
        params.add("scope", "openid api.read");
        params.add("response_type", "id_token token");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        return new RestTemplate().postForEntity(serverRunning.getAccessTokenUri(), request, Map.class);
    }

    private ResponseEntity<Void> makeJwtBearerGrantRequest(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", testAccounts.getAuthorizationHeader("api", "secret"));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
        params.add("assertion", accessToken);
        params.add("scope", "scim.userids");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        return new RestTemplate().postForEntity(serverRunning.getAccessTokenUri(), request, Void.class);
    }
}
