package org.cloudfoundry.identity.uaa.authentication.logout;

import org.cloudfoundry.identity.uaa.authentication.logout.SessionStorage.AppSloSession;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Set;

/**
 * Created by pivotal on 8/11/15.
 */
@Controller
public class SingleLogoutEndpoint {

    private SessionStorage sessionStorage;
    private final RestTemplate restTemplate = new RestTemplate();

    public SingleLogoutEndpoint(SessionStorage sessionStorage) {
        this.sessionStorage = sessionStorage;
    }

    @RequestMapping(value = "/slo", method = RequestMethod.GET)
    public ResponseEntity<String> singleLogout(HttpServletRequest request) {
        String uaaSessionId = request.getSession().getId();

        Set<AppSloSession> appSessions = sessionStorage.getAppSessions(uaaSessionId);

        String response = "";
        for (AppSloSession s : appSessions) {
            HttpHeaders requestHeaders = new HttpHeaders();
            requestHeaders.set("Cookie: ", "JSESSSIONID=" + s.getSessionId());
            HttpEntity<Void> entity = new HttpEntity<>(requestHeaders);

            response += restTemplate.exchange(s.getSloUrl(), HttpMethod.GET, entity, String.class).getBody() + " | ";
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @RequestMapping(value = "/slo_register", method = RequestMethod.POST)
    public ResponseEntity<Void> registerSession(@RequestParam("uaa_session_id") String uaaSessionId,
                                                @RequestParam("app_session_id") String appSessionId,
                                                @RequestParam("app_slo_url") String appSloUrl) {
        sessionStorage.addAppSession(uaaSessionId, appSessionId, appSloUrl);
        return new ResponseEntity<>(HttpStatus.OK);
    }

}
