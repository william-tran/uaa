package org.cloudfoundry.identity.uaa.authentication.logout;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * Created by pivotal on 8/11/15.
 */
public class SessionStorage {

    private Map<String, Set<AppSloSession>> map = new HashMap<>();

    public Set<AppSloSession> getAppSessions(String uaaSessionId) {
        return map.get(uaaSessionId);
    }

    public void addAppSession(String uaaSessionId, String appSessionId, String sloUrl) {
        Set<AppSloSession> appSessions = map.get(uaaSessionId);
        if (appSessions == null) {
           appSessions = new HashSet<>();
        }
        Iterator<AppSloSession> iterator = appSessions.iterator();
        while (iterator.hasNext()) {
            AppSloSession s = iterator.next();
            if (s.getSessionId().equals(appSessionId)) {
                return;
            }
        }
        appSessions.add(new AppSloSession(appSessionId, sloUrl));
    }

    public static class AppSloSession {
        private String sessionId;
        private String sloUrl;

        public AppSloSession(String sessionId, String sloUrl) {
            this.sessionId = sessionId;
            this.sloUrl = sloUrl;
        }

        public String getSessionId() {
            return sessionId;
        }

        public String getSloUrl() {
            return sloUrl;
        }
    }
}
