package org.cloudfoundry.identity.uaa.login;

public interface InvitationsService {
    void inviteUser(String email, String currentUser, String redirectUri);

    String acceptInvitation(String userId, String email, String password, String clientId, String origin);
}
