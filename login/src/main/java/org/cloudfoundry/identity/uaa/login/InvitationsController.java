package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.ClientConstants;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.ExpiringCodeService.CodeNotFoundException;
import org.cloudfoundry.identity.uaa.login.saml.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.UaaIdentityProviderDefinition;
import org.hibernate.validator.constraints.Email;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;


@Controller
@RequestMapping("/invitations")
public class InvitationsController {

    public static final String UAA_ENABLED_AND_SELECTED = "idp.uaa";
    public static final String LDAP_ENABLED_AND_SELECTED = "idp.ldap";
    public static final String SAML_ENABLED_AND_SELECTED = "idp.saml";

    private final InvitationsService invitationsService;
    @Autowired @Qualifier("uaaPasswordValidator") private PasswordValidator passwordValidator;
    @Autowired private ExpiringCodeService expiringCodeService;
    @Autowired private IdentityProviderProvisioning providerProvisioning;
    @Autowired private ClientDetailsService clientDetailsService;

    public InvitationsController(InvitationsService invitationsService) {
        this.invitationsService = invitationsService;
    }

    protected List<String> getProvidersForClient(String clientId) {
        if (clientId==null) {
            return null;
        } else {
            try {
                ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
                return (List<String>) client.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS);
            } catch (NoSuchClientException x) {
                return null;
            }
        }
    }

    protected List<String> getEmailDomain(IdentityProvider provider) {
        AbstractIdentityProviderDefinition definition = null;
        if (provider.getConfig()!=null) {
            switch (provider.getType()) {
                case Origin.UAA: {
                    definition = provider.getConfigValue(UaaIdentityProviderDefinition.class);
                    break;
                }
                case Origin.LDAP: {
                    definition = provider.getConfigValue(LdapIdentityProviderDefinition.class);
                    break;
                }
                case Origin.SAML: {
                    definition = provider.getConfigValue(SamlIdentityProviderDefinition.class);
                    break;
                }
                default: {
                    break;
                }
            }
        }
        if (definition!=null) {
            return definition.getEmailDomain();
        }
        return null;
    }

    protected boolean doesEmailDomainMatchProvider(IdentityProvider provider, String domain) {
        List<String> domainList = getEmailDomain(provider);
        return domainList == null || domainList.size()==0 || domainList.contains(domain);
    }

    protected List<IdentityProvider> filterIdpsForClientAndEmailDomain(String clientId, String email) {
        List<IdentityProvider> providers = providerProvisioning.retrieveActive(IdentityZoneHolder.get().getId());
        if (providers!=null && providers.size()>0) {
            //filter client providers
            List<String> clientFilter = getProvidersForClient(clientId);
            if (clientFilter!=null && clientFilter.size()>0) {
                providers =
                    providers.stream().filter(
                        p -> clientFilter.contains(p.getId())
                    ).collect(Collectors.toList());
            }
            //filter for email domain
            if (email!=null && email.contains("@")) {
                final String domain = email.substring(email.indexOf('@') + 1);
                providers =
                    providers.stream().filter(
                        p -> doesEmailDomainMatchProvider(p, domain)
                    ).collect(Collectors.toList());
            }
        }
        if (providers==null) {
            return Collections.EMPTY_LIST;
        } else {
            return providers;
        }
    }

    @RequestMapping(value = "/new", method = GET)
    public String newInvitePage(Model model, @RequestParam(required = false, value = "redirect_uri") String redirectUri) {
        model.addAttribute("redirect_uri", redirectUri);
        return "invitations/new_invite";
    }


    @RequestMapping(value = "/new.do", method = POST, params = {"email"})
    public String sendInvitationEmail(@Valid @ModelAttribute("email") ValidEmail email, BindingResult result, @RequestParam(value = "redirect_uri", defaultValue = "") String redirectUri, Model model, HttpServletResponse response) {
        if (result.hasErrors()) {
            return handleUnprocessableEntity(model, response, "error_message_code", "invalid_email", "invitations/new_invite");
        }

        UaaPrincipal p = ((UaaPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        String currentUser = p.getName();
        try {
           invitationsService.inviteUser(email.getEmail(), currentUser, redirectUri);
        } catch (UaaException e) {
           return handleUnprocessableEntity(model, response, "error_message_code", "existing_user", "invitations/new_invite");
        }
        return "redirect:sent";
    }

    @RequestMapping(value = "sent", method = GET)
    public String inviteSentPage(Model model) {
        return "invitations/invite_sent";
    }

    @RequestMapping(value = "/accept", method = GET, params = {"code"})
    public String acceptInvitePage(@RequestParam String code, Model model, HttpServletResponse response) throws IOException {
        try {
            Map<String, String> codeData = expiringCodeService.verifyCode(code);
            List<IdentityProvider> providers = filterIdpsForClientAndEmailDomain(codeData.get("client_id"), codeData.get("email"));
            if (providers.size()==0) {

            } else if (providers.size()==1 && Origin.SAML.equals(providers.get(0).getType())) {

            } else {

            }

            UaaPrincipal uaaPrincipal = new UaaPrincipal(codeData.get("user_id"), codeData.get("email"), codeData.get("email"), Origin.UNKNOWN, null, IdentityZoneHolder.get().getId());
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
            SecurityContextHolder.getContext().setAuthentication(token);
            model.addAllAttributes(codeData);
            return "invitations/accept_invite";

        } catch (CodeNotFoundException e) {
            return handleUnprocessableEntity(model, response, "error_message_code", "code_expired", "invitations/accept_invite");
        }
    }

    @RequestMapping(value = "/accept.do", method = POST)
    public String acceptInvitation(@RequestParam("password") String password,
                                   @RequestParam("password_confirmation") String passwordConfirmation,
                                   @RequestParam("client_id") String clientId,
                                   @RequestParam("redirect_uri") String redirectUri,
                                   Model model, HttpServletResponse servletResponse) throws IOException {

        PasswordConfirmationValidation validation = new PasswordConfirmationValidation(password, passwordConfirmation);

        UaaPrincipal principal =  (UaaPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        if (!validation.valid()) {
            model.addAttribute("email", principal.getEmail());
            return handleUnprocessableEntity(model, servletResponse, "error_message_code", validation.getMessageCode(), "invitations/accept_invite");
        }
        try {
            passwordValidator.validate(password);
        } catch (InvalidPasswordException e) {
            model.addAttribute("email", principal.getEmail());
            return handleUnprocessableEntity(model, servletResponse, "error_message", e.getMessagesAsOneString(), "invitations/accept_invite");
        }
        String redirectLocation = invitationsService.acceptInvitation(principal.getId(), principal.getEmail(), password, clientId, Origin.UAA);

        if (!redirectUri.equals("")) {
            return "redirect:" + redirectUri;
        }
        if (redirectLocation != null) {
            return "redirect:" + redirectLocation;
        }
        return "redirect:/home";
    }

    private String handleUnprocessableEntity(Model model, HttpServletResponse response, String attributeKey, String attributeValue, String view) {
        model.addAttribute(attributeKey, attributeValue);
        response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
        return view;
    }

    public static class ValidEmail {
        @Email
        String email;

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }
    }
}
