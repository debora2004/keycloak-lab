package com.identicum.keycloak;
import org.jboss.logging.Logger;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;

import java.net.PasswordAuthentication;
import java.util.Random;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.PasswordForm;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;

import static org.jboss.logging.Logger.getLogger;


public class CustomAuthenticator extends PasswordForm {
	private static final Logger logger = getLogger(CustomAuthenticator.class);
    private static String generatedString;
   
	@Override
	public void authenticate(AuthenticationFlowContext context) {
		// Generar codigo random y mostrarlo en el theme
		MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        String loginHint = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getRealm(), context.getHttpRequest().getHttpHeaders());
		
        Random token = new Random();

        generatedString = token.ints(48, 122 + 1)
        .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
        .limit(10)
        .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
        .toString();

		logger.infov("TOKEN!!!: {0}", generatedString); //Que aparezca en los logs de Keycloak container
        
        LoginFormsProvider form = context.form();
        form.setAttribute("generatedString", generatedString);

        if (context.getUser() != null) {
            form.setAttribute(LoginFormsProvider.USERNAME_HIDDEN, true);
            form.setAttribute(LoginFormsProvider.REGISTRATION_DISABLED, true);
            context.getAuthenticationSession().setAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH, "true");
        } else {
            context.getAuthenticationSession().removeAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH);
            if (loginHint != null || rememberMeUsername != null) {
                if (loginHint != null) {
                    formData.add(AuthenticationManager.FORM_USERNAME, loginHint);
                } else {
                    formData.add(AuthenticationManager.FORM_USERNAME, rememberMeUsername);
                    formData.add("rememberMe", "on");
                }
            }
        }
        Response challengeResponse = challenge(context, formData);
        context.challenge(challengeResponse);
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		// Obtener informacion de la request y validar si es igual al codigo generado
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String pass = formData.getFirst("password");
        logger.infov("Token {0}", generatedString);
        if(!pass.equals(generatedString)){
            return;
        }

		if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }
        // if (!validateForm(context, formData)) {
        //     logger.info("Validate null");
        //     return;
        // }
        
        context.success();
        // super.action(context);
	}

}
