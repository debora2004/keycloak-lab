package com.identicum.keycloak;
import org.jboss.logging.Logger;

import java.util.Random;

import javax.ws.rs.core.MultivaluedMap;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.forms.login.LoginFormsProvider;
import static org.jboss.logging.Logger.getLogger;


public class CustomAuthenticator extends UsernamePasswordForm {
	private static final Logger logger = getLogger(CustomAuthenticator.class);

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		// Generar codigo random y mostrarlo en el theme
		Random token =  new Random();
		logger.infov("TOKEN!!!: {0}", token);
		LoginFormsProvider form = context.form();


		super.authenticate(context);
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		// Obtener informacion de la request y validar si es igual al codigo generado
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		
		super.action(context);
	}

}
