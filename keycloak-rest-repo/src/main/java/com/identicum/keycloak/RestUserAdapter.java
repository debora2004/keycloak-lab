package com.identicum.keycloak;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;

import javax.json.JsonObject;
import java.util.List;
import java.util.Random;

import static java.lang.String.valueOf;
import static org.jboss.logging.Logger.getLogger;
import static org.keycloak.storage.StorageId.keycloakId;

public class RestUserAdapter extends AbstractUserAdapterFederatedStorage {

	private static final Logger logger = getLogger(RestUserAdapter.class);

	RestHandler handler;
	JsonObject user;
	String keycloakId;

	public RestUserAdapter(KeycloakSession session, RealmModel realm, ComponentModel model, JsonObject user) {
		super(session, realm, model);
		this.user = user;
		this.keycloakId = keycloakId(model, user.getString("username"));
	}

	public void setHandler(RestHandler handler) {
		this.handler = handler;
	}

	@Override
	public String getId() {
		return keycloakId;
	}

	@Override
	public String getUsername() {
		return user.getString("username");
	}

	@Override
	public String getFirstName() {
		return user.getString("firstName");
	}

	@Override
	public String getLastName() {
		return user.getString("lastName");
	}

	@Override
	public String getEmail() {
		return user.getString("email");
	}

	@Override
	public void setEnabled(boolean enabled) {
	}

	@Override
	public void setFirstName(String firstName) {
	}

	@Override
	public void setLastName(String lastName) {
	}

	@Override
	public void setEmail(String email) {
	}

	@Override
	public void setUsername(String username) {
		logger.infov("Setting username: {0}", username);
	}

	@Override
	public void setSingleAttribute(String name, String value) {
		logger.infov("Setting single attribute: {0} -> {1}", name, value);
	}

	@Override
	public void setAttribute(String name, List<String> values) {
		logger.infov("Setting attribute: {0} -> {1}", name, values);
	}

	@Override
	public void setEmailVerified(boolean verified) {
		logger.infov("Setting email verified: {0}", verified);
	}

	public static String randomPassword() {
		int leftLimit = 48; // numeral '0'
		int rightLimit = 122; // letter 'z'
		int targetStringLength = 10;
		Random random = new Random();

		String generatedString = random.ints(leftLimit, rightLimit + 1)
				.filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
				.limit(targetStringLength)
				.collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
				.toString();
		logger.infov("Generated random string: {0}", generatedString);
		return generatedString;
	}

}
