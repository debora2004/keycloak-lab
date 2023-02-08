package com.identicum.keycloak;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserRegistrationProvider;

import javax.json.JsonObject;
import static org.jboss.logging.Logger.getLogger;
import static org.keycloak.models.credential.PasswordCredentialModel.TYPE;

public class KeycloakRestRepoProvider implements CredentialInputValidator,
												 UserStorageProvider,
												 UserLookupProvider,
												 UserRegistrationProvider {

	private static final Logger logger = getLogger(KeycloakRestRepoProvider.class);

	protected KeycloakSession session;
	protected ComponentModel model;

	// map of loaded users in this transaction

	protected RestHandler restHandler;

	public KeycloakRestRepoProvider(KeycloakSession session, ComponentModel model, RestHandler restHandler) {
		logger.info("Initializing new RestRepoProvider");
		this.session = session;
		this.model = model;
		this.restHandler = restHandler;
	}

	@Override
	public void close() {
	}

	@Override
	public UserModel getUserByEmail(String email, RealmModel realm) {
		logger.infov("Getting user: {0} by email", email);
		return getUser(email,realm);

	}

	@Override
	public UserModel getUserById(String id, RealmModel realm) {
		logger.infov("Getting user by id: {0}", id);
		return getUser(id,realm);
	}

	@Override
	public UserModel getUserByUsername(String username, RealmModel realm) {
		logger.infov("Getting user: {0} by username", username);
		return getUser(username,realm);
	}

	public UserModel getUser(String query, RealmModel realm) {
		JsonObject userJson = this.restHandler.findUserByUsername(query);
		if (userJson == null) {
			logger.debugv("User {0} not found in repo", query);
			return null;
		}
		RestUserAdapter adapter = new RestUserAdapter(session, realm, model, userJson);
		adapter.setHandler(this.restHandler);

		return adapter;
	}

	@Override
	public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
		return credentialType.equals(TYPE);
	}

	/**
	 * Método que finalmente controla las credenciales
	 */
	@Override
	public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
		return false;
	}

	/**
	 * Indica qué tipo de credenciales puede validar, por ejemplo Password
	 */
	@Override
	public boolean supportsCredentialType(String credentialType) {
		return credentialType.equals(TYPE);
	}

	@Override
	public UserModel addUser(RealmModel realmModel, String username) {
		JsonObject user = restHandler.createUser(username);
		RestUserAdapter adapter = new RestUserAdapter(session, realmModel, model, user);
		adapter.setHandler(restHandler);
		logger.infov("Setting user {0} into cache", username);
		return adapter;
	}

	@Override
	public boolean removeUser(RealmModel realm, UserModel user) {
		// TODO Auto-generated method stub
		return false;
	}

}
