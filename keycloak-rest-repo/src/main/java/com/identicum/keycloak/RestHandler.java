package com.identicum.keycloak;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.ForkFlowException;
import org.keycloak.models.utils.FormMessage;

import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.io.IOException;

import static java.lang.String.format;
import static javax.json.Json.createObjectBuilder;
import static org.apache.http.HttpHeaders.ACCEPT;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static org.apache.http.entity.ContentType.APPLICATION_JSON;
import static org.jboss.logging.Logger.getLogger;

public class RestHandler {

	private static final Logger logger = getLogger(RestHandler.class);
	protected CloseableHttpClient httpClient;
	private final RestConfiguration configuration;

	private final String BACKEND_AUTHENTICATION_ERROR = "BACKEND_AUTHENTICATION_ERROR";

	public RestHandler(RestConfiguration configuration) {
		this.httpClient = HttpClients.custom().build();
		this.configuration = configuration;
	}

	public boolean authenticate(String username, String password) {
		logger.infov("Authenticating user: {0}", username);
		HttpPost httpPost = new HttpPost(configuration.getBaseUrl());
		httpPost.setHeader(ACCEPT, APPLICATION_JSON.getMimeType());
		httpPost.setHeader(CONTENT_TYPE, APPLICATION_JSON.getMimeType());

		JsonObject json = createObjectBuilder()
				.add("username", username)
				.add("password", password)
				.build();
		HttpEntity entity = new ByteArrayEntity(json.toString().getBytes());
		httpPost.setEntity(entity);

		SimpleHttpResponse response = executeCall(httpPost);
		return response.isSuccess();
	}

	public JsonObject findUserByUsername(String username) {
		logger.infov("Finding user by username: {0}", username);

		HttpGet httpget = new HttpGet(configuration.getBaseUrl() + "/search?username="+username);

		SimpleHttpResponse response = executeCall(httpget);
		return response.isSuccess()? response.getResponseAsJsonObject() : null;
	}

	public JsonObject createUser(String username) {
		logger.infov("Creating user {0}", username);

		HttpPost httpPost = new HttpPost(configuration.getBaseUrl() + "/create");
		httpPost.setHeader(CONTENT_TYPE, APPLICATION_JSON.getMimeType());

		JsonObjectBuilder builder = createObjectBuilder();

		JsonObject requestJson = builder.build();
		logger.infov("Setting create body as: {0}", requestJson.toString());
		httpPost.setEntity(new ByteArrayEntity(requestJson.toString().getBytes()));

		SimpleHttpResponse response = executeCall(httpPost);
		stopOnError(response);
		return response.getResponseAsJsonObject();
	}

	/* ------------------------------------------------------------------------ */
	/* HTTP calls handlers                                                      */
	/* ------------------------------------------------------------------------ */

	/**
	 * Close quietly a http response
	 * @param response Response to be closed
	 */
	private void closeQuietly(CloseableHttpResponse response) {
		if (response != null)
			try {
				response.close();
			} catch (IOException io) {
				logger.warn("Error closing http response", io);
			}
	}

	/**
	 * Execute http request with the connection pool and handle the received response.
	 * If the response status is not OK it throws a {@link RuntimeException} to stop the flow.
	 *
	 * @param request Request to be executed with all needed headers.
	 * @return SimpleHttpResponse with code received and body
	 * @throws RuntimeException if status code received is not 200
	 */
	private SimpleHttpResponse executeCall(HttpRequestBase request) {
		logger.infov("Executing Http Request [{0}] on [{1}]", request.getMethod(), request.getURI());
		CloseableHttpResponse response = null;
		try {
			response = httpClient.execute(request);
			String responseString = EntityUtils.toString(response.getEntity(), "UTF-8");
			logger.infov("Response code obtained from server: {0}", response.getStatusLine().getStatusCode());
			logger.infov("Response body obtained from server: {0}", responseString);
			return new SimpleHttpResponse(response.getStatusLine().getStatusCode(), responseString);
		}
		catch(IOException io) {
			logger.errorv(format("Error executing request: %s", io), io);
			throw new ForkFlowException(new FormMessage(""), new FormMessage(BACKEND_AUTHENTICATION_ERROR));
		}
		finally {
			closeQuietly(response);
		}
	}

	private void stopOnError(SimpleHttpResponse response) {
		if(!response.isSuccess()) {
			StringBuffer buffer = new StringBuffer();
			buffer.append("Response status code was not success. Code received: ");
			buffer.append(response.getStatus());
			buffer.append("\nResponse received: ");
			buffer.append("\n" + response.getResponse());
			buffer.append("\nHttp Request was not success. Check logs to get more information");
			logger.errorv(buffer.toString());
			throw new ForkFlowException(new FormMessage(""), new FormMessage(BACKEND_AUTHENTICATION_ERROR));
		}
	}
}