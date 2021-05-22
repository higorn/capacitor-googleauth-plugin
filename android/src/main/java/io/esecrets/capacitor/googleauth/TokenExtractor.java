package io.esecrets.capacitor.googleauth;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerFuture;
import android.accounts.AuthenticatorException;
import android.accounts.OperationCanceledException;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;

import com.getcapacitor.JSObject;
import com.google.android.gms.auth.api.signin.GoogleSignInAccount;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class TokenExtractor {
  private final static String VERIFY_TOKEN_URL = "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=";
  private final static String FIELD_TOKEN_EXPIRES_IN = "expires_in";
  private final static String FIELD_ACCESS_TOKEN = "accessToken";
  private final static String FIELD_TOKEN_EXPIRES = "expires";
  private static final int KAssumeStaleTokenSec = 60;
  private final Context context;

  TokenExtractor(Context context) {
    this.context = context;
  }

  public JSObject getAuthToken(GoogleSignInAccount account) {
    JSONObject accessTokenObject = getAuthToken(account.getAccount(), true);
    JSObject authentication = new JSObject();
    authentication.put("idToken", account.getIdToken());
    try {
      authentication.put(FIELD_ACCESS_TOKEN, accessTokenObject.get(FIELD_ACCESS_TOKEN));
      authentication.put(FIELD_TOKEN_EXPIRES, accessTokenObject.get(FIELD_TOKEN_EXPIRES));
      authentication.put(FIELD_TOKEN_EXPIRES_IN, accessTokenObject.get(FIELD_TOKEN_EXPIRES_IN));
      return authentication;
    } catch (JSONException e) {
      Log.e("JSON parse error", e.getMessage(), e);
      throw new RuntimeException(e);
    }
  }

  private JSONObject getAuthToken(Account account, boolean retry) {
    AccountManager manager = AccountManager.get(context);
    Bundle bundle = getBundle(account, manager);

    String authToken = null;
    try {
      authToken = bundle.getString(AccountManager.KEY_AUTHTOKEN);
      return verifyToken(authToken);
    } catch (TokenVerificationException e) {
      if (retry) {
        manager.invalidateAuthToken("com.google", authToken);
        return getAuthToken(account, false);
      } else {
        throw e;
      }
    }
  }

  private Bundle getBundle(Account account, AccountManager manager) {
    AccountManagerFuture<Bundle> future = manager.getAuthToken(account,
        "oauth2:profile email",
        null, false, null, null);
    try {
      Bundle bundle = future.getResult();
      return bundle;
    } catch (AuthenticatorException | IOException | OperationCanceledException e) {
      Log.e("Get token result error", e.getMessage(), e);
      throw new RuntimeException(e);
    }
  }

  private JSONObject verifyToken(String authToken) {
    String tokenInfo = getTokenInfo(authToken);
    return toJson(authToken, tokenInfo);
  }

  private String getTokenInfo(String authToken) {
    String stringResponse;
    try {
      URL url = new URL(VERIFY_TOKEN_URL + authToken);
      HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
      urlConnection.setInstanceFollowRedirects(true);
      int responseCode = urlConnection.getResponseCode();
      Log.d("Response code", Integer.valueOf(responseCode).toString());
      if (responseCode == 200)
        stringResponse = fromStream(new BufferedInputStream(urlConnection.getInputStream()));
      else {
        stringResponse = fromStream(new BufferedInputStream(urlConnection.getErrorStream()));
        Log.d("Http error: " + responseCode + " - ", stringResponse);
        throw new TokenVerificationException(stringResponse);
      }

      Log.d("AuthenticatedBackend", "token: " + authToken + ", verification: " + stringResponse);
    } catch (IOException e) {
      Log.e("Token validation error", e.getMessage(), e);
      throw new RuntimeException(e);
    }
    return stringResponse;
  }

  public static String fromStream(InputStream is) throws IOException {
    BufferedReader reader = new BufferedReader(new InputStreamReader(is));
    StringBuilder sb = new StringBuilder();
    String line;
    while ((line = reader.readLine()) != null)
      sb.append(line).append("\n");
    reader.close();
    return sb.toString();
  }

  private JSONObject toJson(String authToken, String stringResponse) {
    try {
      JSONObject jsonResponse = new JSONObject(stringResponse);
      int expires_in = jsonResponse.getInt(FIELD_TOKEN_EXPIRES_IN);
      if (expires_in < KAssumeStaleTokenSec) {
        throw new TokenVerificationException("Auth token soon expiring.");
      }
      jsonResponse.put(FIELD_ACCESS_TOKEN, authToken);
      jsonResponse.put(FIELD_TOKEN_EXPIRES, expires_in + (System.currentTimeMillis() / 1000));
      return jsonResponse;
    } catch (JSONException e) {
      Log.e("JSON parse error", e.getMessage(), e);
      throw new RuntimeException(e);
    }
  }

  static class TokenVerificationException extends RuntimeException {
    public TokenVerificationException(String message) {
      super(message);
    }
  }
}
