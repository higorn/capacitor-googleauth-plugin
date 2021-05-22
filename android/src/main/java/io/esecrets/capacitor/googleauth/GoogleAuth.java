package io.esecrets.capacitor.googleauth;

import com.getcapacitor.JSObject;
import com.getcapacitor.PluginCall;
import com.google.android.gms.auth.api.signin.GoogleSignInAccount;

public class GoogleAuth {
  private final TokenExtractor tokenExtractor;

  public GoogleAuth(TokenExtractor tokenExtractor) {
    this.tokenExtractor = tokenExtractor;
  }

  public void signIn(PluginCall call, GoogleSignInAccount account) {
    try {
      JSObject user = getUser(tokenExtractor.getAuthToken(account), account);
      call.resolve(user);
    } catch (TokenExtractor.TokenVerificationException e) {
      call.reject(e.getMessage());
    }
  }

  private JSObject getUser(JSObject authentication, GoogleSignInAccount account) {
    JSObject user = new JSObject();
    user.put("serverAuthCode", account.getServerAuthCode());
    user.put("idToken", account.getIdToken());
    user.put("authentication", authentication);
    user.put("displayName", account.getDisplayName());
    user.put("email", account.getEmail());
    user.put("familyName", account.getFamilyName());
    user.put("givenName", account.getGivenName());
    user.put("id", account.getId());
    user.put("imageUrl", account.getPhotoUrl());
    return user;
  }

  public void refresh(PluginCall call, GoogleSignInAccount account) {
    try {
      call.resolve(tokenExtractor.getAuthToken(account));
    } catch (TokenExtractor.TokenVerificationException e) {
      call.reject(e.getMessage());
    }
  }
}
