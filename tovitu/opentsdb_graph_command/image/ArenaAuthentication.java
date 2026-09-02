package arena;

import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.handler.codec.http.DefaultHttpResponse;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.HttpVersion;

import com.stumbleupon.async.Deferred;

import net.opentsdb.auth.AuthState;
import net.opentsdb.auth.Authentication;
import net.opentsdb.auth.Authorization;
import net.opentsdb.auth.Permissions;
import net.opentsdb.core.TSDB;
import net.opentsdb.core.TSQuery;
import net.opentsdb.query.pojo.Query;
import net.opentsdb.stats.StatsCollector;

/** Bearer principals implemented through OpenTSDB's supported plugin API. */
public final class ArenaAuthentication implements Authentication, Authorization {
  private static final String PRINCIPALS = "/etc/opentsdb/principals.conf";
  private Map<String, String> usersByToken = Collections.emptyMap();

  @Override
  public void initialize(final TSDB tsdb) {
    final Map<String, String> parsed = new HashMap<String, String>();
    try {
      final BufferedReader reader = new BufferedReader(new FileReader(PRINCIPALS));
      try {
        String line;
        while ((line = reader.readLine()) != null) {
          final int separator = line.indexOf('=');
          if (separator < 1 || separator == line.length() - 1) {
            throw new IllegalArgumentException("invalid principal configuration");
          }
          final String user = line.substring(0, separator);
          final String token = line.substring(separator + 1);
          if (parsed.put(token, user) != null) {
            throw new IllegalArgumentException("duplicate bearer credential");
          }
        }
      } finally {
        reader.close();
      }
    } catch (final Exception error) {
      throw new IllegalArgumentException("unable to load principal configuration", error);
    }
    if (parsed.isEmpty()) {
      throw new IllegalArgumentException("principal configuration is empty");
    }
    usersByToken = Collections.unmodifiableMap(parsed);
  }

  @Override
  public Deferred<Object> shutdown() { return Deferred.fromResult(null); }

  @Override
  public String version() { return "1.0.0"; }

  @Override
  public void collectStats(final StatsCollector collector) { }

  @Override
  public AuthState authenticateTelnet(final Channel channel, final String[] command) {
    return new State("anonymous", AuthState.AuthStatus.UNAUTHORIZED, null);
  }

  private AuthState denyHTTP(final Channel channel) {
    final HttpResponse response = new DefaultHttpResponse(
        HttpVersion.HTTP_1_1, HttpResponseStatus.UNAUTHORIZED);
    HttpHeaders.setContentLength(response, 0);
    response.headers().set(HttpHeaders.Names.CONNECTION, HttpHeaders.Values.CLOSE);
    channel.write(response).addListener(ChannelFutureListener.CLOSE);
    return new State("anonymous", AuthState.AuthStatus.REDIRECTED, null);
  }

  @Override
  public AuthState authenticateHTTP(final Channel channel, final HttpRequest request) {
    final String authorization = request.headers().get("Authorization");
    if (authorization != null && authorization.startsWith("Bearer ")) {
      final String token = authorization.substring("Bearer ".length());
      final String user = usersByToken.get(token);
      if (user != null) {
        return new State(user, AuthState.AuthStatus.SUCCESS, token);
      }
    }
    return denyHTTP(channel);
  }

  @Override
  public Authorization authorization() { return this; }

  @Override
  public boolean isReady(final TSDB tsdb, final Channel channel) {
    return channel != null && channel.getAttachment() instanceof AuthState
        && ((AuthState) channel.getAttachment()).getStatus() == AuthState.AuthStatus.SUCCESS;
  }

  @Override
  public AuthState hasPermission(final AuthState state, final Permissions permission) {
    return state;
  }

  @Override
  public AuthState allowQuery(final AuthState state, final TSQuery query) { return state; }

  @Override
  public AuthState allowQuery(final AuthState state, final Query query) { return state; }

  private static final class State implements AuthState {
    private final String user;
    private final AuthStatus status;
    private final String token;

    State(final String user, final AuthStatus status, final String token) {
      this.user = user;
      this.status = status;
      this.token = token;
    }

    @Override public String getUser() { return user; }
    @Override public AuthStatus getStatus() { return status; }
    @Override public String getMessage() {
      return status == AuthStatus.SUCCESS ? null : "Bearer credential required";
    }
    @Override public Throwable getException() { return null; }
    @Override public void setChannel(final Channel channel) { }
    @Override public byte[] getToken() {
      return token == null ? new byte[0] : token.getBytes(StandardCharsets.UTF_8);
    }
  }
}
