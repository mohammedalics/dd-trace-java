package datadog.trace.instrumentation.netty41.client;

import static datadog.trace.bootstrap.instrumentation.api.AgentTracer.activateSpan;
import static datadog.trace.bootstrap.instrumentation.api.AgentTracer.activeSpan;
import static datadog.trace.bootstrap.instrumentation.api.AgentTracer.propagate;
import static datadog.trace.bootstrap.instrumentation.api.AgentTracer.startSpan;
import static datadog.trace.instrumentation.netty41.AttributeKeys.CLIENT_PARENT_ATTRIBUTE_KEY;
import static datadog.trace.instrumentation.netty41.AttributeKeys.CONNECT_PARENT_CONTINUATION_ATTRIBUTE_KEY;
import static datadog.trace.instrumentation.netty41.AttributeKeys.SPAN_ATTRIBUTE_KEY;
import static datadog.trace.instrumentation.netty41.client.NettyHttpClientDecorator.DECORATE;
import static datadog.trace.instrumentation.netty41.client.NettyHttpClientDecorator.DECORATE_SECURE;
import static datadog.trace.instrumentation.netty41.client.NettyHttpClientDecorator.NETTY_CLIENT_REQUEST;
import static datadog.trace.instrumentation.netty41.client.NettyResponseInjectAdapter.SETTER;

import datadog.trace.api.Config;
import datadog.trace.api.PropagationStyle;
import datadog.trace.bootstrap.instrumentation.api.AgentScope;
import datadog.trace.bootstrap.instrumentation.api.AgentSpan;
import datadog.trace.context.TraceScope;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.HttpRequest;
import java.net.InetSocketAddress;

@ChannelHandler.Sharable
public class HttpClientRequestTracingHandler extends ChannelOutboundHandlerAdapter {
  public static final HttpClientRequestTracingHandler INSTANCE =
      new HttpClientRequestTracingHandler();
  private static final Class<ChannelHandler> SSL_HANDLER;

  static {
    Class<?> sslHandler;
    try {
      // This class is in "netty-handler", so ignore if not present.
      ClassLoader cl = HttpClientRequestTracingHandler.class.getClassLoader();
      sslHandler = Class.forName("io.netty.handler.ssl.SslHandler", false, cl);
    } catch (ClassNotFoundException e) {
      sslHandler = null;
    }
    SSL_HANDLER = (Class<ChannelHandler>) sslHandler;
  }

  @Override
  public void write(final ChannelHandlerContext ctx, final Object msg, final ChannelPromise prm) {
    if (!(msg instanceof HttpRequest)) {
      ctx.write(msg, prm);
      return;
    }

    TraceScope parentScope = null;
    final TraceScope.Continuation continuation =
        ctx.channel().attr(CONNECT_PARENT_CONTINUATION_ATTRIBUTE_KEY).getAndRemove();
    if (continuation != null) {
      parentScope = continuation.activate();
    }

    final HttpRequest request = (HttpRequest) msg;

    ctx.channel().attr(CLIENT_PARENT_ATTRIBUTE_KEY).set(activeSpan());
    boolean isSecure = SSL_HANDLER != null && ctx.pipeline().get(SSL_HANDLER) != null;
    NettyHttpClientDecorator decorate = isSecure ? DECORATE_SECURE : DECORATE;

    final AgentSpan span = startSpan(NETTY_CLIENT_REQUEST);
    try (final AgentScope scope = activateSpan(span)) {
      decorate.afterStart(span);
      decorate.onRequest(span, request);
      decorate.onPeerConnection(span, (InetSocketAddress) ctx.channel().remoteAddress());

      // AWS calls are often signed, so we can't add headers without breaking the signature.
      if (!request.headers().contains("amz-sdk-invocation-id")) {
        propagate().inject(span, request.headers(), SETTER);
      } else if (Config.get().isAwsPropagationEnabled()) {
        propagate().inject(span, request.headers(), SETTER, PropagationStyle.XRAY);
      }

      ctx.channel().attr(SPAN_ATTRIBUTE_KEY).set(span);

      try {
        ctx.write(msg, prm);
      } catch (final Throwable throwable) {
        decorate.onError(span, throwable);
        decorate.beforeFinish(span);
        span.finish();
        throw throwable;
      }

      span.startThreadMigration();
    } finally {
      if (null != parentScope) {
        parentScope.close();
      }
    }
  }
}
