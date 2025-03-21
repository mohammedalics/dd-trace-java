package datadog.trace.instrumentation.lettuce5.rx;

import static datadog.trace.bootstrap.instrumentation.api.AgentTracer.activateSpan;
import static datadog.trace.bootstrap.instrumentation.api.AgentTracer.startSpan;
import static datadog.trace.instrumentation.lettuce5.LettuceClientDecorator.DECORATE;
import static datadog.trace.instrumentation.lettuce5.LettuceClientDecorator.REDIS_QUERY;
import static datadog.trace.instrumentation.lettuce5.LettuceInstrumentationUtil.expectsResponse;

import datadog.trace.bootstrap.InstrumentationContext;
import datadog.trace.bootstrap.instrumentation.api.AgentSpan;
import datadog.trace.context.TraceScope;
import io.lettuce.core.protocol.RedisCommand;
import net.bytebuddy.asm.Advice;
import org.reactivestreams.Subscription;

public class RedisSubscriptionSubscribeAdvice {
  public static final class State {
    public final TraceScope parentScope;
    public final AgentSpan span;

    public State(TraceScope parentScope, AgentSpan span) {
      this.parentScope = parentScope;
      this.span = span;
    }
  }

  @Advice.OnMethodEnter(suppress = Throwable.class)
  public static State beforeSubscribe(
      @Advice.This Subscription subscription,
      @Advice.FieldValue("command") RedisCommand command,
      @Advice.FieldValue("subscriptionCommand") RedisCommand subscriptionCommand) {

    TraceScope parentScope = null;
    RedisSubscriptionState state =
        InstrumentationContext.get(Subscription.class, RedisSubscriptionState.class)
            .get(subscription);
    AgentSpan parentSpan = state != null ? state.parentSpan : null;
    if (parentSpan != null) {
      parentScope = activateSpan(parentSpan);
    }
    AgentSpan span = startSpan(REDIS_QUERY);
    InstrumentationContext.get(RedisCommand.class, AgentSpan.class).put(subscriptionCommand, span);
    DECORATE.afterStart(span);
    DECORATE.onCommand(span, command);

    return new State(parentScope, span);
  }

  @Advice.OnMethodExit(suppress = Throwable.class)
  public static void afterSubscribe(
      @Advice.FieldValue("command") RedisCommand command,
      @Advice.FieldValue("subscriptionCommand") RedisCommand subscriptionCommand,
      @Advice.Enter State state) {
    if (!expectsResponse(command)) {
      DECORATE.beforeFinish(state.span);
      state.span.finish();
      InstrumentationContext.get(RedisCommand.class, AgentSpan.class)
          .put(subscriptionCommand, null);
    }
    if (state.parentScope != null) {
      state.parentScope.close();
    }
  }
}
