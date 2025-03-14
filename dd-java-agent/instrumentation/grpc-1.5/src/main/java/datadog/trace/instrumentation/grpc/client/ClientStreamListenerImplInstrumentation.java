package datadog.trace.instrumentation.grpc.client;

import static datadog.trace.agent.tooling.bytebuddy.matcher.NameMatchers.named;
import static datadog.trace.agent.tooling.bytebuddy.matcher.NameMatchers.namedOneOf;
import static datadog.trace.bootstrap.instrumentation.api.AgentTracer.activateSpan;
import static datadog.trace.bootstrap.instrumentation.api.AgentTracer.activeScope;
import static datadog.trace.instrumentation.grpc.client.GrpcClientDecorator.DECORATE;
import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

import com.google.auto.service.AutoService;
import datadog.trace.agent.tooling.Instrumenter;
import datadog.trace.bootstrap.InstrumentationContext;
import datadog.trace.bootstrap.instrumentation.api.AgentScope;
import datadog.trace.bootstrap.instrumentation.api.AgentSpan;
import datadog.trace.context.TraceScope;
import io.grpc.Status;
import io.grpc.internal.ClientStreamListener;
import java.util.Collections;
import java.util.Map;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;

@AutoService(Instrumenter.class)
public class ClientStreamListenerImplInstrumentation extends Instrumenter.Tracing {

  public ClientStreamListenerImplInstrumentation() {
    super("grpc", "grpc-client");
  }

  @Override
  public ElementMatcher<? super TypeDescription> typeMatcher() {
    return named("io.grpc.internal.ClientCallImpl$ClientStreamListenerImpl");
  }

  @Override
  public Map<String, String> contextStore() {
    return Collections.singletonMap(
        "io.grpc.internal.ClientStreamListener", AgentSpan.class.getName());
  }

  @Override
  public String[] helperClassNames() {
    return new String[] {
      packageName + ".GrpcClientDecorator",
      packageName + ".GrpcClientDecorator$1",
      packageName + ".GrpcInjectAdapter"
    };
  }

  @Override
  public void adviceTransformations(AdviceTransformation transformation) {
    transformation.applyAdvice(isConstructor(), getClass().getName() + "$Construct");
    transformation.applyAdvice(
        named("exceptionThrown")
            .and(takesArgument(0, named("io.grpc.Status")))
            .and(takesArguments(1)),
        getClass().getName() + "$ExceptionThrown");
    transformation.applyAdvice(
        namedOneOf("messageRead", "messagesAvailable"), getClass().getName() + "$RecordActivity");
    transformation.applyAdvice(named("headersRead"), getClass().getName() + "$RecordHeaders");
  }

  public static final class Construct {
    @Advice.OnMethodExit
    public static void capture(@Advice.This ClientStreamListener listener) {
      // instrumentation of ClientCallImpl::start ensures this scope is present and valid
      TraceScope scope = activeScope();
      if (scope instanceof AgentScope) {
        AgentSpan span = ((AgentScope) scope).span();
        InstrumentationContext.get(ClientStreamListener.class, AgentSpan.class).put(listener, span);
        // Initiate the span thread migration - the listener may be called on any thread
        span.startThreadMigration();
      }
    }
  }

  public static final class ExceptionThrown {
    @Advice.OnMethodEnter
    public static void exceptionThrown(
        @Advice.This ClientStreamListener listener, @Advice.Argument(0) Status status) {
      if (null != status) {
        AgentSpan span =
            InstrumentationContext.get(ClientStreamListener.class, AgentSpan.class).get(listener);
        if (null != span) {
          DECORATE.onError(span, status.getCause());
          DECORATE.beforeFinish(span);
          // Make sure the span thread migration is finished
          span.finishThreadMigration();
          span.finish();
        }
      }
    }
  }

  public static final class RecordActivity {

    @Advice.OnMethodEnter
    public static AgentScope before(@Advice.This ClientStreamListener listener) {
      // activate the span so serialisation work is accounted for, whichever thread the work is done
      // on
      AgentSpan span =
          InstrumentationContext.get(ClientStreamListener.class, AgentSpan.class).get(listener);
      if (span != null) {
        // Make sure the span thread migration is finished
        span.finishThreadMigration();
        return activateSpan(span);
      }
      return null;
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void after(@Advice.Enter AgentScope scope) {
      if (null != scope) {
        scope.span().finishWork();
        scope.close();
      }
    }
  }

  /*
  A call to 'headersAvailable' is optional - meaning that it may not appear at all but if it appears
  it will be followed by a call to `messageRead`. In order to properly cooperate with the `messageRead` instrumentation
  we must make sure that when this method is finished the associated span is 'migrated' - such that `messageRead`
  instrumentation can correctly 'resume' the span.
   */
  public static final class RecordHeaders {

    @Advice.OnMethodEnter
    public static AgentScope before(@Advice.This ClientStreamListener listener) {
      // activate the span so serialisation work is accounted for, whichever thread the work is done
      // on
      AgentSpan span =
          InstrumentationContext.get(ClientStreamListener.class, AgentSpan.class).get(listener);
      if (span != null) {
        // Make sure the span thread migration is finished
        span.finishThreadMigration();
        return activateSpan(span);
      }
      return null;
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void after(@Advice.Enter AgentScope scope) {
      if (null != scope) {
        // The span must be 'suspended' here so the `messageRead` instrumentation can properly
        // 'resume' it
        scope.span().startThreadMigration();
        scope.close();
      }
    }
  }
}
