package datadog.trace.instrumentation.tomcat;

import static datadog.trace.agent.tooling.bytebuddy.matcher.NameMatchers.named;
import static datadog.trace.bootstrap.instrumentation.api.AgentTracer.activateSpan;
import static datadog.trace.bootstrap.instrumentation.decorator.HttpServerDecorator.DD_SPAN_ATTRIBUTE;
import static datadog.trace.bootstrap.instrumentation.java.concurrent.ExcludeFilter.ExcludeType.RUNNABLE;
import static datadog.trace.instrumentation.tomcat.TomcatDecorator.DD_EXTRACTED_CONTEXT_ATTRIBUTE;
import static datadog.trace.instrumentation.tomcat.TomcatDecorator.DECORATE;
import static java.util.Collections.singletonMap;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;

import com.google.auto.service.AutoService;
import datadog.trace.agent.tooling.ExcludeFilterProvider;
import datadog.trace.agent.tooling.Instrumenter;
import datadog.trace.api.CorrelationIdentifier;
import datadog.trace.api.GlobalTracer;
import datadog.trace.bootstrap.instrumentation.api.AgentScope;
import datadog.trace.bootstrap.instrumentation.api.AgentSpan;
import datadog.trace.bootstrap.instrumentation.java.concurrent.ExcludeFilter;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import org.apache.catalina.connector.CoyoteAdapter;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;

@AutoService(Instrumenter.class)
public final class TomcatServerInstrumentation extends Instrumenter.Tracing
    implements ExcludeFilterProvider {

  public TomcatServerInstrumentation() {
    super("tomcat");
  }

  @Override
  public ElementMatcher<TypeDescription> typeMatcher() {
    return named("org.apache.catalina.connector.CoyoteAdapter");
  }

  @Override
  public String[] helperClassNames() {
    return new String[] {
      packageName + ".RequestExtractAdapter",
      packageName + ".TomcatDecorator",
      packageName + ".RequestURIDataAdapter",
    };
  }

  @Override
  public void adviceTransformations(AdviceTransformation transformation) {
    transformation.applyAdvice(
        named("service")
            .and(takesArgument(0, named("org.apache.coyote.Request")))
            .and(takesArgument(1, named("org.apache.coyote.Response"))),
        TomcatServerInstrumentation.class.getName() + "$ServiceAdvice");
    transformation.applyAdvice(
        named("postParseRequest")
            .and(takesArgument(0, named("org.apache.coyote.Request")))
            .and(takesArgument(1, named("org.apache.catalina.connector.Request")))
            .and(takesArgument(2, named("org.apache.coyote.Response")))
            .and(takesArgument(3, named("org.apache.catalina.connector.Response"))),
        TomcatServerInstrumentation.class.getName() + "$PostParseAdvice");
  }

  @Override
  public Map<ExcludeFilter.ExcludeType, ? extends Collection<String>> excludedClasses() {
    return singletonMap(
        RUNNABLE,
        Arrays.asList(
            "org.apache.tomcat.util.threads.TaskThread$WrappingRunnable",
            "org.apache.tomcat.util.net.SocketProcessorBase",
            "org.apache.tomcat.util.net.AprEndpoint$Poller",
            "org.apache.tomcat.util.net.NioEndpoint$Poller",
            "org.apache.tomcat.util.net.NioEndpoint$PollerEvent",
            "org.apache.tomcat.util.net.AprEndpoint$SocketProcessor",
            "org.apache.tomcat.util.net.JIoEndpoint$SocketProcessor",
            "org.apache.tomcat.util.net.NioEndpoint$SocketProcessor",
            "org.apache.tomcat.util.net.Nio2Endpoint$SocketProcessor",
            "org.apache.tomcat.util.net.NioBlockingSelector$BlockPoller"));
  }

  public static class ServiceAdvice {

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static AgentScope onService(@Advice.Argument(0) org.apache.coyote.Request req) {

      Object existingSpan = req.getAttribute(DD_SPAN_ATTRIBUTE);
      if (existingSpan instanceof AgentSpan) {
        // Request already gone through initial processing, so just activate the span.
        return activateSpan((AgentSpan) existingSpan);
      }

      final AgentSpan.Context.Extracted extractedContext = DECORATE.extract(req);
      req.setAttribute(DD_EXTRACTED_CONTEXT_ATTRIBUTE, extractedContext);

      final AgentSpan span = DECORATE.startSpan(req, extractedContext);
      // This span is finished when Request.recycle() is called by RequestInstrumentation.
      DECORATE.afterStart(span);

      final AgentScope scope = activateSpan(span);
      scope.setAsyncPropagation(true);
      req.setAttribute(DD_SPAN_ATTRIBUTE, span);
      req.setAttribute(CorrelationIdentifier.getTraceIdKey(), GlobalTracer.get().getTraceId());
      req.setAttribute(CorrelationIdentifier.getSpanIdKey(), GlobalTracer.get().getSpanId());
      // request may be processed on any thread; signal thread migration
      span.startThreadMigration();
      return scope;
    }

    @Advice.OnMethodExit(suppress = Throwable.class, onThrowable = Throwable.class)
    public static void closeScope(@Advice.Enter final AgentScope scope) {
      scope.close();
    }

    private void muzzleCheck(CoyoteAdapter adapter, Request request, Response response)
        throws Exception {
      adapter.service(null, null);
      request.recycle(); // just to be safe and ensure it matches consistently.
      response.recycle(); // just to be safe and ensure it matches consistently.
    }
  }

  /**
   * The span is being started before the request is fully parsed out, so we must delay collecting
   * data from the request until after it is fully parsed/populated.
   */
  public static class PostParseAdvice {

    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void afterParse(@Advice.Argument(1) Request req) {
      Object spanObj = req.getAttribute(DD_SPAN_ATTRIBUTE);
      if (spanObj instanceof AgentSpan) {
        Object ctxObj = req.getAttribute(DD_EXTRACTED_CONTEXT_ATTRIBUTE);
        AgentSpan.Context.Extracted ctx =
            ctxObj instanceof AgentSpan.Context.Extracted
                ? (AgentSpan.Context.Extracted) ctxObj
                : null;
        DECORATE.onRequest((AgentSpan) spanObj, req, req, ctx);
      }
    }
  }
}
