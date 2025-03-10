package datadog.trace.instrumentation.tomcat;

import static datadog.trace.agent.tooling.bytebuddy.matcher.NameMatchers.named;
import static datadog.trace.bootstrap.instrumentation.decorator.HttpServerDecorator.DD_SPAN_ATTRIBUTE;
import static datadog.trace.instrumentation.tomcat.TomcatDecorator.DECORATE;
import static net.bytebuddy.matcher.ElementMatchers.takesNoArguments;

import com.google.auto.service.AutoService;
import datadog.trace.agent.tooling.Instrumenter;
import datadog.trace.bootstrap.instrumentation.api.AgentSpan;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import org.apache.catalina.connector.CoyoteAdapter;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;

@AutoService(Instrumenter.class)
public final class RequestInstrumentation extends Instrumenter.Tracing {

  public RequestInstrumentation() {
    super("tomcat");
  }

  @Override
  public ElementMatcher<TypeDescription> typeMatcher() {
    return named("org.apache.catalina.connector.Request");
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
        named("recycle").and(takesNoArguments()),
        RequestInstrumentation.class.getName() + "$RecycleAdvice");
  }

  /**
   * Tomcat recycles request/response objects after the response is sent. This provides a reliable
   * point to finish the server span at the last possible moment.
   */
  public static class RecycleAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void stopSpan(@Advice.This final Request req) {
      Response resp = req.getResponse();

      Object spanObj = req.getAttribute(DD_SPAN_ATTRIBUTE);

      if (spanObj instanceof AgentSpan) {
        /**
         * This advice will be called for both Request and Response. The span is removed from the
         * request so the advice only applies the first invocation. (So it doesn't matter which is
         * recycled first.)
         */
        // value set on the coyote request, so we must remove directly from there.
        req.getCoyoteRequest().setAttribute(DD_SPAN_ATTRIBUTE, null);

        final AgentSpan span = (AgentSpan) spanObj;
        DECORATE.onResponse(span, resp);
        DECORATE.beforeFinish(span);
        // span could have been originated on a different thread and migrated
        span.finishThreadMigration();
        span.finish();
      }
    }

    private void muzzleCheck(CoyoteAdapter adapter, Request request) throws Exception {
      adapter.service(null, null);
      request.recycle();
    }
  }
}
