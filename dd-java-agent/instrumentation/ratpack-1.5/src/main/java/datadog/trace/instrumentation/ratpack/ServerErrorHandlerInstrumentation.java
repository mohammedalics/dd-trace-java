package datadog.trace.instrumentation.ratpack;

import static datadog.trace.agent.tooling.ClassLoaderMatcher.hasClassesNamed;
import static datadog.trace.agent.tooling.bytebuddy.matcher.DDElementMatchers.implementsInterface;
import static datadog.trace.agent.tooling.bytebuddy.matcher.NameMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.isAbstract;
import static net.bytebuddy.matcher.ElementMatchers.not;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;

import com.google.auto.service.AutoService;
import datadog.trace.agent.tooling.Instrumenter;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;

@AutoService(Instrumenter.class)
public class ServerErrorHandlerInstrumentation extends Instrumenter.Tracing {

  public ServerErrorHandlerInstrumentation() {
    super("ratpack");
  }

  @Override
  public ElementMatcher<ClassLoader> classLoaderMatcher() {
    // Optimization for expensive typeMatcher.
    return hasClassesNamed("ratpack.error.ServerErrorHandler");
  }

  @Override
  public ElementMatcher<TypeDescription> typeMatcher() {
    return not(isAbstract()).and(implementsInterface(named("ratpack.error.ServerErrorHandler")));
  }

  @Override
  public String[] helperClassNames() {
    return new String[] {
      packageName + ".RatpackServerDecorator", packageName + ".RequestURIAdapterAdapter",
    };
  }

  @Override
  public void adviceTransformations(AdviceTransformation transformation) {
    transformation.applyAdvice(
        named("error")
            .and(takesArgument(0, named("ratpack.handling.Context")))
            .and(takesArgument(1, Throwable.class)),
        packageName + ".ErrorHandlerAdvice");
  }
}
