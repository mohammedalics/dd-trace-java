package datadog.trace.instrumentation.springweb;

import static datadog.trace.agent.tooling.ClassLoaderMatcher.hasClassesNamed;
import static datadog.trace.agent.tooling.bytebuddy.matcher.DDElementMatchers.extendsClass;
import static datadog.trace.agent.tooling.bytebuddy.matcher.DDElementMatchers.implementsInterface;
import static datadog.trace.agent.tooling.bytebuddy.matcher.NameMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;

import com.google.auto.service.AutoService;
import datadog.trace.agent.tooling.Instrumenter;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;

/**
 * This instrumentation adds the HandlerMappingResourceNameFilter definition to the spring context
 * When the context is created, the filter will be added to the beginning of the filter chain
 */
@AutoService(Instrumenter.class)
public class WebApplicationContextInstrumentation extends Instrumenter.Tracing {
  public WebApplicationContextInstrumentation() {
    super("spring-web");
  }

  @Override
  public ElementMatcher<ClassLoader> classLoaderMatcher() {
    // Optimization for expensive typeMatcher.
    return hasClassesNamed(
        "org.springframework.context.support.AbstractApplicationContext",
        "org.springframework.web.context.WebApplicationContext");
  }

  @Override
  public ElementMatcher<TypeDescription> typeMatcher() {
    return extendsClass(named("org.springframework.context.support.AbstractApplicationContext"))
        .and(implementsInterface(named("org.springframework.web.context.WebApplicationContext")));
  }

  @Override
  public String[] helperClassNames() {
    return new String[] {
      packageName + ".SpringWebHttpServerDecorator",
      packageName + ".ServletRequestURIAdapter",
      packageName + ".HandlerMappingResourceNameFilter",
      packageName + ".HandlerMappingResourceNameFilter$BeanDefinition",
      packageName + ".PathMatchingHttpServletRequestWrapper",
    };
  }

  @Override
  public void adviceTransformations(AdviceTransformation transformation) {
    transformation.applyAdvice(
        isMethod()
            .and(named("postProcessBeanFactory"))
            .and(
                takesArgument(
                    0,
                    named(
                        "org.springframework.beans.factory.config.ConfigurableListableBeanFactory"))),
        WebApplicationContextInstrumentation.class.getName() + "$FilterInjectingAdvice");
  }

  public static class FilterInjectingAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void onEnter(
        @Advice.Argument(0) final ConfigurableListableBeanFactory beanFactory) {
      if (beanFactory instanceof BeanDefinitionRegistry
          && !beanFactory.containsBean("ddDispatcherFilter")) {

        ((BeanDefinitionRegistry) beanFactory)
            .registerBeanDefinition(
                "ddDispatcherFilter", new HandlerMappingResourceNameFilter.BeanDefinition());
      }
    }
  }
}
