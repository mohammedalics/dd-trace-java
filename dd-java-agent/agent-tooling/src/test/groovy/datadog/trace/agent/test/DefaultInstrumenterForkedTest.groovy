package datadog.trace.agent.test

import datadog.trace.agent.tooling.Instrumenter
import datadog.trace.test.util.DDSpecification
import net.bytebuddy.agent.builder.AgentBuilder
import net.bytebuddy.description.type.TypeDescription
import net.bytebuddy.matcher.ElementMatcher

class DefaultInstrumenterForkedTest extends DDSpecification {
  def "default enabled"() {
    setup:
    def target = new TestDefaultInstrumenter("test")
    target.instrument(new AgentBuilder.Default())

    expect:
    target.enabled
    target.applyCalled
  }

  def "default enabled override"() {
    setup:
    target.instrument(new AgentBuilder.Default())

    expect:
    target.enabled == enabled
    target.applyCalled == enabled

    where:
    enabled | target
    true    | new TestDefaultInstrumenter("test") {
        @Override
        protected boolean defaultEnabled() {
          return true
        }
      }
    false   | new TestDefaultInstrumenter("test") {
        @Override
        protected boolean defaultEnabled() {
          return false
        }
      }
  }

  def "default disabled can override to enabled"() {
    setup:
    injectSysConfig("integration.test.enabled", "$enabled")
    def target = new TestDefaultInstrumenter("test") {
        @Override
        protected boolean defaultEnabled() {
          return false
        }
      }
    target.instrument(new AgentBuilder.Default())

    expect:
    target.enabled == enabled
    target.applyCalled == enabled

    where:
    enabled << [true, false]
  }

  def "configure default sys prop as #value"() {
    setup:
    injectSysConfig("integrations.enabled", value)

    when:
    def target = new TestDefaultInstrumenter("test")
    target.instrument(new AgentBuilder.Default())

    then:
    target.enabled == enabled
    target.applyCalled == enabled

    where:
    value   | enabled
    "true"  | true
    "false" | false
    "asdf"  | false
  }

  def "configure default env var as #value"() {
    setup:
    injectEnvConfig("DD_INTEGRATIONS_ENABLED", value)
    def target = new TestDefaultInstrumenter("test")
    target.instrument(new AgentBuilder.Default())

    expect:
    target.enabled == enabled
    target.applyCalled == enabled

    where:
    value   | enabled
    "true"  | true
    "false" | false
    "asdf"  | false
  }

  def "configure sys prop enabled for #value when default is disabled"() {
    setup:
    injectSysConfig("integrations.enabled", "false")
    injectSysConfig("integration.${value}.enabled", "true")
    def target = new TestDefaultInstrumenter(name, altName)
    target.instrument(new AgentBuilder.Default())

    expect:
    target.enabled == enabled
    target.applyCalled == enabled

    where:
    value             | enabled | name          | altName
    "test"            | true    | "test"        | "asdf"
    "duplicate"       | true    | "duplicate"   | "duplicate"
    "bad"             | false   | "not"         | "valid"
    "altTest"         | true    | "asdf"        | "altTest"
    "dash-test"       | true    | "dash-test"   | "asdf"
    "underscore_test" | true    | "asdf"        | "underscore_test"
    "period.test"     | true    | "period.test" | "asdf"
  }

  def "configure env var enabled for #value when default is disabled"() {
    setup:
    injectEnvConfig("DD_INTEGRATIONS_ENABLED", "false")
    injectEnvConfig("DD_INTEGRATION_${value}_ENABLED", "true")

    when:
    def target = new TestDefaultInstrumenter(name, altName)
    target.instrument(new AgentBuilder.Default())

    then:
    System.getenv("DD_INTEGRATION_${value}_ENABLED") == "true"
    target.enabled == enabled
    target.applyCalled == enabled

    where:
    value             | enabled | name          | altName
    "TEST"            | true    | "test"        | "asdf"
    "DUPLICATE"       | true    | "duplicate"   | "duplicate"
    "BAD"             | false   | "not"         | "valid"
    "ALTTEST"         | true    | "asdf"        | "altTest"
    "DASH_TEST"       | true    | "dash-test"   | "asdf"
    "UNDERSCORE_TEST" | true    | "asdf"        | "underscore_test"
    "PERIOD_TEST"     | true    | "period.test" | "asdf"
  }

  class TestDefaultInstrumenter extends Instrumenter.Tracing {
    boolean applyCalled = false

    TestDefaultInstrumenter(
    String instrumentationName) {
      super(instrumentationName)
    }

    TestDefaultInstrumenter(
    String instrumentationName, String additionalName) {
      super(instrumentationName, [additionalName])
    }

    @Override
    ElementMatcher<? super TypeDescription> typeMatcher() {
      applyCalled = true
      return new ElementMatcher() {
          @Override
          boolean matches(Object target) {
            return false
          }
        }
    }

    @Override
    void adviceTransformations(AdviceTransformation transformation) {
    }
  }
}
