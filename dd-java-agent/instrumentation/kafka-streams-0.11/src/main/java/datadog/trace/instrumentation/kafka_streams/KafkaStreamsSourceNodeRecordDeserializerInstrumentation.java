package datadog.trace.instrumentation.kafka_streams;

import static datadog.trace.agent.tooling.bytebuddy.matcher.NameMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.isPublic;
import static net.bytebuddy.matcher.ElementMatchers.returns;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;

import com.google.auto.service.AutoService;
import datadog.trace.agent.tooling.Instrumenter;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.record.TimestampType;

// This is necessary because SourceNodeRecordDeserializer drops the headers.  :-(
@AutoService(Instrumenter.class)
public class KafkaStreamsSourceNodeRecordDeserializerInstrumentation extends Instrumenter.Tracing {

  public KafkaStreamsSourceNodeRecordDeserializerInstrumentation() {
    super("kafka", "kafka-streams");
  }

  @Override
  public ElementMatcher<TypeDescription> typeMatcher() {
    return named("org.apache.kafka.streams.processor.internals.SourceNodeRecordDeserializer");
  }

  @Override
  public void adviceTransformations(AdviceTransformation transformation) {
    transformation.applyAdvice(
        isMethod()
            .and(isPublic())
            .and(named("deserialize"))
            .and(takesArgument(0, named("org.apache.kafka.clients.consumer.ConsumerRecord")))
            .and(returns(named("org.apache.kafka.clients.consumer.ConsumerRecord"))),
        KafkaStreamsSourceNodeRecordDeserializerInstrumentation.class.getName()
            + "$SaveHeadersAdvice");
  }

  public static class SaveHeadersAdvice {

    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void saveHeaders(
        @Advice.Argument(0) final ConsumerRecord incoming,
        @Advice.Return(readOnly = false) ConsumerRecord result) {
      result =
          new ConsumerRecord<>(
              result.topic(),
              result.partition(),
              result.offset(),
              result.timestamp(),
              TimestampType.CREATE_TIME,
              result.checksum(),
              result.serializedKeySize(),
              result.serializedValueSize(),
              result.key(),
              result.value(),
              incoming.headers());
    }
  }
}
