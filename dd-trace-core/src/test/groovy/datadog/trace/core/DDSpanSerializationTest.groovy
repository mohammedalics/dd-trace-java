package datadog.trace.core

import datadog.trace.api.DDId
import datadog.trace.api.sampling.PrioritySampling
import datadog.trace.common.writer.ListWriter
import datadog.trace.common.writer.ddagent.TraceMapperV0_4
import datadog.trace.common.writer.ddagent.TraceMapperV0_5
import datadog.communication.serialization.ByteBufferConsumer
import datadog.communication.serialization.FlushingBuffer
import datadog.communication.serialization.msgpack.MsgPackWriter
import datadog.trace.core.test.DDCoreSpecification
import org.msgpack.core.MessageFormat
import org.msgpack.core.MessagePack
import org.msgpack.core.buffer.ArrayBufferInput
import org.msgpack.value.ValueType

import java.nio.ByteBuffer

class DDSpanSerializationTest extends DDCoreSpecification {

  def "serialize trace with id #value as int"() {
    setup:
    def writer = new ListWriter()
    def tracer = tracerBuilder().writer(writer).build()
    def context = createContext(spanType, tracer, value)
    def span = DDSpan.create(0, context)
    CaptureBuffer capture = new CaptureBuffer()
    def packer = new MsgPackWriter(new FlushingBuffer(1024, capture))
    packer.format(Collections.singletonList(span), new TraceMapperV0_4())
    packer.flush()
    def unpacker = MessagePack.newDefaultUnpacker(new ArrayBufferInput(capture.bytes))
    int traceCount = capture.messageCount
    int spanCount = unpacker.unpackArrayHeader()
    int size = unpacker.unpackMapHeader()

    expect:
    traceCount == 1
    spanCount == 1
    size == 12
    for (int i = 0; i < size; i++) {
      String key = unpacker.unpackString()

      switch (key) {
        case "trace_id":
        case "span_id":
          MessageFormat next = unpacker.nextFormat
          assert next.valueType == ValueType.INTEGER
          if (next == MessageFormat.UINT64) {
            assert value == DDId.from("${unpacker.unpackBigInteger()}")
          } else {
            assert value == DDId.from(unpacker.unpackLong())
          }
          break
        default:
          unpacker.unpackValue()
      }
    }

    cleanup:
    tracer.close()

    where:
    value                                                           | spanType
    DDId.ZERO                                                       | null
    DDId.ONE                                                        | "some-type"
    DDId.from("8223372036854775807")                                | null
    DDId.from("${BigInteger.valueOf(Long.MAX_VALUE).subtract(1G)}") | "some-type"
    DDId.from("${BigInteger.valueOf(Long.MAX_VALUE).add(1G)}")      | null
    DDId.from("${2G.pow(64).subtract(1G)}")                         | "some-type"
  }

  def "serialize trace with id #value as int v0.5"() {
    setup:
    def writer = new ListWriter()
    def tracer = tracerBuilder().writer(writer).build()
    def context = createContext(spanType, tracer, value)
    def span = DDSpan.create(0, context)
    CaptureBuffer capture = new CaptureBuffer()
    def packer = new MsgPackWriter(new FlushingBuffer(1024, capture))
    def traceMapper = new TraceMapperV0_5()
    packer.format(Collections.singletonList(span), traceMapper)
    packer.flush()
    def dictionaryUnpacker = MessagePack.newDefaultUnpacker(traceMapper.dictionary.slice())
    String[] dictionary = new String[traceMapper.encoding.size()]
    for (int i = 0; i < dictionary.length; ++i) {
      dictionary[i] = dictionaryUnpacker.unpackString()
    }
    def unpacker = MessagePack.newDefaultUnpacker(new ArrayBufferInput(capture.bytes))
    int traceCount = capture.messageCount

    int spanCount = unpacker.unpackArrayHeader()
    int size = unpacker.unpackArrayHeader()

    expect:
    traceCount == 1
    spanCount == 1
    size == 12
    for (int i = 0; i < size; i++) {
      switch (i) {
        case 3:
        case 4:
          MessageFormat next = unpacker.nextFormat
          assert next.valueType == ValueType.INTEGER
          if (next == MessageFormat.UINT64) {
            assert value == DDId.from("${unpacker.unpackBigInteger()}")
          } else {
            assert value == DDId.from(unpacker.unpackLong())
          }
          break
        default:
          unpacker.unpackValue()
      }
    }

    cleanup:
    tracer.close()

    where:
    value                                                           | spanType
    DDId.ZERO                                                       | null
    DDId.ONE                                                        | "some-type"
    DDId.from("8223372036854775807")                                | null
    DDId.from("${BigInteger.valueOf(Long.MAX_VALUE).subtract(1G)}") | "some-type"
    DDId.from("${BigInteger.valueOf(Long.MAX_VALUE).add(1G)}")      | null
    DDId.from("${2G.pow(64).subtract(1G)}")                         | "some-type"
  }

  def "serialize trace with baggage and tags correctly v0.4"() {
    setup:
    def writer = new ListWriter()
    def tracer = tracerBuilder().writer(writer).build()
    def context = new DDSpanContext(
      DDId.ONE,
      DDId.ONE,
      DDId.ZERO,
      null,
      "fakeService",
      "fakeOperation",
      "fakeResource",
      PrioritySampling.UNSET,
      null,
      baggage,
      false,
      null,
      tags.size(),
      tracer.pendingTraceFactory.create(DDId.ONE),
      null)
    context.setAllTags(tags)
    def span = DDSpan.create(0, context)
    CaptureBuffer capture = new CaptureBuffer()
    def packer = new MsgPackWriter(new FlushingBuffer(1024, capture))
    packer.format(Collections.singletonList(span), new TraceMapperV0_4())
    packer.flush()
    def unpacker = MessagePack.newDefaultUnpacker(new ArrayBufferInput(capture.bytes))
    int traceCount = capture.messageCount
    int spanCount = unpacker.unpackArrayHeader()
    int size = unpacker.unpackMapHeader()

    expect:
    traceCount == 1
    spanCount == 1
    size == 12
    for (int i = 0; i < size; i++) {
      String key = unpacker.unpackString()

      switch (key) {
        case "meta":
          int packedSize = unpacker.unpackMapHeader()
          Map<String, String> unpackedMeta = [:]
          for (int j = 0; j < packedSize; j++) {
            def k = unpacker.unpackString()
            def v = unpacker.unpackString()
            if (k != "thread.name" && k != "thread.id") {
              unpackedMeta.put(k, v)
            }
          }
          assert unpackedMeta == expected
          break
        default:
          unpacker.unpackValue()
      }
    }

    cleanup:
    tracer.close()

    where:
    baggage       | tags          | expected
    [:]           | [:]           | [:]
    [foo: "bbar"] | [:]           | [foo: "bbar"]
    [foo: "bbar"] | [bar: "tfoo"] | [foo: "bbar", bar: "tfoo"]
    [foo: "bbar"] | [foo: "tbar"] | [foo: "tbar"]
  }

  def "serialize trace with baggage and tags correctly v0.5"() {
    setup:
    def writer = new ListWriter()
    def tracer = tracerBuilder().writer(writer).build()
    def context = new DDSpanContext(
      DDId.ONE,
      DDId.ONE,
      DDId.ZERO,
      null,
      "fakeService",
      "fakeOperation",
      "fakeResource",
      PrioritySampling.UNSET,
      null,
      baggage,
      false,
      null,
      tags.size(),
      tracer.pendingTraceFactory.create(DDId.ONE),
      null)
    context.setAllTags(tags)
    def span = DDSpan.create(0, context)
    CaptureBuffer capture = new CaptureBuffer()
    def packer = new MsgPackWriter(new FlushingBuffer(1024, capture))
    def mapper = new TraceMapperV0_5()
    packer.format(Collections.singletonList(span), mapper)
    packer.flush()
    def unpacker = MessagePack.newDefaultUnpacker(new ArrayBufferInput(capture.bytes))
    int traceCount = capture.messageCount
    int spanCount = unpacker.unpackArrayHeader()
    int size = unpacker.unpackArrayHeader()
    def dictionaryUnpacker = MessagePack.newDefaultUnpacker(mapper.dictionary.slice())
    String[] dictionary = new String[mapper.encoding.size()]
    for (int i = 0; i < dictionary.length; ++i) {
      dictionary[i] = dictionaryUnpacker.unpackString()
    }

    expect:
    traceCount == 1
    spanCount == 1
    size == 12
    for (int i = 0; i < 9; ++i) {
      unpacker.skipValue()
    }

    int packedSize = unpacker.unpackMapHeader()
    Map<String, String> unpackedMeta = [:]
    for (int j = 0; j < packedSize; j++) {
      def k = dictionary[unpacker.unpackInt()]
      def v = dictionary[unpacker.unpackInt()]
      if (k != "thread.name" && k != "thread.id") {
        unpackedMeta.put(k, v)
      }
    }
    assert unpackedMeta == expected

    cleanup:
    tracer.close()

    where:
    baggage       | tags          | expected
    [:]           | [:]           | [:]
    [foo: "bbar"] | [:]           | [foo: "bbar"]
    [foo: "bbar"] | [bar: "tfoo"] | [foo: "bbar", bar: "tfoo"]
    [foo: "bbar"] | [foo: "tbar"] | [foo: "tbar"]
  }

  private class CaptureBuffer implements ByteBufferConsumer {

    private byte[] bytes
    int messageCount

    @Override
    void accept(int messageCount, ByteBuffer buffer) {
      this.messageCount = messageCount
      this.bytes = new byte[buffer.limit() - buffer.position()]
      buffer.get(bytes)
    }
  }

  def createContext(String spanType, CoreTracer tracer, DDId value) {
    DDSpanContext ctx = new DDSpanContext(
      value,
      value,
      DDId.ZERO,
      null,
      "fakeService",
      "fakeOperation",
      "fakeResource",
      PrioritySampling.UNSET,
      null,
      ["a-baggage": "value"],
      false,
      spanType,
      1,
      tracer.pendingTraceFactory.create(DDId.ONE),
      null)
    ctx.setAllTags(["k1": "v1"])
    return ctx
  }
}
