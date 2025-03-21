package datadog.trace.core.propagation;

import static datadog.trace.core.propagation.HttpCodec.FORWARDED_FOR_KEY;
import static datadog.trace.core.propagation.HttpCodec.FORWARDED_HOST_KEY;
import static datadog.trace.core.propagation.HttpCodec.FORWARDED_KEY;
import static datadog.trace.core.propagation.HttpCodec.FORWARDED_PORT_KEY;
import static datadog.trace.core.propagation.HttpCodec.FORWARDED_PROTO_KEY;

import datadog.trace.api.Config;
import datadog.trace.api.DDId;
import datadog.trace.api.Functions;
import datadog.trace.api.cache.DDCache;
import datadog.trace.api.cache.DDCaches;
import datadog.trace.api.sampling.PrioritySampling;
import datadog.trace.bootstrap.instrumentation.api.AgentPropagation;
import datadog.trace.bootstrap.instrumentation.api.TagContext;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public abstract class ContextInterpreter implements AgentPropagation.KeyClassifier {

  protected final Map<String, String> taggedHeaders;

  protected DDId traceId;
  protected DDId spanId;
  protected int samplingPriority;
  protected Map<String, String> tags;
  protected Map<String, String> baggage;
  protected String origin;
  protected String forwarded;
  protected String forwardedProto;
  protected String forwardedHost;
  protected String forwardedIp;
  protected String forwardedPort;
  protected boolean valid;

  protected static final boolean LOG_EXTRACT_HEADER_NAMES = Config.get().isLogExtractHeaderNames();
  private static final DDCache<String, String> CACHE = DDCaches.newFixedSizeCache(64);

  protected String toLowerCase(String key) {
    return CACHE.computeIfAbsent(key, Functions.LowerCase.INSTANCE);
  }

  protected ContextInterpreter(Map<String, String> taggedHeaders) {
    this.taggedHeaders = taggedHeaders;
    reset();
  }

  public abstract static class Factory {

    public ContextInterpreter create(Map<String, String> tagsMapping) {
      return construct(cleanMapping(tagsMapping));
    }

    protected abstract ContextInterpreter construct(Map<String, String> tagsMapping);

    protected Map<String, String> cleanMapping(Map<String, String> taggedHeaders) {
      final Map<String, String> cleanedMapping = new HashMap<>(taggedHeaders.size() * 4 / 3);
      for (Map.Entry<String, String> association : taggedHeaders.entrySet()) {
        cleanedMapping.put(
            association.getKey().trim().toLowerCase(), association.getValue().trim().toLowerCase());
      }
      return cleanedMapping;
    }
  }

  protected final boolean handledForwarding(String key, String value) {
    if (null != value) {
      if (FORWARDED_KEY.equalsIgnoreCase(key)) {
        forwarded = value;
        return true;
      }
      if (FORWARDED_PROTO_KEY.equalsIgnoreCase(key)) {
        forwardedProto = value;
        return true;
      }
      if (FORWARDED_HOST_KEY.equalsIgnoreCase(key)) {
        forwardedHost = value;
        return true;
      }
      if (FORWARDED_FOR_KEY.equalsIgnoreCase(key)) {
        forwardedIp = value;
        return true;
      }
      if (FORWARDED_PORT_KEY.equalsIgnoreCase(key)) {
        forwardedPort = value;
        return true;
      }
    }
    return false;
  }

  public ContextInterpreter reset() {
    traceId = DDId.ZERO;
    spanId = DDId.ZERO;
    samplingPriority = defaultSamplingPriority();
    origin = null;
    forwarded = null;
    forwardedProto = null;
    forwardedHost = null;
    forwardedIp = null;
    forwardedPort = null;
    tags = Collections.emptyMap();
    baggage = Collections.emptyMap();
    valid = true;
    return this;
  }

  TagContext build() {
    if (valid) {
      if (!DDId.ZERO.equals(traceId)) {
        final ExtractedContext context =
            new ExtractedContext(
                traceId,
                spanId,
                samplingPriority,
                origin,
                forwarded,
                forwardedProto,
                forwardedHost,
                forwardedIp,
                forwardedPort,
                baggage,
                tags);
        context.lockSamplingPriority();
        return context;
      } else if (origin != null
          || forwarded != null
          || forwardedProto != null
          || forwardedHost != null
          || forwardedIp != null
          || forwardedPort != null
          || !tags.isEmpty()) {
        return new TagContext(
            origin, forwarded, forwardedProto, forwardedHost, forwardedIp, forwardedPort, tags);
      }
    }
    return null;
  }

  protected void invalidateContext() {
    this.valid = false;
  }

  protected int defaultSamplingPriority() {
    return PrioritySampling.UNSET;
  }
}
