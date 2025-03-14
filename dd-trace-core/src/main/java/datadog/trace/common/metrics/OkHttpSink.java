package datadog.trace.common.metrics;

import static datadog.communication.ddagent.DDAgentFeaturesDiscovery.V6_METRICS_ENDPOINT;
import static datadog.communication.http.OkHttpUtils.buildHttpClient;
import static datadog.communication.http.OkHttpUtils.msgpackRequestBodyOf;
import static datadog.communication.http.OkHttpUtils.prepareRequest;
import static datadog.trace.common.metrics.EventListener.EventType.BAD_PAYLOAD;
import static datadog.trace.common.metrics.EventListener.EventType.DOWNGRADED;
import static datadog.trace.common.metrics.EventListener.EventType.ERROR;
import static datadog.trace.common.metrics.EventListener.EventType.OK;
import static java.util.concurrent.TimeUnit.SECONDS;

import datadog.trace.common.writer.ddagent.DDAgentApi;
import datadog.trace.core.DDTraceCoreInfo;
import datadog.trace.util.AgentTaskScheduler;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.jctools.queues.SpscArrayQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class OkHttpSink implements Sink, EventListener {

  private static final Logger log = LoggerFactory.getLogger(OkHttpSink.class);

  private static final Map<String, String> HEADERS =
      Collections.singletonMap(DDAgentApi.DATADOG_META_TRACER_VERSION, DDTraceCoreInfo.VERSION);

  private final OkHttpClient client;
  private final HttpUrl metricsUrl;
  private final List<EventListener> listeners;
  private final SpscArrayQueue<Request> enqueuedRequests = new SpscArrayQueue<>(10);
  private final AtomicLong lastRequestTime = new AtomicLong();
  private final AtomicLong asyncRequestCounter = new AtomicLong();
  private final long asyncThresholdLatency;
  private final boolean bufferingEnabled;

  private final AtomicBoolean asyncTaskStarted = new AtomicBoolean(false);
  private volatile AgentTaskScheduler.Scheduled<OkHttpSink> future;

  public OkHttpSink(String agentUrl, long timeoutMillis, boolean bufferingEnabled) {
    this(
        buildHttpClient(HttpUrl.get(agentUrl), timeoutMillis),
        agentUrl,
        V6_METRICS_ENDPOINT,
        bufferingEnabled);
  }

  public OkHttpSink(OkHttpClient client, String agentUrl, String path, boolean bufferingEnabled) {
    this(client, agentUrl, path, SECONDS.toNanos(1), bufferingEnabled);
  }

  public OkHttpSink(
      OkHttpClient client,
      String agentUrl,
      String path,
      long asyncThresholdLatency,
      boolean bufferingEnabled) {
    this.client = client;
    this.metricsUrl = HttpUrl.get(agentUrl).resolve(path);
    this.listeners = new CopyOnWriteArrayList<>();
    this.asyncThresholdLatency = asyncThresholdLatency;
    this.bufferingEnabled = bufferingEnabled;
  }

  @Override
  public void accept(int messageCount, ByteBuffer buffer) {
    // if the agent is healthy, then we can send on this thread,
    // without copying the buffer, otherwise this needs to be async,
    // so need to copy and buffer the request, and let it be executed
    // on the main task scheduler as a last resort
    if (!bufferingEnabled || lastRequestTime.get() < asyncThresholdLatency) {
      send(
          prepareRequest(metricsUrl, HEADERS)
              .put(msgpackRequestBodyOf(Collections.singletonList(buffer)))
              .build());
      AgentTaskScheduler.Scheduled<OkHttpSink> future = this.future;
      if (future != null && enqueuedRequests.isEmpty()) {
        // async mode has been started but request latency is normal,
        // there is no pending work, so switch off async mode
        future.cancel();
        asyncTaskStarted.set(false);
      }
    } else {
      if (asyncTaskStarted.compareAndSet(false, true)) {
        this.future =
            AgentTaskScheduler.INSTANCE.scheduleAtFixedRate(
                new Sender(enqueuedRequests), this, 1, 1, SECONDS);
      }
      sendAsync(messageCount, buffer);
    }
  }

  private void sendAsync(int messageCount, ByteBuffer buffer) {
    asyncRequestCounter.getAndIncrement();
    if (!enqueuedRequests.offer(
        prepareRequest(metricsUrl, HEADERS)
            .put(msgpackRequestBodyOf(Collections.singletonList(buffer.duplicate())))
            .build())) {
      log.debug(
          "dropping payload of {} and {}B because sending queue was full",
          messageCount,
          buffer.limit());
    }
  }

  public boolean isInDegradedMode() {
    return asyncTaskStarted.get();
  }

  public long asyncRequestCount() {
    return asyncRequestCounter.get();
  }

  private void send(Request request) {
    long start = System.nanoTime();
    try (final okhttp3.Response response = client.newCall(request).execute()) {
      if (!response.isSuccessful()) {
        handleFailure(response);
      } else {
        onEvent(OK, "");
      }
    } catch (IOException e) {
      onEvent(ERROR, e.getMessage());
    } finally {
      lastRequestTime.set(System.nanoTime() - start);
    }
  }

  @Override
  public void onEvent(EventListener.EventType eventType, String message) {
    for (EventListener listener : listeners) {
      listener.onEvent(eventType, message);
    }
  }

  @Override
  public void register(EventListener listener) {
    this.listeners.add(listener);
  }

  private void handleFailure(okhttp3.Response response) throws IOException {
    final int code = response.code();
    if (code == 404) {
      onEvent(DOWNGRADED, "could not find endpoint");
    } else if (code >= 400 && code < 500) {
      onEvent(BAD_PAYLOAD, response.body().string());
    } else if (code >= 500) {
      onEvent(ERROR, response.body().string());
    }
  }

  private static final class Sender implements AgentTaskScheduler.Task<OkHttpSink> {

    private final SpscArrayQueue<Request> inbox;

    private Sender(SpscArrayQueue<Request> inbox) {
      this.inbox = inbox;
    }

    @Override
    public void run(OkHttpSink target) {
      Request request;
      while ((request = inbox.poll()) != null) {
        target.send(request);
      }
    }
  }
}
