package datadog.smoketest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.datadog.profiling.testing.ProfilingTestUtils;
import com.google.common.collect.Multimap;
import datadog.trace.api.Pair;
import datadog.trace.api.config.ProfilingConfig;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Predicate;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.openjdk.jmc.common.item.Aggregators;
import org.openjdk.jmc.common.item.Attribute;
import org.openjdk.jmc.common.item.IAttribute;
import org.openjdk.jmc.common.item.IItemCollection;
import org.openjdk.jmc.common.item.ItemFilters;
import org.openjdk.jmc.common.unit.IQuantity;
import org.openjdk.jmc.common.unit.QuantityConversionException;
import org.openjdk.jmc.common.unit.UnitLookup;
import org.openjdk.jmc.flightrecorder.JfrLoaderToolkit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class ProfilingIntegrationTest {
  private static final Logger log = LoggerFactory.getLogger(ProfilingIntegrationTest.class);

  @FunctionalInterface
  private interface TestBody {
    void run() throws Exception;
  }

  private static final String VALID_API_KEY = "01234567890abcdef123456789ABCDEF";
  private static final String BOGUS_API_KEY = "bogus";
  private static final int PROFILING_START_DELAY_SECONDS = 1;
  private static final int PROFILING_UPLOAD_PERIOD_SECONDS = 5;
  private static final boolean LEGACY_TRACING_INTEGRATION = true; // default
  private static final boolean ENDPOINT_COLLECTION_ENABLED = true; // default
  // Set the request timeout value to the sum of the initial delay and the upload period
  // multiplied by a safety margin
  private static final int SAFETY_MARGIN = 3;
  private static final int REQUEST_WAIT_TIMEOUT =
      (PROFILING_START_DELAY_SECONDS + PROFILING_UPLOAD_PERIOD_SECONDS) * SAFETY_MARGIN;

  private static final Path LOG_FILE_BASE =
      Paths.get(
          buildDirectory(), "reports", "testProcess." + ProfilingIntegrationTest.class.getName());

  private MockWebServer profilingServer;
  private MockWebServer tracingServer;

  private Process targetProcess = null;
  private Path logFilePath = null;

  @BeforeAll
  static void setupAll() throws Exception {
    Files.createDirectories(LOG_FILE_BASE);
  }

  @BeforeEach
  void setup(final TestInfo testInfo) throws Exception {
    tracingServer = new MockWebServer();
    profilingServer = new MockWebServer();
    tracingServer.setDispatcher(
        new Dispatcher() {
          @Override
          public MockResponse dispatch(final RecordedRequest request) throws InterruptedException {
            return new MockResponse().setResponseCode(200);
          }
        });
    tracingServer.start();
    profilingServer.start();

    profilingServer.enqueue(new MockResponse().setResponseCode(200));

    logFilePath = LOG_FILE_BASE.resolve(testInfo.getDisplayName() + ".log");
  }

  @AfterEach
  void teardown() throws Exception {
    if (targetProcess != null) {
      targetProcess.destroyForcibly();
    }
    try {
      profilingServer.shutdown();
    } finally {
      tracingServer.shutdown();
    }
  }

  @Test
  @DisplayName("Test continuous recording - no jmx delay")
  public void testContinuousRecording_no_jmx_delay(final TestInfo testInfo) throws Exception {
    testWithRetry(
        () -> testContinuousRecording(0, LEGACY_TRACING_INTEGRATION, ENDPOINT_COLLECTION_ENABLED),
        testInfo,
        5);
  }

  @Test
  @DisplayName("Test continuous recording - 1 sec jmx delay")
  public void testContinuousRecording(final TestInfo testInfo) throws Exception {
    testWithRetry(
        () -> testContinuousRecording(1, LEGACY_TRACING_INTEGRATION, ENDPOINT_COLLECTION_ENABLED),
        testInfo,
        5);
  }

  @Test
  @DisplayName("Test continuous recording - checkpoint events")
  public void testContinuousRecordingCheckpointEvents(final TestInfo testInfo) throws Exception {
    testWithRetry(
        () -> testContinuousRecording(0, false, ENDPOINT_COLLECTION_ENABLED), testInfo, 5);
  }

  @Test
  @DisplayName("Test continuous recording - checkpoint events, endpoint events disabled")
  public void testContinuousRecordingCheckpointEventsNoEndpointCollection(final TestInfo testInfo)
      throws Exception {
    testWithRetry(() -> testContinuousRecording(0, false, false), testInfo, 5);
  }

  private void testContinuousRecording(
      final int jmxFetchDelay,
      final boolean legacyTracingIntegration,
      final boolean endpointCollectionEnabled)
      throws Exception {
    try {
      targetProcess =
          createDefaultProcessBuilder(
                  jmxFetchDelay, legacyTracingIntegration, endpointCollectionEnabled, logFilePath)
              .start();

      final RecordedRequest firstRequest = retrieveRequest();

      assertNotNull(firstRequest);
      final Multimap<String, Object> firstRequestParameters =
          ProfilingTestUtils.parseProfilingRequestParameters(firstRequest);

      assertEquals(profilingServer.getPort(), firstRequest.getRequestUrl().url().getPort());
      assertEquals("jfr", getStringParameter("format", firstRequestParameters));
      assertEquals("jfr-continuous", getStringParameter("type", firstRequestParameters));
      assertEquals("jvm", getStringParameter("runtime", firstRequestParameters));

      final Instant firstStartTime =
          Instant.parse(getStringParameter("recording-start", firstRequestParameters));
      final Instant firstEndTime =
          Instant.parse(getStringParameter("recording-end", firstRequestParameters));
      assertNotNull(firstStartTime);
      assertNotNull(firstEndTime);

      final long duration = firstEndTime.toEpochMilli() - firstStartTime.toEpochMilli();
      assertTrue(duration > TimeUnit.SECONDS.toMillis(PROFILING_UPLOAD_PERIOD_SECONDS - 2));
      assertTrue(duration < TimeUnit.SECONDS.toMillis(PROFILING_UPLOAD_PERIOD_SECONDS + 2));

      final Map<String, String> requestTags =
          ProfilingTestUtils.parseTags(firstRequestParameters.get("tags[]"));
      assertEquals("smoke-test-java-app", requestTags.get("service"));
      assertEquals("jvm", requestTags.get("language"));
      assertNotNull(requestTags.get("runtime-id"));
      assertEquals(InetAddress.getLocalHost().getHostName(), requestTags.get("host"));

      byte[] byteData = getParameter("chunk-data", byte[].class, firstRequestParameters);
      assertNotNull(byteData);

      dumpJfrRecording(byteData);

      assertFalse(logHasErrors(logFilePath));
      IItemCollection events = JfrLoaderToolkit.loadEvents(new ByteArrayInputStream(byteData));
      assertTrue(events.hasItems());
      Pair<Instant, Instant> rangeStartAndEnd = getRangeStartAndEnd(events);
      final Instant firstRangeStart = rangeStartAndEnd.getLeft();
      final Instant firstRangeEnd = rangeStartAndEnd.getRight();
      assertTrue(
          firstStartTime.compareTo(firstRangeStart) <= 0,
          () ->
              "First range start "
                  + firstRangeStart
                  + " is before first start time "
                  + firstStartTime);

      final RecordedRequest nextRequest = retrieveRequest();
      assertNotNull(nextRequest);

      final Multimap<String, Object> secondRequestParameters =
          ProfilingTestUtils.parseProfilingRequestParameters(nextRequest);
      final Instant secondStartTime =
          Instant.parse(getStringParameter("recording-start", secondRequestParameters));
      final Instant secondEndTime =
          Instant.parse(getStringParameter("recording-end", secondRequestParameters));
      final long period = secondStartTime.toEpochMilli() - firstStartTime.toEpochMilli();
      final long upperLimit = TimeUnit.SECONDS.toMillis(PROFILING_UPLOAD_PERIOD_SECONDS) * 2;
      assertTrue(
          period > 0 && period <= upperLimit,
          () -> "Upload period = " + period + "ms, expected (0, " + upperLimit + "]ms");

      byteData = getParameter("chunk-data", byte[].class, secondRequestParameters);
      assertNotNull(byteData);
      dumpJfrRecording(byteData);

      events = JfrLoaderToolkit.loadEvents(new ByteArrayInputStream(byteData));
      assertTrue(events.hasItems());
      rangeStartAndEnd = getRangeStartAndEnd(events);
      final Instant secondRangeStart = rangeStartAndEnd.getLeft();
      final Instant secondRangeEnd = rangeStartAndEnd.getRight();
      // So the OracleJdkOngoingRecording and underlying recording seems to
      // either lose precision in the reported times, or filter a bit differently
      // so we can't check these invariants =(
      if (!System.getProperty("java.vendor").contains("Oracle")
          || !System.getProperty("java.version").contains("1.8")) {
        assertTrue(
            secondStartTime.compareTo(secondRangeStart) <= 0,
            () ->
                "Second range start "
                    + secondRangeStart
                    + " is before second start time "
                    + secondStartTime);
        assertTrue(
            firstEndTime.isBefore(secondRangeStart),
            () ->
                "Second range start "
                    + secondRangeStart
                    + " is before or equal to first end time "
                    + firstEndTime);
      }
      // Only non-Oracle JDK 8+ JVMs support custom DD events
      if (!System.getProperty("java.vendor").contains("Oracle")
          || !System.getProperty("java.version").contains("1.8")) {
        assertRecordingEvents(events, legacyTracingIntegration, endpointCollectionEnabled);
      }
    } finally {
      if (targetProcess != null) {
        targetProcess.destroyForcibly();
      }
      targetProcess = null;
    }
  }

  private void dumpJfrRecording(byte[] byteData) {
    try {
      Path dumpPath = Files.createTempFile("dd-dump-", ".jfr");
      Files.write(dumpPath, byteData);
      log.debug("Received profile stored at: {}", dumpPath.toAbsolutePath());
    } catch (IOException ignored) {
    }
  }

  private Instant convertFromQuantity(final IQuantity instant) {
    Instant converted = null;
    try {
      final IQuantity rangeS = instant.in(UnitLookup.EPOCH_S);
      final long es = rangeS.longValue();
      final long ns =
          instant.longValueIn(UnitLookup.EPOCH_NS) - rangeS.longValueIn(UnitLookup.EPOCH_NS);
      converted = Instant.ofEpochSecond(es, ns);
    } catch (final QuantityConversionException ignore) {
    }
    return converted;
  }

  private Pair<Instant, Instant> getRangeStartAndEnd(final IItemCollection events) {
    return events.getUnfilteredTimeRanges().stream()
        .map(
            range -> {
              final Instant convertedStart = convertFromQuantity(range.getStart());
              final Instant convertedEnd = convertFromQuantity(range.getEnd());
              return Pair.of(convertedStart, convertedEnd);
            })
        .reduce(
            Pair.of(null, null),
            (send, newSend) -> {
              Instant start = send.getLeft();
              Instant end = send.getRight();
              final Instant newStart = newSend.getLeft();
              final Instant newEnd = newSend.getRight();
              start =
                  null == start
                      ? newStart
                      : null == newStart ? start : newStart.isBefore(start) ? newStart : start;
              end =
                  null == end ? newEnd : null == newEnd ? end : newEnd.isAfter(end) ? newEnd : end;
              return Pair.of(start, end);
            });
  }

  @Test
  @DisplayName("Test bogus API key")
  void testBogusApiKey(final TestInfo testInfo) throws Exception {
    testWithRetry(
        () -> {
          final int exitDelay =
              PROFILING_START_DELAY_SECONDS + PROFILING_UPLOAD_PERIOD_SECONDS * 2 + 1;

          try {
            targetProcess =
                createProcessBuilder(
                        BOGUS_API_KEY,
                        0,
                        PROFILING_START_DELAY_SECONDS,
                        PROFILING_UPLOAD_PERIOD_SECONDS,
                        LEGACY_TRACING_INTEGRATION,
                        ENDPOINT_COLLECTION_ENABLED,
                        exitDelay,
                        logFilePath)
                    .start();

            /* API key of an incorrect format will cause profiling to get disabled.
              This means no upload requests will be made. We are going to check the log file for
              the presence of a specific message. For this we need to wait for a particular message indicating
              that the profiling system is initializing and then assert for the presence of the expected message
              caused by the API key format error.
            */
            final long ts = System.nanoTime();
            while (!checkLogLines(
                logFilePath, line -> line.contains("Registering scope event factory"))) {
              Thread.sleep(500);
              // Wait at most 30 seconds
              if (System.nanoTime() - ts > 30_000_000_000L) {
                throw new TimeoutException();
              }
            }

            /* An API key with incorrect format will cause profiling to get disabled and the
              following message would be logged.
              The test asserts for the presence of the message.
            */
            assertTrue(
                checkLogLines(
                    logFilePath,
                    it -> it.contains("Profiling: API key doesn't match expected format")));
            assertFalse(logHasErrors(logFilePath));
          } finally {
            if (targetProcess != null) {
              targetProcess.destroyForcibly();
              targetProcess = null;
            }
          }
        },
        testInfo,
        3);
  }

  @Test
  @DisplayName("Test shutdown")
  void testShutdown(final TestInfo testInfo) throws Exception {
    testWithRetry(
        () -> {
          final int exitDelay =
              PROFILING_START_DELAY_SECONDS + PROFILING_UPLOAD_PERIOD_SECONDS * 4 + 1;
          try {
            targetProcess =
                createProcessBuilder(
                        VALID_API_KEY,
                        0,
                        PROFILING_START_DELAY_SECONDS,
                        PROFILING_UPLOAD_PERIOD_SECONDS,
                        LEGACY_TRACING_INTEGRATION,
                        ENDPOINT_COLLECTION_ENABLED,
                        exitDelay,
                        logFilePath)
                    .start();

            final RecordedRequest request = retrieveRequest();
            assertNotNull(request);
            assertFalse(logHasErrors(logFilePath));
            assertTrue(request.getBodySize() > 0);

            // Wait for the app exit with some extra time.
            // The expectation is that agent doesn't prevent app from exiting.
            assertTrue(targetProcess.waitFor(exitDelay + 10, TimeUnit.SECONDS));
          } finally {
            if (targetProcess != null) {
              targetProcess.destroyForcibly();
            }
            targetProcess = null;
          }
        },
        testInfo,
        3);
  }

  private void testWithRetry(final TestBody test, final TestInfo testInfo, final int retries)
      throws Exception {
    int cnt = retries;
    Throwable lastThrowable = null;
    while (cnt >= 0) {
      // clean the lastThrowable first
      lastThrowable = null;
      // clean the log file so the previous errors do not throw off the assertions
      Files.deleteIfExists(logFilePath);
      try {
        test.run();
        break;
      } catch (final Throwable t) {
        lastThrowable = t;
        if (cnt > 0) {
          log.error("Test '{}' failed. Retrying.", testInfo.getDisplayName(), t);
        }
        // retry
      }
      cnt--;
    }
    if (lastThrowable != null) {
      throw new RuntimeException(
          "Failed '" + testInfo.getDisplayName() + "' after " + retries + " retries.",
          lastThrowable);
    }
  }

  private RecordedRequest retrieveRequest() throws Exception {
    return retrieveRequest(5 * REQUEST_WAIT_TIMEOUT, TimeUnit.SECONDS);
  }

  private RecordedRequest retrieveRequest(final long timeout, final TimeUnit timeUnit)
      throws Exception {
    final long ts = System.nanoTime();
    final RecordedRequest request = profilingServer.takeRequest(timeout, timeUnit);
    final long dur = System.nanoTime() - ts;
    log.info(
        "Profiling request retrieved in {} seconds",
        TimeUnit.SECONDS.convert(dur, TimeUnit.NANOSECONDS));
    return request;
  }

  private void assertRecordingEvents(
      final IItemCollection events,
      final boolean legacyTracingIntegration,
      final boolean expectEndpointEvents) {

    if (legacyTracingIntegration) {
      // Check scope events
      final IItemCollection scopeEvents = events.apply(ItemFilters.type("datadog.Scope"));

      assertTrue(scopeEvents.hasItems());
      final IAttribute<IQuantity> cpuTimeAttr =
          Attribute.attr("cpuTime", "cpuTime", UnitLookup.TIMESPAN);

      // filter out scope events without CPU time data
      final IItemCollection filteredScopeEvents =
          scopeEvents.apply(
              ItemFilters.more(cpuTimeAttr, UnitLookup.NANOSECOND.quantity(Long.MIN_VALUE)));
      // make sure there is at least one scope event with CPU time data
      assertTrue(filteredScopeEvents.hasItems());

      assertTrue(
          ((IQuantity)
                      filteredScopeEvents.getAggregate(
                          Aggregators.min("datadog.Scope", cpuTimeAttr)))
                  .longValue()
              >= 10_000L);
    } else {
      // Check checkpoint events
      final IItemCollection checkpointEvents = events.apply(ItemFilters.type("datadog.Checkpoint"));
      assertTrue(checkpointEvents.hasItems());
      // Check endpoint events
      final IItemCollection endpointEvents = events.apply(ItemFilters.type("datadog.Endpoint"));
      assertEquals(expectEndpointEvents, endpointEvents.hasItems());
    }

    // check exception events
    assertTrue(events.apply(ItemFilters.type("datadog.ExceptionSample")).hasItems());
    assertTrue(events.apply(ItemFilters.type("datadog.ExceptionCount")).hasItems());

    // check deadlock events
    assertTrue(events.apply(ItemFilters.type("datadog.Deadlock")).hasItems());
    assertTrue(events.apply(ItemFilters.type("datadog.DeadlockedThread")).hasItems());

    // check available processor events
    final IItemCollection availableProcessorsEvents =
        events.apply(ItemFilters.type("datadog.AvailableProcessorCores"));
    assertTrue(availableProcessorsEvents.hasItems());
    final IAttribute<IQuantity> cpuCountAttr =
        Attribute.attr("availableProcessorCores", "availableProcessorCores", UnitLookup.NUMBER);
    final long val =
        ((IQuantity)
                availableProcessorsEvents.getAggregate(
                    Aggregators.min("datadog.AvailableProcessorCores", cpuCountAttr)))
            .longValue();
    assertEquals(Runtime.getRuntime().availableProcessors(), val);
  }

  private static String getStringParameter(
      final String name, final Multimap<String, Object> parameters) {
    return getParameter(name, String.class, parameters);
  }

  private static <T> T getParameter(
      final String name, final Class<T> type, final Multimap<String, Object> parameters) {
    final List<?> vals = (List<?>) parameters.get(name);
    return (T) vals.get(0);
  }

  private ProcessBuilder createDefaultProcessBuilder(
      final int jmxFetchDelay,
      final boolean legacyTracingIntegration,
      final boolean endpointCollectionEnabled,
      final Path logFilePath) {
    return createProcessBuilder(
        VALID_API_KEY,
        jmxFetchDelay,
        PROFILING_START_DELAY_SECONDS,
        PROFILING_UPLOAD_PERIOD_SECONDS,
        legacyTracingIntegration,
        endpointCollectionEnabled,
        0,
        logFilePath);
  }

  private ProcessBuilder createProcessBuilder(
      final String apiKey,
      final int jmxFetchDelaySecs,
      final int profilingStartDelaySecs,
      final int profilingUploadPeriodSecs,
      final boolean legacyTracingIntegration,
      final boolean endpointCollectionEnabled,
      final int exitDelay,
      final Path logFilePath) {
    return createProcessBuilder(
        profilingServer.getPort(),
        tracingServer.getPort(),
        apiKey,
        jmxFetchDelaySecs,
        profilingStartDelaySecs,
        profilingUploadPeriodSecs,
        legacyTracingIntegration,
        endpointCollectionEnabled,
        exitDelay,
        logFilePath);
  }

  private static ProcessBuilder createProcessBuilder(
      final int profilerPort,
      final int tracerPort,
      final String apiKey,
      final int jmxFetchDelaySecs,
      final int profilingStartDelaySecs,
      final int profilingUploadPeriodSecs,
      final boolean legacyTracingIntegration,
      final boolean endpointCollectionEnabled,
      final int exitDelay,
      final Path logFilePath) {
    final String templateOverride =
        ProfilingIntegrationTest.class.getClassLoader().getResource("overrides.jfp").getFile();

    final List<String> command =
        Arrays.asList(
            javaPath(),
            "-Xmx" + System.getProperty("datadog.forkedMaxHeapSize", "512M"),
            "-Xms" + System.getProperty("datadog.forkedMinHeapSize", "64M"),
            "-javaagent:" + agentShadowJar(),
            "-XX:ErrorFile=/tmp/hs_err_pid%p.log",
            "-Ddd.trace.agent.port=" + tracerPort,
            "-Ddd.service.name=smoke-test-java-app",
            "-Ddd.env=smoketest",
            "-Ddd.version=99",
            "-Ddd.profiling.enabled=true",
            "-Ddd.profiling.auxiliary=async",
            "-Ddd.profiling.agentless=" + (apiKey != null),
            "-Ddd.profiling.start-delay=" + profilingStartDelaySecs,
            "-Ddd.profiling.upload.period=" + profilingUploadPeriodSecs,
            "-Ddd.profiling.url=http://localhost:" + profilerPort,
            "-Ddd.profiling.hotspots.enabled=true",
            "-Ddd.profiling.legacy.tracing.integration=" + legacyTracingIntegration,
            "-Ddd.profiling.endpoint.collection.enabled=" + endpointCollectionEnabled,
            "-Ddatadog.slf4j.simpleLogger.defaultLogLevel=debug",
            "-Dorg.slf4j.simpleLogger.defaultLogLevel=debug",
            "-XX:+IgnoreUnrecognizedVMOptions",
            "-XX:+UnlockCommercialFeatures",
            "-XX:+FlightRecorder",
            "-Ddd." + ProfilingConfig.PROFILING_TEMPLATE_OVERRIDE_FILE + "=" + templateOverride,
            "-Ddd.jmxfetch.start-delay=" + jmxFetchDelaySecs,
            "-jar",
            profilingShadowJar(),
            Integer.toString(exitDelay));
    final ProcessBuilder processBuilder = new ProcessBuilder(command);
    processBuilder.directory(new File(buildDirectory()));

    processBuilder.environment().put("JAVA_HOME", System.getProperty("java.home"));
    processBuilder.environment().put("DD_API_KEY", apiKey);

    processBuilder.redirectErrorStream(true);
    processBuilder.redirectOutput(ProcessBuilder.Redirect.to(logFilePath.toFile()));
    return processBuilder;
  }

  private static String javaPath() {
    final String separator = System.getProperty("file.separator");
    return System.getProperty("java.home") + separator + "bin" + separator + "java";
  }

  private static String buildDirectory() {
    return System.getProperty("datadog.smoketest.builddir");
  }

  private static String agentShadowJar() {
    return System.getProperty("datadog.smoketest.agent.shadowJar.path");
  }

  private static String profilingShadowJar() {
    return System.getProperty("datadog.smoketest.profiling.shadowJar.path");
  }

  private static boolean checkLogLines(final Path logFilePath, final Predicate<String> checker)
      throws IOException {
    return Files.lines(logFilePath).anyMatch(checker);
  }

  private static boolean logHasErrors(final Path logFilePath) throws IOException {
    final boolean[] logHasErrors = new boolean[] {false};
    Files.lines(logFilePath)
        .forEach(
            it -> {
              if (it.contains("ERROR") || it.contains("ASSERTION FAILED")) {
                System.out.println(it);
                logHasErrors[0] = true;
              }
            });
    if (logHasErrors[0]) {
      System.out.println(
          "Test application log is containing errors. See full run logs in " + logFilePath);
    }
    return logHasErrors[0];
  }
}
