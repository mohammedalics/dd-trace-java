import datadog.trace.agent.test.base.HttpServerTest
import groovy.servlet.AbstractHttpServlet

import javax.servlet.AsyncEvent
import javax.servlet.AsyncListener
import javax.servlet.annotation.WebServlet
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.util.concurrent.Phaser

import static datadog.trace.agent.test.base.HttpServerTest.ServerEndpoint.CUSTOM_EXCEPTION
import static datadog.trace.agent.test.base.HttpServerTest.ServerEndpoint.ERROR
import static datadog.trace.agent.test.base.HttpServerTest.ServerEndpoint.EXCEPTION
import static datadog.trace.agent.test.base.HttpServerTest.ServerEndpoint.FORWARDED
import static datadog.trace.agent.test.base.HttpServerTest.ServerEndpoint.QUERY_ENCODED_BOTH
import static datadog.trace.agent.test.base.HttpServerTest.ServerEndpoint.QUERY_ENCODED_QUERY
import static datadog.trace.agent.test.base.HttpServerTest.ServerEndpoint.QUERY_PARAM
import static datadog.trace.agent.test.base.HttpServerTest.ServerEndpoint.REDIRECT
import static datadog.trace.agent.test.base.HttpServerTest.ServerEndpoint.SUCCESS
import static datadog.trace.agent.test.base.HttpServerTest.ServerEndpoint.CREATED
import static datadog.trace.agent.test.base.HttpServerTest.ServerEndpoint.TIMEOUT
import static datadog.trace.agent.test.base.HttpServerTest.ServerEndpoint.TIMEOUT_ERROR

class TestServlet3 {

  public static final long SERVLET_TIMEOUT = 1000

  static HttpServerTest.ServerEndpoint getEndpoint(HttpServletRequest req) {
    // Most correct would be to get the dispatched path from the request
    // This is not part of the spec varies by implementation so the simplest is just removing
    // "/dispatch"
    String truePath = req.servletPath.replace("/dispatch", "")
    return HttpServerTest.ServerEndpoint.forPath(truePath)
  }

  @WebServlet
  static class Sync extends AbstractHttpServlet {
    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) {
      HttpServerTest.ServerEndpoint endpoint = getEndpoint(req)
      HttpServerTest.controller(endpoint) {
        resp.contentType = "text/plain"
        switch (endpoint) {
          case SUCCESS:
            resp.status = endpoint.status
            resp.writer.print(endpoint.body)
            break
          case CREATED:
            resp.status = endpoint.status
            resp.writer.print("${endpoint.body}: ${req.reader.text}")
            break
          case FORWARDED:
            resp.status = endpoint.status
            resp.writer.print(req.getHeader("x-forwarded-for"))
            break
          case QUERY_ENCODED_BOTH:
          case QUERY_ENCODED_QUERY:
          case QUERY_PARAM:
            resp.status = endpoint.status
            resp.writer.print(endpoint.bodyForQuery(req.queryString))
            break
          case REDIRECT:
            resp.sendRedirect(endpoint.body)
            break
          case ERROR:
            resp.sendError(endpoint.status, endpoint.body)
            break
          case EXCEPTION:
            throw new Exception(endpoint.body)
          case CUSTOM_EXCEPTION:
            throw new InputMismatchException(endpoint.body)
        }
      }
    }
  }

  @WebServlet(asyncSupported = true)
  static class Async extends AbstractHttpServlet {
    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) {
      HttpServerTest.ServerEndpoint endpoint = getEndpoint(req)
      def phaser = new Phaser(2)
      def context = req.startAsync()
      context.setTimeout(SERVLET_TIMEOUT)
      if (resp.class.name.startsWith("org.eclipse.jetty")) {
        // this line makes Jetty behave like Tomcat and immediately return 500 to the client
        // otherwise it will continue to repeat the same request until the client times out
        context.addListener(new AsyncListener() {
            void onComplete(AsyncEvent event) throws IOException {}

            void onError(AsyncEvent event) throws IOException {}

            void onStartAsync(AsyncEvent event) throws IOException {}

            @Override
            void onTimeout(AsyncEvent event) throws IOException {
              event.suppliedResponse.status = 500
              event.asyncContext.complete()
            }
          })
      }
      context.start {
        try {
          phaser.arrive()
          HttpServerTest.controller(endpoint) {
            resp.contentType = "text/plain"
            switch (endpoint) {
              case SUCCESS:
                resp.status = endpoint.status
                resp.writer.print(endpoint.body)
                context.complete()
                break
              case CREATED:
                resp.status = endpoint.status
                resp.writer.print("${endpoint.body}: ${req.reader.text}")
                break
              case FORWARDED:
                resp.status = endpoint.status
                resp.writer.print(req.getHeader("x-forwarded-for"))
                context.complete()
                break
              case QUERY_ENCODED_BOTH:
              case QUERY_ENCODED_QUERY:
              case QUERY_PARAM:
                resp.status = endpoint.status
                resp.writer.print(endpoint.bodyForQuery(req.queryString))
                context.complete()
                break
              case REDIRECT:
                resp.sendRedirect(endpoint.body)
                context.complete()
                break
              case ERROR:
                resp.sendError(endpoint.status, endpoint.body)
                context.complete()
                break
              case EXCEPTION:
                throw new Exception(endpoint.body)
              case CUSTOM_EXCEPTION:
                throw new InputMismatchException(endpoint.body)
              case TIMEOUT:
              case TIMEOUT_ERROR:
                sleep context.getTimeout() + 10
                break
            }
          }
        } finally {
          phaser.arriveAndDeregister()
        }
      }
      phaser.arriveAndAwaitAdvance()
      phaser.arriveAndAwaitAdvance()
    }
  }

  @WebServlet(asyncSupported = true)
  static class FakeAsync extends AbstractHttpServlet {
    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) {
      def context = req.startAsync()
      try {
        HttpServerTest.ServerEndpoint endpoint = getEndpoint(req)
        HttpServerTest.controller(endpoint) {
          resp.contentType = "text/plain"
          switch (endpoint) {
            case SUCCESS:
              resp.status = endpoint.status
              resp.writer.print(endpoint.body)
              break
            case CREATED:
              resp.status = endpoint.status
              resp.writer.print("${endpoint.body}: ${req.reader.text}")
              break
            case FORWARDED:
              resp.status = endpoint.status
              resp.writer.print(req.getHeader("x-forwarded-for"))
              break
            case QUERY_ENCODED_BOTH:
            case QUERY_ENCODED_QUERY:
            case QUERY_PARAM:
              resp.status = endpoint.status
              resp.writer.print(endpoint.bodyForQuery(req.queryString))
              break
            case REDIRECT:
              resp.sendRedirect(endpoint.body)
              break
            case ERROR:
              resp.sendError(endpoint.status, endpoint.body)
              break
            case EXCEPTION:
              throw new Exception(endpoint.body)
            case CUSTOM_EXCEPTION:
              throw new InputMismatchException(endpoint.body)
          }
        }
      } finally {
        context.complete()
      }
    }
  }

  @WebServlet(asyncSupported = true)
  static class DispatchImmediate extends AbstractHttpServlet {
    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) {
      def target = req.servletPath.replace("/dispatch", "")
      req.startAsync().dispatch(target)
    }
  }

  @WebServlet(asyncSupported = true)
  static class DispatchAsync extends AbstractHttpServlet {
    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) {
      def target = req.servletPath.replace("/dispatch", "")
      def context = req.startAsync()
      context.start {
        context.dispatch(target)
      }
    }
  }

  // TODO: Add tests for this!
  @WebServlet(asyncSupported = true)
  static class DispatchRecursive extends AbstractHttpServlet {
    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) {
      if (req.servletPath.equals("/recursive")) {
        resp.writer.print("Hello Recursive")
        return
      }
      def depth = Integer.parseInt(req.getParameter("depth"))
      if (depth > 0) {
        req.startAsync().dispatch("/dispatch/recursive?depth=" + (depth - 1))
      } else {
        req.startAsync().dispatch("/recursive")
      }
    }
  }
}
