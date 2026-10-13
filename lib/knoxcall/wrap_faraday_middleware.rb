require "faraday"
require "knoxcall/intercept_pipeline"

module KnoxCall
  module Resources
    class Wrap
      # A Faraday MIDDLEWARE (not an adapter) for stacks an SDK builds itself
      # and lets you add middleware to: insert it anywhere above the adapter
      # and a request the pipeline claims — a Route covers its host + path, or
      # the host is listed — is answered from KnoxCall without ever reaching
      # the SDK's own adapter; every other request continues down the stack
      # untouched. Built by {Wrap#faraday_middleware}:
      #
      #   conn = SomeSDK.connection                          # an SDK-built Faraday stack
      #   conn.builder.insert_before(Faraday::Adapter, *knox.wrap.faraday_middleware(hosts: ["api.resend.com"]))
      #
      # It shares {InterceptPipeline} with the adapter and the Net::HTTP seam,
      # so the decisions are identical.
      class FaradayMiddleware < Faraday::Middleware
        # @param app the next app in the stack
        # @param options [Hash] +pipeline:+ (an {InterceptPipeline}) or the
        #   keyword arguments to build one (+client:+ required)
        def initialize(app, options = {})
          super(app)
          @pipeline = options[:pipeline] || InterceptPipeline.new(**options.reject { |k, _| k == :pipeline })
        end

        def call(env)
          url = env.url.to_s
          method = env.method.to_s.upcase
          decision = @pipeline.decide(url, method)
          headers = {}
          env.request_headers.each { |k, v| headers[k] = v }
          if decision.direct?
            @pipeline.direct_decided(decision, url, method: method, headers: headers)
            return @app.call(env)
          end

          resp = @pipeline.send(decision, url: url, method: method, headers: headers, body: env.body)
          return @app.call(env) if resp == InterceptPipeline::DIRECT

          finish(env, resp)
        rescue KnoxCall::ConnectionTimeoutError => e
          raise Faraday::TimeoutError, e.message
        rescue KnoxCall::NetworkError => e
          raise Faraday::ConnectionFailed, e.message
        end

        private

        # Short-circuit the stack with the Net::HTTPResponse the pipeline
        # returned: the same completion an adapter performs.
        def finish(env, resp)
          headers = {}
          resp.each_header { |k, v| headers[k] = v }
          env.status = resp.code.to_i
          env.reason_phrase = resp.message.to_s.strip
          env.body = resp.body
          env.response_headers = Faraday::Utils::Headers.new.tap { |h| h.update(headers) }
          response = Faraday::Response.new
          env.response = response
          response.finish(env)
        end
      end
    end
  end
end
