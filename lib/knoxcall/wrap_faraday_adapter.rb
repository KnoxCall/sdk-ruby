require "faraday"
require "uri"
require "knoxcall/wrap_transport"
require "knoxcall/intercept_pipeline"

module KnoxCall
  module Resources
    class Wrap
      # A Faraday adapter that routes a wrapped third-party SDK's requests
      # through KnoxCall — the Ruby analogue of the Node SDK's +wrap.fetch()+.
      # It is the TERMINAL adapter in a Faraday connection: instead of
      # performing the HTTP call itself it hands each request to the shared
      # {InterceptPipeline}, which sends it through {KnoxCall::Client#call}
      # (route mode — the Route the intercept manifest names) or
      # {KnoxCall::Client#ephemeral} (transparent mode), the same way
      # {KnoxCall::BoundRoute} delegates to +call+ — no second HTTP stack.
      # Direct decisions (route-around, own hosts, the kill switch, a D4
      # fallback) perform the ORIGINAL request via a plain Faraday adapter.
      #
      # Built and wired by {KnoxCall::Resources::Wrap#faraday_connection}. For
      # SDKs that build their own stack see {Wrap#faraday_middleware}; for the
      # opt-in process-wide seam see {Wrap#intercept!}.
      #
      # This file references +Faraday+ constants at load time, so it is required
      # lazily (only once the +faraday+ gem is confirmed present) — the base SDK
      # never depends on Faraday.
      class FaradayAdapter < Faraday::Adapter
        # @param app the next app in the Faraday stack (the terminal endpoint)
        # @param options [Hash] a single positional options Hash:
        #   - +:pipeline+ [InterceptPipeline] the shared pipeline (built by faraday_connection), or
        #     the {InterceptPipeline#initialize} keywords to build one (+:client+ required)
        #   - +:direct_adapter+ the Faraday adapter used for direct calls (default Faraday.default_adapter)
        def initialize(app, options = {})
          super(app)
          @direct_adapter = options[:direct_adapter]
          @pipeline = options[:pipeline] ||
                      InterceptPipeline.new(all_hosts: true, **options.reject { |k, _| %i[pipeline direct_adapter].include?(k) })
          @mutex = Mutex.new
        end

        # The pipeline (ready / refresh / manifest / stop).
        attr_reader :pipeline

        def call(env)
          # Capture the request BEFORE super: super installs env.response,
          # after which some Faraday versions read env.body as the response body.
          url = env.url.to_s
          method = env.method.to_s.upcase
          body = env.body
          request_headers = env.request_headers
          headers = {}
          request_headers.each { |k, v| headers[k] = v }
          super

          decision = @pipeline.decide(url, method)
          if decision.direct?
            # Decided BEFORE sending — never "try KnoxCall then fall back",
            # which would already have transited. The ORIGINAL request is
            # forwarded untouched.
            @pipeline.direct_decided(decision, url, method: method, headers: headers)
            return direct_call(env, method, body, request_headers)
          end

          resp = @pipeline.send(decision, url: url, method: method, headers: headers, body: body)
          return direct_call(env, method, body, request_headers) if resp == InterceptPipeline::DIRECT

          finish(env, resp)
        rescue KnoxCall::ConnectionTimeoutError => e
          # Map KnoxCall transport failures onto Faraday's own error types so a
          # wrapped SDK's retry/rescue logic (which knows Faraday, not KnoxCall)
          # still fires.
          raise Faraday::TimeoutError, e.message
        rescue KnoxCall::NetworkError => e
          raise Faraday::ConnectionFailed, e.message
        end

        private

        # Convert the Net::HTTPResponse returned by ephemeral()/call() into a
        # Faraday response and hand control back up the stack.
        def finish(env, resp)
          headers = {}
          resp.each_header { |k, v| headers[k] = v }
          save_response(env, resp.code.to_i, resp.body, headers, resp.message)
          @app.call(env)
        end

        # Perform the ORIGINAL request against the real upstream, untouched,
        # via a plain Faraday adapter — never through KnoxCall.
        def direct_call(env, method, body, request_headers)
          conn = @mutex.synchronize { @direct_conn ||= build_direct_connection }
          resp = conn.run_request(method.downcase.to_sym, env.url, body, request_headers)
          # `headers`, not `response_headers` — the latter is a Faraday::Env
          # method, not a Faraday::Response one.
          save_response(env, resp.status, resp.body, resp.headers, resp.reason_phrase)
          @app.call(env)
        end

        def build_direct_connection
          spec = @direct_adapter || Faraday.default_adapter
          Faraday.new { |f| f.adapter(*Array(spec)) }
        end
      end
    end
  end
end

# Advanced use: reference the adapter by symbol in a hand-built Faraday stack
# (`f.adapter :knoxcall, pipeline: ...`). faraday_connection references the
# adapter CLASS directly, so this symbol registration is a convenience only.
begin
  Faraday::Adapter.register_middleware(knoxcall: KnoxCall::Resources::Wrap::FaradayAdapter)
rescue StandardError
  # best-effort: registration is purely for the `:knoxcall` shorthand; the
  # supported entrypoint (faraday_connection) uses the class directly, so a
  # register_middleware signature drift across Faraday versions must not break
  # the feature.
  nil
end
