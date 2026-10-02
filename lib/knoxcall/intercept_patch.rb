require "net/http"
require "knoxcall/errors"
require "knoxcall/intercept_pipeline"

module KnoxCall
  # What {Resources::Wrap#intercept!} returns: the route-aware controls plus
  # +uninstall+.
  class InterceptHandle
    attr_reader :pipeline

    def initialize(pipeline)
      @pipeline = pipeline
      @active = true
    end

    def active? = @active

    # Stop intercepting and drop the manifest. Ruby cannot un-prepend a module,
    # so the seam stays on +Net::HTTP+ but calls +super+ immediately once no
    # handle is active — every request goes exactly where it did before.
    # Idempotent.
    def uninstall
      return unless @active

      @active = false
      @pipeline.stop
      Intercept.clear(self)
      nil
    end
    alias stop uninstall

    def manifest = @pipeline.manifest
    def ready = @pipeline.ready
    def refresh = @pipeline.refresh
  end

  # The opt-in, EXPERIMENTAL process-wide seam (founder decision D7,
  # 2026-09-25): a module prepended onto +Net::HTTP+ so that +Net::HTTP#request+
  # — the one method every Net::HTTP verb, +Net::HTTP.get+, Faraday's default
  # adapter, +rest-client+ and +httparty+ funnel through — consults the
  # route-aware pipeline first. Not reached: Typhoeus / Curb / +http.rb+ (their
  # own socket layer). One handle per process.
  #
  # This is a convenience, not a security boundary: it is a process global, it
  # composes with other Net::HTTP patchers (WebMock, VCR, APM agents) in
  # install order, and a request made while a handle is active is decided by
  # the same table as every other seam. Route mode is the custody path — the
  # key never enters your process.
  module Intercept
    @mutex = Mutex.new
    @installed = nil
    @prepended_on = nil

    class << self
      # The active handle, or nil.
      def installed
        @mutex.synchronize { @installed }
      end

      # Prepend the seam (once per +Net::HTTP+ class — the constant is re-read
      # so a class swapped in later, WebMock-style, is covered) and activate the
      # handle. A second install while one is active is refused.
      def install(pipeline)
        @mutex.synchronize do
          raise Error, "wrap.intercept! is already installed in this process; uninstall the existing handle first" if @installed

          target = ::Net::HTTP
          unless @prepended_on.equal?(target)
            target.prepend(NetHTTPRequest)
            @prepended_on = target
          end
          @installed = InterceptHandle.new(pipeline)
        end
      end

      def clear(handle)
        @mutex.synchronize { @installed = nil if @installed.equal?(handle) }
      end

      # The full URL a +Net::HTTP+ instance + request pair addresses.
      def url_for(http, req)
        "#{origin_for(http)}#{req.path}"
      end

      # The origin a +Net::HTTP+ instance connects to, as a URL with no path
      # (+http://host:port+) — what the seam can decide on BEFORE a request
      # exists, at connect time.
      def origin_for(http)
        ssl = http.use_ssl?
        scheme = ssl ? "https" : "http"
        host = http.address.to_s
        host = "[#{host}]" if host.include?(":") && !host.start_with?("[")
        default = ssl ? 443 : 80
        authority = http.port == default ? host : "#{host}:#{http.port}"
        "#{scheme}://#{authority}"
      end
    end

    # The prepended seam. +request+ is where every Net::HTTP call lands —
    # but +Net::HTTP+ CONNECTS in +start+, before +request+ ever runs, so a
    # request the seam is about to reroute would still open a TCP (and TLS)
    # connection to the real upstream first, and fail outright when that host
    # is unreachable from the process. Measured by the CI smoke (#1000): the
    # echo lives on the runner's loopback, the container's loopback refuses,
    # and +Net::HTTP.get_response+ died in +connect+ before KnoxCall was ever
    # asked. So +connect+ is part of the seam too: a host the decision table
    # would reroute defers its connection, and a request that ends up direct
    # — unlisted, route-around, the kill switch, or the +unavailable: :direct+
    # fallback — connects at that moment instead.
    module NetHTTPRequest
      def connect
        handle = Intercept.installed
        if !@knoxcall_connect_now && handle && handle.active? && !InterceptContext.suppressed? &&
           !handle.pipeline.decide("#{Intercept.origin_for(self)}/", "GET").direct?
          @knoxcall_connect_deferred = true
          return
        end
        super
      end
      private :connect

      def request(req, body = nil, &block)
        handle = Intercept.installed
        if handle.nil? || !handle.active? || InterceptContext.suppressed?
          knoxcall_connect_if_deferred
          return super
        end

        url = Intercept.url_for(self, req)
        decision = handle.pipeline.decide(url, req.method)
        if decision.direct?
          direct_headers = {}
          req.each_header { |k, v| direct_headers[k] = v }
          handle.pipeline.direct_decided(decision, url, method: req.method, headers: direct_headers)
          knoxcall_connect_if_deferred
          return super
        end

        # The body is held in memory (Net::HTTP's own requirement for a resend
        # too), so a resend after a routing refusal is replayable.
        stream = req.body_stream
        payload = body || req.body || stream&.read
        headers = {}
        req.each_header { |k, v| headers[k] = v }

        resp = handle.pipeline.send(decision, url: url, method: req.method, headers: headers, body: payload)
        if resp == InterceptPipeline::DIRECT
          # Perform the ORIGINAL request ourselves — connecting now, since the
          # connection was deferred for this host. A consumed body stream is
          # replaced by its bytes so Net::HTTP can send them.
          knoxcall_connect_if_deferred
          if stream
            req.body_stream = nil
            req.body = payload
            return super(req, nil, &block)
          end
          return super(req, body, &block)
        end

        yield resp if block_given?
        resp
      end

      private

      # Establish the connection +connect+ deferred, through the real
      # +Net::HTTP#connect+, exactly once.
      def knoxcall_connect_if_deferred
        return unless @knoxcall_connect_deferred

        @knoxcall_connect_deferred = false
        @knoxcall_connect_now = true
        begin
          connect
        ensure
          @knoxcall_connect_now = false
        end
      end
    end
  end
end
