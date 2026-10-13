require "uri"
require "time"
require "ipaddr"
require "knoxcall/errors"
require "knoxcall/warnings"
require "knoxcall/wrap_transport"

module KnoxCall
  # Uncovered-egress observations (PARITY §21.3; founder decisions 2026-09-26).
  # Ruby mirror of +sdk/knoxcall-node/src/egress-observations.ts+.
  #
  # A route-aware seam sees every outbound request the process makes and
  # sends only the covered ones through KnoxCall. The rest go direct — and
  # among them are calls that carry a credential the platform does not hold:
  # "uncovered egress". This module records those (host, first path segment,
  # method, credential header NAME) in memory and reports the aggregate to
  # +POST /v1/wrap/egress-observations+ ({Resources::Wrap#report_egress_observations}),
  # so the dashboard can show a tenant which credentials are still leaving
  # their process un-custodied.
  #
  # What is recorded is bounded on purpose, and the bound is the feature:
  # names, never values — the credential header's NAME, never its value; the
  # FIRST path segment only — never the query string, never the body, never a
  # deeper path; counts per (host, segment, method, header) with first/last
  # seen. Only a DIRECT decision with reason +:unlisted+ is observed —
  # +:own_host+, +:route_around+, +:kill_switch+, +:outside_context+ and
  # +:unparseable+ never are.
  #
  # Nothing here may add latency to, raise into, or alter the application's
  # request: {EgressObservationReporter#record} is synchronous and cheap, the
  # flush runs on a background thread (Ruby threads never keep a process
  # alive), and every failure is swallowed after one warning. The reporter is
  # process memory only.
  module EgressObservations
    # Exact (case-insensitive) header names that carry a credential. The
    # shared fixture +sdk/fixtures/egress-observation.json+ pins this list.
    CREDENTIAL_HEADER_ALLOWLIST = %w[
      authorization proxy-authorization x-api-key api-key apikey x-apikey x-auth-token x-access-token
      x-token token x-secret x-secret-key x-client-secret ocp-apim-subscription-key x-goog-api-key
      x-amz-security-token x-shopify-access-token klaviyo-api-key x-hubspot-api-key
    ].freeze

    # A lower-cased header name ending in one of these also counts.
    CREDENTIAL_HEADER_SUFFIXES = %w[-api-key -token -secret -auth].freeze

    RANK = CREDENTIAL_HEADER_ALLOWLIST.each_with_index.to_h.freeze

    # The methods the server accepts (upper-case); anything else is +invalid_method+.
    METHODS = %w[GET HEAD POST PUT PATCH DELETE OPTIONS CONNECT TRACE].freeze

    # The server's shape checks (src/wrap/egress-observations.ts).
    HEADER_NAME_RE = /\A[a-z0-9][a-z0-9_-]*\z/
    FIRST_SEGMENT_RE = %r{\A/[A-Za-z0-9._~!$&'()*+,;=:@%-]{0,255}\z}
    MAX_HEADER_NAME_LENGTH = 64

    # A credential in the first path segment (server #1022). Some APIs put one
    # in the path (Telegram's /bot<id>:<secret>/...). The server stores such a
    # segment as "/"; the SDK applies the SAME rule before sending.
    MAX_PLAIN_FIRST_SEGMENT_LENGTH = 64
    CREDENTIAL_SEGMENT_PREFIXES = [
      /\Abot\d+:/i,
      /\A(sk|pk|rk)_(live|test)_/i,
      /\Ask-/,
      /\Axox[abposr]-/,
      /\Agh[pousr]_/,
      /\Agithub_pat_/,
      /\Aglpat-/,
      /\Ashp(at|ca|pa|ss)_/,
      /\A(AKIA|ASIA)[0-9A-Z]{12,}/,
      /\AAIza[0-9A-Za-z_-]{20,}/,
      /\AeyJ[A-Za-z0-9_-]{8,}/,
      /\ASG\./
    ].freeze

    module_function

    # Whether a header NAME (any casing) is credential-bearing.
    def credential_header_name?(name)
      n = name.to_s.strip.downcase
      return false if n.empty? || n.length > MAX_HEADER_NAME_LENGTH || !HEADER_NAME_RE.match?(n)
      return true if RANK.key?(n)

      CREDENTIAL_HEADER_SUFFIXES.any? { |s| n.length > s.length && n.end_with?(s) }
    end

    # The credential header NAME to report for a request, or nil. Allowlist
    # entries win in allowlist order; then the lexicographically smallest
    # suffix match. A header whose value is empty after stripping never
    # counts. Only names are read — values are looked at solely to discard
    # empties and are never returned. +headers+ is a Hash (any casing; values
    # String or Array) or an Enumerable of +[name, value]+ pairs.
    def credential_header_name(headers)
      best = nil
      best_rank = CREDENTIAL_HEADER_ALLOWLIST.length + 1
      best_suffix = nil
      (headers || []).each do |raw_name, raw_value|
        name = raw_name.to_s.strip.downcase
        next if name.empty?
        next if Array(raw_value).all? { |v| v.to_s.strip.empty? }

        rank = RANK[name]
        if rank
          if rank < best_rank
            best_rank = rank
            best = name
          end
          next
        end
        next unless credential_header_name?(name)

        best_suffix = name if best_suffix.nil? || name < best_suffix
      end
      best || best_suffix
    end

    # Whether a first segment (+/+ + one segment) looks like it carries a
    # credential — the server's rule, on the raw and percent-decoded forms.
    def first_segment_looks_like_credential?(first_segment)
      raw = first_segment.to_s.delete_prefix("/")
      return false if raw.empty?

      decoded = raw.gsub(/%\h\h/) { |m| m[1..].hex.chr }.force_encoding(Encoding::UTF_8).scrub
      [raw, decoded].uniq.any? do |s|
        s.length > MAX_PLAIN_FIRST_SEGMENT_LENGTH ||
          CREDENTIAL_SEGMENT_PREFIXES.any? { |re| re.match?(s) } ||
          s.scan(/[A-Za-z0-9_-]{24,}/).any? { |run| [/[a-z]/, /[A-Z]/, /[0-9]/].count { |re| re.match?(run) } >= 2 }
      end
    end

    # +/+ or +/<first path segment>+ of the URL — never the query, never
    # deeper. Exactly one leading slash is consumed, so +//double+ reports +/+.
    def first_segment(url)
      path = begin
        URI.parse(url.to_s).path.to_s
      rescue URI::InvalidURIError
        ""
      end
      "/#{path.delete_prefix('/').split('/', 2).first}"
    end

    # The whole classifier, pure: the four identifying fields for this
    # request, or nil when it carries no credential-bearing header. The
    # caller has ALREADY decided the request is direct + +:unlisted+.
    def observation_for(url, method, headers)
      host = begin
        WrapTransport.normalize_host(URI.parse(url.to_s).host)
      rescue URI::InvalidURIError
        ""
      end
      return nil if host.nil? || host.empty? || ip_literal?(host) # the server drops it (ip_literal)

      upper = (method.to_s.empty? ? "GET" : method.to_s).upcase
      return nil unless METHODS.include?(upper)

      segment = first_segment(url)
      segment = "/" if first_segment_looks_like_credential?(segment) # reported as "/"; the entry is kept
      return nil unless FIRST_SEGMENT_RE.match?(segment)

      name = credential_header_name(headers)
      return nil if name.nil?

      { host: host, first_segment: segment, method: upper, header_name: name }
    end

    def ip_literal?(host)
      IPAddr.new(host)
      true
    rescue IPAddr::Error, ArgumentError
      false
    end

    # +KNOXCALL_OBSERVE_UNCOVERED=off|false|0+ turns the reporter off (read
    # when a pipeline is built).
    def disabled_by_env?
      %w[off 0 false].include?(ENV.fetch("KNOXCALL_OBSERVE_UNCOVERED", "").strip.downcase)
    end
  end

  # In-memory aggregation of uncovered-egress observations for ONE pipeline,
  # flushed in the background. Thread-safe; bounded; never raises.
  class EgressObservationReporter
    DEFAULT_FLUSH_INTERVAL = 60.0
    DEFAULT_FLUSH_AT_KEYS = 200
    DEFAULT_MAX_KEYS = 1_000
    DEFAULT_MAX_PER_REQUEST = 200

    # @param report [#call] performs +POST /v1/wrap/egress-observations+ with at most +max_per_request+ observations
    # @param on_flush [#call, nil] +{accepted:, dropped:}+ after each accepted report (never per observation)
    def initialize(report, on_flush: nil, flush_interval: DEFAULT_FLUSH_INTERVAL, flush_at_keys: DEFAULT_FLUSH_AT_KEYS,
                   max_keys: DEFAULT_MAX_KEYS, max_per_request: DEFAULT_MAX_PER_REQUEST, now: nil, rand: nil)
      @report = report
      @on_flush = on_flush
      @interval = flush_interval
      @flush_at = flush_at_keys
      @max_keys = max_keys
      @max_per = max_per_request
      @now = now || -> { Time.now.to_f }
      @rand = rand || -> { Kernel.rand }
      @mutex = Mutex.new
      @buffer = {}
      @timer = nil
      @flushing = false
      @stopped = false
      @forbidden = false
      @warned_overflow = false
      @warned_failed = false
    end

    # Distinct keys currently held.
    def size = @mutex.synchronize { @buffer.size }
    def stopped? = @stopped
    # True once the endpoint answered 403: reporting is off for the life of this reporter.
    def forbidden? = @forbidden

    # The observations that would be sent now (a copy, in first-seen order).
    def pending = @mutex.synchronize { @buffer.values.map { |e| wire(e) } }

    # Record one uncovered credentialed call. Synchronous, never raises.
    def record(obs)
      return if @stopped || @forbidden

      key = [obs[:host], obs[:first_segment], obs[:method], obs[:header_name]]
      at = @now.call
      flush_now = false
      arm = false
      warn_overflow = false
      @mutex.synchronize do
        hit = @buffer[key]
        if hit
          hit[:count] += 1
          hit[:last_seen] = at
          return
        end
        if @buffer.size >= @max_keys
          warn_overflow = !@warned_overflow
          @warned_overflow = true
        else
          @buffer[key] = { host: key[0], first_segment: key[1], method: key[2], header_name: key[3], count: 1,
                           first_seen: at, last_seen: at }
          if @buffer.size >= @flush_at
            flush_now = true
          else
            arm = @timer.nil?
          end
        end
      end
      if warn_overflow
        Warnings.warn_once("KNOXCALL_EGRESS_OBSERVATIONS_OVERFLOW",
                           "KnoxCall: more than #{@max_keys} distinct uncovered-egress observations are pending; " \
                           "new ones are dropped until the next flush.")
      end
      if flush_now
        Thread.new { flush }.tap { |t| t.name = "knoxcall-egress-observations" }
      elsif arm
        arm_timer
      end
      nil
    rescue StandardError
      # best-effort: telemetry must never reach the application's request.
      nil
    end

    # Send what is pending now, synchronously, inside the SDK's own suppressed
    # scope so the report is never itself intercepted. A concurrent flush
    # returns immediately. Never raises: a 403 ends reporting for good
    # (warned once); any other failure drops the batch (warned once) and is
    # never retried in a loop.
    def flush
      batch = nil
      @mutex.synchronize do
        return if @flushing || @forbidden || @buffer.empty?

        @flushing = true
        cancel_timer_locked
        batch = @buffer.values.map { |e| wire(e) }
        @buffer.clear
      end
      begin
        suppressed { deliver(batch) }
      ensure
        @mutex.synchronize { @flushing = false }
      end
      nil
    end

    # Stop the timer and flush once more. Idempotent.
    def stop
      return if @stopped

      @stopped = true
      @mutex.synchronize { cancel_timer_locked }
      flush
      nil
    end

    private

    def deliver(batch)
      batch.each_slice(@max_per) do |chunk|
        begin
          res = @report.call(chunk)
        rescue PermissionDeniedError
          # The key lacks routes:read: reporting is off for good. Anything
          # recorded from here on is dropped at the door.
          @forbidden = true
          @mutex.synchronize { @buffer.clear }
          Warnings.warn_once("KNOXCALL_EGRESS_OBSERVATIONS_FORBIDDEN",
                             "KnoxCall: the credential cannot report uncovered-egress observations (HTTP 403 — it " \
                             "lacks routes:read); reporting is off for this interceptor. Grant the scope, or pass " \
                             "observe_uncovered: false to silence this.")
          return
        rescue StandardError => e
          # best-effort: the batch is dropped, never retried in a loop, never
          # surfaced into the application's own request.
          unless @warned_failed
            @warned_failed = true
            Warnings.warn_once("KNOXCALL_EGRESS_OBSERVATIONS_FAILED",
                               "KnoxCall: reporting uncovered-egress observations failed (#{e.class}: #{e.message}); " \
                               "the batch was dropped.")
          end
          return
        end
        next unless @on_flush

        begin
          @on_flush.call(accepted: (res && (res["accepted"] || res[:accepted])).to_i,
                         dropped: (res && (res["dropped"] || res[:dropped])).to_i)
        rescue StandardError
          # A caller's hook must never break the reporter.
          nil
        end
      end
    end

    def suppressed(&block)
      if defined?(KnoxCall::InterceptContext)
        KnoxCall::InterceptContext.suppressed(&block)
      else
        yield
      end
    end

    def arm_timer
      delay = [0.001, @interval * (1 + (@rand.call * 0.2 - 0.1))].max # ±10 %
      @mutex.synchronize do
        return if @stopped || @timer

        @timer = Thread.new do
          sleep delay
          @mutex.synchronize { @timer = nil }
          flush
        rescue StandardError
          nil
        end
        @timer.name = "knoxcall-egress-observations-timer"
      end
    end

    def cancel_timer_locked
      t = @timer
      @timer = nil
      t&.kill unless t.equal?(Thread.current)
    end

    def wire(e)
      { host: e[:host], first_segment: e[:first_segment], method: e[:method], header_name: e[:header_name],
        count: e[:count], first_seen: iso(e[:first_seen]), last_seen: iso(e[:last_seen]) }
    end

    def iso(ts) = Time.at(ts).utc.strftime("%Y-%m-%dT%H:%M:%S.%LZ")
  end
end
