require "knoxcall/errors"
require "knoxcall/warnings"

module KnoxCall
  # The SDK-side copy of the intercept manifest — fetched, held, refreshed
  # (route-aware-interception-plan.md §2.5; PARITY §21.1). One per transport /
  # interceptor; process memory only; dropped on +stop+.
  #
  # Ruby idiom (as Python): the manifest is refreshed LAZILY at the TTL — the
  # first request after +ttl_seconds+ pays one management call — rather than
  # by a background thread. Behaviourally the same contract ("hold the manifest
  # for ttl_seconds, then refresh"), and it works identically under Puma
  # threads, a forked Unicorn/Sidekiq worker and a plain script, with no
  # thread to own.
  #
  # - single-flight: concurrent refreshes share one fetch (a caller that waited
  #   on the mutex while another refreshed takes that answer);
  # - stale-but-valid: a failed refresh keeps the last GOOD manifest and backs
  #   off exponentially from the second consecutive failure (cap 8×TTL);
  # - a 401/403/404 from the manifest endpoint — the credential lacks
  #   routes:read, or an older server — is NOT a routing failure: the store
  #   warns once, behaves as "no manifest" (every listed host stays on the
  #   ephemeral path exactly as before this feature), and re-checks at 10×TTL;
  # - out-of-cycle refreshes (a route-mode refusal, a promoted-route hint, an
  #   explicit +refresh+) are rate-limited so a burst costs one call.
  #
  # Discovery failing open is deliberate and bounded: it can only leave a host
  # on the path it was on before the manifest existed. The DATA-PLANE hop is
  # where fail-closed lives (D4), and that is in the intercept pipeline.
  class InterceptManifestStore
    DEFAULT_TTL_SECONDS = 60
    MAX_BACKOFF_FACTOR = 8
    PERMISSION_RECHECK_FACTOR = 10
    MONOTONIC = -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }

    attr_reader :manifest, :version, :last_error
    # Seconds between out-of-cycle refreshes (a refusal, a hint, an explicit
    # refresh); a burst inside the gap costs one call.
    attr_accessor :min_refresh_gap

    # @param fetch [#call] performs GET /v1/wrap/intercept-manifest and returns the Hash.
    #   When it accepts an +if_none_match:+ keyword the store passes the version it
    #   holds on every poll after the first (+If-None-Match: W/"<version>"+ on the
    #   wire) and reads +nil+ as the server's 304: keep the manifest, restart the
    #   TTL clock, fire no +on_refresh+ (PARITY §21.1 "Conditional poll"). A
    #   zero-argument callable is accepted and simply polls unconditionally.
    # @param on_refresh [#call, nil] receives {reason:, version:, added:, removed:} after a change
    # @param on_error [#call, nil] receives the exception of a failed refresh
    # @param min_refresh_gap [Numeric] seconds between out-of-cycle refreshes
    # @param now [#call] the clock (monotonic seconds); a test seam
    def initialize(fetch, on_refresh: nil, on_error: nil, min_refresh_gap: 5.0, now: MONOTONIC)
      @fetch = fetch
      @fetch_conditional = self.class.accepts_if_none_match?(fetch)
      @on_refresh = on_refresh
      @on_error = on_error
      @min_refresh_gap = min_refresh_gap
      @now = now
      @manifest = nil
      @version = nil
      @expires_at = 0.0 # stale until the first refresh
      @last_refresh_at = -1e9
      @failures = 0
      @permission_denied = false
      @last_error = nil
      @stopped = false
      @seq = 0
      @mutex = Mutex.new
    end

    def permission_denied? = @permission_denied
    def stopped? = @stopped

    # Whether +fetch+ can take +if_none_match:+ (a keyword, or **rest). Decided
    # once at construction so a zero-argument test/user seam keeps working.
    def self.accepts_if_none_match?(fetch)
      return false unless fetch.respond_to?(:parameters)

      fetch.parameters.any? do |kind, name|
        (%i[key keyreq].include?(kind) && name == :if_none_match) || kind == :keyrest
      end
    end

    # Whether the next request should refresh before deciding.
    def stale?
      !@stopped && @now.call >= @expires_at
    end

    # A promoted-route hint arrived: make the NEXT request refresh (rate-limited).
    def hint
      @mutex.synchronize { @expires_at = @now.call if @now.call - @last_refresh_at >= @min_refresh_gap }
    end

    # Drop the manifest and refuse further refreshes.
    def stop
      @mutex.synchronize do
        @stopped = true
        @manifest = nil
        @version = nil
      end
    end

    # Refresh if stale (first load, TTL expiry, a hint), then return the manifest.
    def ensure
      refresh("ttl", force: true) if stale?
      @manifest
    end

    # Refresh now. Single-flight; rate-limited unless +force+. Returns the
    # manifest the store holds afterwards (nil after a permission refusal).
    # Never raises for a fetch failure — the store has already applied
    # stale-keep / backoff; read +last_error+.
    def refresh(reason, force: false)
      return nil if @stopped

      seq_before = @seq # bumped when an attempt COMPLETES
      @mutex.synchronize do
        return nil if @stopped
        # An attempt completed while we waited on the mutex: take its answer
        # (single-flight — the refresh we queued behind is the one we wanted).
        return @manifest if @seq != seq_before
        return @manifest if !force && @now.call - @last_refresh_at < @min_refresh_gap

        do_refresh(reason)
      end
    end

    private

    # Runs under @mutex. Hooks are invoked inside the lock deliberately kept
    # cheap; a hook must not call back into the store.
    def do_refresh(reason)
      @last_refresh_at = @now.call
      begin
        # Every poll after the first is conditional on the held version; the
        # server answers 304 (→ nil) when nothing changed, and that is a
        # success: keep the manifest, restart the TTL clock, fire no hook.
        nxt = @fetch_conditional && @version ? @fetch.call(if_none_match: @version) : @fetch.call
      rescue StandardError => e
        @seq += 1 # this attempt is over: a waiter that queued behind it takes its answer
        @last_error = e
        @on_error&.call(e)
        status = e.is_a?(APIError) ? e.status_code : nil
        if [401, 403, 404].include?(status)
          # Not a routing failure: the credential cannot read routes, or the
          # server predates the manifest. Every listed host stays ephemeral,
          # as it was before this feature existed. Warn once, re-check slowly.
          @permission_denied = true
          @manifest = nil
          @version = nil
          Warnings.warn_once(
            "KNOXCALL_INTERCEPT_MANIFEST_UNAVAILABLE",
            "KnoxCall intercept manifest unavailable (HTTP #{status}): route-aware interception is off " \
            "for this client — listed hosts use the ephemeral proxy. Grant the credential `routes:read` " \
            "(or upgrade the server) to enable it."
          )
          @expires_at = @now.call + DEFAULT_TTL_SECONDS * PERMISSION_RECHECK_FACTOR
        else
          # Transport or server fault: keep the last good manifest, back off
          # from the second consecutive failure.
          @failures = [@failures + 1, 30].min
          factor = [2**(@failures - 1), MAX_BACKOFF_FACTOR].min
          base = ttl_of(@manifest)
          @expires_at = @now.call + [base * factor, base * MAX_BACKOFF_FACTOR].min
        end
        return @manifest
      end

      @seq += 1
      prev = @manifest
      @failures = 0
      @permission_denied = false
      @last_error = nil
      if nxt.nil?
        # Not modified: the held manifest stands for another TTL.
        @expires_at = @now.call + ttl_of(prev)
        return @manifest
      end
      version = nxt["version"].to_s
      if prev.nil? || @version != version
        before = (prev ? prev["routes"] : []).to_h { |e| [entry_key(e), e] }
        after = (nxt["routes"] || []).to_h { |e| [entry_key(e), e] }
        added = after.reject { |k, _| before.key?(k) }.values
        removed = before.reject { |k, _| after.key?(k) }.values
        @manifest = nxt
        @version = version
        if @on_refresh && (!added.empty? || !removed.empty? || prev.nil?)
          @on_refresh.call(reason: reason, version: version, added: added, removed: removed)
        end
      end
      @expires_at = @now.call + ttl_of(nxt)
      @manifest
    end

    def ttl_of(manifest)
      ttl = manifest && manifest["ttl_seconds"]
      ttl.is_a?(Numeric) && ttl.positive? ? ttl.to_f : DEFAULT_TTL_SECONDS.to_f
    end

    def entry_key(e)
      [e["host"], e["base_path"], e["slug"]]
    end
  end
end
