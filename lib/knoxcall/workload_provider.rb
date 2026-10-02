require "digest"
require "knoxcall/errors"
require "knoxcall/token_exchange"
require "knoxcall/warnings"

module KnoxCall
  # Workload-identity credential provider — WIF plan Phase 4.3.
  #
  # Mirrors +auth/workload-provider.ts+ in the Node SDK; +sdk/PARITY.md+ is the
  # authoritative contract for every language.
  #
  # {KnoxCall.exchange_token} is one-shot: it trades one OIDC assertion for one
  # capability token and hands the caller an +expires_in+ to manage. That is
  # fine for a script that makes one call and exits, and wrong for anything
  # long-lived — a Sidekiq worker, a long CI job, an agent process — where the
  # token silently expires mid-run and the caller discovers it as a 401 they
  # then have to interpret.
  #
  # This provider owns that lifecycle: cache the token, refresh it before it
  # dies, and never hand out one that is about to expire.
  #
  # == The part that is not like other refresh loops
  #
  # A KnoxCall workload assertion is SINGLE-USE. The exchange spends the whole
  # assertion — the server claims a hash of it before minting (WIF Phase 1.2),
  # so presenting the same bytes twice is refused with "subject_token has
  # already been exchanged". A refresh therefore cannot re-send the assertion it
  # used last time; it needs a FRESH one from the platform every single time.
  #
  # That makes the obvious implementation — capture the assertion once, reuse it
  # on refresh — not merely suboptimal but broken, and broken in a way that only
  # shows up when the first refresh fires, i.e. minutes into production rather
  # than in anyone's smoke test. So the provider takes a SOURCE it calls before
  # every exchange, and refuses to send an assertion whose bytes it has already
  # spent ({StaleAssertionError}). It fails loudly at the real cause rather than
  # forwarding a doomed request and surfacing the server's replay refusal, which
  # reads as "my credentials were rejected".
  #
  # == The two-tier schedule
  #
  # ADVISORY (expiry − 120s): refresh opportunistically. If it fails, the token
  # in hand is still valid, so the caller is served and the failure is a
  # warning, not an exception. A transient blip near a refresh boundary must not
  # take down a worker that has two minutes of perfectly good credential left.
  #
  # MANDATORY (expiry − 30s): refresh or raise. Below this line the token may
  # die in flight — between the provider handing it over and the request
  # reaching the server — and a 401 from an expired capability token is exactly
  # the confusing failure this provider exists to prevent.
  #
  # The gap between the two tiers is the whole point: it buys 90 seconds in
  # which a failing token source or a flaky network is survivable rather than
  # fatal.
  #
  #   provider = KnoxCall::WorkloadCredentialProvider.new(
  #     assertion: -> { File.read(ENV.fetch("AWS_WEB_IDENTITY_TOKEN_FILE")) },
  #     tenant: "acme"
  #   )
  #   headers["Authorization"] = "Bearer #{provider.access_token}"
  #
  # Thread-safe: a Mutex gives single-flight semantics, which matters more here
  # than in an ordinary refresh loop — each exchange spends an assertion, and a
  # thundering herd would burn N of them and have N−1 refused.
  class WorkloadCredentialProvider
    # Refresh opportunistically below this much remaining life; failure is survivable.
    ADVISORY_REFRESH_SECONDS = 120

    # Refresh or raise below this much remaining life; the token may die in flight.
    MANDATORY_REFRESH_SECONDS = 30

    # @param assertion [#call] called before EVERY exchange; must return a FRESH
    #   assertion each time. On GitHub Actions a fetch of
    #   ACTIONS_ID_TOKEN_REQUEST_URL; on EKS a read of the projected token file.
    #   Returning a value captured once at startup is the failure this provider
    #   detects rather than tolerates.
    # @param resource [String, nil] RFC 8707 resource indicator. +nil+ means
    #   "not asked for"; an EMPTY string is sent through and refused
    #   invalid_target, because dropping it silently would mint an UNCONFINED
    #   token while the caller believes it is confined.
    # @param audience [String] defaults to KNOXCALL_AUDIENCE
    # @param tenant [String, nil] tenant slug — one of tenant or base_url is
    #   REQUIRED: +/v1/oauth/token+ is served only on the tenant data-plane host.
    # @param sandbox [Boolean] the Test data space. Carried through verbatim:
    #   dropping it would send a Test-mode workload's assertion to the Live
    #   host, where it matches no binding.
    # @param base_url [String, nil] full data-plane origin; wins over tenant
    # @param timeout [Integer] per-request timeout in seconds
    # @param clock [#call] test seam returning epoch seconds as a Float
    def initialize(assertion:, resource: nil, audience: KNOXCALL_AUDIENCE,
                   tenant: nil, sandbox: false, base_url: nil, timeout: 30,
                   clock: -> { Time.now.to_f })
      unless assertion.respond_to?(:call)
        raise ArgumentError, "WorkloadCredentialProvider needs an `assertion:` that responds to " \
                             "#call and returns the workload's CURRENT OIDC id_token. KnoxCall " \
                             "assertions are single-use, so it is called before every exchange."
      end
      # Fail at construction rather than at the first refresh, which may be
      # minutes into a long-running process.
      KnoxCall.exchange_base_url(tenant, sandbox, base_url)

      @assertion = assertion
      @resource = resource
      @audience = audience
      @tenant = tenant
      @sandbox = sandbox
      @base_url = base_url
      @timeout = timeout
      @clock = clock
      @mutex = Mutex.new
      @token = nil
      @expires_at = 0.0
      # SHA-256 of every assertion this provider has spent. Never the assertion.
      @spent = {}
    end

    # A capability token with more than MANDATORY_REFRESH_SECONDS of life left.
    #
    # @return [String] the capability token
    # @raise [StaleAssertionError] when the source returns spent or empty bytes
    # @raise [TokenExchangeError] on a refusal inside the mandatory window
    # @raise [NetworkError] on a transport failure inside the mandatory window
    def access_token
      @mutex.synchronize do
        remaining = @token ? @expires_at - @clock.call : -1.0

        return @token if @token && remaining > ADVISORY_REFRESH_SECONDS

        if @token && remaining > MANDATORY_REFRESH_SECONDS
          # ADVISORY tier: try, but the token in hand is still good.
          begin
            return refresh
          rescue StandardError => e
            # best-effort: the caller still has a valid credential, and raising
            # here would convert a survivable blip into an outage. The MANDATORY
            # tier raises for real if the condition persists.
            Warnings.warn_once(
              "KNOXCALL_WORKLOAD_ADVISORY_REFRESH",
              "KnoxCall: advisory token refresh failed (#{e.message}); continuing with the " \
              "current token, which expires in #{remaining.round}s"
            )
            return @token
          end
        end

        # MANDATORY tier, or nothing cached at all.
        refresh
      end
    end

    private

    # Exchange a fresh assertion. Called with @mutex held, which is what makes
    # the exchange single-flight.
    def refresh
      assertion = @assertion.call
      unless assertion.is_a?(String) && !assertion.empty?
        raise StaleAssertionError, "the workload assertion source returned nothing. It must " \
                                   "return the workload's current OIDC id_token on every call."
      end

      fingerprint = Digest::SHA256.hexdigest(assertion)
      if @spent.key?(fingerprint)
        raise StaleAssertionError,
              "the workload assertion source returned an assertion that has already been " \
              "exchanged. KnoxCall assertions are single-use, so each refresh needs a NEWLY " \
              "minted one — call the platform's token endpoint inside the source (for example " \
              "re-fetch ACTIONS_ID_TOKEN_REQUEST_URL, or re-read the projected service-account " \
              "token file) rather than capturing one value at startup."
      end

      res = KnoxCall.exchange_token(
        subject_token: assertion,
        resource: @resource,
        audience: @audience,
        tenant: @tenant,
        sandbox: @sandbox,
        base_url: @base_url,
        timeout: @timeout
      )

      # Recorded only after the exchange returns, so a network failure does not
      # burn a fingerprint the caller could legitimately retry with. The server
      # claims the assertion before it mints, so a SUCCESS is what makes those
      # bytes unusable.
      @spent[fingerprint] = true

      @token = res["access_token"]
      @expires_at = @clock.call + res["expires_in"].to_f
      @token
    end
  end
end
