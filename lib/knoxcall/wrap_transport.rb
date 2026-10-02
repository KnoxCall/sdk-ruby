require "uri"

module KnoxCall
  # Pure, transport-agnostic helpers behind the Ruby wrap transport
  # ({KnoxCall::Resources::Wrap#faraday_connection}) — the analogue of the Node
  # SDK's +src/wrap-transport.ts+. Deliberately free of any Faraday dependency
  # so they load with the base SDK and stay unit-testable without the optional
  # gem.
  #
  # A wrapped third-party SDK keeps its own serialization, retries, idempotency
  # keys and error types; only its HTTP transport is swapped for one that
  # re-targets each request through KnoxCall's ephemeral proxy in transparent
  # mode. The provider credential the SDK sets on its +Authorization+ header is
  # LIFTED out-of-band (transit mode, the default) or replaced by a named
  # escrowed credential (escrow mode) — the raw key never forwards as a header
  # and is never logged.
  module WrapTransport
    module_function

    # Built-in route-around defaults. Mirrors the SERVER's raw-PAN refusal
    # (src/client-api/ephemeral-proxy.ts PAN_ENDPOINT_DENYLIST) so a wrapped
    # SDK's raw-card call is sent straight to the provider instead of
    # hard-failing on the server-side 403. Deliberately conservative and
    # identical in spirit to the Node DEFAULT_ROUTE_AROUND.
    DEFAULT_ROUTE_AROUND = [
      { host: "api.stripe.com", path_prefix: "/v1/tokens",
        reason: "raw-card endpoint (PCI): sent direct to the provider" },
      { host: "api.stripe.com", path_prefix: "/v1/sources",
        reason: "raw-card endpoint (PCI): sent direct to the provider" }
    ].freeze

    # Upstream headers the shim must NOT forward through ephemeral(): the
    # provider Authorization is lifted out-of-band; Host/Content-Length are
    # recomputed by the transport.
    DROP_FORWARDED = %w[authorization host content-length].freeze

    # Read a rule value tolerating both symbol and string keys, so a
    # caller-supplied Hash reads naturally either way.
    def rule_value(rule, key)
      return nil unless rule.is_a?(Hash)

      rule.key?(key) ? rule[key] : rule[key.to_s]
    end

    # PARITY §21's host contract: lower-case, surrounding whitespace and IPv6
    # brackets stripped, a single trailing dot stripped — so a trailing-dot
    # FQDN ("api.stripe.com.") can't dodge an exact-match rule. The server's
    # PAN denylist and the intercept manifest normalize the same way.
    def normalize_host(host)
      host.to_s.strip.downcase.delete_prefix("[").delete_suffix("]").sub(/\.\z/, "")
    end

    # The first route-around rule matching this URL, or +nil+. A trailing-dot
    # FQDN ("api.stripe.com.") resolves to the same host but would dodge an
    # exact-match rule — both sides are normalized, matching the server's PAN
    # denylist and the Node wrapper.
    def match_route_around(url, rules)
      u = begin
        URI.parse(url)
      rescue URI::InvalidURIError
        return nil
      end
      host = normalize_host(u.host)
      return nil if host.empty?

      Array(rules).each do |r|
        next if host != normalize_host(rule_value(r, :host))

        prefix = rule_value(r, :path_prefix)
        next if prefix && !u.path.to_s.start_with?(prefix.to_s)

        return r
      end
      nil
    end

    # Validate caller-supplied route-around rules: a +host+ that isn't a bare
    # DNS hostname (a scheme/port/path slipped in) can never match a parsed URL
    # host and would silently disable the rule — fail loud instead. Mirrors the
    # Node assertRouteAroundRules and the escrow allowed-hosts contract.
    def assert_route_around_rules(rules)
      Array(rules).each do |r|
        h = rule_value(r, :host).to_s.strip
        parsed = begin
          URI.parse("https://#{h}").host.to_s
        rescue URI::InvalidURIError
          ""
        end
        next unless h.empty? || normalize_host(parsed) != normalize_host(h)

        raise WrapSandboxMismatchError,
              "invalid route_around host #{rule_value(r, :host).inspect}: " \
              "expected a bare DNS hostname (no scheme, port, or path)."
      end
    end

    # Both-must-agree (PARITY §18): a Stripe +sk_+/+rk_+ key's Test/Live prefix
    # must match the client's sandbox flag, so a test key can never be wrapped
    # by a live client (or vice versa). Publishable +pk_+ keys are rejected
    # outright — they are not server credentials. Non-Stripe schemes we cannot
    # classify are left alone. +authorization_value+ is the full header value,
    # e.g. "Bearer sk_live_…".
    def assert_key_matches_sandbox(authorization_value, sandbox)
      return if authorization_value.nil? || authorization_value.to_s.empty?

      sandbox = sandbox ? true : false
      # Trim BEFORE stripping the scheme: a leading space would otherwise stop
      # the anchored Bearer from matching, leaving the whole value in +token+
      # and silently skipping the check (Node review regression #1).
      token = authorization_value.to_s.strip.sub(/\ABearer\s+/i, "").strip
      if token.match?(/\Apk_(?:test|live)_/)
        raise WrapSandboxMismatchError,
              "A Stripe publishable key (pk_…) is not a server credential and cannot be wrapped. " \
              "Use a secret (sk_…) or restricted (rk_…) key."
      end

      m = /\A(?:sk|rk)_(test|live)_/.match(token)
      return unless m # unknown / non-Stripe scheme — nothing to assert

      key_is_test = m[1] == "test"
      return if key_is_test == sandbox

      raise WrapSandboxMismatchError,
            "Provider key is a #{key_is_test ? 'TEST' : 'LIVE'} key but the KnoxCall client was " \
            "constructed with sandbox=#{sandbox}. Test keys require sandbox:true, live keys require " \
            "sandbox:false — construct a matching client."
    end

    # The upstream headers to forward (everything the SDK set except the dropped
    # ones), keyed as the SDK supplied them.
    def forwardable_headers(headers)
      out = {}
      headers.each do |k, v|
        out[k] = v unless DROP_FORWARDED.include?(k.to_s.downcase)
      end
      out
    end
  end
end
