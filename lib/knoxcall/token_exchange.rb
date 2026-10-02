require "net/http"
require "uri"
require "json"
require "openssl"

require "knoxcall/warnings"

module KnoxCall
  # The only grant_type POST /v1/oauth/token accepts.
  TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange".freeze
  # The only subject_token_type it accepts.
  ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token".freeze
  # The default (and only supported) audience.
  KNOXCALL_AUDIENCE = "knoxcall:gateway".freeze

  # Exchange a CI OIDC token for a short-lived AI-gateway capability token
  # (RFC 8693 token exchange, AIGW-26).
  #
  #   res = KnoxCall.exchange_token(subject_token: ci_id_token, tenant: "acme")
  #   # res["access_token"] is an agent-kind token for POST /v1/ai/...
  #
  # Like KnoxCall.signup this is a module-level function and NOT a method on a
  # constructed client, and for a stronger reason: the whole point is that CI
  # holds no KnoxCall credential. Constructing a client to reach this endpoint
  # would require the very secret the flow exists to remove — so NO
  # Authorization header is sent. The subject_token IS the credential, verified
  # against the issuer's published JWKS.
  #
  # Pass +resource+ — the +resource+ field of an MCP server's create/get
  # response — to narrow the minted token to +tool+ kind, confined to exactly
  # that one <tt>/v1/mcp/<slug></tt> and refused on <tt>/v1/ai</tt>. Leave it
  # +nil+ (the default) for an +agent+-kind token: an EMPTY STRING is sent
  # through and refused +invalid_target+, because dropping it silently would
  # mint an UNCONFINED token while the caller believes it is
  # audience-restricted.
  #
  # THE HOST MATTERS, and getting it wrong looks like a credential failure.
  # <tt>/v1/oauth/token</tt> is part of the DATA plane: +src/server.ts+ hands
  # <tt>/v1/ai/</tt>, <tt>/v1/mcp/</tt> and <tt>/v1/oauth/</tt> to the proxy
  # router only when the request lands on a tenant data-plane host
  # (<tt>{slug}.knoxcall.com</tt>, <tt>sandbox-{slug}...</tt>). Verified against a
  # running server on 2026-08-25: the same request answers 400 +invalid_grant+ on
  # +acme.knoxcall.com+ and *401* on +api.knoxcall.com+ - a caller who points this
  # at the management host reads that 401 as "my CI token was rejected" when the
  # endpoint is simply not served there. So +tenant+ (or an explicit +base_url+)
  # is REQUIRED: there is no safe default to guess.
  #
  # NOT the tenant OAuth 2.1 token endpoint at
  # <tt>https://api.knoxcall.com/oauth/token</tt> (root host, no +/v1+), which
  # mints +kc_+ MANAGEMENT tokens from +client_credentials+ and friends.
  #
  # Returns the RFC 8693 §2.2.1 body — +access_token+, +issued_token_type+,
  # +token_type+, +expires_in+, +scope+. A BARE OAuth body, not the
  # <tt>{data, meta}</tt> envelope the rest of /v1 returns.
  #
  # @param subject_token [String] the workload's OIDC id_token, JWS-compact
  # @param resource [String, nil] RFC 8707 resource indicator; nil to omit
  # @param audience [String] defaults to KNOXCALL_AUDIENCE
  # @param tenant [String, nil] tenant slug; becomes https://{tenant}.knoxcall.com
  # @param sandbox [Boolean] use https://sandbox-{tenant}.knoxcall.com
  # @param base_url [String, nil] full data-plane origin; wins over +tenant+
  # @param timeout [Numeric] open/read timeout in seconds (default 30)
  # @return [Hash] the RFC 8693 response body
  # @raise [TokenExchangeError] on any refusal — carries +status_code+ and
  #   +error_type+ (the RFC 6749 §5.2 code)
  # @raise [ArgumentError] when neither +tenant+ nor +base_url+ is given, or the
  #   tenant slug is not a DNS label
  # @raise [NetworkError, ConnectionTimeoutError] on transport failure
  def self.exchange_token(subject_token:, resource: nil, audience: KNOXCALL_AUDIENCE,
                          tenant: nil, sandbox: false, base_url: nil, timeout: 30)
    origin = exchange_base_url(tenant, sandbox, base_url)
    # the request carries the workload OIDC id_token, which IS a credential -- the
    # whole point of the flow. PARITY 15 already warns when a CLIENT is constructed
    # against plaintext http to a non-loopback host, and this function deliberately
    # constructs no client, so without this the control exists on one path and is
    # simply absent on the parallel one. A warning rather than a refusal because the
    # acceptance harness and local dev legitimately use http://127.0.0.1.
    if Warnings.insecure_remote_url?(origin)
      Warnings.warn_once(
        "KNOXCALL_INSECURE_TRANSPORT",
        "KnoxCall: exchanging a workload OIDC token over plaintext HTTP to #{origin} - the " \
        "subject token is a credential and is readable on the wire. Use https://."
      )
    end
    uri = URI.parse(origin + "/v1/oauth/token")
    payload = {
      "grant_type" => TOKEN_EXCHANGE_GRANT,
      "subject_token" => subject_token,
      "subject_token_type" => ID_TOKEN_TYPE,
      "audience" => audience
    }
    payload["resource"] = resource unless resource.nil?

    req = Net::HTTP::Post.new(uri)
    req["Content-Type"] = "application/json"
    req["Accept"] = "application/json"
    req["User-Agent"] = SDK_VERSION
    req.body = JSON.generate(payload)

    resp = begin
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = timeout
      http.read_timeout = timeout
      http.start { |h| h.request(req) }
    rescue Net::OpenTimeout, Net::ReadTimeout => e
      raise ConnectionTimeoutError, "token exchange timed out: #{e.message}"
    rescue OpenSSL::SSL::SSLError, EOFError, SocketError, SystemCallError, IOError => e
      raise NetworkError, "token exchange failed: #{e.class}: #{e.message}"
    end

    # A non-JSON error page (a proxy 502) parses to nil and falls through to
    # the status check rather than masking the status.
    parsed = begin
      JSON.parse(resp.body.to_s)
    rescue JSON::ParserError
      nil
    end
    status = resp.code.to_i
    token = parsed.is_a?(Hash) && parsed["access_token"].is_a?(String) ? parsed["access_token"] : nil

    if status >= 400 || token.nil? || token.empty?
      # AIGW-163: this endpoint is on the TENANT DATA PLANE, so when the AI
      # gateway has failed to boot it is answered by the plane's 503 sentinel —
      # the data-plane envelope with code "ai_gateway_unavailable" and a
      # Retry-After — not by an RFC 6749 error. Typing it means a CI job is told
      # to wait rather than handed a generic exchange failure. The discriminator
      # is exact: an RFC 6749 body carries no `code` at all.
      ai_err = KnoxCall.ai_gateway_error_from(status, parsed, resp)
      raise ai_err if ai_err

      code = parsed.is_a?(Hash) && parsed["error"].is_a?(String) ? parsed["error"] : "token_exchange_failed"
      message = if parsed.is_a?(Hash) && parsed["error_description"].is_a?(String)
                  parsed["error_description"]
                else
                  "Token exchange failed with status #{status}"
                end
      raise TokenExchangeError.new(message, status_code: status, error_type: code, body: parsed)
    end
    parsed
  end

  # A tenant slug becomes a hostname, so it must be a bare DNS label: a slug
  # adopted from config or an environment variable that is not one
  # ("evil.com#") would send the workload OIDC token to an attacker host.
  TENANT_SLUG_RE = /\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/i.freeze

  # The data-plane origin for {exchange_token}. There is no default.
  def self.exchange_base_url(tenant, sandbox, base_url)
    return base_url.chomp("/") if base_url && !base_url.empty?

    if tenant.nil? || tenant.empty?
      raise ArgumentError,
            "exchange_token needs a tenant slug or a base_url: POST /v1/oauth/token is " \
            "served only on the tenant data-plane host " \
            "(https://{tenant}.knoxcall.com). Pointing it at api.knoxcall.com answers " \
            "401, which reads like a rejected subject_token but means the endpoint is " \
            "not there."
    end
    unless TENANT_SLUG_RE.match?(tenant)
      raise ArgumentError,
            "invalid tenant slug #{tenant.inspect} - expected a DNS label; refusing to " \
            "send a subject token to a host derived from it"
    end

    host = sandbox ? "sandbox-#{tenant}" : tenant
    "https://#{host}.knoxcall.com"
  end
end
