require "json"

module KnoxCall
  class Error < StandardError; end

  # Raised by credential auto-detection when NO usable credential is found —
  # no explicit creds (flat options or bootstrap:), no KNOXCALL_ACCESS_TOKEN /
  # KNOXCALL_API_KEY / KNOXCALL_CLIENT_ID + KNOXCALL_CLIENT_SECRET, and no
  # `knoxcall login` credentials file. A subclass of the base KnoxCall::Error —
  # this SDK's bootstrap error, as there is no separate BootstrapError class —
  # so existing `rescue KnoxCall::Error` keeps working, but distinctly typed so
  # callers can branch on "not logged in — offer KnoxCall.login" versus a
  # genuine misconfiguration (PARITY §1/§14). Also raised by the interactive
  # login helpers when prompting would be unsafe (no TTY / CI / opt-out).
  class NotAuthenticatedError < Error; end

  class APIError < Error
    attr_reader :status_code, :headers, :body
    # Machine-readable error code — the server envelope's `error.type` (Shape A)
    # or the bare `error` code string (flat Shape C). +nil+ when the body carried
    # no code. Branch on this rather than string-matching the message.
    attr_reader :code
    # Correlation id for KnoxCall server logs — the `X-Request-Id` response
    # header when present, else the id carried in the body. +nil+ if neither.
    attr_reader :request_id

    def initialize(message, status_code, headers: nil, body: nil, code: nil, request_id: nil)
      super("KnoxCall API error #{status_code}: #{message}")
      @status_code = status_code
      @headers = headers || {}
      @body = body
      @code = code
      @request_id = request_id
    end

    # Alias for #code — the canonical /v1 envelope names this field `type`,
    # so callers that think in server terms can read `e.type`.
    def type = @code
  end

  class AuthenticationError < APIError; end
  class PermissionDeniedError < APIError; end
  # Deprecated: pre-release name (also shadows Ruby's ::PermissionError when
  # the module is included). Use PermissionDeniedError. Remove before 2.0.
  PermissionError = PermissionDeniedError

  # 402 — a plan/billing limit was hit. Two error types share this status:
  # "plan_limit" (a counted quota was reached) and "plan_feature" (the
  # capability itself is not on the tier). The mapping is on STATUS, so both
  # land here.
  # Distinct from PermissionDeniedError (403) so a caller can show an
  # "upgrade" prompt rather than an "access denied" one. Carries #code /
  # #type / #request_id like the other typed errors.
  class PaymentRequiredError < APIError; end

  class NotFoundError < APIError; end

  # 409 — the request conflicts with server state (e.g. a duplicate name, or an
  # idempotency-key reuse with a different body). Retrying verbatim will not
  # resolve it, so the client never replays a 409.
  class ConflictError < APIError; end

  # 422 — the request body failed server-side validation. When the server
  # returns a per-field breakdown it is available via #fields.
  class ValidationError < APIError
    # Per-field validation messages ({field => [msg, ...]}) when the server
    # supplied them, else +nil+.
    def fields
      @body.is_a?(Hash) ? @body["fields"] : nil
    end
  end

  class RateLimitError < APIError
    # Server-requested delay in seconds, if a Retry-After header was sent.
    def retry_after
      v = @headers["retry-after"]
      v && v.to_f
    end
  end

  # 5xx. #retry_after is whole seconds from +Retry-After+ when the server sent
  # one: a 503 +dependency_unavailable+ — KnoxCall could not reach one of its
  # own dependencies in time and did not serve the request — does, and the
  # retry loop honours it exactly as a 429's (PARITY §4). +nil+ when absent: a
  # plain 5xx keeps the jittered backoff. Digits only — an HTTP-date is legal
  # but is not delta-seconds.
  class ServerError < APIError
    def retry_after
      v = @headers["retry-after"]
      v.is_a?(String) && v.strip.match?(/\A\d+\z/) ? v.strip.to_f : nil
    end
  end

  # A refusal from the AI *data plane* (+POST {agent_url}/…+), typed.
  #
  # WHY IT IS ITS OWN CLASS. The data plane is not the Management API: it
  # answers <tt>{error, error_description, code}</tt> with the machine-readable
  # code in BOTH +error+ and +code+ (AIGW-163), while the management plane
  # answers the nested <tt>{"error" => {"type", "message", "request_id"}}</tt>.
  # A +code+ of "budget_exceeded" and a +code+ of "not_found" come from
  # different contracts, and the status alone cannot tell them apart.
  #
  # The SDK does not make the data-plane call for you — that is the design: you
  # point an existing provider client at the agent's +agent_url+ and it works
  # unchanged. So this class is paired with KnoxCall.ai_gateway_error_from,
  # which types whatever that client hands back.
  #
  # A subclass of APIError (and so of the base Error), so an existing
  # <tt>rescue KnoxCall::APIError</tt> still catches it (PARITY §1).
  class AIGatewayError < APIError
    # The human sentence. Rewritten whenever a clearer wording is found —
    # branch on #code, never on this.
    attr_reader :error_description
    # Whole seconds from +Retry-After+, or +nil+.
    #
    # Absence is meaningful: the gateway sends no header rather than a guess, so
    # +nil+ means "back off on your own schedule", never "retry now".
    attr_reader :retry_after

    def initialize(message, status_code, error_description:, retry_after: nil, **kwargs)
      super(message, status_code, **kwargs)
      @error_description = error_description
      @retry_after = retry_after
    end
  end

  # Does this parsed body look like the AI data plane's envelope?
  #
  # +error+ and +code+ must both be present AND equal: the pre-AIGW-163 auth
  # shape had a +code+ that was not the +error+, and accepting it would make
  # +code+ mean two things again.
  def self.ai_gateway_error_body?(body)
    return false unless body.is_a?(Hash)

    body["error"].is_a?(String) &&
      body["code"].is_a?(String) &&
      body["error_description"].is_a?(String) &&
      body["error"] == body["code"]
  end

  # Type a refusal a provider client received from an agent's data-plane URL.
  #
  # Returns +nil+ when +body+ is not the data plane's envelope, so a caller
  # falls through to its own handling rather than being handed a mislabelled
  # error:
  #
  #   res = Net::HTTP.post(URI("#{agent['agent_url']}/v1/messages"), payload)
  #   if res.code.to_i >= 400
  #     err = KnoxCall.ai_gateway_error_from(res.code.to_i, JSON.parse(res.body), res)
  #     sleep(err.retry_after || 60) if err&.code == "budget_exceeded"
  #     raise err || "HTTP #{res.code}"
  #   end
  #
  # +headers+ accepts a Hash or anything with +[]+ (a Net::HTTPResponse), or nil.
  def self.ai_gateway_error_from(status, body, headers = nil)
    return nil unless ai_gateway_error_body?(body)

    read = lambda do |name|
      next nil if headers.nil?

      value = begin
        headers[name] || headers[name.downcase]
      rescue StandardError
        nil
      end
      value.is_a?(String) ? value : nil
    end

    raw_retry = (read.call("Retry-After") || "").strip
    # An HTTP-date Retry-After is legal but is not delta-seconds; nil is the
    # right reading of one we cannot use.
    retry_after = raw_retry.match?(/\A\d+\z/) ? raw_retry.to_i : nil
    request_id = read.call("X-Request-Id")
    request_id = body["request_id"] if request_id.nil? && body["request_id"].is_a?(String)

    AIGatewayError.new(
      body["error_description"],
      status,
      error_description: body["error_description"],
      retry_after: retry_after,
      code: body["code"],
      request_id: request_id,
      headers: headers.is_a?(Hash) ? headers : nil,
      body: body
    )
  end

  # The token endpoint returned something unusable (non-JSON 200 from an edge
  # proxy, missing access_token, a DPoP-bound token this SDK can't use, ...).
  class TokenError < Error; end

  # Transport-level failure — the request may never have reached the server.
  class NetworkError < Error; end
  class ConnectionTimeoutError < NetworkError; end

  # A webhook delivery failed verification in Client.construct_event (missing
  # header, signature mismatch, stale timestamp, non-JSON body). The message
  # says what failed without ever echoing the signature or the secret.
  class WebhookSignatureVerificationError < Error; end

  # Raised by the wrap Faraday transport (wrap.faraday_connection) when a
  # wrapped SDK's provider key contradicts the client's sandbox flag —
  # both-must-agree (PARITY §18): a Stripe TEST key can never be wrapped by a
  # LIVE client (or vice versa), and a publishable (pk_…) key is refused
  # outright. Also raised for a malformed route-around host. A subclass of the
  # base KnoxCall::Error so existing `rescue KnoxCall::Error` keeps working; it
  # is a configuration mistake, never a transport failure.
  class WrapSandboxMismatchError < Error; end

  # KnoxCall.signup failed — validation, slug conflict, rate limit, or an
  # unexpected response body. Carries the server's machine-readable error
  # type (e.g. "slug_taken") and the request id for support.
  class SignupError < Error
    attr_reader :status_code, :error_type, :request_id, :body

    def initialize(message, status_code:, error_type: nil, request_id: nil, body: nil)
      super(message)
      @status_code = status_code
      @error_type = error_type
      @request_id = request_id
      @body = body
    end
  end

  # KnoxCall.exchange_token failed — the RFC 8693 exchange at
  # POST /v1/oauth/token was refused, or returned a body with no
  # access_token. +error_type+ is the RFC 6749 §5.2 code: "invalid_grant",
  # "invalid_target", "unsupported_grant_type", "invalid_request" or
  # "server_error".
  class TokenExchangeError < Error
    attr_reader :status_code, :error_type, :body

    def initialize(message, status_code:, error_type: nil, body: nil)
      super(message)
      @status_code = status_code
      @error_type = error_type
      @body = body
    end
  end

  # A WorkloadCredentialProvider assertion source returned bytes that were
  # already spent on a previous exchange, so sending them could only have been
  # refused. This is a caller-side configuration error, not a credential
  # rejection, and it says so: the message names the cause and what to do,
  # because the alternative is a replay refusal from the server that reads like
  # "your CI identity is not trusted".
  class StaleAssertionError < Error; end

  # Build the typed error for a >= 400 Net::HTTPResponse. Mirrors the Node
  # SDK's errorFromResponse (sdk/knoxcall-node/src/error.ts).
  def self.error_from_response(resp)
    status = resp.code.to_i
    data = begin
      JSON.parse(resp.body.to_s)
    rescue JSON::ParserError
      nil
    end

    headers = {}
    resp.each_header { |k, v| headers[k.downcase] = v }

    body = data.is_a?(Hash) ? data : {}
    err = body["error"]

    # The KnoxCall /v1 API returns errors as {error:{type,message,request_id}}
    # (the `error` value is a HASH) — Shape A, the canonical envelope. We stay
    # tolerant of the flat shapes some non-/v1 surfaces still use:
    #   B: {error:"<message>", statusCode, errorId}
    #   C: {error:"<code>", message}   — `error` is a CODE, `message` is human.
    if err.is_a?(Hash)
      msg = presence(err["message"]) || presence(err["type"]) || "HTTP #{status}"
      code = err["type"].is_a?(String) ? err["type"] : nil
      body_request_id = err["request_id"].is_a?(String) ? err["request_id"] : nil
    else
      # Flat shapes. Prefer a human `error_description`/`message` over the bare
      # `error` (a code string in Shape C, a message in Shape B), so Shape C
      # surfaces the human text — not the code — while still recording the code.
      msg = presence(body["error_description"]) ||
            presence(body["message"]) ||
            presence(err) ||
            "HTTP #{status}"
      # AIGW-163: the AI data plane sends the code in BOTH `error` and `code`.
      # Prefer the explicit `code` — a future surface could carry one that is
      # not mirrored, and reading the mirror would silently lose it.
      code = presence(body["code"]) || (err.is_a?(String) ? err : nil)
      body_request_id =
        (body["request_id"].is_a?(String) ? body["request_id"] : nil) ||
        (body["errorId"].is_a?(String) ? body["errorId"] : nil)
    end

    # Correlation id: prefer the X-Request-Id response header (now always emitted
    # by the API) then fall back to the id carried in the body.
    request_id = headers["x-request-id"] || body_request_id

    klass = case status
            when 401 then AuthenticationError
            when 402 then PaymentRequiredError
            when 403 then PermissionDeniedError
            when 404 then NotFoundError
            when 409 then ConflictError
            when 422 then ValidationError
            when 429 then RateLimitError
            when 500.. then ServerError
            else APIError
            end
    klass.new(msg, status, headers: headers, body: data, code: code, request_id: request_id)
  end

  # A non-empty String, else nil — collapses "" and non-strings to nil so the
  # message/code fallbacks skip them.
  def self.presence(v)
    v if v.is_a?(String) && !v.empty?
  end
  private_class_method :presence
end
