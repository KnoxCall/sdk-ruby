require "net/http"
require "uri"
require "json"
require "openssl"

module KnoxCall
  # Headless signup — the one /v1 surface that needs no credentials, so these
  # are module-level functions rather than resources on a constructed client.
  #
  # TWO steps since 2026-08-28 (founder decision F-25). +signup+ never returns
  # a credential: it returns a claim handle and emails a sign-in link, and the
  # starter key is minted when that link has been clicked and the claim is
  # collected:
  #
  #   accepted = KnoxCall.signup({ email: "dev@example.com", tenant_name: "Acme Inc" })
  #   handle   = accepted["claim_handle"]
  #
  #   # …the account owner clicks the emailed sign-in link…
  #   claim = KnoxCall.claim_signup(handle)
  #   while claim["status"] == "pending"
  #     sleep accepted["poll_after_seconds"]
  #     claim = KnoxCall.claim_signup(handle)
  #   end
  #
  #   # claim["starter"]["api_key"]["api_key"] is shown exactly once — store it now.
  #   client = KnoxCall::Client.new(api_key: claim["starter"]["api_key"]["api_key"], sandbox: true)

  # The shared credential-less POST. Note what it does NOT treat as an error:
  # a 202. Both endpoints use it for a normal, credential-less success, so any
  # sub-400 response carrying a +data+ object is returned unchanged.
  #
  # @api private
  def self._signup_post(path, payload, what, base_url, timeout)
    uri = URI.parse((base_url || DEFAULT_API_BASE).chomp("/") + path)
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
      raise ConnectionTimeoutError, "#{what} request timed out: #{e.message}"
    rescue OpenSSL::SSL::SSLError, EOFError, SocketError, SystemCallError, IOError => e
      raise NetworkError, "#{what} request failed: #{e.class}: #{e.message}"
    end

    parsed = begin
      JSON.parse(resp.body.to_s)
    rescue JSON::ParserError
      nil
    end
    status = resp.code.to_i
    data = parsed.is_a?(Hash) && parsed["data"].is_a?(Hash) ? parsed["data"] : nil
    if status >= 400 || data.nil?
      err = parsed.is_a?(Hash) && parsed["error"].is_a?(Hash) ? parsed["error"] : {}
      message = err["message"].is_a?(String) ? err["message"] : "#{what} failed with status #{status}"
      request_id = err["request_id"] || resp["x-request-id"]
      raise SignupError.new(
        message,
        status_code: status,
        error_type: err["type"].is_a?(String) ? err["type"] : nil,
        request_id: request_id.is_a?(String) ? request_id : nil,
        body: parsed
      )
    end
    data
  end

  # Start creating a KnoxCall account.
  #
  # Always answers 202 with an opaque +claim_handle+ and emails a sign-in link
  # — no account, tenant or credential exists until that link is clicked.
  # Collect the starter kit afterwards with {claim_signup}. Rate limited to 3
  # signups/hour/IP.
  #
  # Enumeration-safe: the reply is identical for an address that already has an
  # account (it receives a sign-in link and a handle that stays "pending").
  #
  # +input+ fields: +email+ (required), +tenant_name+ (required), +full_name+,
  # +tenant_slug+ (omit to have one derived — recommended), +country+,
  # +region+ ("us"|"eu"|"au").
  #
  # @param input [Hash] the signup fields (symbol or string keys)
  # @param base_url [String, nil] management API base (default https://api.knoxcall.com)
  # @param timeout [Numeric] open/read timeout in seconds (default 30)
  # @return [Hash] +status+, +claim_handle+, +claim_path+, +poll_after_seconds+,
  #   +expires_at+, +message+, +documentation+ — and never a credential
  # @raise [SignupError] on any HTTP failure or unexpected body — carries
  #   +status_code+, +error_type+ (e.g. "slug_taken"), +request_id+
  # @raise [NetworkError, ConnectionTimeoutError] on transport failure
  def self.signup(input, base_url: nil, timeout: 30)
    _signup_post("/v1/signup", input, "Signup", base_url, timeout)
  end

  # Poll a claim handle returned by {signup}.
  #
  # Returns <tt>{"status" => "pending", ...}</tt> — a 202, and a normal SUCCESS
  # — until the emailed sign-in link has been clicked, then once returns
  # <tt>{"status" => "ready", ...}</tt> with the tenant and a one-time
  # Test-mode API key. Polling again after that raises {SignupError} (409); an
  # unknown or expired handle raises it with 404.
  #
  # Do not poll faster than the +poll_after_seconds+ that {signup} returned.
  #
  # @param claim_handle [String] the handle returned by {signup}
  # @param base_url [String, nil] management API base (default https://api.knoxcall.com)
  # @param timeout [Numeric] open/read timeout in seconds (default 30)
  # @return [Hash] +status+ plus either the pending fields or +tenant+,
  #   +starter+, +sandbox+, +documentation+
  # @raise [SignupError] 404 unknown/expired, 409 already collected, or any
  #   other HTTP failure
  # @raise [NetworkError, ConnectionTimeoutError] on transport failure
  def self.claim_signup(claim_handle, base_url: nil, timeout: 30)
    _signup_post("/v1/signup/claim", { claim_handle: claim_handle }, "Signup claim", base_url, timeout)
  end
end
