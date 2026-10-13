# frozen_string_literal: true

require "uri"

module KnoxCall
  # The DPoP server nonce (RFC 9449 §8) — PARITY §7.1, client Phase 4.3.
  #
  # KnoxCall answers EVERY request that carried a +DPoP+ proof header with
  # <tt>DPoP-Nonce: <value></tt>: mints, refusals and successful calls alike, on
  # <tt>POST /oauth/token</tt>, +/v1+, the tenant data plane, the self-hosted
  # proxy and the AI gateway. The value is stateless, changes every minute, and
  # the server accepts the current and the previous minute's — so a nonce is
  # good for 60–120 s.
  #
  # The server's rule is VERIFY-IF-PRESENT: a proof carrying a +nonce+ claim
  # must carry one the server would issue now, and a proof carrying none is
  # still accepted. So sending one is an optimisation and a readiness step,
  # never a requirement, and a client that never learned a nonce keeps working.
  #
  # WHAT THIS IS. A per-origin memory of the last nonce seen, plus the predicate
  # that recognises the server's "use a nonce" refusal. Both are deliberately
  # tiny and have no I/O.
  #
  # * Keyed by ORIGIN (scheme + host + port), because that is what the nonce is
  #   scoped to: the management API and a tenant's data plane are different
  #   origins and issue different values. Keyed coarser and a cross-origin
  #   nonce would be sent and refused; keyed finer (a path) and almost every
  #   request would start without one.
  # * Last-write-wins, no expiry. A nonce is not a secret and needs no storage
  #   beyond the process. It need not be fresh either: the worst a stale one
  #   costs is the single documented retry, and the server deliberately refuses
  #   a stale nonce BEFORE claiming the proof's +jti+, so that retry is not then
  #   refused for an unrelated reason.
  # * Guarded by a Mutex: one client may be shared across threads.
  module DpopNonce
    # The response header the server sends on every DPoP-carrying request.
    HEADER = "dpop-nonce"

    # The RFC 9449 §8 error code: in the OAuth body on the authorization
    # server, in +WWW-Authenticate+ on a resource server.
    USE_DPOP_NONCE = "use_dpop_nonce"

    # +scheme://host[:port]+ — the scope a nonce belongs to, or +nil+ when the
    # URL has no host, which simply means "do not remember this one".
    def self.origin_of(url)
      uri = URI.parse(url.to_s)
      return nil if uri.scheme.nil? || uri.host.nil?

      port = uri.port
      default = uri.scheme == "https" ? 443 : 80
      host = port && port != default ? "#{uri.host}:#{port}" : uri.host
      "#{uri.scheme}://#{host}".downcase
    rescue URI::InvalidURIError
      nil
    end

    # Whether a refusal is the server asking for a (fresh) nonce.
    #
    # RFC 9449 splits the two surfaces and so does KnoxCall, which is why this
    # takes all three inputs rather than just a status:
    #
    # * <tt>POST /oauth/token</tt> (authorization server, §8.1) answers *400*
    #   with the OAuth body <tt>{"error": "use_dpop_nonce", …}</tt>;
    # * +/v1+, the tenant data plane, the self-hosted proxy and the AI gateway
    #   (resource server, §8.2) answer *401* with
    #   <tt>WWW-Authenticate: DPoP error="use_dpop_nonce"</tt>. On +/v1+ the
    #   body's error type says it too, but the tenant data plane keeps its
    #   deliberately opaque +Unauthorized+ body, SO THE HEADER IS THE ONLY
    #   SIGNAL THERE. Reading the body alone would make this work on /v1 and
    #   silently not on the data plane.
    def self.refusal?(status:, code: nil, headers: nil)
      return false unless [400, 401].include?(status.to_i)
      return true if code.to_s == USE_DPOP_NONCE

      challenge = (headers || {})["www-authenticate"].to_s
      challenge.downcase.include?(USE_DPOP_NONCE)
    end

    # Whether a raised SDK error is that refusal.
    def self.refusal_error?(err)
      return false unless err.respond_to?(:status_code)

      refusal?(
        status: err.status_code,
        code: err.respond_to?(:code) ? err.code : nil,
        headers: err.respond_to?(:headers) ? err.headers : nil
      )
    end

    # The last +DPoP-Nonce+ seen per origin. See the module docs.
    class Store
      def initialize
        @by_origin = {}
        @mutex = Mutex.new
      end

      # Record the nonce on a response, if it carried one. Returns it.
      #
      # +headers+ may be a Hash with lower-cased keys or a Net::HTTPResponse;
      # both are accepted because the two call sites have one each, and a
      # caller converting first is a caller who can forget to.
      def remember(url, headers)
        value = extract(headers)
        return nil if value.nil? || value.empty?

        origin = DpopNonce.origin_of(url)
        return nil if origin.nil?

        @mutex.synchronize { @by_origin[origin] = value }
        value
      end

      # The nonce to put in a proof for +url+, or +nil+ when this origin has not
      # answered yet (which is fine — the server accepts a proof with no nonce
      # claim, and +sign+ omits the claim for +nil+).
      def get(url)
        origin = DpopNonce.origin_of(url)
        return nil if origin.nil?

        @mutex.synchronize { @by_origin[origin] }
      end

      def forget(url)
        origin = DpopNonce.origin_of(url)
        return if origin.nil?

        @mutex.synchronize { @by_origin.delete(origin) }
      end

      # A copy, for tests and debugging.
      def snapshot
        @mutex.synchronize { @by_origin.dup }
      end

      private

      def extract(headers)
        return nil if headers.nil?
        return headers[HEADER].to_s.strip if headers.is_a?(Hash)
        return headers[HEADER].to_s.strip if headers.respond_to?(:[])

        nil
      end
    end
  end
end
