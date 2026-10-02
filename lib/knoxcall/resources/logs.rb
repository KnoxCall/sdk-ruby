module KnoxCall
  module Resources
    # Request Logs — the per-call proxy log, and Merkle inclusion proofs.
    #
    # Distinct from {AuditLogs}, which is the CHANGE log (who edited what).
    # This is the record of requests that went THROUGH the proxy, and {#proof}
    # is the evidence that a given entry existed, unaltered, when it was
    # anchored.
    class Logs
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # One page of the request log feed. Params: +cursor+, +limit+,
      # +route_id+, +status_code+. Returns the {data, meta} envelope.
      #
      # Keyset, not offset: ordering is ascending +cursor+ and stable across
      # calls. Delivery is AT LEAST ONCE — dedupe on +request_id+.
      # +meta.next_cursor+ is OPAQUE; pass it back verbatim. A +nil+
      # +next_cursor+ means the feed is drained to the watermark, NOT that it
      # has ended.
      #
      # Captured request/response BODIES are never returned here at any
      # permission level. The identity fields (+src_ip+, +matched_client_id+,
      # +identification_method+) require +log:read_identity+ and are ABSENT
      # rather than nil when denied; +meta._redacted+ says so.
      def list(**params) = @client.request("GET", "/v1/logs", query: params.empty? ? nil : params)

      # Yield every row, walking the cursor transparently until the feed is
      # drained to the watermark. Returns a lazy Enumerator when no block is
      # given.
      def each(**params, &block)
        enum = paginate_cursor(params) { |p| list(**p) }
        block ? enum.each(&block) : enum
      end

      # One request by its +request_id+ (the +X-Request-Id+ header value).
      def get(request_id) = unwrap(@client.request("GET", "/v1/logs/#{encode(request_id)}"))

      # Merkle inclusion proof for one request.
      #
      # Returns for every outcome — read +anchored+ and +verified+ rather than
      # rescuing. +verified: false+ with +reason: "range_incomplete"+ is the
      # expected result for an old entry whose anchored range has since been
      # trimmed by retention, and is NOT a sign of tampering;
      # +"root_mismatch"+ is. A proof is never returned alongside a failed
      # verification.
      def proof(request_id) = unwrap(@client.request("GET", "/v1/logs/#{encode(request_id)}/proof"))
    end
  end
end
