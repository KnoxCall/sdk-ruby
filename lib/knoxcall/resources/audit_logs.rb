module KnoxCall
  module Resources
    class AuditLogs
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # Paginated. Params: page (default 1), per_page (default 20, max 100),
      # plus endpoint filters. Returns the {data, meta} envelope.
      def list(**params) = @client.request("GET", "/v1/audit-logs", query: params.empty? ? nil : params)

      # Yield every audit-log row, walking pages transparently. Returns a
      # lazy Enumerator when no block is given.
      def each(**params, &block)
        enum = paginate(params) { |p| list(**p) }
        block ? enum.each(&block) : enum
      end

      # One page of the keyset audit event feed — the endpoint a SIEM shipper
      # should use. Params: +cursor+, +limit+, +action+, +action_prefix+,
      # +resource_type+.
      #
      # {#list} is offset-paginated over +created_at DESC+, which is right for
      # a console and wrong for a feed: rows written while you page shift the
      # offsets underneath you, so events are skipped or repeated with no way
      # to tell which. This is ordered by a monotonic sequence and resumes from
      # an opaque cursor.
      #
      # +action+ is exact-match; +action_prefix+ subscribes to a whole SURFACE
      # — <tt>"ai_gateway."</tt> covers every AI-gateway action INCLUDING names
      # added after your integration was built, which exact-match cannot.
      #
      # Delivery is AT LEAST ONCE — dedupe on +id+. +meta.next_cursor+ is
      # OPAQUE; pass it back verbatim.
      def events(**params) = @client.request("GET", "/v1/audit-logs/events", query: params.empty? ? nil : params)

      # Yield every audit event, walking the cursor until the feed is drained
      # to the watermark. Returns a lazy Enumerator when no block is given.
      def each_event(**params, &block)
        enum = paginate_cursor(params) { |p| events(**p) }
        block ? enum.each(&block) : enum
      end
    end
  end
end
