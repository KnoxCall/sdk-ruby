require "uri"

module KnoxCall
  module Resources
    # The server wraps every JSON success response in +{ "data": ..., "meta": ... }+
    # (see sdk/PARITY.md §4). Resource methods unwrap:
    #
    # - single-object methods return +data+ (via {#unwrap});
    # - paginated lists return the envelope as-is —
    #   <tt>{"data" => [...], "meta" => {"total", "page", "per_page",
    #   "total_pages", "request_id"}}</tt> — and take +page+ / +per_page+
    #   params (server default 20, cap 100);
    # - bare-array endpoints unwrap +data+ to a plain Array (no page params);
    # - the +each+/+each_*+ auto-pagers walk pages until
    #   +page >= meta.total_pages+ or an empty page.
    #
    # TWO endpoints are keyset/cursor paginated instead, deliberately:
    # <tt>GET /v1/audit-logs/events</tt> and <tt>GET /v1/logs</tt>. Offset
    # pagination over a table that is being written to skips and repeats rows
    # with no way to tell which — fine for a console, wrong for a feed. Use
    # {#paginate_cursor} for those. (Earlier revisions of this comment said
    # there was no cursor pagination anywhere on the API; that stopped being
    # true when the audit event feed shipped.)
    module UnwrapsEnvelope
      private

      # Unwrap +data+ from a {data, meta} envelope. Tolerates a bare payload
      # (self-hosted / older servers) by passing it through unchanged.
      def unwrap(response)
        response.is_a?(Hash) && response.key?("data") ? response["data"] : response
      end

      # Unwrap +data+ and fold the response's top-level +warning+ into it —
      # the oauth-clients create/rotate-secret endpoints bypass the standard
      # success() wrapper server-side and carry the warning beside +data+.
      def unwrap_with_warning(response)
        data = unwrap(response)
        if data.is_a?(Hash) && response.is_a?(Hash) && response["warning"].is_a?(String)
          data = data.merge("warning" => response["warning"])
        end
        data
      end

      # Page-based auto-pager (PARITY §4): starts at +params[:page]+ (default
      # 1), fetches a page via the block, yields each row, and stops when
      # +page >= meta.total_pages+ or a page comes back empty (defensive).
      # Lazy: nothing is fetched until the Enumerator is consumed.
      def paginate(params, &fetch_page)
        Enumerator.new do |yielder|
          page = (params[:page] || 1).to_i
          page = 1 if page < 1
          loop do
            result = fetch_page.call(params.merge(page: page))
            rows = result.is_a?(Hash) && result["data"].is_a?(Array) ? result["data"] : []
            rows.each { |row| yielder << row }
            total_pages = result.is_a?(Hash) ? result.dig("meta", "total_pages") : nil
            break if rows.empty? || !total_pages.is_a?(Numeric) || page >= total_pages
            page += 1
          end
        end
      end

      # Cursor auto-pager for the keyset feeds. Starts at +params[:cursor]+,
      # yields each row, and STOPS when the server reports
      # +meta.next_cursor == nil+ — which means the feed is drained to the
      # watermark, NOT that it has ended. To keep following it, call again
      # later with the last cursor you saw; an Enumerator that blocked forever
      # would be unusable from a batch job.
      #
      # +next_cursor+ is OPAQUE: it is passed back verbatim and never parsed.
      # Delivery is at-least-once — dedupe on +meta.dedupe_on+.
      # Lazy: nothing is fetched until the Enumerator is consumed.
      def paginate_cursor(params, &fetch_page)
        Enumerator.new do |yielder|
          cursor = params[:cursor]
          loop do
            result = fetch_page.call(cursor.nil? ? params : params.merge(cursor: cursor))
            rows = result.is_a?(Hash) && result["data"].is_a?(Array) ? result["data"] : []
            rows.each { |row| yielder << row }
            nxt = result.is_a?(Hash) ? result.dig("meta", "next_cursor") : nil
            break if nxt.nil?
            cursor = nxt
          end
        end
      end

      def encode(s) = URI.encode_www_form_component(s.to_s)
    end
  end
end
