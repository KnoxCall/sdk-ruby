module KnoxCall
  module Resources
    # Promotion opportunities (GET/POST /v1/opportunities) — mirrors
    # src/client-api/opportunities.ts.
    #
    # "We detected outbound API usage → create a route", from two sources
    # (agent_monitor + gateway_traffic). #list refreshes gateway detection on
    # read; #accept promotes a suggestion to a durable route + secret binding;
    # #dismiss drops a pending suggestion.
    #
    # Each opportunity row is
    # {id, source ("agent_monitor"|"gateway_traffic"), service,
    #  destination_host, status ("pending"|"snoozed"|"onboarded"|"dismissed"),
    #  confidence, suggested_route_json, evidence_json, accepted_route_id,
    #  created_at, updated_at, acted_at}.
    class Opportunities
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # List promotion opportunities (refreshes gateway detection on read).
      # Paginated. Params: status ("pending"|"snoozed"|"onboarded"|
      # "dismissed"), page (default 1), per_page (default 20, max 100).
      # Returns the {data, meta} envelope.
      def list(**params) = @client.request("GET", "/v1/opportunities", query: params.empty? ? nil : params)

      # Yield every opportunity, walking pages transparently. Returns a lazy
      # Enumerator when no block is given.
      def each(**params, &block)
        enum = paginate(params) { |p| list(**p) }
        block ? enum.each(&block) : enum
      end

      # Promote a gateway suggestion to a durable route + secret binding.
      #
      # All body fields are optional: +collection_name+ (else the suggestion's,
      # else "Wrapped APIs"), +environment+ (else the tenant default), +secret+
      # (name/id to bind, else an escrowed wrap credential for the host is
      # auto-bound), +header_name+ (default Authorization) and +value_prefix+
      # (default "Bearer ").
      #
      # @return [Hash] unwrapped {opportunity_id, route: {id, slug, name},
      #   collection_id, environment}
      def accept(id, collection_name: nil, environment: nil, secret: nil,
                 header_name: nil, value_prefix: nil)
        body = {}
        body[:collection_name] = collection_name unless collection_name.nil?
        body[:environment]     = environment     unless environment.nil?
        body[:secret]          = secret          unless secret.nil?
        body[:header_name]     = header_name      unless header_name.nil?
        body[:value_prefix]    = value_prefix     unless value_prefix.nil?
        unwrap(@client.request("POST", "/v1/opportunities/#{encode(id)}/accept", body: body))
      end

      # Dismiss a pending suggestion.
      #
      # @return [Hash] unwrapped {opportunity_id, status: "dismissed"}
      def dismiss(id) = unwrap(@client.request("POST", "/v1/opportunities/#{encode(id)}/dismiss"))
    end
  end
end
