module KnoxCall
  module Resources
    class Routes
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # Paginated. Params: page (default 1), per_page (default 20, max 100),
      # plus endpoint filters. Returns the envelope:
      # {"data" => [...], "meta" => {"total", "page", "per_page", "total_pages", "request_id"}}.
      def list(**params) = @client.request("GET", "/v1/routes", query: params.empty? ? nil : params)

      # Yield every route, walking pages transparently. Returns a lazy
      # Enumerator when no block is given.
      def each(**params, &block)
        enum = paginate(params) { |p| list(**p) }
        block ? enum.each(&block) : enum
      end

      def get(route_id) = unwrap(@client.request("GET", "/v1/routes/#{encode(route_id)}"))
      def create(**input) = unwrap(@client.request("POST", "/v1/routes", body: input))
      def update(route_id, **input) = unwrap(@client.request("PATCH", "/v1/routes/#{encode(route_id)}", body: input))
      # Returns {"deleted" => true}.
      def delete(route_id) = unwrap(@client.request("DELETE", "/v1/routes/#{encode(route_id)}"))

      # Paginated request logs. Params: page, per_page, plus filters.
      def get_logs(route_id, **params) = @client.request("GET", "/v1/routes/#{encode(route_id)}/logs", query: params.empty? ? nil : params)

      # Yield every log row, walking pages transparently. Returns a lazy
      # Enumerator when no block is given.
      def each_log(route_id, **params, &block)
        enum = paginate(params) { |p| get_logs(route_id, **p) }
        block ? enum.each(&block) : enum
      end

      # Bare array — no pagination.
      def list_environments(route_id) = unwrap(@client.request("GET", "/v1/routes/#{encode(route_id)}/environments"))
      def upsert_environment(route_id, env_name, **input) = unwrap(@client.request("PUT", "/v1/routes/#{encode(route_id)}/environments/#{encode(env_name)}", body: input))
      # Returns {"deleted" => true}.
      def delete_environment(route_id, env_name) = unwrap(@client.request("DELETE", "/v1/routes/#{encode(route_id)}/environments/#{encode(env_name)}"))

      # -- Relay field-actions (declarative field-level encrypt/decrypt/tokenize) --

      # Bare array — no pagination.
      def list_actions(route_id) = unwrap(@client.request("GET", "/v1/routes/#{encode(route_id)}/actions"))
      # input: direction: ("request"|"response"), action: ("encrypt"|"decrypt"|
      # "tokenize"|"detokenize"), selectors: [String], plus optional key_name:,
      # data_role:, content_type:, sort_order:.
      def create_action(route_id, **input) = unwrap(@client.request("POST", "/v1/routes/#{encode(route_id)}/actions", body: input))
      def delete_action(route_id, action_id) = unwrap(@client.request("DELETE", "/v1/routes/#{encode(route_id)}/actions/#{encode(action_id)}"))
    end
  end
end
