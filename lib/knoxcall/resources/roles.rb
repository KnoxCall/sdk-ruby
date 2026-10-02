module KnoxCall
  module Resources
    # Read-only role catalog (IaC plan §6 item 1.3).
    #
    # Roles are created and edited on the MFA-gated admin surface; /v1 exposes
    # them so `api_keys.create(role_ids: [...])` can be written in code instead
    # of by copying a UUID out of a browser URL bar. The rules a role grants are
    # deliberately not exposed.
    class Roles
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # Paginated. Params: subject_kind ("api_key" | "user"), page, per_page.
      # Only roles whose applies_to includes "api_key" may be passed in
      # `role_ids` when creating a key. Returns the {data, meta} envelope.
      def list(**params) = @client.request("GET", "/v1/roles", query: params.empty? ? nil : params)

      # Yield every role, walking pages transparently. Returns a lazy
      # Enumerator when no block is given.
      def each(**params, &block)
        enum = paginate(params) { |p| list(**p) }
        block ? enum.each(&block) : enum
      end
    end
  end
end
