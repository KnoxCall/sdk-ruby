module KnoxCall
  module Resources
    class ApiKeys
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # Paginated. Params: page (default 1), per_page (default 20, max 100).
      # Returns the {data, meta} envelope.
      def list(**params) = @client.request("GET", "/v1/api-keys", query: params.empty? ? nil : params)

      # Yield every API key, walking pages transparently. Returns a lazy
      # Enumerator when no block is given.
      def each(**params, &block)
        enum = paginate(params) { |p| list(**p) }
        block ? enum.each(&block) : enum
      end

      # The response's "api_key" plaintext is shown exactly once — store it now.
      #
      # `role_ids:` (array of role UUIDs) attaches permission roles in the SAME
      # transaction as the key. Discover them with
      # `client.roles.list(subject_kind: "api_key")`. A key created with no role
      # is default-denied on every policy-gated endpoint.
      #
      # A key can never mint a key more privileged than itself: if a requested
      # role grants something this credential does not hold, the server answers
      # 403 privilege_escalation (a PermissionDeniedError) naming the offending
      # grant verbatim.
      def create(**input) = unwrap(@client.request("POST", "/v1/api-keys", body: input))
      # Returns {"revoked" => true}.
      def revoke(key_id) = unwrap(@client.request("DELETE", "/v1/api-keys/#{encode(key_id)}"))
    end
  end
end
