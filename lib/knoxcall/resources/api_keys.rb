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
      # transaction as the key. Only the SEEDED key roles are accepted
      # (`seeded: true` — Key — Invoke, Key — Read-only, Key — Editor,
      # Key — Infrastructure); any other role is refused 403 forbidden, because
      # custom roles are being retired. Discover them with
      # `client.roles.list(subject_kind: "api_key")` and filter on `seeded`. A
      # key created with no role is default-denied on every policy-gated endpoint.
      #
      # A key can never mint a key more privileged than itself: if a requested
      # role grants something this credential does not hold, the server answers
      # 403 privilege_escalation (a PermissionDeniedError) naming the offending
      # grant verbatim.
      #
      # Expiry: pass AT MOST ONE of `expires_in_days:` (1-365),
      # `expires_at:` (ISO 8601, future, at most 365 days out) and
      # `never_expires: true`. Two or more is 400 conflicting_expiry_fields;
      # out of range or in the past is 400 invalid_expiry. Both are the
      # existing 400 class, discriminated by the error type.
      #
      # **Passing none of them does NOT mean "no expiry" — the key gets 90
      # days.** Read `created["expires_at"]` for the instant that was applied;
      # it is nil only when `never_expires: true` was sent. Keyword arguments
      # are forwarded verbatim, so an unpassed key is absent from the body
      # rather than sent as null — which is the difference between "apply the
      # default" and "never expires".
      def create(**input) = unwrap(@client.request("POST", "/v1/api-keys", body: input))
      # Returns {"revoked" => true}.
      def revoke(key_id) = unwrap(@client.request("DELETE", "/v1/api-keys/#{encode(key_id)}"))
    end
  end
end
