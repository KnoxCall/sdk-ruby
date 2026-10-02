module KnoxCall
  module Resources
    # OAuth client registry. These endpoints bypass the standard success()
    # wrapper server-side: `data` has no accompanying meta, the list is NOT
    # paginated, and create/rotate_secret carry a top-level `warning` string —
    # surfaced here as an optional "warning" key on the returned Hash.
    class OAuthClients
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # Bare array — no pagination.
      def list = unwrap(@client.request("GET", "/v1/oauth-clients"))
      def get(id) = unwrap(@client.request("GET", "/v1/oauth-clients/#{encode(id)}"))
      # The response's "client_secret" (nil for public clients) is shown
      # exactly once — store it now. A server-side warning, when present, is
      # attached as the "warning" key.
      def create(**input) = unwrap_with_warning(@client.request("POST", "/v1/oauth-clients", body: input))
      # Returns {"id" => String}.
      def update(id, **input) = unwrap(@client.request("PATCH", "/v1/oauth-clients/#{encode(id)}", body: input))
      # The new "client_secret" is shown exactly once. The server's warning
      # is attached as the "warning" key.
      #
      # Rotation is containment: every access and refresh token the OLD secret
      # minted is revoked in the same transaction as the re-key, so they stop
      # working immediately rather than at their TTL. A rotation whose
      # revocation cannot complete is refused and the old secret keeps working —
      # you never hold a new secret for a client whose old tokens are still live.
      def rotate_secret(id) = unwrap_with_warning(@client.request("POST", "/v1/oauth-clients/#{encode(id)}/rotate-secret", body: {}))
      # Returns {"revoked" => true}.
      def revoke(id) = unwrap(@client.request("DELETE", "/v1/oauth-clients/#{encode(id)}"))
    end
  end
end
