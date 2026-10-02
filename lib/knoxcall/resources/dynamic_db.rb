module KnoxCall
  module Resources
    class DynamicDb
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # -- Connections --

      # Bare array — no pagination.
      def list = unwrap(@client.request("GET", "/v1/dyn-db-credentials"))
      def get(name) = unwrap(@client.request("GET", "/v1/dyn-db-credentials/#{encode(name)}"))
      def create(**input) = unwrap(@client.request("POST", "/v1/dyn-db-credentials", body: input))
      # Returns {"updated" => <name String>}.
      def update(name, **input) = unwrap(@client.request("PATCH", "/v1/dyn-db-credentials/#{encode(name)}", body: input))
      # Returns {"deleted" => <name String>} (NOT a boolean — server contract).
      def delete(name) = unwrap(@client.request("DELETE", "/v1/dyn-db-credentials/#{encode(name)}"))
      # Returns {"rotated", "fingerprint_updated"}.
      def rotate_ssh_key(name, ssh_private_key:, ssh_passphrase: nil, ssh_host_fingerprint: nil)
        body = { ssh_private_key: ssh_private_key }
        body[:ssh_passphrase] = ssh_passphrase if ssh_passphrase
        body[:ssh_host_fingerprint] = ssh_host_fingerprint if ssh_host_fingerprint
        unwrap(@client.request("POST", "/v1/dyn-db-credentials/#{encode(name)}/rotate-ssh-key", body: body))
      end

      # -- Roles --

      # Bare array — no pagination.
      def list_roles(connection_name) = unwrap(@client.request("GET", "/v1/dyn-db-credentials/#{encode(connection_name)}/roles"))
      def create_role(connection_name, **input) = unwrap(@client.request("POST", "/v1/dyn-db-credentials/#{encode(connection_name)}/roles", body: input))
      # Returns {"updated" => <role String>}.
      def update_role(connection_name, role, **input) = unwrap(@client.request("PATCH", "/v1/dyn-db-credentials/#{encode(connection_name)}/roles/#{encode(role)}", body: input))
      # Returns {"deleted" => <role String>}.
      def delete_role(connection_name, role) = unwrap(@client.request("DELETE", "/v1/dyn-db-credentials/#{encode(connection_name)}/roles/#{encode(role)}"))

      # -- Credential minting + leases --

      # The response's "password" is shown exactly once — store it now.
      # Returns {"username", "password", "expires_at", "lease_id" (Integer),
      # "connection_name", "role_name"}.
      def mint(connection_name, role, ttl_seconds: nil)
        body = ttl_seconds ? { ttl_seconds: ttl_seconds } : {}
        unwrap(@client.request("POST", "/v1/dyn-db-credentials/#{encode(connection_name)}/creds/#{encode(role)}", body: body))
      end
      # Returns {"leases" => [...], "total", "limit", "offset"} — this list
      # really is limit/offset (inside data), the one list on the API that is
      # neither page/per_page nor a bare array.
      #
      # Only LIVE leases are returned — status "active", "renewing" or
      # "errored", i.e. every lease whose database user may still exist on your
      # server. Expired and revoked leases have had their user dropped and are
      # neither listed nor counted in "total". +connection+ is an exact match on
      # the connection's name, scoped to the caller's Live/Test space.
      #
      # "errored" is included deliberately: renewal was abandoned after five
      # consecutive failures, so nothing is refreshing or expiring that lease.
      # It is also the set counted by the 409 "has N active credential lease(s)"
      # a connection or role delete returns, so anything blocking a delete is
      # listed here and can be revoked.
      def list_leases(limit: nil, offset: nil, connection: nil)
        q = { limit: limit, offset: offset, connection: connection }.compact
        unwrap(@client.request("GET", "/v1/dyn-db-credentials/leases", query: q.empty? ? nil : q))
      end
      # Returns {"revoked" => <lease_id Integer>}.
      def revoke_lease(lease_id) = unwrap(@client.request("POST", "/v1/dyn-db-credentials/leases/#{encode(lease_id)}/revoke", body: {}))
    end
  end
end
