module KnoxCall
  module Resources
    class Agents
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # Bare array — no pagination.
      def list = unwrap(@client.request("GET", "/v1/agents"))
      # The response's "agent_secret" is shown exactly once — store it now.
      # (The server hand-rolls this 201: data carries the secret, meta only
      # {secret_shown_once: true} — unwrapping still applies.)
      # Requires an explicit `agent:create` policy grant: a wildcard (`*:*`) rule
      # does not satisfy it, including the `legacy_admin` policy every key created
      # before 2026-06-30 still carries. The seeded Key - Infrastructure and Key -
      # Editor roles name the action literally and are unaffected. Without it the
      # call returns 403. Every successful mint also emails the account's owners.
      def create(name) = unwrap(@client.request("POST", "/v1/agents", body: { name: name }))
      # Returns {"revoked" => true}.
      def revoke(agent_id) = unwrap(@client.request("DELETE", "/v1/agents/#{encode(agent_id)}"))
      # Bare array (server-capped at 50 rows) — no pagination.
      def get_tamper_events(agent_id) = unwrap(@client.request("GET", "/v1/agents/#{encode(agent_id)}/tamper-events"))
    end
  end
end
