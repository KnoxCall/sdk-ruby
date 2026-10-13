module KnoxCall
  module Resources
    class Clients
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # Paginated. Params: page (default 1), per_page (default 20, max 100).
      # Returns the {data, meta} envelope.
      def list(**params) = @client.request("GET", "/v1/clients", query: params.empty? ? nil : params)

      # Yield every calling client, walking pages transparently. Returns a
      # lazy Enumerator when no block is given.
      def each(**params, &block)
        enum = paginate(params) { |p| list(**p) }
        block ? enum.each(&block) : enum
      end

      def get(client_id) = unwrap(@client.request("GET", "/v1/clients/#{encode(client_id)}"))
      def create(**input) = unwrap(@client.request("POST", "/v1/clients", body: input))
      def update(client_id, **input) = unwrap(@client.request("PATCH", "/v1/clients/#{encode(client_id)}", body: input))
      # Returns {"deleted" => true}.
      def delete(client_id) = unwrap(@client.request("DELETE", "/v1/clients/#{encode(client_id)}"))

      # Bare array — no pagination. Secret material is redacted server-side.
      def list_credentials(client_id) = unwrap(@client.request("GET", "/v1/clients/#{encode(client_id)}/credentials"))
      # For mtls "issue" mode the response carries a ONE-SHOT "reveal"
      # ({certificate_pem, private_key_pem, ca_chain_pem}) — store it now.
      def create_credential(client_id, kind:, label:, data: nil)
        body = { kind: kind, label: label }
        body[:data] = data if data
        unwrap(@client.request("POST", "/v1/clients/#{encode(client_id)}/credentials", body: body))
      end
      def update_credential(client_id, credential_id, **input) = unwrap(@client.request("PATCH", "/v1/clients/#{encode(client_id)}/credentials/#{encode(credential_id)}", body: input))
      # Returns {"deleted" => true}.
      def delete_credential(client_id, credential_id) = unwrap(@client.request("DELETE", "/v1/clients/#{encode(client_id)}/credentials/#{encode(credential_id)}"))
    end
  end
end
