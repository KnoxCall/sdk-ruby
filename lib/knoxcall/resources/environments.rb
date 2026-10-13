module KnoxCall
  module Resources
    class Environments
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # Bare array — no pagination.
      def list = unwrap(@client.request("GET", "/v1/environments"))
      def create(**input) = unwrap(@client.request("POST", "/v1/environments", body: input))
      def update(env_id, **input) = unwrap(@client.request("PATCH", "/v1/environments/#{encode(env_id)}", body: input))
      # Returns {"deleted" => true}.
      def delete(env_id) = unwrap(@client.request("DELETE", "/v1/environments/#{encode(env_id)}"))
    end
  end
end
