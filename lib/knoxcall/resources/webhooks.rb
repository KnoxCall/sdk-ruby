module KnoxCall
  module Resources
    class Webhooks
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # Paginated. Params: page (default 1), per_page (default 20, max 100).
      # Returns the {data, meta} envelope.
      def list(**params) = @client.request("GET", "/v1/webhooks", query: params.empty? ? nil : params)

      # Yield every webhook, walking pages transparently. Returns a lazy
      # Enumerator when no block is given.
      def each(**params, &block)
        enum = paginate(params) { |p| list(**p) }
        block ? enum.each(&block) : enum
      end

      def get(webhook_id) = unwrap(@client.request("GET", "/v1/webhooks/#{encode(webhook_id)}"))
      # The response's "secret_key" (the HMAC endpoint secret) is shown
      # exactly once — store it now.
      def create(**input) = unwrap(@client.request("POST", "/v1/webhooks", body: input))
      def update(webhook_id, **input) = unwrap(@client.request("PATCH", "/v1/webhooks/#{encode(webhook_id)}", body: input))
      # Returns {"deleted" => true}.
      def delete(webhook_id) = unwrap(@client.request("DELETE", "/v1/webhooks/#{encode(webhook_id)}"))

      # Paginated delivery logs. Params: page, per_page.
      def get_logs(webhook_id, **params) = @client.request("GET", "/v1/webhooks/#{encode(webhook_id)}/logs", query: params.empty? ? nil : params)

      # Yield every delivery-log row, walking pages transparently. Returns a
      # lazy Enumerator when no block is given.
      def each_log(webhook_id, **params, &block)
        enum = paginate(params) { |p| get_logs(webhook_id, **p) }
        block ? enum.each(&block) : enum
      end

      # Returns {"event_types" => [{"value", "label", "description"}, ...]}.
      def list_event_types = unwrap(@client.request("GET", "/v1/webhooks/event-types"))
      # Fire a synthetic webhook.test event; returns the delivery result.
      def test(webhook_id) = unwrap(@client.request("POST", "/v1/webhooks/#{encode(webhook_id)}/test"))

      # Verify an incoming webhook delivery AND parse it in one step — see
      # {KnoxCall::Client.construct_event} for the full contract (formats,
      # tolerance, returned Hash shape).
      def construct_event(...) = Client.construct_event(...)
    end
  end
end
