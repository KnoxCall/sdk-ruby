module KnoxCall
  module Resources
    class Vaults
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # Paginated. Params: page (default 1), per_page (default 20, max 100).
      # Returns the {data, meta} envelope.
      def list(**params) = @client.request("GET", "/v1/vaults", query: params.empty? ? nil : params)

      # Yield every vault, walking pages transparently. Returns a lazy
      # Enumerator when no block is given.
      def each(**params, &block)
        enum = paginate(params) { |p| list(**p) }
        block ? enum.each(&block) : enum
      end

      # Returns the vault plus "stats" => {token_count, active_count, expiring_in_24h}.
      def get(name_or_id) = unwrap(@client.request("GET", "/v1/vaults/#{encode(name_or_id)}"))
      def create(**input) = unwrap(@client.request("POST", "/v1/vaults", body: input))
      def update(name_or_id, **input) = unwrap(@client.request("PATCH", "/v1/vaults/#{encode(name_or_id)}", body: input))
      # Returns {"deleted" => true}.
      def delete(name_or_id) = unwrap(@client.request("DELETE", "/v1/vaults/#{encode(name_or_id)}"))
      # Returns {"new_version" => Integer}.
      def rotate(name_or_id) = unwrap(@client.request("POST", "/v1/vaults/#{encode(name_or_id)}/rotate", body: {}))

      # -- Token operations --

      # Returns {"id", "token", "expires_at", "created_at"}.
      # card_exp_month / card_exp_year are the CARD's own expiry, for a `pan`
      # vault only -- not ttl_seconds, which is how long the TOKEN lives. Both
      # or neither; the year is four digits (2029, never 29). Supplying them
      # subscribes the token to the `vault.token.expiring` webhook, emitted 60
      # and 30 days before the card expires. Offering them to a non-`pan` vault
      # raises a validation_error. The result carries "card_expires_on".
      #
      # The result also carries "card_funding_type" ("credit" / "debit" /
      # "prepaid") and "card_issuing_country" (ISO 3166-1 alpha-2), derived
      # from the card's first six digits. BOTH ARE nil ON EVERY TOKEN TODAY
      # and will be until KnoxCall licenses a BIN table -- treat them as
      # optional indefinitely.
      def tokenize(name_or_id, value:, metadata: nil, ttl_seconds: nil, card_exp_month: nil, card_exp_year: nil)
        body = { value: value }
        body[:metadata] = metadata if metadata
        body[:ttl_seconds] = ttl_seconds if ttl_seconds
        body[:card_exp_month] = card_exp_month if card_exp_month
        body[:card_exp_year] = card_exp_year if card_exp_year
        unwrap(@client.request("POST", "/v1/vaults/#{encode(name_or_id)}/tokens", body: body))
      end
      # Returns {"tokens" => [...], "count" => Integer}. Each value needs "value";
      # optional "metadata", "ttl_seconds", and -- for a `pan` vault --
      # "card_exp_month" / "card_exp_year". A refusal names the offending index
      # and rolls the whole batch back.
      def bulk_tokenize(name_or_id, values) = unwrap(@client.request("POST", "/v1/vaults/#{encode(name_or_id)}/tokens/bulk", body: { values: values }))

      # Paginated. Params: page (default 1), per_page (default 20, max 100).
      # Returns the {data, meta} envelope.
      def list_tokens(name_or_id, **params) = @client.request("GET", "/v1/vaults/#{encode(name_or_id)}/tokens", query: params.empty? ? nil : params)

      # Yield every token row, walking pages transparently. Returns a lazy
      # Enumerator when no block is given.
      def each_token(name_or_id, **params, &block)
        enum = paginate(params) { |p| list_tokens(name_or_id, **p) }
        block ? enum.each(&block) : enum
      end

      # Reveal the original value. Returns {"id", "token", "value",
      # "value_b64", "metadata", "expires_at", "created_at", "crypto_key_version"}.
      def detokenize(name_or_id, id_or_token) = unwrap(@client.request("GET", "/v1/vaults/#{encode(name_or_id)}/tokens/#{encode(id_or_token)}"))
      # Returns {"updated" => true}.
      def update_token(name_or_id, id_or_token, metadata:) = unwrap(@client.request("PATCH", "/v1/vaults/#{encode(name_or_id)}/tokens/#{encode(id_or_token)}", body: { metadata: metadata }))
      # Returns {"deleted" => true}.
      def delete_token(name_or_id, id_or_token) = unwrap(@client.request("DELETE", "/v1/vaults/#{encode(name_or_id)}/tokens/#{encode(id_or_token)}"))
    end
  end
end
