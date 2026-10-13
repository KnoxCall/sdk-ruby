module KnoxCall
  module Resources
    class Crypto
      include UnwrapsEnvelope

      # Sentinel so #inspect can double as Object#inspect when called with no
      # argument (consoles / p / rspec output) — see #inspect below.
      UNSET = Object.new.freeze
      private_constant :UNSET

      def initialize(client) = @client = client

      # -- Key management --

      # Bare array — no pagination.
      def list_keys = unwrap(@client.request("GET", "/v1/crypto/keys"))
      def get_key(name) = unwrap(@client.request("GET", "/v1/crypto/keys/#{encode(name)}"))
      def create_key(**input) = unwrap(@client.request("POST", "/v1/crypto/keys", body: input))
      # Raise or lower the key's destroy safety latch. A version can only be
      # destroyed while +deletion_allowed+ is true, and every new key ships with
      # it false; destroy_key_version on a latched key is refused with a 409
      # (deletion_not_allowed), which is a client error and must not be retried
      # unchanged. Returns {"name" => String, "deletion_allowed" => Boolean}.
      def update_key(name, deletion_allowed:) = unwrap(@client.request("PATCH", "/v1/crypto/keys/#{encode(name)}", body: { deletion_allowed: deletion_allowed }))
      # Returns {"new_version" => Integer}.
      def rotate_key(name) = unwrap(@client.request("POST", "/v1/crypto/keys/#{encode(name)}/rotate", body: {}))
      # Returns {"destroyed" => Integer} — the destroyed version.
      def destroy_key_version(name, version) = unwrap(@client.request("DELETE", "/v1/crypto/keys/#{encode(name)}/versions/#{version}"))
      # Returns {"pem", "jwk", "key_version"}. version travels as a query param.
      def get_public_key(name, version: nil)
        query = version ? { version: version } : nil
        unwrap(@client.request("GET", "/v1/crypto/keys/#{encode(name)}/public-key", query: query))
      end

      # -- Keyed transit encryption --

      # Returns {"ciphertext", "key_version"}.
      def encrypt(name, **input) = unwrap(@client.request("POST", "/v1/crypto/keys/#{encode(name)}/encrypt", body: input))
      # Returns {"plaintext_b64", "key_version"} by default; pass
      # format: "utf8" (a query param) for a decoded "plaintext" instead.
      def decrypt(name, ciphertext:, format: nil)
        query = format ? { format: format } : nil
        unwrap(@client.request("POST", "/v1/crypto/keys/#{encode(name)}/decrypt", query: query, body: { ciphertext: ciphertext }))
      end
      # Returns {"ciphertext", "key_version"}.
      def rewrap(name, ciphertext:) = unwrap(@client.request("POST", "/v1/crypto/keys/#{encode(name)}/rewrap", body: { ciphertext: ciphertext }))

      # -- Portable kc: encryption (structure-preserving, top-level /v1) --
      # Distinct from the keyed transit encrypt above: these take arbitrary
      # JSON and return the same shape with scalar leaves swapped for
      # portable, self-describing `kc:` ciphertext strings.

      # Returns {"ciphertext" => <same shape, leaves encrypted>, "key", "key_version"}.
      def encrypt_data(data, key: nil, role: nil)
        body = { data: data }
        body[:key] = key if key
        body[:role] = role if role
        unwrap(@client.request("POST", "/v1/encrypt", body: body))
      end

      # Returns {"plaintext" => <same shape, leaves decrypted>}.
      def decrypt_data(data, role: nil)
        body = { data: data }
        body[:role] = role if role
        unwrap(@client.request("POST", "/v1/decrypt", body: body))
      end

      # Metadata about a single `kc:` ciphertext string — no decryption.
      # Returns {"encrypted", "scheme", "version", "datatype", "key_ref", "fingerprint"}.
      # With no argument this behaves as Object#inspect so consoles still work.
      def inspect(value = UNSET)
        return super() if value.equal?(UNSET)
        unwrap(@client.request("POST", "/v1/inspect", body: { value: value }))
      end

      # Mint a single-use, payload-pinned client-side capability token. Hand
      # the returned "token" to a browser/agent so it can reveal exactly the
      # bound data (a kc: ciphertext for "decrypt", a vault token for
      # "detokenize") once, via POST /v1/client/{decrypt,detokenize}, without
      # an API key. input: action:, data:, plus optional role:, ttl_seconds:.
      # Returns {"token", "expires_at", "action"}.
      def mint_client_token(**input) = unwrap(@client.request("POST", "/v1/client-tokens", body: input))

      # The public bits a browser needs to seal values client-side (public
      # key + key_ref). Your backend calls this and hands the JSON to the
      # page; no private material is included.
      def get_sealing_bundle(key: nil)
        query = key ? { key: key } : nil
        unwrap(@client.request("GET", "/v1/encrypt/sealing-bundle", query: query))
      end

      # -- Signing --

      # Returns {"signature", "key_version"}.
      def sign(name, **input) = unwrap(@client.request("POST", "/v1/crypto/keys/#{encode(name)}/sign", body: input))
      # Returns {"valid", "key_version"}.
      def verify(name, **input) = unwrap(@client.request("POST", "/v1/crypto/keys/#{encode(name)}/verify", body: input))

      # -- JWT --

      # Returns {"token", "key_version", "alg"}.
      def sign_jwt(name, claims, header_overrides: nil)
        body = { claims: claims }
        body[:header_overrides] = header_overrides if header_overrides
        unwrap(@client.request("POST", "/v1/crypto/keys/#{encode(name)}/jwt", body: body))
      end
      # Returns {"valid"} plus, when valid, "claims"/"key_version"/"alg"/"kid"
      # (or "error" when not).
      def verify_jwt(name, token, expected: nil)
        body = { token: token }
        body[:expected] = expected if expected
        unwrap(@client.request("POST", "/v1/crypto/keys/#{encode(name)}/jwt/verify", body: body))
      end

      # -- Webhook signing --

      # Returns {"signature_header" ("t=<unix>,v1=<hex>"), "timestamp_seconds",
      # "key_version", "format" ("stripe")}.
      def sign_webhook(name, **input) = unwrap(@client.request("POST", "/v1/crypto/keys/#{encode(name)}/webhook-sign", body: input))
    end
  end
end
