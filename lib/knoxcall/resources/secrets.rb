module KnoxCall
  module Resources
    class Secrets
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # Paginated. Params: page (default 1), per_page (default 20, max 100),
      # plus endpoint filters. Returns the {data, meta} envelope.
      def list(**params) = @client.request("GET", "/v1/secrets", query: params.empty? ? nil : params)

      # Yield every secret, walking pages transparently. Returns a lazy
      # Enumerator when no block is given.
      def each(**params, &block)
        enum = paginate(params) { |p| list(**p) }
        block ? enum.each(&block) : enum
      end

      # Fetch one secret's metadata. The value is never returned.
      #
      # The result carries an "environments" array — one entry per environment
      # holding a value, ordered by environment name, each
      # {environment_name, value_version, updated_at, expires_at_override}.
      # "value_version" counts genuine value writes for that environment
      # (starting at 1) and moves ONLY when the stored value changes:
      # rotations, admin value/certificate updates and platform-managed
      # custodial key rotation. It deliberately does not move for OAuth2 token
      # refreshes, expiry-override edits, certificate metadata re-parsing, or a
      # re-encryption of the same plaintext under a new tenant key. Compare it
      # with the version your own last write returned to detect a rotation
      # performed outside your tooling — "updated_at" cannot do that, because
      # non-value writes move it too.
      def get(secret_id) = unwrap(@client.request("GET", "/v1/secrets/#{encode(secret_id)}"))
      def create(**input) = unwrap(@client.request("POST", "/v1/secrets", body: input))

      # Create an OAuth2-provider secret (the proxy injects the provider's access
      # token into upstream requests). The base #create cannot carry these
      # fields, so POST the typed /v1/secrets/oauth2 route. Requires +name+,
      # +provider+ and +client_id+; for most grant types also supply either
      # +client_secret+ or +mtls_certificate_id+.
      def create_oauth2(name:, provider:, client_id:, client_secret: nil,
                        mtls_certificate_id: nil, scopes: nil, auth_url: nil,
                        token_url: nil, grant_type: nil, username: nil,
                        password: nil, collection_id: nil)
        body = { name: name, provider: provider, client_id: client_id }
        body[:client_secret]       = client_secret       unless client_secret.nil?
        body[:mtls_certificate_id] = mtls_certificate_id unless mtls_certificate_id.nil?
        body[:scopes]              = scopes              unless scopes.nil?
        body[:auth_url]            = auth_url            unless auth_url.nil?
        body[:token_url]           = token_url           unless token_url.nil?
        body[:grant_type]          = grant_type          unless grant_type.nil?
        body[:username]            = username            unless username.nil?
        body[:password]            = password            unless password.nil?
        body[:collection_id]       = collection_id       unless collection_id.nil?
        unwrap(@client.request("POST", "/v1/secrets/oauth2", body: body))
      end

      # Create a certificate / mTLS secret. Requires +name+ and
      # +certificate_content+ (PEM text, or base64 for binary formats);
      # +certificate_type+ is one of pem|pfx|p12|crt|cer|key|pkcs7|p7b|p7c and
      # defaults to "pem".
      def create_certificate(name:, certificate_content:, private_key: nil,
                            passphrase: nil, certificate_type: "pem",
                            collection_id: nil)
        body = { name: name, certificate_content: certificate_content,
                 certificate_type: certificate_type }
        body[:private_key]   = private_key   unless private_key.nil?
        body[:passphrase]    = passphrase    unless passphrase.nil?
        body[:collection_id] = collection_id unless collection_id.nil?
        unwrap(@client.request("POST", "/v1/secrets/certificate", body: body))
      end

      def update(secret_id, **input) = unwrap(@client.request("PATCH", "/v1/secrets/#{encode(secret_id)}", body: input))
      # Returns {"deleted" => true}.
      def delete(secret_id) = unwrap(@client.request("DELETE", "/v1/secrets/#{encode(secret_id)}"))

      # Rotate a secret's value for one environment.
      #
      # "value_version" in the result is the environment's version AFTER this
      # write — 1 when this call stored the environment's first value,
      # otherwise the previous version plus one. It is the version this call
      # produced, so storing it has no read-after-write race with a concurrent
      # rotation; compare it later against #get's
      # environments[].value_version to detect a rotation performed outside
      # your tooling.
      def set_value(secret_id, value:, environment: nil)
        body = { value: value }
        body[:environment] = environment if environment
        unwrap(@client.request("PUT", "/v1/secrets/#{encode(secret_id)}/value", body: body))
      end

      def get_oauth_token(secret_id, environment: nil)
        query = environment ? { environment: environment } : nil
        unwrap(@client.request("GET", "/v1/secrets/#{encode(secret_id)}/oauth2/token", query: query))
      end
    end
  end
end
