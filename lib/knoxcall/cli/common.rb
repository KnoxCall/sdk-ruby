require "json"
require "net/http"
require "uri"
require "fileutils"

module KnoxCall
  module CLI
    # Reserved alias accepted by /oauth/authorize and the device endpoints; the
    # server lazily provisions the tenant's real CLI client and returns its id
    # as the +client_id+ extension member on the token response.
    CLI_CLIENT_ID = "knoxcall-cli"

    # Expected CLI failure — printed as a one-line message, never a backtrace.
    class Error < StandardError; end

    # Shared CLI plumbing — token-endpoint POSTs, profile persistence.
    module Common
      module_function

      # POST a urlencoded form; return [status, parsed-JSON-or-empty-hash].
      #
      # Connection failures raise CLI::Error with a human message. HTTP error
      # statuses are returned, not raised — device polling needs the error codes.
      def post_form(url, form, timeout: 30)
        uri = URI.parse(url)
        req = Net::HTTP::Post.new(uri)
        req["Content-Type"] = "application/x-www-form-urlencoded"
        req["Accept"] = "application/json"
        req["User-Agent"] = SDK_VERSION
        req.body = URI.encode_www_form(form)

        resp = begin
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = uri.scheme == "https"
          http.open_timeout = timeout
          http.read_timeout = timeout
          http.start { |h| h.request(req) }
        rescue Net::OpenTimeout, Net::ReadTimeout, OpenSSL::SSL::SSLError,
               EOFError, SocketError, SystemCallError, IOError => e
          raise Error, "could not reach #{url}: #{e.message}"
        end

        body = begin
          JSON.parse(resp.body.to_s)
        rescue JSON::ParserError
          nil
        end
        [resp.code.to_i, body.is_a?(Hash) ? body : {}]
      end

      def token_error_message(status, body)
        detail = CredentialsFile.presence(body["error_description"]) ||
                 CredentialsFile.presence(body["error"]) || "HTTP #{status}"
        "sign-in failed: #{detail}"
      end

      # Store a successful token response as a credentials-file profile.
      #
      # Persists the +tenant+ and +client_id+ extension members — refreshes
      # must use the REAL per-tenant client id, not the +knoxcall-cli+ alias.
      # The write happens UNDER the cross-process file lock so a login racing
      # a concurrent refresh never loses a rotation.
      def persist_login(path:, profile:, base_url:, token_body:, fallback_tenant: nil)
        expires_in = begin
          Float(token_body["expires_in"] || 3600)
        rescue ArgumentError, TypeError
          3600.0
        end
        record = {
          "tenant" => CredentialsFile.presence(token_body["tenant"]) || fallback_tenant,
          "base_url" => base_url,
          "client_id" => CredentialsFile.presence(token_body["client_id"]) || CLI_CLIENT_ID,
          "refresh_token" => token_body["refresh_token"],
          "access_token" => token_body["access_token"],
          "access_token_expires_at" => CredentialsFile.format_expiry(Time.now + expires_in),
          "scope" => token_body["scope"] || ""
        }
        # The lock file lives next to the target — on a first-ever login the
        # directory does not exist yet, so create it before acquiring.
        FileUtils.mkdir_p(File.dirname(path), mode: 0o700)
        CredentialsFile::Lock.new(path).with_lock do
          CredentialsFile.write_profile(path, profile, record)
        end
        record
      end

      # Default management base: KNOXCALL_BASE_URL env > (sandbox|production)
      # host. An explicit --base-url beats both (handled by the caller).
      def default_base_url(sandbox)
        env = ENV["KNOXCALL_BASE_URL"]
        return env if env && !env.empty?
        sandbox ? "https://sandbox.#{DEFAULT_CLOUD_HOST}" : DEFAULT_API_BASE
      end
    end
  end
end
