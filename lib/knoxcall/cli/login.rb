require "socket"
require "securerandom"
require "openssl"
require "uri"
require "rbconfig"

module KnoxCall
  module CLI
    # `knoxcall login` — auth-code+PKCE via loopback redirect, or device flow.
    module Login
      DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

      module_function

      # -- PKCE (RFC 7636, S256 only) --------------------------------------------

      # Return [code_verifier, code_challenge] — S256, unpadded base64url.
      def generate_pkce_pair
        verifier = base64url(SecureRandom.bytes(48))
        challenge = base64url(OpenSSL::Digest::SHA256.digest(verifier))
        [verifier, challenge]
      end

      def base64url(bytes)
        [bytes].pack("m0").tr("+/", "-_").delete("=")
      end

      def build_authorize_url(base_url, redirect_uri:, state:, code_challenge:, tenant: nil)
        params = {
          "response_type" => "code",
          "client_id" => CLI_CLIENT_ID,
          "redirect_uri" => redirect_uri,
          "state" => state,
          "code_challenge" => code_challenge,
          "code_challenge_method" => "S256"
        }
        params["tenant"] = tenant if CredentialsFile.presence(tenant)
        "#{base_url}/oauth/authorize?#{URI.encode_www_form(params)}"
      end

      # -- Loopback redirect receiver (RFC 8252 §7.3) ------------------------------

      # One-shot loopback HTTP server on 127.0.0.1:0 for the authorize redirect.
      #
      # Serves until one GET /callback arrives (anything else — favicon probes
      # and the like — gets a 404 and the listener keeps going).
      class LoopbackServer
        attr_reader :port

        def initialize(host = "127.0.0.1")
          @server = TCPServer.new(host, 0)
          @port = @server.addr[1]
          @mutex = Mutex.new
          @cond = ConditionVariable.new
          @result = nil
          @thread = Thread.new { serve }
          @thread.report_on_exception = false
        end

        # Block until the browser hits /callback; validate state, return the code.
        def wait_for_code(expected_state:, timeout: 300.0)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          result = @mutex.synchronize do
            while @result.nil?
              remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
              raise Error, "timed out waiting for the browser sign-in to complete" if remaining <= 0
              @cond.wait(@mutex, remaining)
            end
            @result
          end

          if CredentialsFile.presence(result["error"])
            detail = CredentialsFile.presence(result["error_description"]) || result["error"]
            raise Error, "authorization failed: #{detail}"
          end
          unless OpenSSL.secure_compare(result["state"].to_s, expected_state)
            raise Error, "state mismatch in the OAuth callback — possible CSRF, aborting"
          end
          code = CredentialsFile.presence(result["code"])
          raise Error, "no authorization code in the OAuth callback" unless code
          code
        end

        def close
          begin
            @server.close
          rescue IOError
            # already closed
          end
          @thread.join(2) || @thread.kill
        end

        private

        def serve
          loop do
            socket = @server.accept
            begin
              handle(socket)
            ensure
              begin
                socket.close
              rescue IOError, SystemCallError
                # peer already gone
              end
            end
            break unless @mutex.synchronize { @result.nil? }
          end
        rescue IOError, SystemCallError
          # listener closed — shutting down
        end

        def handle(socket)
          request_line = socket.gets
          return unless request_line
          while (line = socket.gets) # drain headers
            break if line.strip.empty?
          end
          method, target, = request_line.split(" ", 3)
          path, query = target.to_s.split("?", 2)
          unless method == "GET" && path == "/callback"
            respond(socket, "404 Not Found", page(failed: true))
            return
          end

          result = {}
          begin
            URI.decode_www_form(query.to_s).each { |k, v| result[k] = v unless result.key?(k) }
          rescue ArgumentError
            # malformed query — treated as an empty callback below
          end
          failed = result.key?("error") || result["code"].to_s.empty?
          respond(socket, "200 OK", page(failed: failed))

          @mutex.synchronize do
            @result ||= result
            @cond.signal
          end
        end

        def page(failed:)
          "<!doctype html><meta charset='utf-8'><title>KnoxCall CLI</title>" \
            "<body style='font-family:system-ui;margin:4rem auto;max-width:28rem'>" +
            (if failed
               "<h1>Sign-in failed</h1><p>Return to your terminal for details.</p>"
             else
               "<h1>Signed in</h1><p>You can close this window and return to your terminal.</p>"
             end) + "</body>"
        end

        def respond(socket, status_line, html)
          body = html.encode("utf-8")
          socket.write(
            "HTTP/1.1 #{status_line}\r\n" \
            "Content-Type: text/html; charset=utf-8\r\n" \
            "Content-Length: #{body.bytesize}\r\n" \
            "Connection: close\r\n\r\n"
          )
          socket.write(body)
        rescue IOError, SystemCallError
          # browser hung up mid-response — the query is what matters
        end
      end

      # -- Flows -------------------------------------------------------------------

      def auth_code_flow(base_url, tenant: nil, open_browser: nil, timeout: 300.0)
        verifier, challenge = generate_pkce_pair
        state = SecureRandom.urlsafe_base64(24)
        server = LoopbackServer.new
        begin
          redirect_uri = "http://127.0.0.1:#{server.port}/callback"
          url = build_authorize_url(base_url, redirect_uri: redirect_uri, state: state,
                                              code_challenge: challenge, tenant: tenant)
          puts "Opening your browser to sign in. If it does not open, visit:\n\n  #{url}\n\n"
          begin
            (open_browser || method(:open_browser_default)).call(url)
          rescue StandardError
            # URL is printed; a broken browser launcher is not fatal
          end
          code = server.wait_for_code(expected_state: state, timeout: timeout)
        ensure
          server.close
        end

        status, body = Common.post_form(
          "#{base_url}/oauth/token",
          {
            "grant_type" => "authorization_code",
            "code" => code,
            "redirect_uri" => redirect_uri,
            "client_id" => CLI_CLIENT_ID,
            "code_verifier" => verifier
          }
        )
        if status >= 400 || !CredentialsFile.presence(body["access_token"])
          raise Error, Common.token_error_message(status, body)
        end
        body
      end

      # Open the system browser; failures are non-fatal (the URL is always
      # printed first). start/open/xdg-open per OS.
      def open_browser_default(url)
        clean = url.gsub('"', "%22")
        case RbConfig::CONFIG["host_os"]
        when /mswin|mingw|cygwin/
          # single-string form runs through cmd.exe, where `start` lives; the
          # quotes keep &-separated query params inside one argument
          system(%(start "" "#{clean}"), out: File::NULL, err: File::NULL)
        when /darwin/
          system("open", url, out: File::NULL, err: File::NULL)
        else
          system("xdg-open", url, out: File::NULL, err: File::NULL)
        end
      end

      # Poll the token endpoint per RFC 8628 §3.5, honoring interval + slow_down.
      # Sleeps BEFORE the first poll; `sleeper` is injectable for tests.
      def poll_device_token(base_url, device_code, client_id: CLI_CLIENT_ID, interval: 5,
                            expires_in: 900.0, sleeper: ->(s) { sleep(s) })
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + expires_in
        loop do
          if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
            raise Error, "device authorization expired — run `knoxcall login` again"
          end
          sleeper.call(interval)
          status, body = Common.post_form(
            "#{base_url}/oauth/token",
            { "grant_type" => DEVICE_GRANT, "device_code" => device_code, "client_id" => client_id }
          )
          return body if status < 400 && CredentialsFile.presence(body["access_token"])

          case body["error"]
          when "authorization_pending"
            next
          when "slow_down"
            interval += 5
          when "expired_token"
            raise Error, "the device code expired — run `knoxcall login` again"
          when "access_denied"
            raise Error, "sign-in was denied"
          else
            raise Error, Common.token_error_message(status, body)
          end
        end
      end

      def device_flow(base_url, sleeper: ->(s) { sleep(s) })
        status, body = Common.post_form(
          "#{base_url}/oauth/device_authorization", { "client_id" => CLI_CLIENT_ID }
        )
        if status >= 400 || !CredentialsFile.presence(body["device_code"])
          raise Error, Common.token_error_message(status, body)
        end

        verification_uri = body["verification_uri"].to_s
        user_code = body["user_code"].to_s
        puts "To sign in, open:\n\n  #{verification_uri}\n\nand enter the code:\n\n  #{user_code}\n\n"
        complete = CredentialsFile.presence(body["verification_uri_complete"])
        puts "(or open #{complete} directly)\n\n" if complete
        puts "Waiting for approval…"

        interval = begin
          Integer(body["interval"] || 5)
        rescue ArgumentError, TypeError
          5
        end
        expires_in = begin
          Float(body["expires_in"] || 900)
        rescue ArgumentError, TypeError
          900.0
        end
        poll_device_token(base_url, body["device_code"],
                          interval: interval, expires_in: expires_in, sleeper: sleeper)
      end

      # -- Command entry -------------------------------------------------------------

      def run(options, sleeper: nil, open_browser: nil)
        base_url = (options[:base_url] || Common.default_base_url(options[:sandbox])).chomp("/")
        path = CredentialsFile.resolve_path
        profile = CredentialsFile.resolve_profile(options[:profile])

        token_body =
          if options[:device] || options[:no_browser]
            device_flow(base_url, sleeper: sleeper || ->(s) { sleep(s) })
          else
            auth_code_flow(base_url, tenant: options[:tenant], open_browser: open_browser)
          end

        record = Common.persist_login(path: path, profile: profile, base_url: base_url,
                                      token_body: token_body, fallback_tenant: options[:tenant])
        tenant = CredentialsFile.presence(record["tenant"]) || "(tenant not reported)"
        puts "\nLogged in to #{tenant} (#{base_url})"
        scope = CredentialsFile.presence(record["scope"])
        puts "Scopes: #{scope}" if scope
        puts "Credentials written to #{path} (profile '#{profile}')"
        unless CredentialsFile.presence(record["refresh_token"])
          puts "Warning: no refresh token was issued — access will expire without renewal."
        end
        0
      end
    end
  end
end
