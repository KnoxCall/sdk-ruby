module KnoxCall
  module CLI
    # `knoxcall ai exchange` — RFC 8693 workload federation from a terminal.
    #
    # Mirrors knoxcall-python's knoxcall/cli/ai.py (the PARITY §13 reference):
    # same flags, same messages, same exit codes.
    #
    # The one KnoxCall command that needs no `knoxcall login` and no KnoxCall
    # credential at all: the CI workload's own OIDC id_token IS the credential,
    # and the server verifies it against the issuer's published JWKS.
    #
    #   export KC_TOKEN="$(knoxcall ai exchange --tenant acme)"
    #
    # Two rules this command exists to enforce, because both are easy to get
    # wrong in a CI script and neither fails in a way that names itself:
    #
    #   1. The subject token is read from the environment, NEVER a flag. An argv
    #      value lands in shell history, in +ps+ output, and in the CI log line
    #      that echoes the command. Same rule +knoxcall init+ applies to
    #      KNOXCALL_WRAP_SECRET.
    #   2. The host is the tenant data plane, and there is no default. On
    #      api.knoxcall.com this endpoint answers 401, which reads as "my CI
    #      token was rejected" and sends people hunting through their issuer's
    #      JWKS.
    #
    # Only the token goes to stdout, so <tt>$(...)</tt> captures exactly the
    # token.
    module Ai
      # The subject token is read from here, never from argv. See rule 1 above.
      SUBJECT_TOKEN_ENV = "KNOXCALL_SUBJECT_TOKEN".freeze

      module_function

      def run(options)
        subject_token = (ENV[SUBJECT_TOKEN_ENV] || "").strip
        if subject_token.empty?
          raise Error,
                "#{SUBJECT_TOKEN_ENV} is not set — put your CI provider's OIDC id_token there " \
                "(a flag would land in shell history, ps output and the CI log). GitHub Actions: " \
                "request one with `id-token: write` and the ACTIONS_ID_TOKEN_REQUEST_URL endpoint, " \
                'audience "knoxcall:gateway".'
        end

        tenant = options[:tenant]
        base_url = options[:base_url]
        if (tenant.nil? || tenant.empty?) && (base_url.nil? || base_url.empty?)
          raise Error,
                "one of --tenant or --base-url is required: POST /v1/oauth/token is served only on " \
                "the tenant data-plane host (https://{tenant}.knoxcall.com). Pointing it at " \
                "api.knoxcall.com answers 401, which reads like a rejected subject_token but means " \
                "the endpoint is not there."
        end

        kwargs = {
          subject_token: subject_token,
          tenant: tenant,
          sandbox: options[:sandbox] == true,
          base_url: base_url
        }
        # `resource` is only passed when the flag was GIVEN: the SDK
        # distinguishes nil from an empty string, and an empty one is a server
        # refusal rather than "no resource".
        kwargs[:resource] = options[:resource] if options.key?(:resource)
        kwargs[:audience] = options[:audience] if options[:audience]

        result = KnoxCall.exchange_token(**kwargs)
        token = result["access_token"]
        raise Error, "the exchange returned no access_token" if token.nil? || token.empty?

        # stdout: the token, nothing else. stderr: everything a human wants.
        puts token
        kind = options.key?(:resource) ? "tool (MCP, resource-bound)" : "agent"
        ttl = result["expires_in"].is_a?(Integer) ? ", valid #{result['expires_in']}s" : ""
        warn "exchanged for a #{kind} token#{ttl}"
        0
      end
    end
  end
end
