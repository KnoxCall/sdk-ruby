require "rbconfig"
require "knoxcall/cli/common"
require "knoxcall/cli/login"

module KnoxCall
  # Interactive first-run authentication — OPT-IN, and NEVER on the request
  # path (PARITY §14).
  #
  # The persistent credential (`knoxcall login` -> ~/.knoxcall/credentials.json,
  # rotating refresh token) already survives restarts; these helpers just let
  # the SDK *initiate* that login programmatically. Because an SDK is embedded
  # in someone else's process (production servers, CI, background jobs), a
  # browser/device flow must be an explicit, TTY-gated call — never a silent
  # side effect of a normal API call. Client construction and #call never
  # trigger this; they raise NotAuthenticatedError when no credential is found.
  #
  #   client = KnoxCall.ensure_login              # reuse a stored profile, else prompt once
  #   client = KnoxCall.login(mode: "device")     # force a fresh interactive login
  #
  # They reuse the already-tested CLI auth-code+PKCE loopback / RFC 8628 device
  # flow (KnoxCall::CLI::Login) and its persist helper (KnoxCall::CLI::Common),
  # so there is exactly one implementation of each flow.
  class << self
    # Run the interactive browser (loopback) or device-code login, persist the
    # credential to ~/.knoxcall/credentials.json, and return a ready client
    # bound to the written profile.
    #
    # @param tenant [String, nil] tenant hint for the authorize URL (optional;
    #   discovered otherwise)
    # @param sandbox [Boolean] target the sandbox host / Test data plane
    # @param base_url [String, nil] management base URL override
    #   (default production/sandbox, or KNOXCALL_BASE_URL)
    # @param profile [String, nil] credentials-file profile to write/read
    #   (default: KNOXCALL_PROFILE or "default")
    # @param mode ["auto", "browser", "device"] "auto" opens a browser on a
    #   desktop TTY, else falls back to the device flow
    # @param timeout [Numeric] loopback wait timeout for the browser flow (s)
    # @param allow_non_interactive [Boolean] bypass the TTY / CI /
    #   KNOXCALL_NO_INTERACTIVE guard (default false)
    # @param open_browser [#call, nil] custom browser launcher (defaults to the
    #   OS opener) — receives the authorize URL
    # @param client_options [Hash] extra options forwarded to the returned
    #   KnoxCall::Client (symbol keys)
    # @return [KnoxCall::Client] a client bound to the freshly-written profile
    # @raise [NotAuthenticatedError] when prompting is unsafe (no TTY, CI, or
    #   KNOXCALL_NO_INTERACTIVE) and allow_non_interactive is not set
    def login(tenant: nil, sandbox: false, base_url: nil, profile: nil,
              mode: "auto", timeout: 300.0, allow_non_interactive: false,
              open_browser: nil, client_options: {})
      mode = mode.to_s
      unless %w[auto browser device].include?(mode)
        raise ArgumentError, %(mode must be "auto", "browser", or "device" (got #{mode.inspect}))
      end
      interactive_guard(allow_non_interactive)

      resolved_base = (base_url || CLI::Common.default_base_url(sandbox)).chomp("/")
      resolved_profile = CredentialsFile.resolve_profile(profile)
      use_device = mode == "device" || (mode == "auto" && !desktop_browser?)

      token_body =
        if use_device
          CLI::Login.device_flow(resolved_base)
        else
          CLI::Login.auth_code_flow(resolved_base, tenant: tenant,
                                                   open_browser: open_browser, timeout: timeout)
        end

      CLI::Common.persist_login(
        path: CredentialsFile.resolve_path,
        profile: resolved_profile,
        base_url: resolved_base,
        token_body: token_body,
        fallback_tenant: tenant
      )
      client_from_profile(resolved_profile, sandbox, client_options)
    end

    # Return a client from an already-stored credential for the profile when one
    # is present (no prompt, no network), otherwise run the interactive {#login}
    # once. The ergonomic "make sure I'm authenticated, then give me a client"
    # entry point. Accepts the same options as {#login}.
    #
    # @return [KnoxCall::Client]
    def ensure_login(tenant: nil, sandbox: false, base_url: nil, profile: nil,
                     mode: "auto", timeout: 300.0, allow_non_interactive: false,
                     open_browser: nil, client_options: {})
      resolved_profile = CredentialsFile.resolve_profile(profile)
      if CredentialsFile.profile_available?(CredentialsFile.resolve_path, resolved_profile)
        return client_from_profile(resolved_profile, sandbox, client_options)
      end
      login(tenant: tenant, sandbox: sandbox, base_url: base_url, profile: profile,
            mode: mode, timeout: timeout, allow_non_interactive: allow_non_interactive,
            open_browser: open_browser, client_options: client_options)
    end

    private

    # Refuse to pop a browser or block on a device code where doing so is
    # unsafe: a non-interactive process (no TTY), CI, or an explicit opt-out.
    # The caller can override with allow_non_interactive when they know it is
    # safe (PARITY §14).
    def interactive_guard(allow_non_interactive)
      return if allow_non_interactive
      if env_set?("KNOXCALL_NO_INTERACTIVE") || env_set?("CI")
        raise NotAuthenticatedError,
              "interactive login is disabled here (KNOXCALL_NO_INTERACTIVE or CI is set). " \
              "Provision a non-interactive credential (client_id/secret or workload OIDC) instead."
      end
      unless $stdin.tty? && $stdout.tty?
        raise NotAuthenticatedError,
              "no interactive terminal detected — run `knoxcall login` in a terminal, " \
              "or provision a non-interactive credential (client_id/secret or workload OIDC)."
      end
    end

    # A present, non-empty env var counts as "set" — mirrors node's
    # truthy-string test (so CI=false still counts as CI being present).
    def env_set?(name)
      value = ENV[name]
      !value.nil? && !value.empty?
    end

    # Headless CI is already blocked by interactive_guard, so this only chooses
    # browser-vs-device on a real TTY. On Linux, require a display server.
    def desktop_browser?
      if RbConfig::CONFIG["host_os"] =~ /linux/
        env_set?("DISPLAY") || env_set?("WAYLAND_DISPLAY")
      else
        true
      end
    end

    # Build a client bound to a stored profile. Construction performs no network
    # I/O; the StoredCredentials bootstrap seeds tenant/base_url from the file
    # (unless overridden) and refreshes tokens under the file lock at first use.
    def client_from_profile(profile, sandbox, client_options)
      opts = (client_options || {}).merge(
        bootstrap: StoredCredentials.new(profile: profile),
        sandbox: sandbox
      )
      Client.new(opts)
    end
  end
end
