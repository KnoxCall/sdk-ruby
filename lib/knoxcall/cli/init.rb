module KnoxCall
  module CLI
    # `knoxcall init` — get started wrapping a provider SDK through KnoxCall
    # (sdk-wrapping #17.4; PARITY §13). Mirrors the Node reference (src/cli/init.ts).
    #
    # SAFE BY DESIGN — this does NOT provision a tenant. It works against the
    # tenant you are already signed in to (`knoxcall login`). Two modes:
    #
    #   knoxcall init
    #       Scaffold mode: confirm who you're signed in as and print a two-step
    #       wrap quickstart. No writes.
    #
    #   knoxcall init --provider stripe --secret-name wrap-stripe --host api.stripe.com
    #       One-shot escrow: move a provider key into KnoxCall custody and print
    #       the gateway base_url to point your SDK at. The KEY is read from the
    #       KNOXCALL_WRAP_SECRET env var (never a flag) so it stays out of your
    #       shell history/argv. Escrow is idempotent-ish server-side (409 on a
    #       duplicate name).
    #
    # Tenant provisioning + a fully headless one-shot flow are a deliberate
    # follow-up — a CLI that mints tenants is a bigger, riskier surface.
    module Init
      module_function

      def run(options)
        # Auth: reuse the stored login. Never provision.
        path = CredentialsFile.resolve_path
        profile = CredentialsFile.resolve_profile(options[:profile])
        if CredentialsFile.read_profile(path, profile).nil?
          raise Error, "not logged in (profile '#{profile}') — run `knoxcall login` first"
        end

        client_opts = { bootstrap: StoredCredentials.new(path: path, profile: profile) }
        client_opts[:base_url] = options[:base_url] if CredentialsFile.presence(options[:base_url])
        client_opts[:sandbox] = true if options[:sandbox]
        client = Client.new(**client_opts)

        account = client.account.get || {}
        tenant = CredentialsFile.presence(account["name"]) ||
                 CredentialsFile.presence(account["company_name"]) ||
                 CredentialsFile.presence(account["slug"]) || "(unknown)"
        puts "Signed in as #{tenant}."

        # One-shot escrow mode: --provider selects it; the other bits are then required.
        if CredentialsFile.presence(options[:provider])
          return escrow_mode(client, options)
        end

        scaffold_mode
      end

      # One-shot escrow: escrow the key (read from KNOXCALL_WRAP_SECRET, never a
      # flag) then mint the gateway base_url. The raw key is never printed.
      def escrow_mode(client, options)
        name = options[:secret_name].to_s.strip
        host = options[:host].to_s.strip.downcase
        value = ENV["KNOXCALL_WRAP_SECRET"]
        raise Error, "--secret-name is required with --provider" if name.empty?
        raise Error, "--host is required with --provider" if host.empty?
        if value.nil? || value.empty?
          raise Error, "set the provider key in the KNOXCALL_WRAP_SECRET env var (not a flag)"
        end

        client.wrap.escrow(provider: options[:provider], name: name, value: value, hosts: [host])
        res = client.wrap.gateway_url(secret: name, host: host)
        puts ""
        puts "Escrowed '#{name}' for #{host} — your provider key is now in KnoxCall custody."
        puts "Point a base-URL-only SDK at:"
        puts "  #{res['base_url']}"
        puts ""
        puts "…or transport-wrap an SDK that takes an injected Faraday connection:"
        puts "  knox = KnoxCall::Client.new  # your KnoxCall key"
        puts "  conn = knox.wrap.faraday_connection(url: \"https://#{host}\")"
        0
      end

      # Scaffold mode: print the two-step quickstart, no writes.
      def scaffold_mode
        puts ""
        puts "Wrap a provider SDK through KnoxCall in two steps:"
        puts ""
        puts "1) Move the provider key into custody (key via KNOXCALL_WRAP_SECRET):"
        puts "   KNOXCALL_WRAP_SECRET=sk_live_… \\"
        puts "   knoxcall init --provider stripe --secret-name wrap-stripe --host api.stripe.com"
        puts ""
        puts "2) Route your SDK through KnoxCall (the key never re-enters your process):"
        puts "   knox = KnoxCall::Client.new  # your KnoxCall key"
        puts "   conn = knox.wrap.faraday_connection(url: \"https://api.stripe.com\")"
        puts "   # …or point a base-URL-only SDK at the base_url that step 1 prints."
        0
      end
    end
  end
end
