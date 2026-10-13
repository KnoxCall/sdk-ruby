module KnoxCall
  module CLI
    # `knoxcall ai` — the AI-gateway CONTROL plane from a terminal (AIGW-162).
    #
    # Mirrors the Node reference (sdk/knoxcall-node/src/cli/ai-control.ts):
    # same flags, same messages, same stdout/stderr split, same exit codes.
    #
    # `ai exchange` (ai.rb) is the data-plane door: it needs no login, because
    # the CI workload's OIDC token IS the credential. Everything here is the
    # opposite — it acts as the signed-in tenant, through the same
    # ~/.knoxcall/credentials.json profile `login` writes and `whoami` reads.
    #
    # WHY THIS EXISTS. Until now the five SDK CLIs shipped exactly one `ai`
    # sub-command, `exchange`. A capable `knoxcall ai gateways|agents|mint|usage`
    # lived in a standalone `cli/` package that was never published, never
    # tested, never in CI and not in the workspaces — and it could not create a
    # secret, a gateway or an agent, so it could not get you to a first call
    # either. So there was no CLI golden path at all: the only way from "I have
    # an API key" to "my app is calling an LLM through KnoxCall" was the browser
    # or hand-written HTTP.
    #
    # The golden path these commands exist to make true, from a tenant with
    # nothing in it:
    #
    #     export ANTHROPIC_API_KEY=sk-ant-...
    #     knoxcall ai create-agent --name copilot --slug copilot \
    #         --provider anthropic --secret-from-env ANTHROPIC_API_KEY
    #     knoxcall ai mint --agent <id>
    #     curl "$AGENT_URL/v1/messages" -H "Authorization: Bearer $TOKEN" ...
    #
    # Two commands, then a real streamed call. +create-agent+ prints the agent
    # id, the +agent_url+ and the exact next command, so the path is
    # discoverable without re-reading the docs.
    #
    # THREE RULES, each one a bug this shape invites:
    #
    #   1. A PROVIDER KEY IS NEVER AN ARGV VALUE. +--secret-from-env NAME+ names
    #      the environment variable to read; there is deliberately no
    #      +--secret-value+. An argv value lands in shell history, in +ps+
    #      output and in the CI log line that echoes the command. Same rule
    #      +ai exchange+ applies to KNOXCALL_SUBJECT_TOKEN and +init+ to
    #      KNOXCALL_WRAP_SECRET.
    #
    #   2. NO POSITIONAL ARGUMENTS. Four of the five SDK CLIs hand-roll their
    #      parser and reject positionals outright; only python gets them free
    #      from argparse. Ids are flags (+--gateway+, +--agent+) so the surface
    #      is the same in all five rather than "the same except in Ruby".
    #
    #   3. AN AGENT WITHOUT AN UPSTREAM IS REFUSED HERE, not at its first call.
    #      The API accepts create_agent with no provider/upstream_secret_id and
    #      stores an agent whose first data-plane request 502s (AIGW-161). A
    #      command whose entire purpose is "get me to a working call" must not
    #      be able to produce that, so +--provider+ and one of +--secret+ /
    #      +--secret-from-env+ are required together.
    #
    # No HTTP lives here: every call goes through the typed SDK resources
    # (client.ai_gateway, client.secrets).
    module AiControl
      module_function

      # A client acting as the signed-in tenant, or a refusal telling them to
      # log in. Obtained exactly the way `whoami` and `init` obtain theirs.
      def client_for(options)
        path = CredentialsFile.resolve_path
        profile = CredentialsFile.resolve_profile(options[:profile])
        if CredentialsFile.read_profile(path, profile).nil?
          raise Error, "not logged in (profile '#{profile}') — run `knoxcall login`"
        end

        client_opts = { bootstrap: StoredCredentials.new(path: path, profile: profile) }
        client_opts[:base_url] = options[:base_url] if presence(options[:base_url])
        client_opts[:sandbox] = true if options[:sandbox]
        Client.new(**client_opts)
      end

      def presence(value) = CredentialsFile.presence(value)

      def required(value, flag)
        found = presence(value)
        raise Error, "#{flag} is required" if found.nil?

        found
      end

      # -- knoxcall ai gateways -------------------------------------------------

      def gateways(options)
        client = client_for(options)
        rows = client.ai_gateway.list_gateways(per_page: 100)["data"] || []
        if rows.empty?
          warn "No AI gateways. `knoxcall ai create-agent` will create one for you."
          return 0
        end

        rows.each { |g| puts "#{g['id']}  #{g['slug']}  #{g['name']}" }
        0
      end

      # -- knoxcall ai agents --gateway ID --------------------------------------

      def agents(options)
        gateway_id = required(options[:gateway], "--gateway")
        client = client_for(options)
        rows = client.ai_gateway.list_agents(gateway_id, per_page: 100)["data"] || []
        if rows.empty?
          warn "No agents in that gateway."
          return 0
        end

        # agent_url is on every projection since AIGW-161, so a list is enough
        # to point an SDK at an existing agent — no follow-up GET.
        rows.each { |a| puts "#{a['id']}  #{a['slug']}  #{a['agent_url']}" }
        0
      end

      # -- knoxcall ai create-agent ---------------------------------------------

      def create_agent(options)
        slug = required(options[:slug], "--slug")
        # Rule 3: refuse here rather than let the API store an agent with no
        # upstream whose first data-plane call 502s.
        provider = required(options[:provider], "--provider")
        if presence(options[:secret]).nil? && presence(options[:secret_from_env]).nil?
          raise Error,
                "one of --secret or --secret-from-env is required: an agent created without an " \
                "upstream credential is accepted by the API and 502s on its first call."
        end

        client = client_for(options)
        gateway_id = resolve_gateway(client, options[:gateway])
        secret_id = resolve_secret(client, options)

        body = {
          name: presence(options[:name]) || slug,
          slug: slug,
          provider: provider,
          upstream_secret_id: secret_id
        }
        body[:upstream] = options[:upstream] if presence(options[:upstream])
        body[:default_model] = options[:model] if presence(options[:model])
        agent = client.ai_gateway.create_agent(gateway_id, **body)

        # stdout: the agent id, so $(...) captures exactly that. Everything a
        # human needs next goes to stderr, including the command that follows.
        puts agent["id"]
        warn "\n  agent:     #{agent['slug']} (#{agent['id']})"
        warn "  gateway:   #{gateway_id}"
        warn "  provider:  #{provider}"
        warn "  base_url:  #{agent['agent_url']}" if presence(agent["agent_url"])
        warn "\n  Next:  knoxcall ai mint --agent #{agent['id']}"
        0
      end

      # Resolve the gateway to create under.
      #
      # +--gateway+ takes an id OR a slug. With no +--gateway+: use the tenant's
      # only gateway, or create one when they have none — that is what makes the
      # command work on a fresh tenant, which is the whole point. With SEVERAL
      # and no flag it refuses and lists them rather than picking: "whichever
      # sorts first" is how the quickstart wizard silently landed a second agent
      # in the wrong gateway.
      def resolve_gateway(client, wanted)
        rows = client.ai_gateway.list_gateways(per_page: 100)["data"] || []
        wanted = presence(wanted)
        if wanted
          hit = rows.find { |g| g["id"] == wanted || g["slug"] == wanted }
          raise Error, "no gateway '#{wanted}' — this tenant has: #{gateway_list(rows)}" if hit.nil?

          return hit["id"]
        end
        return rows.first["id"] if rows.length == 1

        if rows.empty?
          created = client.ai_gateway.create_gateway(name: "Default", slug: "default")
          warn "created gateway #{created['slug']} (#{created['id']})"
          return created["id"]
        end

        raise Error,
              "--gateway is required: this tenant has #{rows.length} gateways " \
              "(#{gateway_list(rows)}). Picking one for you would put the agent somewhere " \
              "you did not choose."
      end

      def gateway_list(rows)
        listed = rows.map { |g| "#{g['slug']} (#{g['id']})" }.join(", ")
        listed.empty? ? "none" : listed
      end

      # Resolve the upstream secret, escrowing one from the environment if asked.
      #
      # The key is read from ENV[NAME], never from a flag — see rule 1.
      # Re-running with the same +--secret-from-env+ reuses the existing secret
      # by name rather than creating a second copy of the same credential.
      def resolve_secret(client, options)
        secret = presence(options[:secret])
        return secret if secret

        env_name = required(options[:secret_from_env], "--secret or --secret-from-env")
        value = (ENV[env_name] || "").strip
        if value.empty?
          raise Error,
                "#{env_name} is not set — put your provider key there. There is deliberately no " \
                "--secret-value flag: an argv value lands in shell history, ps output and the CI log."
        end

        name = "ai-gateway-#{presence(options[:slug]) || 'agent'}-key"
        hit = (client.secrets.list(per_page: 100)["data"] || []).find { |s| s["name"] == name }
        if hit
          warn "reusing secret '#{name}' (#{hit['id']})"
          return hit["id"]
        end

        created = client.secrets.create(name: name, value: value)
        warn "escrowed secret '#{name}' (#{created['id']}) — the key is now in KnoxCall custody"
        created["id"]
      end

      # -- knoxcall ai mint --agent ID ------------------------------------------

      def mint(options)
        agent_id = required(options[:agent], "--agent")
        client = client_for(options)
        body = {}
        body[:kind] = options[:kind] if presence(options[:kind])
        body[:name] = options[:name] if presence(options[:name])
        minted = client.ai_gateway.mint_token(agent_id, **body)

        # The plaintext is returned ONCE. stdout carries only the token so
        # `> token.txt` captures the token and nothing else; the metadata and
        # the warning go to stderr.
        puts minted["token"]
        warn "\n  id:       #{minted['id']}"
        warn "  kind:     #{minted['kind']}"
        warn "  prefix:   #{minted['prefix']}"
        warn "  dpop:     #{minted['dpop_required']}"
        warn "  expires:  #{minted['expires_at'] || 'never'}"
        warn "\n  Save this token now — it will not be shown again."
        0
      end

      # -- knoxcall ai usage ----------------------------------------------------

      def usage(options)
        client = client_for(options)
        agent_id = presence(options[:agent])
        params = { period: presence(options[:period]) || "30d" }
        params[:agent_id] = agent_id if agent_id
        rollup = client.ai_gateway.usage(**params)
        totals = rollup["totals"] || {}

        puts "Usage — last #{rollup['period_days']} days#{agent_id ? " (agent #{agent_id})" : ''}"
        puts "  requests:      #{totals['requests']}"
        puts "  input tokens:  #{totals['input_tokens']}"
        puts "  output tokens: #{totals['output_tokens']}"
        puts format("  cost (USD):    %.4f", totals["cost_usd"].to_f)
        puts "  unpriced:      #{totals['unpriced_requests']}"

        by_model = rollup["by_model"] || []
        if by_model.empty?
          puts "\nNo usage in this period."
          return 0
        end

        puts "\nBy model:"
        by_model.each do |m|
          puts format("  %s/%s  %s req  in %s  out %s  $%.4f",
                      m["provider"], m["model"], m["requests"],
                      m["input_tokens"], m["output_tokens"], m["cost_usd"].to_f)
        end
        0
      end
    end
  end
end
