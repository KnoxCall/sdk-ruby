module KnoxCall
  module Resources
    # AI Gateway control plane (server: src/client-api/ai-gateway.ts).
    #
    # A gateway holds one or more agents; each agent mints capability tokens
    # used by the AI egress data plane. Following this SDK's convention for a
    # resource with sub-collections (see routes/vaults), the sub-collections
    # are FLAT methods on one resource, grouped by prefix:
    # +*_gateway+, +*_agent+, +*_token+, plus {#usage}.
    #
    #   client.ai_gateway.list_gateways
    #   gw = client.ai_gateway.create_gateway(name: "Prod", slug: "prod")
    #   ag = client.ai_gateway.create_agent(gw["id"], name: "Support", slug: "support")
    #   tok = client.ai_gateway.mint_token(ag["id"], kind: "agent")
    #   tok["token"] # plaintext — shown ONCE, store it now
    #
    # The sandbox/test client (KnoxCall::Client.new(sandbox: true)) mints
    # test-env tokens server-side; no env parameter is threaded through these
    # methods.
    class AiGateway
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # -- Gateways ----------------------------------------------------------

      # Paginated. Params: page (default 1), per_page (default 20, max 100).
      # Returns the {data, meta} envelope.
      def list_gateways(**params) = @client.request("GET", "/v1/ai-gateway/gateways", query: params.empty? ? nil : params)

      # Yield every gateway, walking pages transparently. Returns a lazy
      # Enumerator when no block is given.
      def each_gateway(**params, &block)
        enum = paginate(params) { |p| list_gateways(**p) }
        block ? enum.each(&block) : enum
      end

      # body: name:, slug:, description?, budget_daily_usd?, budget_monthly_usd?,
      #       budget_overage_action? ('block' | 'warn', AIGW-150 — what happens
      #       when a cap is spent; refuses on BOTH data planes under 'block').
      def create_gateway(**input) = unwrap(@client.request("POST", "/v1/ai-gateway/gateways", body: input))
      def get_gateway(gateway_id) = unwrap(@client.request("GET", "/v1/ai-gateway/gateways/#{encode(gateway_id)}"))
      # patch: name?, description?, budget_daily_usd?, budget_monthly_usd?,
      #        budget_overage_action? ('block' | 'warn', AIGW-150).
      def update_gateway(gateway_id, **patch) = unwrap(@client.request("PATCH", "/v1/ai-gateway/gateways/#{encode(gateway_id)}", body: patch))
      # Returns {"id", "status"}.
      def delete_gateway(gateway_id) = unwrap(@client.request("DELETE", "/v1/ai-gateway/gateways/#{encode(gateway_id)}"))

      # -- Agents ------------------------------------------------------------

      # Paginated. Params: page (default 1), per_page (default 20, max 100).
      # Returns the {data, meta} envelope.
      def list_agents(gateway_id, **params) = @client.request("GET", "/v1/ai-gateway/gateways/#{encode(gateway_id)}/agents", query: params.empty? ? nil : params)

      # Yield every agent under a gateway, walking pages transparently. Returns
      # a lazy Enumerator when no block is given.
      def each_agent(gateway_id, **params, &block)
        enum = paginate(params) { |p| list_agents(gateway_id, **p) }
        block ? enum.each(&block) : enum
      end

      # body: name:, slug:, description?, primary_route_id?, provider?,
      # upstream_secret_id?, upstream?, default_model?, model_allowlist?,
      # model_denylist?, budget_daily_usd?, budget_monthly_usd?,
      # streaming_enabled?, firewall_policy_id?, pii_redact_policy_id?,
      # pii_request_mode? (off|tokenize), pii_response_mode? (redact|detokenize).
      #
      # AIGW-100: pii_request_mode: decides what happens to the PROMPT before it
      # leaves KnoxCall (default 'tokenize'); pii_response_mode: decides what
      # happens to the answer (default 'detokenize'). 'off' on the request side
      # is the only configuration on which the provider receives the real
      # value.
      #
      # provider: composes the upstream route for you, INSTEAD of primary_route_id:.
      # It is a plain string and the catalog is SERVER-side (fourteen ids at the
      # time of writing, from anthropic and openai through groq, bedrock and
      # openai-compatible); a bad value returns a 400 naming the valid set, so do
      # not mirror the list here. KnoxCall creates
      # an ai-gateway-<slug> route pointing at the provider, injecting
      # upstream_secret_id: through the envelope store, and sets default_model
      # from its pricebook default.
      #
      # upstream: is required for the four providers whose endpoint is yours
      # rather than the vendor's: azure-openai, ollama, bedrock and
      # openai-compatible. It is not defaulted: a bedrock or openai-compatible
      # agent created without upstream: is refused with a 400 at create time.
      #
      # Supply provider: or primary_route_id:, NEVER BOTH (400). Supplying
      # neither creates an agent with no upstream and no credential template,
      # whose first data-plane call 502s.
      #
      # Every agent projection -- create, get, update and the list rows -- carries
      # "agent_url": the data-plane base URL, https://{tenant}.knoxcall.com/v1/ai/{slug}.
      # Point an AI SDK's base_url there with a capability token as the API key. It
      # is server-computed rather than stored, so it MOVES when the slug changes,
      # and is "" when the tenant slug cannot be resolved -- treat empty as "not
      # available", never as a URL.
      def create_agent(gateway_id, **input) = unwrap(@client.request("POST", "/v1/ai-gateway/gateways/#{encode(gateway_id)}/agents", body: input))
      # Agents are addressed by their own id once created (not nested under the gateway).
      def get_agent(agent_id) = unwrap(@client.request("GET", "/v1/ai-gateway/agents/#{encode(agent_id)}"))
      def update_agent(agent_id, **patch) = unwrap(@client.request("PATCH", "/v1/ai-gateway/agents/#{encode(agent_id)}", body: patch))
      # Returns {"id", "status"}.
      def delete_agent(agent_id) = unwrap(@client.request("DELETE", "/v1/ai-gateway/agents/#{encode(agent_id)}"))

      # -- MCP servers -------------------------------------------------------

      # Paginated. Params: page (default 1), per_page (default 20, max 100).
      # Returns the {data, meta} envelope.
      # AIGW-151/150: an MCP server also carries `pii_redact_policy_id` (the
      # tenant policy whose recognizers apply to its tool arguments and results)
      # and the five `guardrail_webhook_*` fields (the tenant's own scanner,
      # offered BOTH directions — there is no streaming carve-out on this plane).
      # A policy or secret id this tenant does not own is refused 422.
      #
      # AIGW-152: an MCP server is a Live or a Test object. The row carries the
      # mode of the API key that created it, every read and write below is
      # confined to that key's own space (a Live key does not see a Test server
      # at all), and `sandbox` on the response is READ-ONLY — passing it to
      # create/update is ignored, never honoured.
      def list_mcp_servers(gateway_id, **params) = @client.request("GET", "/v1/ai-gateway/gateways/#{encode(gateway_id)}/mcp-servers", query: params.empty? ? nil : params)

      # Yield every MCP server under a gateway, walking pages transparently.
      # Returns a lazy Enumerator when no block is given.
      def each_mcp_server(gateway_id, **params, &block)
        enum = paginate(params) { |p| list_mcp_servers(gateway_id, **p) }
        block ? enum.each(&block) : enum
      end

      # Register an upstream MCP server. KnoxCall proxies it at the returned
      # "connect_url" and governs every tool call before it reaches the upstream.
      #
      # body: name:, slug:, upstream_url:, description?, transport?,
      # allowed_tools?, pii_inspection?, auth?.
      #
      # upstream_url must be a public https:// address — private, loopback,
      # link-local and cloud-metadata destinations are refused, because the
      # request carries your decrypted upstream credential. Every value in
      # auth[:headers] must reference a KnoxCall secret, e.g.
      # {Authorization: "Bearer {{secret_id:<uuid>}}"}; a literal credential is
      # refused with 422. allowed_tools EMPTY means the server advertises
      # nothing. server_type "collection" is not accepted — the data plane does
      # not serve it yet.
      #
      # The result carries BOTH "connect_url" (where an MCP client points) and
      # "resource" (the RFC 8707 value a token for it must be bound to).
      def create_mcp_server(gateway_id, **input) = unwrap(@client.request("POST", "/v1/ai-gateway/gateways/#{encode(gateway_id)}/mcp-servers", body: input))
      # MCP servers are addressed by their own id once created.
      def get_mcp_server(server_id) = unwrap(@client.request("GET", "/v1/ai-gateway/mcp-servers/#{encode(server_id)}"))
      # patch: name?, description?, upstream_url?, transport?, allowed_tools?,
      # pii_inspection?, auth?, status? ("active"|"paused"; DELETE archives).
      def update_mcp_server(server_id, **patch) = unwrap(@client.request("PATCH", "/v1/ai-gateway/mcp-servers/#{encode(server_id)}", body: patch))
      # Returns {"id", "status"}.
      def delete_mcp_server(server_id) = unwrap(@client.request("DELETE", "/v1/ai-gateway/mcp-servers/#{encode(server_id)}"))

      # -- MCP tools ---------------------------------------------------------

      # Paginated tool metadata rows. What a client can actually call is the
      # intersection of the server's allowed_tools, the upstream's real tools
      # and the token's own tool scope.
      def list_mcp_tools(server_id, **params) = @client.request("GET", "/v1/ai-gateway/mcp-servers/#{encode(server_id)}/tools", query: params.empty? ? nil : params)

      # Yield every tool row for a server. Lazy Enumerator when no block given.
      def each_mcp_tool(server_id, **params, &block)
        enum = paginate(params) { |p| list_mcp_tools(server_id, **p) }
        block ? enum.each(&block) : enum
      end

      # Insert or update a tool row by tool_name.
      # body: tool_name:, description?, input_schema?, enabled?.
      def upsert_mcp_tool(server_id, **input) = unwrap(@client.request("POST", "/v1/ai-gateway/mcp-servers/#{encode(server_id)}/tools", body: input))
      # patch: description?, input_schema?, enabled?.
      def update_mcp_tool(server_id, tool_id, **patch) = unwrap(@client.request("PATCH", "/v1/ai-gateway/mcp-servers/#{encode(server_id)}/tools/#{encode(tool_id)}", body: patch))
      # Returns {"id", "deleted"}.
      def delete_mcp_tool(server_id, tool_id) = unwrap(@client.request("DELETE", "/v1/ai-gateway/mcp-servers/#{encode(server_id)}/tools/#{encode(tool_id)}"))

      # -- Delegated-OAuth connections (AIGW-190) ------------------------------
      #
      # A connection holds ONE person's upstream refresh token, envelope-encrypted
      # under the tenant key. Nothing here returns it, redacted or otherwise.
      #
      # There is deliberately no #connect_mcp_server: consent has to be given by
      # the person whose credential it is, so the flow starts from a signed-in
      # KnoxCall session in the admin console. An API key is not a person.

      # One page of the people who have connected their upstream account to this
      # MCP server. Params: page, per_page. Returns the {data, meta} envelope.
      def list_mcp_grants(server_id, **params) = @client.request("GET", "/v1/ai-gateway/mcp-servers/#{encode(server_id)}/grants", query: params.empty? ? nil : params)

      # Yield every connection on this server, walking pages transparently.
      # Returns a lazy Enumerator when no block is given.
      def each_mcp_grant(server_id, **params, &block)
        enum = paginate(params) { |p| list_mcp_grants(server_id, **p) }
        block ? enum.each(&block) : enum
      end

      # Revoke ONE person's connection. The stored tokens are destroyed.
      def revoke_mcp_grant(server_id, grant_id) = unwrap(@client.request("DELETE", "/v1/ai-gateway/mcp-servers/#{encode(server_id)}/grants/#{encode(grant_id)}"))

      # Revoke EVERY connection on this server (offboarding in one call).
      def revoke_all_mcp_grants(server_id) = unwrap(@client.request("DELETE", "/v1/ai-gateway/mcp-servers/#{encode(server_id)}/grants"))

      # -- Tokens ------------------------------------------------------------

      # Paginated; never returns plaintext (the plaintext is only in
      # {#mint_token}'s response). Params: page, per_page. Returns the
      # {data, meta} envelope.
      def list_tokens(agent_id, **params) = @client.request("GET", "/v1/ai-gateway/agents/#{encode(agent_id)}/tokens", query: params.empty? ? nil : params)

      # Yield every token row for an agent, walking pages transparently.
      # Returns a lazy Enumerator when no block is given.
      def each_token(agent_id, **params, &block)
        enum = paginate(params) { |p| list_tokens(agent_id, **p) }
        block ? enum.each(&block) : enum
      end

      # Mint a capability token. body: name?, kind? (agent|read|tool|oneshot),
      # dpop_required?, dpop_jkt?, expires_in_seconds?.
    # Defaults to 30 days when omitted; clamped to [60s, 90d]. A non-expiring token cannot be minted.
    # Returns
      # {"id", "name"?, "kind", "prefix", "token", "dpop_required", "expires_at"}
      # — "token" is the plaintext credential, shown ONCE; store it now.
      def mint_token(agent_id, **input) = unwrap(@client.request("POST", "/v1/ai-gateway/agents/#{encode(agent_id)}/tokens", body: input))
      # Returns {"id", "revoked" => true}.
      def revoke_token(agent_id, token_id) = unwrap(@client.request("DELETE", "/v1/ai-gateway/agents/#{encode(agent_id)}/tokens/#{encode(token_id)}"))

      # -- Firewall policies --------------------------------------------------
      #
      # Prompt-firewall policies are TENANT-scoped and shared across gateways;
      # attach one to an agent with firewall_policy_id. An agent with no policy
      # still runs the built-in prompt-injection patterns but can never exceed
      # "warn" — attach a policy with action: "block" to have matching requests
      # refused with HTTP 400 firewall_block on the data plane.

      # Paginated. Params: page, per_page. Returns the {data, meta} envelope.
      def list_firewall_policies(**params) = @client.request("GET", "/v1/ai-gateway/firewall-policies", query: params.empty? ? nil : params)

      # Yield every firewall policy, walking pages transparently.
      def each_firewall_policy(**params, &block)
        enum = paginate(params) { |p| list_firewall_policies(**p) }
        block ? enum.each(&block) : enum
      end

      # body: name:, heuristics? ([{name:, kind: "regex"|"keyword", pattern:,
      # flags?}]), canary_enabled?, action? ("block"|"warn"|"tag", default
      # "warn"). Re-using an existing name creates version N+1.
      #
      # Every regex rule is compiled server-side with the same linear-time
      # engine the data plane runs, so lookahead/lookbehind/backreferences are a
      # 400 here rather than a rule that silently matches nothing at scan time.
      def create_firewall_policy(**input) = unwrap(@client.request("POST", "/v1/ai-gateway/firewall-policies", body: input))

      def get_firewall_policy(policy_id) = unwrap(@client.request("GET", "/v1/ai-gateway/firewall-policies/#{encode(policy_id)}"))

      # Updates in place — the version is NOT bumped. Rules are re-validated.
      def update_firewall_policy(policy_id, **patch) = unwrap(@client.request("PATCH", "/v1/ai-gateway/firewall-policies/#{encode(policy_id)}", body: patch))

      # Refused with 409 policy_in_use while any agent or MCP server is still
      # attached. Returns {"id", "deleted" => true}.
      def delete_firewall_policy(policy_id) = unwrap(@client.request("DELETE", "/v1/ai-gateway/firewall-policies/#{encode(policy_id)}"))

      # Dry-run rules against sample text; saves nothing. Rules are compiled
      # first, so this refuses exactly what create/update refuse. Returns
      # {"matched", "matches" => [{"rule", "span", "matched"}], "skipped" => []}.
      def test_firewall_rules(text:, heuristics: nil)
        body = { text: text }
        body[:heuristics] = heuristics unless heuristics.nil?
        unwrap(@client.request("POST", "/v1/ai-gateway/firewall-policies/test", body: body))
      end
      # Every token under a gateway, INCLUDING gateway-level tokens with no
      # agent (the shape POST /v1/oauth/token mints for MCP). {#list_tokens}
      # filters on the agent and cannot see them. Plaintext is never returned.
      def list_gateway_tokens(gateway_id, **params) = @client.request("GET", "/v1/ai-gateway/gateways/#{encode(gateway_id)}/tokens", query: params.empty? ? nil : params)

      # Yield every token under a gateway. Lazy Enumerator when no block given.
      def each_gateway_token(gateway_id, **params, &block)
        enum = paginate(params) { |p| list_gateway_tokens(gateway_id, **p) }
        block ? enum.each(&block) : enum
      end

      # Revoke any token under a gateway, including a gateway-level one. Use
      # this rather than {#revoke_token} for a token minted by
      # POST /v1/oauth/token: that token has no agent, so the per-agent revoke
      # can never match it. Returns {"id", "revoked"}.
      def revoke_gateway_token(gateway_id, token_id) = unwrap(@client.request("DELETE", "/v1/ai-gateway/gateways/#{encode(gateway_id)}/tokens/#{encode(token_id)}"))

      # -- PII policies -------------------------------------------------------
      #
      # PII redaction policies are TENANT-scoped and shared across gateways,
      # exactly like firewall policies; attach one to an agent with
      # pii_redact_policy_id. Until AIGW-160 they lived only on the admin plane,
      # so {#create_agent} accepted a pii_redact_policy_id that no /v1 call
      # could produce.
      #
      # A policy row is {"id", "tenant_id", "name", "version",
      # "recognizer_ids" => [uuid], "default_action" ("redact"|"tokenize"|
      # "whitelist"|"warn"), "description" (may be nil), "created_at"}.

      # Paginated. Params: page, per_page. Returns the {data, meta} envelope.
      def list_pii_policies(**params) = @client.request("GET", "/v1/ai-gateway/pii-policies", query: params.empty? ? nil : params)

      # Yield every PII policy, walking pages transparently. Returns a lazy
      # Enumerator when no block is given.
      def each_pii_policy(**params, &block)
        enum = paginate(params) { |p| list_pii_policies(**p) }
        block ? enum.each(&block) : enum
      end

      # body: name:, recognizer_ids? ([uuid]), default_action? (default
      # "redact"), description?.
      #
      # An EMPTY recognizer_ids means "every enabled recognizer this tenant
      # owns", NOT "none" — omitting the field gives you the WIDEST policy, not
      # an inert one. Every id you do list must be a recognizer this tenant
      # owns: a foreign or unknown id is a 400 recognizer_not_found at write
      # time, rather than a stored value that resolves to nothing at scan time
      # and quietly runs fewer detectors than the policy names.
      def create_pii_policy(**input) = unwrap(@client.request("POST", "/v1/ai-gateway/pii-policies", body: input))

      def get_pii_policy(policy_id) = unwrap(@client.request("GET", "/v1/ai-gateway/pii-policies/#{encode(policy_id)}"))

      # Updates in place — the version is NOT bumped. patch: recognizer_ids?,
      # default_action?, description?. recognizer_ids is re-validated the same
      # way, and an empty array still means "every enabled recognizer".
      def update_pii_policy(policy_id, **patch) = unwrap(@client.request("PATCH", "/v1/ai-gateway/pii-policies/#{encode(policy_id)}", body: patch))

      # Refused with 409 policy_in_use while any agent still references it. The
      # foreign key is ON DELETE SET NULL, so an unchecked delete would detach
      # every bound agent and turn redaction OFF for each of them with no error
      # anywhere. Detach the agents first. Returns {"id", "deleted" => true}.
      def delete_pii_policy(policy_id) = unwrap(@client.request("DELETE", "/v1/ai-gateway/pii-policies/#{encode(policy_id)}"))

      # -- PII recognizers ----------------------------------------------------
      #
      # A recognizer is one tenant-defined detector: {"id", "tenant_id", "name",
      # "kind" ("regex"|"aho_corasick"|"presidio_pattern"|"presidio_ner"|
      # "presidio_custom"), "pattern", "context_words" => [String] (words that
      # must appear nearby for a match to count), "confidence" (Float),
      # "action", "format" (token format for "tokenize", nil otherwise),
      # "enabled", "created_at"}. enabled: false mutes a recognizer without
      # losing its definition.

      # Paginated. Params: page, per_page. Returns the {data, meta} envelope.
      def list_pii_recognizers(**params) = @client.request("GET", "/v1/ai-gateway/pii-recognizers", query: params.empty? ? nil : params)

      # Yield every PII recognizer, walking pages transparently. Returns a lazy
      # Enumerator when no block is given.
      def each_pii_recognizer(**params, &block)
        enum = paginate(params) { |p| list_pii_recognizers(**p) }
        block ? enum.each(&block) : enum
      end

      # body: name:, kind:, pattern:, context_words?, confidence? (0-1, default
      # 0.85), action?, format?, enabled?.
      #
      # A "regex" pattern is compiled server-side with the same linear-time
      # engine the data plane runs, so lookahead, lookbehind and backreferences
      # are a 400 here rather than a recognizer that is silently skipped at scan
      # time (fail open). action "whitelist" exempts the matched shape from
      # every OTHER detector, so a whitelist pattern that matches arbitrary text
      # is a kill switch for the built-in tier and the server refuses it.
      def create_pii_recognizer(**input) = unwrap(@client.request("POST", "/v1/ai-gateway/pii-recognizers", body: input))

      # Dry-run a candidate pattern against sample text; saves nothing.
      # +pattern+ and +text+ are required; kind:, action:, context_words: and
      # name: are optional.
      #
      # It compiles with the SAME engine the data plane runs, so a pattern that
      # passes here is one that will actually execute. Do NOT preview with a
      # local Regexp: Ruby accepts lookahead, lookbehind and backreferences the
      # server refuses, so a local preview shows matches for a recognizer that
      # can never run and then 400s on save.
      #
      # Returns {"matched", "matches" => [{"span" => [start, stop], "matched",
      # "replacement", "entity_type"}]}.
      def test_pii_recognizer(pattern:, text:, kind: nil, action: nil, context_words: nil, name: nil)
        body = { pattern: pattern, text: text }
        body[:kind] = kind unless kind.nil?
        body[:action] = action unless action.nil?
        body[:context_words] = context_words unless context_words.nil?
        body[:name] = name unless name.nil?
        unwrap(@client.request("POST", "/v1/ai-gateway/pii-recognizers/test", body: body))
      end

      def get_pii_recognizer(recognizer_id) = unwrap(@client.request("GET", "/v1/ai-gateway/pii-recognizers/#{encode(recognizer_id)}"))

      # The server validates the MERGED state, not the patch, so
      # action: "whitelist" on its own is still checked against the STORED
      # pattern. patch: any of the create fields.
      def update_pii_recognizer(recognizer_id, **patch) = unwrap(@client.request("PATCH", "/v1/ai-gateway/pii-recognizers/#{encode(recognizer_id)}", body: patch))

      # Refused with 409 recognizer_in_use while any PII policy still lists it:
      # an empty recognizer_ids means "every enabled recognizer", so dropping
      # the id would WIDEN each listing policy rather than shrink it. Remove it
      # from every policy first. Returns {"id", "deleted" => true}.
      def delete_pii_recognizer(recognizer_id) = unwrap(@client.request("DELETE", "/v1/ai-gateway/pii-recognizers/#{encode(recognizer_id)}"))

      # -- Usage -------------------------------------------------------------

      # Cost/token usage rollup. Params: period ("7d"|"30d"|"90d"), agent_id?.
      # Returns {"period_days", "by_model" => [{"provider", "model", "requests",
      # "input_tokens", "output_tokens", "cost_usd", "unpriced_requests"}],
      # "totals" => {...}}.
      def usage(**params) = unwrap(@client.request("GET", "/v1/ai-gateway/usage", query: params.empty? ? nil : params))

      # FinOps export: aggregated spend grouped by user|team|agent|model|
      # provider|"tag:<key>", over a period. +group_by+ is required; +period+
      # ("7d"|"30d"|"90d") and +agent_id+ are optional. The SDK always sends
      # format=json (nil optionals are dropped by the client's query compaction).
      # Returns {"group_by", "period_days", "rows" => [{"group", "requests",
      # "input_tokens", "output_tokens", "cost_usd", "unpriced_requests"}]}.
      def export_usage(group_by:, period: nil, agent_id: nil)
        query = { group_by: group_by, period: period, agent_id: agent_id, format: "json" }
        unwrap(@client.request("GET", "/v1/ai-gateway/usage/export", query: query))
      end
    end
  end
end
