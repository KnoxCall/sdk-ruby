# Resource-layer envelope handling (PARITY §4/§11): the server wraps every
# JSON response in {data, meta}; single-object methods unwrap `data`,
# paginated lists return the envelope and take page/per_page, bare-array
# endpoints unwrap to plain arrays, the each/each_* auto-pagers walk pages.
# Every mock here is the REAL server shape (src/client-api/helpers.ts) —
# never a bare object, never a cursor.

RSpec.describe "KnoxCall resources" do
  RES_API = "https://api.example.test".freeze

  # A pre-acquired kc_ token: no token-endpoint round trip, so stub #N is
  # API call #N.
  def new_client(**opts)
    KnoxCall::Client.new(
      tenant: "acme",
      base_url: RES_API,
      proxy_base_url: "https://acme.example.test",
      api_key: "kc_live_x",
      retry_base_delay: 0.001,
      **opts
    )
  end

  # success(res, data, meta?) — {data, meta: {request_id}}
  def envelope(data)
    { data: data, meta: { request_id: "req-#{rand(10_000)}" } }
  end

  # paginated(res, data[], total, page, perPage) — meta carries the page math
  def paginated(rows, total:, page:, per_page:)
    {
      data: rows,
      meta: {
        total: total, page: page, per_page: per_page,
        total_pages: (total.to_f / per_page).ceil, request_id: "req-#{rand(10_000)}"
      }
    }
  end

  def stub_json(method, url, payload, status: 200)
    stub_request(method, url).to_return(
      status: status, body: JSON.generate(payload),
      headers: { "Content-Type" => "application/json" }
    )
  end

  # -- Envelope & pagination ---------------------------------------------------------

  describe "envelope and pagination" do
    it "returns the envelope from a paginated list and sends page params" do
      stub = stub_json(:get, "#{RES_API}/v1/routes?page=2&per_page=2&collection_id=c_9",
                       paginated([{ id: "r_1" }, { id: "r_2" }], total: 42, page: 2, per_page: 2))

      page = new_client.routes.list(page: 2, per_page: 2, collection_id: "c_9")

      expect(stub).to have_been_requested.once
      expect(page["data"]).to eq([{ "id" => "r_1" }, { "id" => "r_2" }])
      expect(page["meta"]["total"]).to eq(42)
      expect(page["meta"]["total_pages"]).to eq(21)
    end

    it "unwraps single-object responses (no ['data'] indirection)" do
      stub_json(:get, "#{RES_API}/v1/routes/r_1",
                envelope({ id: "r_1", name: "orders", slug: "default-orders" }))

      route = new_client.routes.get("r_1")

      expect(route["name"]).to eq("orders")
      expect(route).not_to have_key("data")
      expect(route).not_to have_key("meta")
    end

    it "unwraps delete to the deleted flag" do
      stub_json(:delete, "#{RES_API}/v1/routes/r_1", envelope({ deleted: true }))
      expect(new_client.routes.delete("r_1")).to eq("deleted" => true)
    end

    it "walks all pages with each and stops at total_pages" do
      stub_json(:get, "#{RES_API}/v1/routes?page=1&per_page=2",
                paginated([{ id: "r_1" }, { id: "r_2" }], total: 5, page: 1, per_page: 2))
      stub_json(:get, "#{RES_API}/v1/routes?page=2&per_page=2",
                paginated([{ id: "r_3" }, { id: "r_4" }], total: 5, page: 2, per_page: 2))
      last = stub_json(:get, "#{RES_API}/v1/routes?page=3&per_page=2",
                       paginated([{ id: "r_5" }], total: 5, page: 3, per_page: 2))

      ids = []
      new_client.routes.each(per_page: 2) { |route| ids << route["id"] }

      expect(ids).to eq(%w[r_1 r_2 r_3 r_4 r_5])
      expect(last).to have_been_requested.once # exactly total_pages fetches, no page 4
    end

    it "stops each defensively on an empty page" do
      # meta claims more pages, but an empty page must stop the walk.
      stub_json(:get, "#{RES_API}/v1/secrets?page=1&per_page=1",
                paginated([{ id: "s_1" }], total: 50, page: 1, per_page: 1))
      empty = stub_json(:get, "#{RES_API}/v1/secrets?page=2&per_page=1",
                        paginated([], total: 50, page: 2, per_page: 1))

      rows = new_client.secrets.each(per_page: 1).to_a

      expect(rows.length).to eq(1)
      expect(empty).to have_been_requested.once
    end

    it "starts each at the requested page" do
      stub_json(:get, "#{RES_API}/v1/vaults?page=3&per_page=1",
                paginated([{ id: "v_3" }], total: 3, page: 3, per_page: 1))

      rows = new_client.vaults.each(page: 3, per_page: 1).to_a

      expect(rows).to eq([{ "id" => "v_3" }])
    end

    it "returns a lazy Enumerator when each is given no block" do
      first_page = stub_json(:get, "#{RES_API}/v1/routes?page=1&per_page=2",
                             paginated([{ id: "r_1" }, { id: "r_2" }], total: 6, page: 1, per_page: 2))

      enum = new_client.routes.each(per_page: 2)
      expect(enum).to be_a(Enumerator)
      expect(first_page).not_to have_been_requested # nothing fetched yet

      expect(enum.take(2).map { |r| r["id"] }).to eq(%w[r_1 r_2])
      expect(first_page).to have_been_requested.once # and page 2 never fetched
    end

    it "walks sub-list pages with each_log" do
      stub_json(:get, "#{RES_API}/v1/routes/r_1/logs?page=1&per_page=1",
                paginated([{ id: "l_1" }], total: 2, page: 1, per_page: 1))
      stub_json(:get, "#{RES_API}/v1/routes/r_1/logs?page=2&per_page=1",
                paginated([{ id: "l_2" }], total: 2, page: 2, per_page: 1))

      ids = new_client.routes.each_log("r_1", per_page: 1).map { |l| l["id"] }
      expect(ids).to eq(%w[l_1 l_2])
    end

    it "unwraps bare-array endpoints to plain arrays without page params" do
      client = new_client
      rows = [{ "id" => "x_1" }, { "id" => "x_2" }]
      calls = {
        "/v1/environments" => -> { client.environments.list },
        "/v1/agents" => -> { client.agents.list },
        "/v1/crypto/keys" => -> { client.crypto.list_keys },
        "/v1/routes/r_1/environments" => -> { client.routes.list_environments("r_1") },
        "/v1/clients/c_1/credentials" => -> { client.clients.list_credentials("c_1") },
        "/v1/dyn-db-credentials" => -> { client.dynamic_db.list },
        "/v1/pki/roots" => -> { client.pki.list_roots }
      }
      calls.each do |path, call|
        # An exact-URL stub (no query) proves no pagination params are sent.
        stub_json(:get, "#{RES_API}#{path}", envelope(rows))
        expect(call.call).to eq(rows), path
      end
    end
  end

  # -- Route field-actions --------------------------------------------------------

  describe "route field-actions" do
    it "lists, creates, and deletes actions" do
      client = new_client
      stub_json(:get, "#{RES_API}/v1/routes/r_1/actions",
                envelope([{ id: "a_1", direction: "request", action: "encrypt" }]))
      actions = client.routes.list_actions("r_1")
      expect(actions.first["id"]).to eq("a_1")

      created_body = nil
      stub_request(:post, "#{RES_API}/v1/routes/r_1/actions")
        .with { |req| created_body = JSON.parse(req.body); true }
        .to_return(status: 200, body: JSON.generate(envelope({ id: "a_2", direction: "response", action: "decrypt" })))
      created = client.routes.create_action("r_1", direction: "response", action: "decrypt",
                                                   selectors: ["$.card.number"])
      expect(created_body["selectors"]).to eq(["$.card.number"])
      expect(created["id"]).to eq("a_2")

      stub_json(:delete, "#{RES_API}/v1/routes/r_1/actions/a_2", envelope({ deleted: "a_2" }))
      expect(client.routes.delete_action("r_1", "a_2")).to eq("deleted" => "a_2")
    end
  end

  # -- Portable kc: encryption -------------------------------------------------------

  describe "portable encryption" do
    it "covers encrypt_data / decrypt_data / inspect / mint_client_token / get_sealing_bundle" do
      client = new_client

      sent = nil
      stub_request(:post, "#{RES_API}/v1/encrypt")
        .with { |req| sent = JSON.parse(req.body); true }
        .to_return(status: 200, body: JSON.generate(
          envelope({ ciphertext: { ssn: "kc:v1:abc" }, key: "app-default", key_version: 3 })
        ))
      out = client.crypto.encrypt_data({ ssn: "123-45-6789" }, key: "app-default", role: "pii")
      expect(sent).to eq("data" => { "ssn" => "123-45-6789" }, "key" => "app-default", "role" => "pii")
      expect(out["ciphertext"]["ssn"]).to eq("kc:v1:abc")
      expect(out["key_version"]).to eq(3)

      stub_json(:post, "#{RES_API}/v1/decrypt", envelope({ plaintext: { ssn: "123-45-6789" } }))
      out = client.crypto.decrypt_data({ ssn: "kc:v1:abc" })
      expect(out["plaintext"]["ssn"]).to eq("123-45-6789")

      stub_json(:post, "#{RES_API}/v1/inspect", envelope({ encrypted: true, scheme: "ecies-p256", version: 1 }))
      out = client.crypto.inspect("kc:v1:abc")
      expect(out["encrypted"]).to be(true)

      stub_json(:post, "#{RES_API}/v1/client-tokens",
                envelope({ token: "kct_once", expires_at: "2026-07-02T00:05:00Z", action: "decrypt" }))
      out = client.crypto.mint_client_token(action: "decrypt", data: "kc:v1:abc", ttl_seconds: 300)
      expect(out["token"]).to eq("kct_once")

      stub_json(:get, "#{RES_API}/v1/encrypt/sealing-bundle?key=app-default",
                envelope({ public_key: "BJf...", key_ref: { appKeyId: "k_1" } }))
      out = client.crypto.get_sealing_bundle(key: "app-default")
      expect(out["key_ref"]["appKeyId"]).to eq("k_1")
    end

    it "keeps crypto.inspect with no argument as Object#inspect (no HTTP)" do
      expect(new_client.crypto.inspect).to match(/KnoxCall::Resources::Crypto/)
    end
  end

  # -- Crypto path fidelity (server: src/client-api/crypto.ts) -------------------------

  describe "crypto endpoint paths" do
    it "matches the server's jwt / jwt-verify / webhook-sign paths" do
      client = new_client

      jwt = stub_json(:post, "#{RES_API}/v1/crypto/keys/signing-key/jwt",
                      envelope({ token: "eyJ...", key_version: 1, alg: "ES256" }))
      client.crypto.sign_jwt("signing-key", { sub: "user_1" })
      expect(jwt).to have_been_requested.once

      verify = stub_json(:post, "#{RES_API}/v1/crypto/keys/signing-key/jwt/verify",
                         envelope({ valid: true, claims: { sub: "user_1" } }))
      out = client.crypto.verify_jwt("signing-key", "eyJ...")
      expect(verify).to have_been_requested.once
      expect(out["valid"]).to be(true)

      whs = stub_json(:post, "#{RES_API}/v1/crypto/keys/signing-key/webhook-sign",
                      envelope({ signature_header: "t=1,v1=aa", timestamp_seconds: 1,
                                 key_version: 1, format: "stripe" }))
      client.crypto.sign_webhook("signing-key", payload: "{}")
      expect(whs).to have_been_requested.once
    end

    it "sends decrypt format and public-key version as query params" do
      client = new_client

      sent = nil
      stub_request(:post, "#{RES_API}/v1/crypto/keys/transit-key/decrypt?format=utf8")
        .with { |req| sent = JSON.parse(req.body); true }
        .to_return(status: 200, body: JSON.generate(envelope({ plaintext: "hi", key_version: 1 })))
      out = client.crypto.decrypt("transit-key", ciphertext: "vault:v1:abc", format: "utf8")
      expect(sent).to eq("ciphertext" => "vault:v1:abc") # format travels as query, not body
      expect(out["plaintext"]).to eq("hi")

      pub = stub_json(:get, "#{RES_API}/v1/crypto/keys/signing-key/public-key?version=2",
                      envelope({ pem: "-----BEGIN PUBLIC KEY-----", jwk: {}, key_version: 2 }))
      client.crypto.get_public_key("signing-key", version: 2)
      expect(pub).to have_been_requested.once
    end
  end

  # -- PKI ---------------------------------------------------------------------------

  describe "pki" do
    it "returns raw PEM text and uses the server's paths" do
      client = new_client
      pem = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"

      stub_request(:get, "#{RES_API}/v1/pki/roots/internal-ca/cert")
        .to_return(status: 200, body: pem, headers: { "Content-Type" => "text/x-pem-file" })
      expect(client.pki.get_root_cert("internal-ca")).to eq(pem) # raw text, no JSON wrapper

      rotate = stub_json(:post, "#{RES_API}/v1/pki/roots/internal-ca/rotate-intermediate",
                         envelope({ intermediate_id: "i_2", not_after: "2027-07-02T00:00:00Z" }))
      out = client.pki.rotate_intermediate("internal-ca")
      expect(rotate).to have_been_requested.once
      expect(out["intermediate_id"]).to eq("i_2")

      issued_body = nil
      stub_request(:post, "#{RES_API}/v1/pki/roots/internal-ca/issue/web-servers")
        .with { |req| issued_body = JSON.parse(req.body); true }
        .to_return(status: 200, body: JSON.generate(envelope(
          { serial_hex: "ab12", cert_pem: "CERT", private_key_pem: "KEY",
            ca_chain_pem: "CHAIN", not_before: "x", not_after: "y" }
        )))
      issued = client.pki.issue_cert("internal-ca", "web-servers", common_name: "api.internal.test")
      expect(issued_body["common_name"]).to eq("api.internal.test")
      expect(issued["serial_hex"]).to eq("ab12")

      revoke_body = nil
      stub_request(:post, "#{RES_API}/v1/pki/roots/internal-ca/revoke")
        .with { |req| revoke_body = JSON.parse(req.body); true }
        .to_return(status: 200, body: JSON.generate(envelope({ revoked: true })))
      client.pki.revoke_cert("internal-ca", "ab12", reason: "compromised")
      expect(revoke_body).to eq("serial_hex" => "ab12", "reason" => "compromised")
    end
  end

  # -- OAuth clients (no meta; top-level warning folded in) -----------------------------

  describe "oauth clients" do
    it "unwraps the meta-less endpoints and folds the warning in" do
      client = new_client

      # list: {data: rows}, no meta, NO pagination
      stub_json(:get, "#{RES_API}/v1/oauth-clients",
                { data: [{ id: "oc_1", client_id: "kc_client_1" }] })
      expect(client.oauth_clients.list.first["client_id"]).to eq("kc_client_1")

      # create: {data: {...}, warning?: str} — warning folded into the result
      stub_json(:post, "#{RES_API}/v1/oauth-clients", {
                  data: { id: "oc_2", client_id: "kc_client_2", client_secret: "shh" },
                  warning: "Store this secret now; it cannot be shown again."
                }, status: 201)
      created = client.oauth_clients.create(name: "ci", grant_types: ["client_credentials"])
      expect(created["client_id"]).to eq("kc_client_2")
      expect(created["warning"]).to eq("Store this secret now; it cannot be shown again.")

      stub_json(:post, "#{RES_API}/v1/oauth-clients/oc_2/rotate-secret", {
                  data: { client_id: "kc_client_2", client_secret: "shh2" },
                  warning: "Old secret invalidated."
                })
      rotated = client.oauth_clients.rotate_secret("oc_2")
      expect(rotated["client_secret"]).to eq("shh2")
      expect(rotated["warning"]).to eq("Old secret invalidated.")

      stub_json(:delete, "#{RES_API}/v1/oauth-clients/oc_2", { data: { revoked: true } })
      expect(client.oauth_clients.revoke("oc_2")).to eq("revoked" => true)
    end
  end

  # -- Agents (hand-rolled 201 with once-only secret) -------------------------------------

  describe "agents" do
    it "unwraps create's once-only agent_secret" do
      stub_json(:post, "#{RES_API}/v1/agents", {
                  data: { id: "ag_1", name: "ci-agent", agent_id: "agent_abc", status: "active",
                          require_verified_build: false, created_at: "x", agent_secret: "as_once" },
                  meta: { secret_shown_once: true }
                }, status: 201)

      agent = new_client.agents.create("ci-agent")

      expect(agent["agent_secret"]).to eq("as_once")
      expect(agent).not_to have_key("meta")
    end
  end

  # -- Dynamic DB (leases keep real limit/offset inside data) ------------------------------

  describe "dynamic db" do
    it "unwraps leases with their limit/offset pagination inside data" do
      client = new_client
      stub_json(:get, "#{RES_API}/v1/dyn-db-credentials/leases?limit=10&offset=0&connection=analytics-db",
                envelope({ leases: [{ id: 7, status: "active" }], total: 1, limit: 10, offset: 0 }))

      out = client.dynamic_db.list_leases(limit: 10, offset: 0, connection: "analytics-db")
      expect(out["leases"].first["id"]).to eq(7)
      expect(out["total"]).to eq(1)

      stub_json(:post, "#{RES_API}/v1/dyn-db-credentials/leases/7/revoke", envelope({ revoked: 7 }))
      expect(client.dynamic_db.revoke_lease(7)).to eq("revoked" => 7)
    end
  end

  # -- Vault token pagination ---------------------------------------------------------

  describe "vault tokens" do
    it "paginates list_tokens and walks pages with each_token" do
      client = new_client

      stub_json(:get, "#{RES_API}/v1/vaults/cards/tokens?page=2&per_page=1",
                paginated([{ id: "t_1" }], total: 3, page: 2, per_page: 1))
      page = client.vaults.list_tokens("cards", page: 2, per_page: 1)
      expect(page["data"].first["id"]).to eq("t_1")

      WebMock.reset!
      stub_json(:get, "#{RES_API}/v1/vaults/cards/tokens?page=1&per_page=1",
                paginated([{ id: "t_1" }], total: 2, page: 1, per_page: 1))
      stub_json(:get, "#{RES_API}/v1/vaults/cards/tokens?page=2&per_page=1",
                paginated([{ id: "t_2" }], total: 2, page: 2, per_page: 1))
      ids = client.vaults.each_token("cards", per_page: 1).map { |t| t["id"] }
      expect(ids).to eq(%w[t_1 t_2])
    end

    it "unwraps vault delete to the deleted boolean (server contract)" do
      stub_json(:delete, "#{RES_API}/v1/vaults/cards", envelope({ deleted: true }))
      expect(new_client.vaults.delete("cards")).to eq("deleted" => true)
    end

    it "unwraps vault token delete to the deleted boolean (server contract)" do
      stub_json(:delete, "#{RES_API}/v1/vaults/cards/tokens/t_1", envelope({ deleted: true }))
      expect(new_client.vaults.delete_token("cards", "t_1")).to eq("deleted" => true)
    end
  end

  # -- Webhooks management ---------------------------------------------------------------

  describe "webhooks management" do
    it "unwraps event types and test deliveries" do
      client = new_client

      stub_json(:get, "#{RES_API}/v1/webhooks/event-types", envelope(
                  { event_types: [{ value: "request.success", label: "Request success", description: "..." }] }
                ))
      out = client.webhooks.list_event_types
      expect(out["event_types"].first["value"]).to eq("request.success")

      stub_json(:post, "#{RES_API}/v1/webhooks/wh_1/test",
                envelope({ success: true, status: 200, response_time_ms: 31 }))
      out = client.webhooks.test("wh_1")
      expect(out["success"]).to be(true)
    end
  end

  # -- Account -----------------------------------------------------------------------------

  describe "account" do
    it "unwraps get and get_usage" do
      client = new_client
      stub_json(:get, "#{RES_API}/v1/account",
                envelope({ id: "tn_1", slug: "acme", subscription_plan: "free" }))
      account = client.account.get
      expect(account["slug"]).to eq("acme")
      expect(account).not_to have_key("data")

      stub_json(:get, "#{RES_API}/v1/account/usage",
                envelope({ plan: "free", api_calls: { used: 1, limit: 1000, percentage: 0 } }))
      expect(client.account.get_usage["api_calls"]["used"]).to eq(1)
    end
  end

  # -- Wrap-credential escrow (POST /v1/wrap/credentials) ----------------------------------

  describe "wrap credential escrow" do
    it "posts provider/name/value/hosts and unwraps the metadata (value never returned)" do
      client = new_client

      sent = nil
      stub_request(:post, "#{RES_API}/v1/wrap/credentials")
        .with { |req| sent = JSON.parse(req.body); true }
        .to_return(status: 201, body: JSON.generate(envelope(
          { secret_id: "sec_1", name: "stripe-key", provider: "stripe",
            allowed_hosts: ["api.stripe.com"], sandbox: false }
        )), headers: { "Content-Type" => "application/json" })

      out = client.wrap.escrow(provider: "stripe", name: "stripe-key",
                               value: "sk_live_raw_secret", hosts: ["api.stripe.com"])

      # The request carries exactly the four contract fields, value included once.
      expect(sent).to eq(
        "provider" => "stripe", "name" => "stripe-key",
        "value" => "sk_live_raw_secret", "hosts" => ["api.stripe.com"]
      )
      # The envelope is unwrapped to bare metadata; the raw value is never echoed.
      expect(out["secret_id"]).to eq("sec_1")
      expect(out["allowed_hosts"]).to eq(["api.stripe.com"])
      expect(out["sandbox"]).to be(false)
      expect(out).not_to have_key("data")
      expect(out).not_to have_key("meta")
      expect(out).not_to have_key("value")
    end
  end

  # -- Wrap-gateway management (POST/GET/DELETE /v1/wrap/tokens) ----------------------------

  describe "wrap gateway tokens" do
    WG_ID = "wgt_9a2f".freeze

    it "mints a gateway token, sending secret always and only the supplied optionals" do
      client = new_client

      sent = nil
      stub_request(:post, "#{RES_API}/v1/wrap/tokens")
        .with { |req| sent = JSON.parse(req.body); true }
        .to_return(status: 201, body: JSON.generate(envelope(
          { id: WG_ID, token: "wgt_secret_bearer", base_url: "https://api.example.test/wg/wgt_secret_bearer/api.stripe.com",
            host: "api.stripe.com", secret_id: "sec_1", sandbox: false,
            expires_at: "2026-09-01T00:00:00Z" }
        )), headers: { "Content-Type" => "application/json" })

      out = client.wrap.gateway_url(secret: "stripe-key", host: "api.stripe.com", ttl_seconds: 3600)

      # secret is always sent; label was nil so it's compacted out; ttl travels snake_case.
      expect(sent).to eq("secret" => "stripe-key", "host" => "api.stripe.com", "ttl_seconds" => 3600)
      expect(out["id"]).to eq(WG_ID)
      expect(out["token"]).to eq("wgt_secret_bearer")
      expect(out["base_url"]).to include("/wg/")
      expect(out["secret_id"]).to eq("sec_1")
      expect(out["expires_at"]).to eq("2026-09-01T00:00:00Z")
      expect(out).not_to have_key("data")
      expect(out).not_to have_key("meta")
    end

    it "gateway_url with only the required secret POSTs a single-key body" do
      client = new_client
      sent = nil
      stub_request(:post, "#{RES_API}/v1/wrap/tokens")
        .with { |req| sent = JSON.parse(req.body); true }
        .to_return(status: 201, body: JSON.generate(envelope(
          { id: WG_ID, token: "t", base_url: "https://api.example.test/wg/t/api.stripe.com",
            host: "api.stripe.com", secret_id: "sec_1", sandbox: false, expires_at: nil }
        )), headers: { "Content-Type" => "application/json" })

      client.wrap.gateway_url(secret: "stripe-key")

      expect(sent).to eq("secret" => "stripe-key") # host/ttl_seconds/label/style all compacted away
    end

    it "forwards style and surfaces base_url_style when a style is requested" do
      client = new_client
      sent = nil
      stub_request(:post, "#{RES_API}/v1/wrap/tokens")
        .with { |req| sent = JSON.parse(req.body); true }
        .to_return(status: 201, body: JSON.generate(envelope(
          { id: WG_ID, token: "t", base_url: "https://acme.wrap.example.test",
            base_url_style: "subdomain", host: "api.stripe.com", secret_id: "sec_1",
            sandbox: false, expires_at: nil }
        )), headers: { "Content-Type" => "application/json" })

      out = client.wrap.gateway_url(secret: "stripe-key", host: "api.stripe.com", style: "subdomain")

      expect(sent).to eq("secret" => "stripe-key", "host" => "api.stripe.com", "style" => "subdomain")
      expect(out["base_url_style"]).to eq("subdomain")
    end

    it "omits style from the body when it is not supplied (additive, opt-in)" do
      client = new_client
      sent = nil
      stub_request(:post, "#{RES_API}/v1/wrap/tokens")
        .with { |req| sent = JSON.parse(req.body); true }
        .to_return(status: 201, body: JSON.generate(envelope(
          { id: WG_ID, token: "t", base_url: "https://api.example.test/wg/t/api.stripe.com",
            host: "api.stripe.com", secret_id: "sec_1", sandbox: false, expires_at: nil }
        )), headers: { "Content-Type" => "application/json" })

      client.wrap.gateway_url(secret: "stripe-key", host: "api.stripe.com")

      expect(sent).not_to have_key("style")
    end

    it "lists gateway tokens as metadata only (the token is never returned)" do
      client = new_client
      stub_json(:get, "#{RES_API}/v1/wrap/tokens", envelope({ tokens: [
        { id: WG_ID, secret_id: "sec_1", host: "api.stripe.com", label: "prod",
          created_at: "t", expires_at: nil, revoked_at: nil, last_used_at: nil }
      ] }))

      tokens = client.wrap.list_gateway_tokens

      expect(tokens).to be_an(Array)
      expect(tokens.first["id"]).to eq(WG_ID)
      expect(tokens.first["host"]).to eq("api.stripe.com")
      expect(tokens.first).not_to have_key("token") # metadata only
    end

    it "fetches the intercept manifest and forwards the environment only when asked" do
      client = new_client
      manifest = {
        version: "sha256:abc", ttl_seconds: 60, environment: "production", sandbox: false,
        routes: [{ host: "api.hubapi.com", base_path: "/crm/v3", slug: "hubspot", route_id: "r-1",
                   requires_clients: false, allowed_methods: nil, updated_at: "2026-09-25T00:00:00.000Z" }]
      }
      stub_json(:get, "#{RES_API}/v1/wrap/intercept-manifest", envelope(manifest))
      stub_json(:get, "#{RES_API}/v1/wrap/intercept-manifest?environment=staging",
                envelope(manifest.merge(environment: "staging")))

      m = client.wrap.intercept_manifest
      expect(m["version"]).to eq("sha256:abc")
      expect(m["ttl_seconds"]).to eq(60)
      expect(m["routes"].first["host"]).to eq("api.hubapi.com")
      expect(m["routes"].first["slug"]).to eq("hubspot")
      expect(m["routes"].first["base_path"]).to eq("/crm/v3")

      staging = client.wrap.intercept_manifest(environment: "staging")
      expect(staging["environment"]).to eq("staging")
      expect(a_request(:get, "#{RES_API}/v1/wrap/intercept-manifest?environment=staging")).to have_been_made.once
    end

    it "revokes a single gateway token by id (URL-encoded) and unwraps {id, revoked}" do
      client = new_client
      stub_json(:delete, "#{RES_API}/v1/wrap/tokens/#{WG_ID}", envelope({ id: WG_ID, revoked: true }))

      out = client.wrap.revoke_gateway_token(WG_ID)

      expect(a_request(:delete, "#{RES_API}/v1/wrap/tokens/#{WG_ID}")).to have_been_made
      expect(out).to eq("id" => WG_ID, "revoked" => true)
      expect(out).not_to have_key("data")
    end
  end

  # -- role_ids + the role catalog (IaC plan §6 item 1.3) ----------------------------------

  describe "api key roles" do
    ROLE_UUID = "b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d".freeze

    it "sends role_ids verbatim and unwraps the returned id and role_ids" do
      client = new_client
      stub_json(:post, "#{RES_API}/v1/api-keys", envelope({
        id: "f0a1b2c3-d4e5-6f7a-8b9c-0d1e2f3a4b5c",
        key_id: "tk_a1", api_key: "tk_a1_secret", key_prefix: "tk_a1",
        key_type: "standard", name: "tf", role_ids: [ROLE_UUID], message: "save it"
      }))

      created = client.api_keys.create(name: "tf", role_ids: [ROLE_UUID])

      expect(created["id"]).to eq("f0a1b2c3-d4e5-6f7a-8b9c-0d1e2f3a4b5c")
      expect(created["role_ids"]).to eq([ROLE_UUID])
      expect(a_request(:post, "#{RES_API}/v1/api-keys")
        .with(body: { name: "tf", role_ids: [ROLE_UUID] })).to have_been_made
    end

    it "lists roles with subject_kind and returns the envelope" do
      client = new_client
      stub_json(:get, "#{RES_API}/v1/roles?subject_kind=api_key", paginated([{
        id: ROLE_UUID, name: "Key — Infrastructure", description: nil,
        applies_to: ["api_key"], is_default: false, seeded: true
      }], total: 1, page: 1, per_page: 20))

      page = client.roles.list(subject_kind: "api_key")

      expect(page["data"][0]["seeded"]).to be(true)
      expect(page["data"][0]["applies_to"]).to eq(["api_key"])
      expect(page["meta"]["total"]).to eq(1)
    end

    it "raises PermissionDeniedError naming the refused grant on 403 privilege_escalation" do
      client = new_client
      stub_json(:post, "#{RES_API}/v1/api-keys", { error: {
        type: "privilege_escalation",
        message: 'This API key cannot grant a permission it does not itself hold. '                  'Refused grant: {"resource_type":"vault","actions":["create"],"effect":"allow"}',
        request_id: "req-1"
      } }, status: 403)

      expect { client.api_keys.create(name: "x", role_ids: [ROLE_UUID]) }
        .to raise_error(KnoxCall::PermissionDeniedError, /resource_type/)
    end
  end

  # -- Promotion opportunities (/v1/opportunities) -----------------------------------------

  describe "opportunities" do
    OPP_ID = "op_7f3c".freeze

    it "GETs /v1/opportunities with status/page params and returns the envelope" do
      stub = stub_json(:get, "#{RES_API}/v1/opportunities?status=pending&page=2&per_page=2",
                       paginated([
                         { id: OPP_ID, source: "gateway_traffic", service: "stripe",
                           destination_host: "api.stripe.com", status: "pending",
                           confidence: 0.9, suggested_route_json: {}, evidence_json: {},
                           accepted_route_id: nil, created_at: "t", updated_at: "t", acted_at: nil }
                       ], total: 3, page: 2, per_page: 2))

      page = new_client.opportunities.list(status: "pending", page: 2, per_page: 2)

      expect(stub).to have_been_requested.once
      expect(page["data"][0]["id"]).to eq(OPP_ID)
      expect(page["data"][0]["source"]).to eq("gateway_traffic")
      expect(page["meta"]["total"]).to eq(3)
    end

    it "POSTs .../accept with the body and unwraps route/collection/environment" do
      client = new_client

      sent = nil
      stub_request(:post, "#{RES_API}/v1/opportunities/#{OPP_ID}/accept")
        .with { |req| sent = JSON.parse(req.body); true }
        .to_return(status: 200, body: JSON.generate(envelope(
          { opportunity_id: OPP_ID,
            route: { id: "r_1", slug: "wrapped-apis-stripe", name: "stripe" },
            collection_id: "c_1", environment: "production" }
        )), headers: { "Content-Type" => "application/json" })

      out = client.opportunities.accept(OPP_ID, collection_name: "Wrapped APIs",
                                        environment: "production", secret: "stripe-key",
                                        header_name: "Authorization", value_prefix: "Bearer ")

      expect(sent).to eq(
        "collection_name" => "Wrapped APIs", "environment" => "production",
        "secret" => "stripe-key", "header_name" => "Authorization", "value_prefix" => "Bearer "
      )
      expect(out["opportunity_id"]).to eq(OPP_ID)
      expect(out["route"]).to eq("id" => "r_1", "slug" => "wrapped-apis-stripe", "name" => "stripe")
      expect(out["collection_id"]).to eq("c_1")
      expect(out["environment"]).to eq("production")
      expect(out).not_to have_key("data")
      expect(out).not_to have_key("meta")
    end

    it "accept with no options POSTs an empty body" do
      client = new_client
      sent = nil
      stub_request(:post, "#{RES_API}/v1/opportunities/#{OPP_ID}/accept")
        .with { |req| sent = JSON.parse(req.body); true }
        .to_return(status: 200, body: JSON.generate(envelope(
          { opportunity_id: OPP_ID, route: { id: "r_1", slug: nil, name: "stripe" },
            collection_id: "c_1", environment: "default" }
        )), headers: { "Content-Type" => "application/json" })

      client.opportunities.accept(OPP_ID)

      expect(sent).to eq({})
    end

    it "POSTs .../dismiss and unwraps the dismissed status" do
      client = new_client
      stub_json(:post, "#{RES_API}/v1/opportunities/#{OPP_ID}/dismiss",
                envelope({ opportunity_id: OPP_ID, status: "dismissed" }))

      out = client.opportunities.dismiss(OPP_ID)

      expect(a_request(:post, "#{RES_API}/v1/opportunities/#{OPP_ID}/dismiss")).to have_been_made
      expect(out).to eq("opportunity_id" => OPP_ID, "status" => "dismissed")
      expect(out).not_to have_key("data")
    end
  end
end
