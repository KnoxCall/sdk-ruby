# Workflows control-plane resource (server: src/client-api/workflows.ts; node
# reference src/resources/workflows.ts, PARITY §11). Every mock here is the
# REAL server envelope: single-object methods get {data, meta}; paginated lists
# get {data:[...], meta:{total, page, per_page, total_pages, request_id}} —
# never a bare object, never a cursor. Mutating methods carry the ULID
# idempotency key (Client#request), matching every other resource.

RSpec.describe "KnoxCall Workflows" do
  WF_API = "https://api.example.test".freeze

  # Pre-acquired kc_ token: no token-endpoint round trip, so stub #N is API
  # call #N.
  def new_client(**opts)
    KnoxCall::Client.new(
      tenant: "acme",
      base_url: WF_API,
      proxy_base_url: "https://acme.example.test",
      api_key: "kc_live_x",
      retry_base_delay: 0.001,
      **opts
    )
  end

  def envelope(data, meta = {})
    { data: data, meta: { request_id: "req-#{rand(10_000)}" }.merge(meta) }
  end

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

  it "is registered on the client" do
    expect(new_client.workflows).to be_a(KnoxCall::Resources::Workflows)
  end

  # -- List / iterate ----------------------------------------------------------

  describe "list and iterate" do
    it "returns the envelope from list and sends page params" do
      stub = stub_json(:get, "#{WF_API}/v1/workflows?page=2&per_page=2",
                       paginated([{ id: "wf_1" }, { id: "wf_2" }], total: 5, page: 2, per_page: 2))

      page = new_client.workflows.list(page: 2, per_page: 2)

      expect(stub).to have_been_requested.once
      expect(page["data"]).to eq([{ "id" => "wf_1" }, { "id" => "wf_2" }])
      expect(page["meta"]["total"]).to eq(5)
      expect(page["meta"]["total_pages"]).to eq(3)
    end

    it "walks every workflow with each and stops at total_pages" do
      stub_json(:get, "#{WF_API}/v1/workflows?page=1&per_page=1",
                paginated([{ id: "wf_1" }], total: 2, page: 1, per_page: 1))
      last = stub_json(:get, "#{WF_API}/v1/workflows?page=2&per_page=1",
                       paginated([{ id: "wf_2" }], total: 2, page: 2, per_page: 1))

      ids = new_client.workflows.each(per_page: 1).map { |w| w["id"] }

      expect(ids).to eq(%w[wf_1 wf_2])
      expect(last).to have_been_requested.once # exactly total_pages fetches, no page 3
    end

    it "exposes iterate as an alias of each (cross-SDK naming parity)" do
      stub_json(:get, "#{WF_API}/v1/workflows?page=1&per_page=2",
                paginated([{ id: "wf_1" }, { id: "wf_2" }], total: 2, page: 1, per_page: 2))

      enum = new_client.workflows.iterate(per_page: 2)
      expect(enum).to be_a(Enumerator)
      expect(enum.map { |w| w["id"] }).to eq(%w[wf_1 wf_2])
    end
  end

  # -- CRUD --------------------------------------------------------------------

  describe "get / create / update / delete" do
    it "unwraps get" do
      stub_json(:get, "#{WF_API}/v1/workflows/wf_1",
                envelope({ id: "wf_1", name: "Nightly sync", enabled: true, version: 3 }))

      wf = new_client.workflows.get("wf_1")
      expect(wf["name"]).to eq("Nightly sync")
      expect(wf).not_to have_key("data")
      expect(wf).not_to have_key("meta")
    end

    it "creates a workflow (POST + body), unwraps data, and carries an idempotency key" do
      sent = nil
      idem = nil
      stub_request(:post, "#{WF_API}/v1/workflows")
        .with do |req|
          sent = JSON.parse(req.body)
          idem = req.headers.transform_keys(&:downcase)["x-idempotency-key"]
          true
        end
        .to_return(status: 201, body: JSON.generate(envelope({ id: "wf_9", name: "Nightly sync", version: 1 })))

      definition = { "nodes" => [{ "id" => "n1" }], "edges" => [] }
      wf = new_client.workflows.create(name: "Nightly sync", definition: definition, enabled: true)

      expect(sent).to eq("name" => "Nightly sync", "definition" => definition, "enabled" => true)
      expect(wf["id"]).to eq("wf_9")
      expect(wf).not_to have_key("data")
      expect(idem).to be_a(String)
      expect(idem).not_to be_empty # mutating requests carry the ULID idempotency key (PARITY §4)
    end

    it "updates a workflow (PATCH + body) and unwraps data" do
      patched = nil
      stub_request(:patch, "#{WF_API}/v1/workflows/wf_1")
        .with { |req| patched = JSON.parse(req.body); true }
        .to_return(status: 200, body: JSON.generate(envelope({ id: "wf_1", name: "Renamed", version: 4 })))

      out = new_client.workflows.update("wf_1", name: "Renamed")
      expect(patched).to eq("name" => "Renamed")
      expect(out["name"]).to eq("Renamed")
      expect(out["version"]).to eq(4)
    end

    it "unwraps delete to the deleted flag" do
      stub_json(:delete, "#{WF_API}/v1/workflows/wf_1", envelope({ id: "wf_1", deleted: true }))
      expect(new_client.workflows.delete("wf_1")).to eq("id" => "wf_1", "deleted" => true)
    end

    # PARITY §11 Workflows — "an unpublishable definition may never be the
    # running one". CREATE keeps the caller's data and withholds the switch;
    # UPDATE refuses. Both are reachable on an ordinary request, so both are
    # pinned.
    it "surfaces enabled:false verbatim on create when the server withholds the switch" do
      stub_request(:post, "#{WF_API}/v1/workflows")
        .to_return(status: 200,
                   body: JSON.generate(envelope({ id: "wf_9", name: "Nightly sync", enabled: false })),
                   headers: { "Content-Type" => "application/json" })

      # The definition's steps are incomplete, so the row is created NOT
      # enabled. This is a normal success, not an error — and the SDK reports
      # what the SERVER stored rather than echoing the request back, or a caller
      # believes a workflow is running that is not.
      wf = new_client.workflows.create(name: "Nightly sync", definition: { "nodes" => [] }, enabled: true)
      expect(wf["enabled"]).to be false
    end

    it "raises the typed 422 on update and does not retry it" do
      stub = stub_json(:patch, "#{WF_API}/v1/workflows/wf_1",
                       { error: { type: "invalid_definition",
                                  message: 'This workflow cannot be enabled: node "n1": HTTP method is required',
                                  request_id: "req-1" } },
                       status: 422)

      expect { new_client.workflows.update("wf_1", enabled: true) }
        .to raise_error(KnoxCall::ValidationError)
      # A client error: retrying it unchanged burns the tenant's rate limit and
      # can never succeed.
      expect(stub).to have_been_requested.once
    end
  end

  # -- Execute -----------------------------------------------------------------

  describe "execute" do
    it "posts {input} to /execute, unwraps the ack, and carries an idempotency key" do
      sent = nil
      idem = nil
      stub_request(:post, "#{WF_API}/v1/workflows/wf_1/execute")
        .with do |req|
          sent = JSON.parse(req.body)
          idem = req.headers.transform_keys(&:downcase)["x-idempotency-key"]
          true
        end
        .to_return(status: 201, body: JSON.generate(envelope({ id: "ex_1", workflow_id: "wf_1", status: "queued" })))

      run = new_client.workflows.execute("wf_1", input: { "since" => "2026-08-01" })

      expect(sent).to eq("input" => { "since" => "2026-08-01" })
      expect(run).to eq("id" => "ex_1", "workflow_id" => "wf_1", "status" => "queued")
      expect(idem).to be_a(String)
      expect(idem).not_to be_empty
    end

    it "sends an empty body when no input is given (matches the node reference)" do
      sent = nil
      stub_request(:post, "#{WF_API}/v1/workflows/wf_1/execute")
        .with { |req| sent = JSON.parse(req.body); true }
        .to_return(status: 201, body: JSON.generate(envelope({ id: "ex_2", workflow_id: "wf_1", status: "queued" })))

      new_client.workflows.execute("wf_1")
      expect(sent).to eq({}) # {} rather than {"input":null}
    end
  end

  # -- Executions (runs) -------------------------------------------------------

  describe "executions" do
    it "lists a workflow's executions (paginated envelope, nested path)" do
      stub_json(:get, "#{WF_API}/v1/workflows/wf_1/executions?page=1&per_page=20",
                paginated([{ id: "ex_1", status: "success" }], total: 1, page: 1, per_page: 20))

      page = new_client.workflows.list_executions("wf_1", page: 1, per_page: 20)
      expect(page["data"].first["id"]).to eq("ex_1")
      expect(page["meta"]["total"]).to eq(1)
    end

    it "walks executions with each_execution (and iterate_executions alias)" do
      stub_json(:get, "#{WF_API}/v1/workflows/wf_1/executions?page=1&per_page=1",
                paginated([{ id: "ex_1" }], total: 2, page: 1, per_page: 1))
      stub_json(:get, "#{WF_API}/v1/workflows/wf_1/executions?page=2&per_page=1",
                paginated([{ id: "ex_2" }], total: 2, page: 2, per_page: 1))

      ids = new_client.workflows.each_execution("wf_1", per_page: 1).map { |e| e["id"] }
      expect(ids).to eq(%w[ex_1 ex_2])

      # iterate_executions is a true alias of each_execution.
      expect(new_client.workflows.method(:iterate_executions).original_name)
        .to eq(:each_execution)
    end

    it "fetches one execution on the top-level executions path (not nested under the workflow)" do
      stub_json(:get, "#{WF_API}/v1/workflows/executions/ex_1",
                envelope({ id: "ex_1", workflow_id: "wf_1", status: "success",
                           node_executions: [{ "node_id" => "n1", "status" => "success" }] }))

      ex = new_client.workflows.get_execution("ex_1")
      expect(ex["status"]).to eq("success")
      expect(ex["node_executions"].first["node_id"]).to eq("n1")
      expect(ex).not_to have_key("meta")
    end

    it "cancels a running execution on /executions/:id/cancel and unwraps" do
      stub_json(:post, "#{WF_API}/v1/workflows/executions/ex_1/cancel",
                envelope({ id: "ex_1", status: "cancelling" }))
      expect(new_client.workflows.cancel_execution("ex_1")).to eq("id" => "ex_1", "status" => "cancelling")
    end
  end
end
