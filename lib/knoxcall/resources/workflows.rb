module KnoxCall
  module Resources
    # Workflows control plane (server: src/client-api/workflows.ts; node
    # reference src/resources/workflows.ts, PARITY §11). Automations built in
    # the workflow builder: list/get/create/update/delete, execute (queue a
    # run), and the execution (run) sub-collection.
    #
    #   client.workflows.list(page: 1, per_page: 20)
    #   wf  = client.workflows.create(name: "Nightly sync", definition: { nodes: [...], edges: [...] })
    #   run = client.workflows.execute(wf["id"], input: { since: "2026-08-01" })
    #   client.workflows.each_execution(wf["id"]) { |ex| puts ex["status"] }
    #
    # A workflow row is a plain Hash with string keys: "id", "name",
    # "description", "definition", "environment", "enabled", "version",
    # "sandbox", "timeout_seconds", "published_at", "created_at", "updated_at"
    # (plus "run_count" on list). An execution row: "id", "workflow_id",
    # "status", "trigger_type", "started_at", "completed_at",
    # "execution_time_ms", "error_message", "workflow_version", "created_at"
    # (plus "node_executions" on get_execution).
    #
    # Mutating methods carry the ULID idempotency key like every other resource
    # (added by Client#request on non-GET/HEAD methods), so a replayed execute
    # returns the same execution.
    #
    # The sandbox/test client (KnoxCall::Client.new(sandbox: true)) is scoped to
    # the Test data plane server-side; no env parameter is threaded through.
    class Workflows
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # -- Workflows ---------------------------------------------------------

      # Paginated. Params: page (default 1), per_page (default 20, max 100),
      # plus endpoint filters. Returns the {data, meta} envelope.
      def list(**params) = @client.request("GET", "/v1/workflows", query: params.empty? ? nil : params)

      # Yield every workflow, walking pages transparently. Returns a lazy
      # Enumerator when no block is given. Also available as +iterate+ for
      # cross-SDK naming parity (node/python name the auto-pager iterate).
      def each(**params, &block)
        enum = paginate(params) { |p| list(**p) }
        block ? enum.each(&block) : enum
      end
      alias_method :iterate, :each

      def get(workflow_id) = unwrap(@client.request("GET", "/v1/workflows/#{encode(workflow_id)}"))

      # body: name:, definition: ({nodes:, edges:}), plus optional description:,
      # trigger_config:, environment:, enabled:.
      def create(**input) = unwrap(@client.request("POST", "/v1/workflows", body: input))
      def update(workflow_id, **input) = unwrap(@client.request("PATCH", "/v1/workflows/#{encode(workflow_id)}", body: input))
      # Returns {"id", "deleted" => true}.
      def delete(workflow_id) = unwrap(@client.request("DELETE", "/v1/workflows/#{encode(workflow_id)}"))

      # Queue a run. Idempotent — Client#request attaches a ULID key that is
      # stable across retries. The optional +input+ becomes the run's {input}
      # body (omitted entirely when nil, matching the node reference). Returns
      # the execution ack {"id", "workflow_id", "status"}.
      def execute(workflow_id, input: nil)
        body = input.nil? ? {} : { input: input }
        unwrap(@client.request("POST", "/v1/workflows/#{encode(workflow_id)}/execute", body: body))
      end

      # -- Executions (runs) -------------------------------------------------

      # Paginated. Params: page, per_page, plus filters. Returns the
      # {data, meta} envelope.
      def list_executions(workflow_id, **params) = @client.request("GET", "/v1/workflows/#{encode(workflow_id)}/executions", query: params.empty? ? nil : params)

      # Yield every execution for a workflow, walking pages transparently.
      # Returns a lazy Enumerator when no block is given. Also available as
      # +iterate_executions+ for cross-SDK naming parity.
      def each_execution(workflow_id, **params, &block)
        enum = paginate(params) { |p| list_executions(workflow_id, **p) }
        block ? enum.each(&block) : enum
      end
      alias_method :iterate_executions, :each_execution

      # Executions are addressed by their own id (not nested under the workflow).
      def get_execution(execution_id) = unwrap(@client.request("GET", "/v1/workflows/executions/#{encode(execution_id)}"))
      # Returns {"id", "status"}.
      def cancel_execution(execution_id) = unwrap(@client.request("POST", "/v1/workflows/executions/#{encode(execution_id)}/cancel"))
    end
  end
end
