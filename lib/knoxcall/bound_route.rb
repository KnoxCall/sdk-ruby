module KnoxCall
  # A route with bound call defaults — see Client#route.
  #
  #   printnode = client.route("3f1e2c9a-...", environment: "production")
  #   computers = JSON.parse(printnode.get("/computers").body)
  #   printnode.post("/printjobs", body: payload)
  #
  # Holds only the client reference, route id, and defaults (never a token
  # or any pipeline state), so retries and 401 re-mint behave exactly as on
  # Client#call. Per-call values win over bound defaults; headers merge
  # per-key with per-call winning. A nil per-call value inherits the bound
  # default — there is no "explicitly clear" mechanism; construct another
  # handle instead.
  class BoundRoute
    def initialize(client, route, environment: nil, headers: {}, timeout: nil)
      @client = client
      @route = route
      @environment = environment
      @headers = (headers || {}).dup.freeze
      @timeout = timeout
      freeze
    end

    def request(method, path = "/", body: nil, headers: {}, environment: nil, query: nil, timeout: nil)
      @client.call(
        @route,
        method: method,
        path: path,
        body: body,
        headers: @headers.merge(headers || {}),
        environment: environment.nil? ? @environment : environment,
        query: query,
        timeout: timeout.nil? ? @timeout : timeout
      )
    end

    def get(path = "/", **kw)    = request("GET", path, **kw)
    def post(path = "/", **kw)   = request("POST", path, **kw)
    def put(path = "/", **kw)    = request("PUT", path, **kw)
    def patch(path = "/", **kw)  = request("PATCH", path, **kw)
    def delete(path = "/", **kw) = request("DELETE", path, **kw)

    def inspect
      "#<KnoxCall::BoundRoute route=#{@route.inspect} environment=#{@environment.inspect}>"
    end
  end
end
