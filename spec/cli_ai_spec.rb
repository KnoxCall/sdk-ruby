# CLI tests — `knoxcall ai exchange` (RFC 8693 workload federation).
#
# The python CLI is PARITY §13's reference implementation, so these mirror
# sdk/knoxcall-python/tests/test_cli_ai.py assertion for assertion: the subject
# token comes from the environment and never from argv, a host is required
# rather than guessed, stdout carries the token and nothing else, and the exit
# codes are 0 / 1 / 2.

require "stringio"
require "knoxcall/cli"

RSpec.describe "KnoxCall CLI — ai exchange" do
  let(:env_var) { KnoxCall::CLI::Ai::SUBJECT_TOKEN_ENV }

  let(:ok_body) do
    {
      access_token: "kc_live_agt_deadbeef",
      issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
      token_type: "Bearer",
      expires_in: 900
    }
  end

  around do |example|
    ENV.delete(env_var)
    example.run
  ensure
    ENV.delete(env_var)
  end

  # Run the CLI with captured stdout/stderr; returns [exit code, out, err].
  def run_cli(argv)
    old_out = $stdout
    old_err = $stderr
    out = StringIO.new
    err = StringIO.new
    $stdout = out
    $stderr = err
    code = KnoxCall::CLI.run(argv)
    [code, out.string, err.string]
  ensure
    $stdout = old_out
    $stderr = old_err
  end

  # -- parsing ---------------------------------------------------------------

  it "lists ai in the root help" do
    code, out, = run_cli(["--help"])
    expect(code).to eq(0)
    expect(out).to include("ai")
    expect(out).to include("AI gateway operations")
  end

  it "prints the ai group help listing every sub-command and exits 0" do
    # AIGW-162: the group grew from one sub-command to six. The help is the
    # only place a user discovers them, so it is asserted rather than assumed.
    code, out, = run_cli(%w[ai --help])
    expect(code).to eq(0)
    expect(out).to include("usage: knoxcall ai [-h] {exchange,gateways,agents,create-agent,mint,usage} ...")
    %w[exchange gateways agents create-agent mint usage].each { |sub| expect(out).to include(sub) }
  end

  it "prints the exchange sub-command's own help and exits 0" do
    code, out, = run_cli(%w[ai exchange --help])
    expect(code).to eq(0)
    expect(out).to include("usage: knoxcall ai exchange")
    expect(out).to include("--resource")
    # The control-plane flags belong to OTHER sub-commands and must not appear.
    expect(out).not_to include("--period")
    expect(out).not_to include("--secret-from-env")
  end

  it "treats a missing sub-command as a usage error" do
    code, _, err = run_cli(%w[ai])
    expect(code).to eq(2)
    expect(err).to include("a sub-command is required")
  end

  it "treats an unknown sub-command as a usage error" do
    code, _, err = run_cli(%w[ai nope])
    expect(code).to eq(2)
    expect(err).to include("invalid choice: 'nope'")
  end

  it "has no --subject-token flag" do
    # An argv value lands in shell history, ps output and the CI log line, so
    # there must be no way to pass one. This asserts the ABSENCE of a flag —
    # adding `--subject-token` later would fail here.
    code, _, err = run_cli(%w[ai exchange --subject-token a.b.c])
    expect(code).to eq(2)
    expect(err).to include("--subject-token")
  end

  # -- behaviour -------------------------------------------------------------

  it "refuses when the environment variable is unset" do
    code, _, err = run_cli(%w[ai exchange --tenant acme])
    expect(code).to eq(1)
    expect(err).to include(env_var)
    expect(err).to start_with("error: ")
  end

  it "refuses to guess a host" do
    # api.knoxcall.com answers 401 for this request — the endpoint is not served
    # there — and that 401 reads as "your CI token was rejected".
    ENV[env_var] = "a.b.c"
    code, _, err = run_cli(%w[ai exchange])
    expect(code).to eq(1)
    expect(err).to include("--tenant")
    expect(err).to include("401")
  end

  it "prints only the token on stdout" do
    ENV[env_var] = "header.payload.sig"
    stub = stub_request(:post, "https://acme.knoxcall.com/v1/oauth/token")
           .to_return(status: 200, body: JSON.generate(ok_body),
                      headers: { "Content-Type" => "application/json" })

    code, out, err = run_cli(%w[ai exchange --tenant acme])

    expect(code).to eq(0)
    # stdout is captured with $(...), so it must be exactly the token.
    expect(out).to eq("kc_live_agt_deadbeef\n")
    expect(err).to include("agent token")
    expect(stub).to have_been_requested
  end

  it "derives the sandbox data-plane host" do
    ENV[env_var] = "a.b.c"
    stub = stub_request(:post, "https://sandbox-acme.knoxcall.com/v1/oauth/token")
           .to_return(status: 200, body: JSON.generate(ok_body))

    expect(run_cli(%w[ai exchange --tenant acme --sandbox]).first).to eq(0)
    expect(stub).to have_been_requested
  end

  it "omits resource unless it was asked for" do
    ENV[env_var] = "a.b.c"
    sent = nil
    stub_request(:post, "https://acme.knoxcall.com/v1/oauth/token")
      .with { |req| sent = JSON.parse(req.body); true }
      .to_return(status: 200, body: JSON.generate(ok_body))

    run_cli(%w[ai exchange --tenant acme])
    expect(sent).not_to have_key("resource")
  end

  it "narrows the token with --resource and says so" do
    ENV[env_var] = "a.b.c"
    sent = nil
    stub_request(:post, "https://acme.knoxcall.com/v1/oauth/token")
      .with { |req| sent = JSON.parse(req.body); true }
      .to_return(status: 200, body: JSON.generate(ok_body))

    code, _, err = run_cli(["ai", "exchange", "--tenant", "acme",
                            "--resource", "https://acme.knoxcall.com/v1/mcp/gh"])

    expect(code).to eq(0)
    expect(sent["resource"]).to eq("https://acme.knoxcall.com/v1/mcp/gh")
    expect(err).to include("tool (MCP, resource-bound)")
  end

  it "exits 1 on a server refusal, with no backtrace" do
    ENV[env_var] = "a.b.c"
    stub_request(:post, "https://acme.knoxcall.com/v1/oauth/token").to_return(
      status: 400,
      body: '{"error":"invalid_grant","error_description":"No tenant bindings registered"}'
    )

    code, _, err = run_cli(%w[ai exchange --tenant acme])
    expect(code).to eq(1)
    expect(err).to start_with("error: ")
    expect(err).to include("No tenant bindings")
  end

  it "warns when the exchange would cross a plaintext hop" do
    # The subject token IS a credential, so a plaintext hop leaks it. PARITY 15
    # already warns when a CLIENT is constructed against plaintext http; the
    # exchange deliberately constructs no client, so the control had to be added
    # on that path too or it would exist on one and be absent on the parallel one.
    KnoxCall::Warnings._reset_for_tests
    ENV[env_var] = "a.b.c"
    stub_request(:post, "http://evil.example/v1/oauth/token")
      .to_return(status: 200, body: JSON.generate(ok_body))

    _, _, err = run_cli(%w[ai exchange --base-url http://evil.example])
    expect(err).to include("plaintext HTTP")
  end

  it "does not warn for https, or for http on loopback" do
    # The acceptance harness and local dev both use http://127.0.0.1, so a
    # refusal here would be wrong and a warning there would be noise.
    KnoxCall::Warnings._reset_for_tests
    ENV[env_var] = "a.b.c"
    stub_request(:post, "https://acme.test/v1/oauth/token")
      .to_return(status: 200, body: JSON.generate(ok_body))
    stub_request(:post, "http://127.0.0.1:3000/v1/oauth/token")
      .to_return(status: 200, body: JSON.generate(ok_body))

    _, _, err1 = run_cli(%w[ai exchange --base-url https://acme.test])
    _, _, err2 = run_cli(%w[ai exchange --base-url http://127.0.0.1:3000])
    expect(err1 + err2).not_to include("plaintext HTTP")
  end

  it "never prints the token to stderr" do
    ENV[env_var] = "a.b.c"
    stub_request(:post, "https://acme.knoxcall.com/v1/oauth/token")
      .to_return(status: 200, body: JSON.generate(ok_body))

    _, _, err = run_cli(%w[ai exchange --tenant acme])
    expect(err).not_to include("kc_live_agt_deadbeef")
  end
end

# AIGW-162 — the `ai` control-plane sub-commands.
#
# `exchange` is the data-plane door and needs no login; these five act as the
# signed-in tenant, through the same ~/.knoxcall/credentials.json profile
# `login` writes and `whoami` reads. They exist because there was no CLI golden
# path at all: the five SDK CLIs shipped `exchange` alone, and the capable
# standalone `cli/` was unpublished, untested, un-CI'd, and could not create a
# secret, a gateway or an agent — so it could not reach a first call either.
#
# Mirrors the Node reference's control-plane block
# (sdk/knoxcall-node/test/cli-ai.test.ts) assertion for assertion, plus the
# behavioural cases that need a real HTTP round trip.
RSpec.describe "KnoxCall CLI — ai control plane" do
  let(:api) { "https://api.example.test" }

  around do |example|
    vars = %w[KNOXCALL_TENANT KNOXCALL_ENVIRONMENT KNOXCALL_ACCESS_TOKEN
              KNOXCALL_API_KEY KNOXCALL_CLIENT_ID KNOXCALL_CLIENT_SECRET
              KNOXCALL_BASE_URL KNOXCALL_API_BASE_URL KNOXCALL_PROXY_BASE_URL
              KNOXCALL_PROFILE ANTHROPIC_API_KEY]
    vars.each { |k| ENV.delete(k) }
    Dir.mktmpdir("knoxcall-cli-ai") do |dir|
      @creds_path = File.join(dir, "credentials.json")
      # spec_helper's outer around restores the pre-suite value afterwards.
      ENV["KNOXCALL_CREDENTIALS_FILE"] = @creds_path
      example.run
    end
  ensure
    vars.each { |k| ENV.delete(k) }
  end

  # Run the CLI with captured stdout/stderr; returns [exit code, out, err].
  def run_cli(argv)
    old_out = $stdout
    old_err = $stderr
    out = StringIO.new
    err = StringIO.new
    $stdout = out
    $stderr = err
    code = KnoxCall::CLI.run(argv)
    [code, out.string, err.string]
  ensure
    $stdout = old_out
    $stderr = old_err
  end

  def parse!(argv)
    parsed = KnoxCall::CLI.parse(argv)
    raise "expected #{argv.inspect} to parse, got exit #{parsed}" unless parsed.is_a?(Array)

    parsed[1]
  end

  # A fresh stored login, so the SDK client uses the seeded access token
  # directly (no token-endpoint round trip) — the whoami/init spec setup.
  def seed_login(profile: "default")
    KnoxCall::CredentialsFile.write_profile(
      @creds_path, profile,
      {
        "tenant" => "acme", "base_url" => api, "client_id" => "kc_cli_real",
        "refresh_token" => "rt_1", "access_token" => "kc_fresh",
        "access_token_expires_at" => KnoxCall::CredentialsFile.format_expiry(Time.now + 3600)
      }
    )
  end

  def envelope(data)
    { data: data, meta: { request_id: "req-1" } }
  end

  def page_of(rows)
    {
      data: rows,
      meta: { total: rows.length, page: 1, per_page: 100, total_pages: 1, request_id: "req-1" }
    }
  end

  def stub_json(method, url, payload, status: 200)
    stub_request(method, url).to_return(
      status: status, body: JSON.generate(payload),
      headers: { "Content-Type" => "application/json" }
    )
  end

  # Capture the JSON body of a POST while answering it.
  def capture_post(url, payload, status: 201)
    seen = {}
    stub_request(:post, url)
      .with { |req| seen[:body] = JSON.parse(req.body.to_s); true }
      .to_return(status: status, body: JSON.generate(payload),
                 headers: { "Content-Type" => "application/json" })
    seen
  end

  # -- parsing ---------------------------------------------------------------

  it "parses every sub-command with its own flag table" do
    gateways = parse!(%w[ai gateways --profile ci --base-url https://api.example.test --sandbox])
    expect(gateways[:ai_command]).to eq("gateways")
    expect(gateways[:profile]).to eq("ci")
    expect(gateways[:base_url]).to eq("https://api.example.test")
    expect(gateways[:sandbox]).to be(true)

    agents = parse!(%w[ai agents --gateway gw_1])
    expect(agents[:ai_command]).to eq("agents")
    expect(agents[:gateway]).to eq("gw_1")

    created = parse!(%w[ai create-agent --slug copilot --provider anthropic
                        --secret-from-env ANTHROPIC_API_KEY --model claude-sonnet-5])
    expect(created[:ai_command]).to eq("create-agent")
    expect(created[:slug]).to eq("copilot")
    expect(created[:provider]).to eq("anthropic")
    expect(created[:secret_from_env]).to eq("ANTHROPIC_API_KEY")
    expect(created[:model]).to eq("claude-sonnet-5")

    minted = parse!(%w[ai mint --agent ag_1 --kind read])
    expect(minted[:ai_command]).to eq("mint")
    expect(minted[:agent]).to eq("ag_1")
    expect(minted[:kind]).to eq("read")

    used = parse!(%w[ai usage --period 7d])
    expect(used[:ai_command]).to eq("usage")
    expect(used[:period]).to eq("7d")
  end

  it "keys the flag table by SUB-command, not by the ai group" do
    # One shared table would accept `ai exchange --period 30d` and silently
    # ignore it, which is the opposite of what every other command does with an
    # unknown flag (usage error, exit 2). Each of these is a flag that exists on
    # a DIFFERENT ai sub-command, so a shared table would let them all through.
    expect(run_cli(%w[ai exchange --period 30d]).first).to eq(2)
    expect(run_cli(%w[ai gateways --agent ag_1]).first).to eq(2)
    expect(run_cli(%w[ai mint --provider anthropic]).first).to eq(2)
    expect(run_cli(%w[ai usage --secret-from-env X]).first).to eq(2)
    # …and the other direction: the control plane does not take exchange's flags.
    expect(run_cli(%w[ai gateways --audience knoxcall:gateway]).first).to eq(2)
  end

  it "has no flag that would put a provider key in argv" do
    # Same rule as --subject-token: the key is read from the environment named
    # by --secret-from-env. This asserts the ABSENCE of --secret-value, so
    # adding one later fails here rather than in someone's shell history.
    code, _, err = run_cli(%w[ai create-agent --slug x --secret-value sk-ant-live])
    expect(code).to eq(2)
    expect(err).to include("--secret-value")
  end

  it "takes ids as flags, never positionals" do
    # Four of the five SDK CLIs hand-roll their parser and reject positionals
    # outright, so a positional id would be a surface that differs by language.
    expect(run_cli(%w[ai agents gw_1]).first).to eq(2)
    expect(run_cli(%w[ai mint ag_1]).first).to eq(2)
    code, _, err = run_cli(%w[ai gateways extra])
    expect(code).to eq(2)
    expect(err).to include("unrecognized arguments: extra")
  end

  it "gives each control-plane sub-command its own help" do
    code, out, = run_cli(%w[ai create-agent --help])
    expect(code).to eq(0)
    expect(out).to include("usage: knoxcall ai create-agent")
    expect(out).to include("--secret-from-env")
    expect(out).to include("--provider")
    expect(out).not_to include("--period")

    code, out, = run_cli(%w[ai usage --help])
    expect(code).to eq(0)
    expect(out).to include("usage: knoxcall ai usage")
    expect(out).to include("--period")
    expect(out).not_to include("--slug")
  end

  # -- refusals that must fire before any network call -----------------------

  it "refuses to create an agent with no upstream credential" do
    # The API ACCEPTS this and stores an agent whose first data-plane call 502s
    # (AIGW-161). A command whose whole purpose is reaching a working call must
    # not be able to produce one — and the refusal comes BEFORE the login check,
    # so the message names the real problem.
    code, _, err = run_cli(%w[ai create-agent --slug copilot --provider anthropic])
    expect(code).to eq(1)
    expect(err).to include("--secret or --secret-from-env is required")
    expect(err).to include("502s on its first call")
    expect(err).to start_with("error: ")
    expect(err).not_to include("not logged in")
  end

  it "requires --provider on create-agent" do
    code, _, err = run_cli(%w[ai create-agent --slug copilot --secret sec_1])
    expect(code).to eq(1)
    expect(err).to include("--provider is required")
  end

  it "requires --agent on mint and --gateway on agents" do
    code, _, err = run_cli(%w[ai mint])
    expect(code).to eq(1)
    expect(err).to include("--agent is required")

    code, _, err = run_cli(%w[ai agents])
    expect(code).to eq(1)
    expect(err).to include("--gateway is required")
  end

  it "tells you to log in, and reaches no network, with no stored profile" do
    # WebMock has net connect disabled, so an attempted request fails the
    # example rather than passing quietly.
    code, _, err = run_cli(%w[ai gateways])
    expect(code).to eq(1)
    expect(err).to include("not logged in (profile 'default')")
    expect(err).to include("knoxcall login")
  end

  # -- behaviour --------------------------------------------------------------

  it "lists gateways as `id  slug  name`" do
    seed_login
    stub_json(:get, "#{api}/v1/ai-gateway/gateways?per_page=100",
              page_of([{ id: "gw_1", slug: "prod", name: "Prod" }]))

    code, out, = run_cli(%w[ai gateways])
    expect(code).to eq(0)
    expect(out).to eq("gw_1  prod  Prod\n")
  end

  it "points at create-agent when the tenant has no gateways" do
    seed_login
    stub_json(:get, "#{api}/v1/ai-gateway/gateways?per_page=100", page_of([]))

    code, out, err = run_cli(%w[ai gateways])
    expect(code).to eq(0)
    expect(out).to eq("")
    expect(err).to include("knoxcall ai create-agent")
  end

  it "lists agents with the agent_url, so no follow-up GET is needed" do
    seed_login
    stub_json(:get, "#{api}/v1/ai-gateway/gateways/gw_1/agents?per_page=100",
              page_of([{ id: "ag_1", slug: "copilot",
                         agent_url: "https://acme.knoxcall.com/v1/ai/copilot" }]))

    code, out, = run_cli(%w[ai agents --gateway gw_1])
    expect(code).to eq(0)
    expect(out).to eq("ag_1  copilot  https://acme.knoxcall.com/v1/ai/copilot\n")
  end

  it "escrows the key from the environment, printing only the agent id on stdout" do
    seed_login
    ENV["ANTHROPIC_API_KEY"] = "sk-ant-live-xyz"
    stub_json(:get, "#{api}/v1/ai-gateway/gateways?per_page=100",
              page_of([{ id: "gw_1", slug: "prod", name: "Prod" }]))
    stub_json(:get, "#{api}/v1/secrets?per_page=100", page_of([]))
    secret = capture_post("#{api}/v1/secrets",
                          envelope({ id: "sec_9", name: "ai-gateway-copilot-key" }))
    agent = capture_post("#{api}/v1/ai-gateway/gateways/gw_1/agents",
                         envelope({ id: "ag_1", slug: "copilot",
                                    agent_url: "https://acme.knoxcall.com/v1/ai/copilot" }))

    code, out, err = run_cli(%w[ai create-agent --slug copilot --provider anthropic
                                --secret-from-env ANTHROPIC_API_KEY])

    expect(code).to eq(0)
    # stdout is captured with $(...), so it must be exactly the id.
    expect(out).to eq("ag_1\n")
    expect(secret[:body]).to eq("name" => "ai-gateway-copilot-key", "value" => "sk-ant-live-xyz")
    expect(agent[:body]).to eq("name" => "copilot", "slug" => "copilot",
                               "provider" => "anthropic", "upstream_secret_id" => "sec_9")
    # The literal next command, so the golden path needs no doc lookup.
    expect(err).to include("knoxcall ai mint --agent ag_1")
    expect(err).to include("https://acme.knoxcall.com/v1/ai/copilot")
    # The raw provider key is NEVER printed, on either stream.
    expect(out + err).not_to include("sk-ant-live-xyz")
  end

  it "reuses an existing secret of the same name rather than duplicating the credential" do
    seed_login
    ENV["ANTHROPIC_API_KEY"] = "sk-ant-live-xyz"
    stub_json(:get, "#{api}/v1/ai-gateway/gateways?per_page=100",
              page_of([{ id: "gw_1", slug: "prod", name: "Prod" }]))
    stub_json(:get, "#{api}/v1/secrets?per_page=100",
              page_of([{ id: "sec_old", name: "ai-gateway-copilot-key" }]))
    agent = capture_post("#{api}/v1/ai-gateway/gateways/gw_1/agents",
                         envelope({ id: "ag_1", slug: "copilot", agent_url: "" }))

    code, _, err = run_cli(%w[ai create-agent --slug copilot --provider anthropic
                              --secret-from-env ANTHROPIC_API_KEY])

    expect(code).to eq(0)
    expect(agent[:body]["upstream_secret_id"]).to eq("sec_old")
    expect(err).to include("reusing secret 'ai-gateway-copilot-key' (sec_old)")
    expect(a_request(:post, "#{api}/v1/secrets")).not_to have_been_made
    # agent_url "" means "not available" — never printed as a URL.
    expect(err).not_to include("base_url:")
  end

  it "uses --secret as-is, escrowing nothing" do
    seed_login
    stub_json(:get, "#{api}/v1/ai-gateway/gateways?per_page=100",
              page_of([{ id: "gw_1", slug: "prod", name: "Prod" }]))
    agent = capture_post("#{api}/v1/ai-gateway/gateways/gw_1/agents",
                         envelope({ id: "ag_1", slug: "copilot", agent_url: "" }))

    code, = run_cli(%w[ai create-agent --slug copilot --provider anthropic --secret sec_given])

    expect(code).to eq(0)
    expect(agent[:body]["upstream_secret_id"]).to eq("sec_given")
    expect(a_request(:get, "#{api}/v1/secrets?per_page=100")).not_to have_been_made
  end

  it "creates a Default gateway on a tenant that has none" do
    seed_login
    ENV["ANTHROPIC_API_KEY"] = "sk-ant-live-xyz"
    stub_json(:get, "#{api}/v1/ai-gateway/gateways?per_page=100", page_of([]))
    gateway = capture_post("#{api}/v1/ai-gateway/gateways",
                           envelope({ id: "gw_new", slug: "default", name: "Default" }))
    stub_json(:get, "#{api}/v1/secrets?per_page=100", page_of([]))
    stub_json(:post, "#{api}/v1/secrets", envelope({ id: "sec_9" }), status: 201)
    stub_json(:post, "#{api}/v1/ai-gateway/gateways/gw_new/agents",
              envelope({ id: "ag_2", slug: "copilot", agent_url: "" }), status: 201)

    code, out, err = run_cli(%w[ai create-agent --slug copilot --provider anthropic
                                --secret-from-env ANTHROPIC_API_KEY])

    expect(code).to eq(0)
    expect(gateway[:body]).to eq("name" => "Default", "slug" => "default")
    expect(out).to eq("ag_2\n")
    expect(err).to include("created gateway default (gw_new)")
  end

  it "refuses to pick a gateway when the tenant has several" do
    # "whichever sorts first" is how the quickstart wizard silently landed a
    # second agent in the wrong gateway.
    seed_login
    ENV["ANTHROPIC_API_KEY"] = "sk-ant-live-xyz"
    stub_json(:get, "#{api}/v1/ai-gateway/gateways?per_page=100",
              page_of([{ id: "gw_1", slug: "prod", name: "Prod" },
                       { id: "gw_2", slug: "staging", name: "Staging" }]))

    code, _, err = run_cli(%w[ai create-agent --slug copilot --provider anthropic
                              --secret-from-env ANTHROPIC_API_KEY])

    expect(code).to eq(1)
    expect(err).to include("--gateway is required")
    expect(err).to include("prod (gw_1)")
    expect(err).to include("staging (gw_2)")
    # Nothing was escrowed and no agent was created.
    expect(a_request(:post, "#{api}/v1/secrets")).not_to have_been_made
  end

  it "resolves --gateway by slug as well as by id, and names what it has when it cannot" do
    seed_login
    stub_json(:get, "#{api}/v1/ai-gateway/gateways?per_page=100",
              page_of([{ id: "gw_1", slug: "prod", name: "Prod" },
                       { id: "gw_2", slug: "staging", name: "Staging" }]))
    agent = capture_post("#{api}/v1/ai-gateway/gateways/gw_2/agents",
                         envelope({ id: "ag_9", slug: "copilot", agent_url: "" }))

    code, out, = run_cli(%w[ai create-agent --slug copilot --provider anthropic
                            --secret sec_1 --gateway staging])
    expect(code).to eq(0)
    expect(out).to eq("ag_9\n")
    expect(agent[:body]["slug"]).to eq("copilot")

    code, _, err = run_cli(%w[ai create-agent --slug copilot --provider anthropic
                              --secret sec_1 --gateway nope])
    expect(code).to eq(1)
    expect(err).to include("no gateway 'nope'")
    expect(err).to include("prod (gw_1)")
    expect(err).to include("staging (gw_2)")
  end

  it "refuses when the named environment variable is unset, and says why there is no flag" do
    seed_login
    stub_json(:get, "#{api}/v1/ai-gateway/gateways?per_page=100",
              page_of([{ id: "gw_1", slug: "prod", name: "Prod" }]))

    code, _, err = run_cli(%w[ai create-agent --slug copilot --provider anthropic
                              --secret-from-env ANTHROPIC_API_KEY])

    expect(code).to eq(1)
    expect(err).to include("ANTHROPIC_API_KEY is not set")
    expect(err).to include("--secret-value")
    expect(err).to include("shell history")
    expect(a_request(:post, "#{api}/v1/secrets")).not_to have_been_made
  end

  it "prints only the minted token on stdout, with the once-only warning on stderr" do
    seed_login
    minted = capture_post(
      "#{api}/v1/ai-gateway/agents/ag_1/tokens",
      envelope({ id: "tok_1", kind: "read", prefix: "kc_live_agt_ab",
                 token: "kc_live_agt_secret", dpop_required: false,
                 expires_at: "2026-10-01T00:00:00.000Z" })
    )

    code, out, err = run_cli(%w[ai mint --agent ag_1 --kind read --name ci])

    expect(code).to eq(0)
    # `> token.txt` must capture the token and nothing else.
    expect(out).to eq("kc_live_agt_secret\n")
    expect(minted[:body]).to eq("kind" => "read", "name" => "ci")
    expect(err).to include("Save this token now")
    expect(err).to include("prefix:   kc_live_agt_ab")
    expect(err).not_to include("kc_live_agt_secret")
  end

  it "prints the usage rollup, defaulting the period to 30d" do
    seed_login
    stub_json(:get, "#{api}/v1/ai-gateway/usage?period=30d",
              envelope({ period_days: 30,
                         totals: { requests: 12, input_tokens: 100, output_tokens: 200,
                                   cost_usd: 0.42, unpriced_requests: 1 },
                         by_model: [{ provider: "anthropic", model: "claude-sonnet-5",
                                      requests: 12, input_tokens: 100, output_tokens: 200,
                                      cost_usd: 0.42, unpriced_requests: 1 }] }))

    code, out, = run_cli(%w[ai usage])

    expect(code).to eq(0)
    expect(out).to include("Usage — last 30 days")
    expect(out).to include("requests:      12")
    expect(out).to include("cost (USD):    0.4200")
    expect(out).to include("anthropic/claude-sonnet-5  12 req  in 100  out 200  $0.4200")
  end

  it "scopes usage to one agent and honours --period" do
    seed_login
    stub_json(:get, "#{api}/v1/ai-gateway/usage?period=7d&agent_id=ag_1",
              envelope({ period_days: 7, totals: {}, by_model: [] }))

    code, out, = run_cli(%w[ai usage --period 7d --agent ag_1])

    expect(code).to eq(0)
    expect(out).to include("(agent ag_1)")
    expect(out).to include("No usage in this period.")
  end

  it "exits 1 on a server refusal, with no backtrace" do
    seed_login
    stub_json(:get, "#{api}/v1/ai-gateway/gateways?per_page=100",
              { error: { type: "forbidden", message: "missing scope ai_gateway:read" } },
              status: 403)

    code, _, err = run_cli(%w[ai gateways])

    expect(code).to eq(1)
    expect(err).to start_with("error: ")
    expect(err).to include("missing scope ai_gateway:read")
  end
end
