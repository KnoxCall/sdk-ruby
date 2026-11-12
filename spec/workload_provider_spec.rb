# KnoxCall::WorkloadCredentialProvider — WIF Phase 4.3. Twin of the Node SDK's
# test/workload-provider.test.ts; sdk/PARITY.md is the shared contract.
#
# The contract worth testing is not "it caches a token". It is the two rules
# that come from KnoxCall assertions being SINGLE-USE:
#
#   1. every exchange reads a FRESH assertion from the source, and an assertion
#      whose bytes were already spent is refused locally with an error that
#      names the real cause — rather than forwarded to be refused as a replay,
#      which reads as "your CI identity was rejected";
#   2. N concurrent callers cause ONE exchange, because each exchange spends an
#      assertion and a herd would burn N of them to have N−1 refused.
#
# Plus the two-tier boundary: advisory failures are survivable, mandatory ones
# are not, and the 90 seconds between them is the point of having two tiers.

RSpec.describe KnoxCall::WorkloadCredentialProvider do
  # expires_in, what the gateway mints today. A method rather than a constant:
  # a constant assigned inside a describe block lands on Object and collides
  # across spec files.
  def lifetime
    900
  end

  # A mutable clock the provider reads through its `clock:` seam. Returns the
  # [holder, callable] pair; advance with `holder[0] += seconds`.
  def clock_pair(start = 1_000_000.0)
    holder = [start]
    [holder, -> { holder[0] }]
  end

  def token_body(token)
    JSON.generate(
      access_token: token,
      issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
      token_type: "Bearer",
      expires_in: lifetime
    )
  end

  # Records every request body the provider sends, and answers with a fresh
  # token — or fails the Nth call when `fail_on` matches.
  def stub_exchange(host: "acme", fail_on: nil)
    sent = []
    n = 0
    stub_request(:post, "https://#{host}.knoxcall.com/v1/oauth/token")
      .with { |req| sent << JSON.parse(req.body); true }
      .to_return do
        n += 1
        if fail_on == n
          { status: 500, body: '{"error":"server_error","error_description":"token endpoint 503"}',
            headers: { "Content-Type" => "application/json" } }
        else
          { status: 200, body: token_body("kp_live_tok#{n}"),
            headers: { "Content-Type" => "application/json" } }
        end
      end
    sent
  end

  # A distinct assertion per call, as a real platform token endpoint produces.
  def fresh_source
    n = 0
    -> { n += 1; "assertion-#{n}" }
  end

  def provider(tick, assertion: nil, **opts)
    described_class.new(
      assertion: assertion || fresh_source,
      tenant: "acme",
      clock: tick,
      **opts
    )
  end

  before { KnoxCall::Warnings._reset_for_tests }

  # -- the single-use rule ---------------------------------------------------

  it "reads a fresh assertion for EVERY exchange, never reusing the first" do
    sent = stub_exchange
    at, tick = clock_pair
    p = provider(tick)

    p.access_token
    at[0] += lifetime - (described_class::MANDATORY_REFRESH_SECONDS / 2.0)
    p.access_token

    expect(sent.length).to eq(2)
    expect(sent[0]["subject_token"]).to eq("assertion-1")
    expect(sent[1]["subject_token"]).to eq("assertion-2")
  end

  it "refuses a source that returns the SAME assertion, and says why — without sending it" do
    sent = stub_exchange
    at, tick = clock_pair
    p = provider(tick, assertion: -> { "captured-once-at-startup" })

    p.access_token
    expect(sent.length).to eq(1)

    at[0] += lifetime # force a mandatory refresh
    expect { p.access_token }.to raise_error(KnoxCall::StaleAssertionError, /single-use/)
    # The refusal explains what to do, not just what happened.
    expect { p.access_token }.to raise_error(KnoxCall::StaleAssertionError, /NEWLY minted/)

    # The doomed request is never made: the whole point is to fail at the real
    # cause instead of surfacing the server's replay refusal.
    expect(sent.length).to eq(1), "a spent assertion was sent to the server"
  end

  it "refuses an empty assertion before any exchange" do
    sent = stub_exchange
    _at, tick = clock_pair
    p = provider(tick, assertion: -> { "" })

    expect { p.access_token }.to raise_error(KnoxCall::StaleAssertionError)
    expect(sent.length).to eq(0)
  end

  it "does NOT burn the assertion on a failed exchange — the same bytes may be retried" do
    # The server claims the assertion before minting, so only a SUCCESS makes
    # those bytes unusable. Burning the fingerprint on a network error would
    # strand a caller whose assertion is still perfectly good.
    sent = stub_exchange(fail_on: 1)
    _at, tick = clock_pair
    p = provider(tick, assertion: -> { "retryable-assertion" })

    expect { p.access_token }.to raise_error(KnoxCall::TokenExchangeError)
    expect(p.access_token).to start_with("kp_live_")
    expect(sent.length).to eq(2)
    expect(sent[1]["subject_token"]).to eq("retryable-assertion")
  end

  # -- the two-tier schedule -------------------------------------------------

  it "serves the cached token untouched while it is comfortably alive" do
    sent = stub_exchange
    at, tick = clock_pair
    p = provider(tick)

    first = p.access_token
    at[0] += lifetime - described_class::ADVISORY_REFRESH_SECONDS - 10

    expect(p.access_token).to eq(first)
    expect(sent.length).to eq(1)
  end

  it "refreshes opportunistically once inside the advisory window" do
    sent = stub_exchange
    at, tick = clock_pair
    p = provider(tick)

    p.access_token
    at[0] += lifetime - described_class::ADVISORY_REFRESH_SECONDS + 10
    p.access_token

    expect(sent.length).to eq(2)
  end

  it "an advisory-window failure is SURVIVABLE — the valid token is still served" do
    stub_exchange(fail_on: 2)
    at, tick = clock_pair
    p = provider(tick)

    first = p.access_token
    at[0] += lifetime - described_class::ADVISORY_REFRESH_SECONDS + 10

    # Survivable is not silent: the operator must still learn the token endpoint
    # is failing, or the first symptom is the mandatory-tier raise. Stubbing the
    # warning also keeps the spec run quiet.
    expect(KnoxCall::Warnings).to receive(:warn_once)
      .with("KNOXCALL_WORKLOAD_ADVISORY_REFRESH", /advisory token refresh failed/)

    expect(p.access_token).to eq(first),
                              "a survivable blip took down a caller with valid credentials"
  end

  it "a mandatory-window failure RAISES — the token may die in flight" do
    stub_exchange(fail_on: 2)
    at, tick = clock_pair
    p = provider(tick)

    p.access_token
    at[0] += lifetime - described_class::MANDATORY_REFRESH_SECONDS + 10

    expect { p.access_token }.to raise_error(KnoxCall::TokenExchangeError)
  end

  # -- concurrency -----------------------------------------------------------

  it "N simultaneous callers spend ONE assertion, not N" do
    sent = stub_exchange
    calls = 0
    lock = Mutex.new
    source = -> { lock.synchronize { calls += 1 }; "assertion-#{calls}" }
    _at, tick = clock_pair
    p = provider(tick, assertion: source)

    tokens = 8.times.map { Thread.new { p.access_token } }.map(&:value)

    expect(sent.length).to eq(1), "a thundering herd burned one assertion per caller"
    expect(calls).to eq(1)
    expect(tokens.uniq.length).to eq(1)
  end

  # -- what reaches the exchange ---------------------------------------------

  it "passes the resource and audience through, and the Test data space" do
    sent = stub_exchange(host: "sandbox-acme")
    _at, tick = clock_pair
    p = provider(tick, resource: "https://mcp.example/servers/s1",
                                audience: KnoxCall::KNOXCALL_AUDIENCE, sandbox: true)

    p.access_token

    expect(sent[0]["resource"]).to eq("https://mcp.example/servers/s1")
    expect(sent[0]["audience"]).to eq(KnoxCall::KNOXCALL_AUDIENCE)
    expect(sent[0]["subject_token_type"]).to eq(KnoxCall::ID_TOKEN_TYPE)
  end

  it "omits resource when it was not asked for" do
    # Sending resource="" would be refused invalid_target; sending nothing mints
    # an unconfined agent token. The provider must not turn one into the other.
    sent = stub_exchange
    _at, tick = clock_pair
    provider(tick).access_token

    expect(sent[0]).not_to have_key("resource")
  end

  it "refuses construction without an assertion source or a host" do
    # Both failures belong at construction, not minutes into a long process.
    expect { described_class.new(assertion: "not-callable", tenant: "acme") }
      .to raise_error(ArgumentError, /single-use/)
    # ArgumentError, not a KnoxCall::Error: this SDK deliberately has no
    # BootstrapError class (see errors.rb), so `exchange_base_url` raises
    # ArgumentError and the provider propagates the SDK's own contract rather
    # than inventing a type. Python and Go raise BootstrapError at this point.
    expect { described_class.new(assertion: -> { "x" }) }
      .to raise_error(ArgumentError, /tenant slug or a base_url/)
  end
end
