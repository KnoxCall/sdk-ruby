# The SDK-side manifest store (route-aware-interception-plan.md §2.5), Ruby
# idiom: LAZY refresh at the TTL, single-flight, stale-keep with backoff,
# permission refusals as "no manifest" with one warning, rate-limited hints.
# The clock is injected so every schedule is asserted as a value.

RSpec.describe KnoxCall::InterceptManifestStore do
  def entry(host, slug, base = "/")
    { "host" => host, "base_path" => base, "slug" => slug, "route_id" => "id-#{slug}",
      "requires_clients" => false, "allowed_methods" => nil, "updated_at" => nil }
  end

  def manifest(routes, version: nil)
    { "version" => version || "v:#{routes.map { |r| r['slug'] }.join(',')}", "ttl_seconds" => 60,
      "environment" => "production", "sandbox" => false, "routes" => routes }
  end

  let(:clock) { [1000.0] }
  let(:now) { -> { clock[0] } }

  before { KnoxCall::Warnings._reset_for_tests }

  it "fetches once on the first ensure and reports every entry as added" do
    calls = 0
    refreshes = []
    store = described_class.new(-> { calls += 1; manifest([entry("a.example", "a")]) },
                                on_refresh: ->(info) { refreshes << info }, now: now)
    expect(store.stale?).to be(true)
    store.ensure
    store.ensure # fresh: no second call
    expect(calls).to eq(1)
    expect(store.manifest["routes"].map { |r| r["slug"] }).to eq(["a"])
    expect(store.version).to eq("v:a")
    expect(refreshes.first[:reason]).to eq("ttl")
    expect(refreshes.first[:added]).to eq([entry("a.example", "a")])
    expect(refreshes.first[:removed]).to eq([])
  end

  it "is stale after the TTL and reports only the diff" do
    routes = [entry("a.example", "a")]
    refreshes = []
    store = described_class.new(-> { manifest(routes) }, on_refresh: ->(info) { refreshes << info }, now: now)
    store.ensure
    clock[0] += 59
    expect(store.stale?).to be(false)
    routes = [entry("b.example", "b")]
    clock[0] += 2
    expect(store.stale?).to be(true)
    store.ensure
    expect(store.manifest["routes"].map { |r| r["slug"] }).to eq(["b"])
    expect(refreshes.last[:added]).to eq([entry("b.example", "b")])
    expect(refreshes.last[:removed]).to eq([entry("a.example", "a")])
  end

  it "fires no refresh hook for an unchanged version" do
    refreshes = []
    store = described_class.new(-> { manifest([entry("a.example", "a")]) },
                                on_refresh: ->(info) { refreshes << info }, now: now)
    store.ensure
    clock[0] += 61
    store.ensure
    expect(refreshes.length).to eq(1)
  end

  it "keeps the last good manifest on a transport fault and backs off from the second failure" do
    fail = false
    calls = 0
    errors = []
    store = described_class.new(lambda {
      calls += 1
      raise KnoxCall::NetworkError, "network error: ECONNRESET" if fail

      manifest([entry("a.example", "a")])
    }, on_error: ->(e) { errors << e }, now: now)
    store.ensure
    fail = true
    clock[0] += 61
    store.ensure # 2nd call, fails
    expect(calls).to eq(2)
    expect(store.manifest["routes"].length).to eq(1) # stale-but-valid
    expect(store.last_error).to be_a(KnoxCall::NetworkError)
    expect(errors.length).to eq(1)
    # one transient failure keeps the TTL…
    clock[0] += 61
    store.ensure
    expect(calls).to eq(3)
    # …the second consecutive failure doubles it: nothing at +60, a call at +120
    clock[0] += 61
    store.ensure
    expect(calls).to eq(3)
    clock[0] += 61
    store.ensure
    expect(calls).to eq(4)
  end

  it "treats a permission refusal as no manifest, warns once and re-checks slowly" do
    denied = true
    calls = 0
    store = described_class.new(lambda {
      calls += 1
      raise KnoxCall::PermissionDeniedError.new("insufficient scope", 403) if denied

      manifest([entry("a.example", "a")])
    }, now: now)

    expect { store.ensure }.to output(/routes:read/).to_stderr
    expect(store.manifest).to be_nil
    expect(store.permission_denied?).to be(true)
    clock[0] += 5 * 60
    expect { store.ensure }.not_to output.to_stderr # not yet re-checked, and never warned twice
    expect(calls).to eq(1)
    denied = false
    clock[0] += 301
    store.ensure
    expect(calls).to eq(2)
    expect(store.permission_denied?).to be(false)
    expect(store.manifest["routes"].length).to eq(1)
  end

  it "treats a 404 from an older server as no manifest too" do
    store = described_class.new(-> { raise KnoxCall::NotFoundError.new("no such route", 404) }, now: now)
    expect { store.ensure }.to output(/HTTP 404/).to_stderr
    expect(store.permission_denied?).to be(true)
  end

  it "shares one fetch between concurrent forced refreshes" do
    calls = 0
    entered = Queue.new
    gate = Queue.new
    store = described_class.new(lambda {
      calls += 1
      entered << true
      gate.pop
      manifest([entry("a.example", "a")])
    }, now: now)

    t1 = Thread.new { store.refresh("a", force: true) }
    entered.pop # the first caller is inside the fetch, holding the lock
    t2 = Thread.new { store.refresh("b", force: true) }
    sleep 0.01 until t2.status == "sleep" # the second caller is waiting on the mutex
    gate << true
    expect([t1.value, t2.value].map { |m| m["version"] }).to eq(%w[v:a v:a])
    expect(calls).to eq(1)
  end

  it "rate-limits out-of-cycle refreshes; force bypasses the gap" do
    calls = 0
    store = described_class.new(-> { calls += 1; manifest([]) }, now: now, min_refresh_gap: 5.0)
    store.refresh("start", force: true)
    store.refresh("hint") # inside the gap → no call
    expect(calls).to eq(1)
    clock[0] += 6
    store.refresh("hint")
    expect(calls).to eq(2)
    store.refresh("manual", force: true)
    expect(calls).to eq(3)
  end

  it "makes the next request refresh after a hint, rate-limited" do
    calls = 0
    store = described_class.new(-> { calls += 1; manifest([]) }, now: now)
    store.ensure
    store.hint # inside the 5 s gap of the refresh just done: ignored
    expect(store.stale?).to be(false)
    clock[0] += 6
    store.hint
    expect(store.stale?).to be(true)
    store.ensure
    expect(calls).to eq(2)
  end

  it "drops the manifest on stop and refuses to refresh" do
    store = described_class.new(-> { manifest([entry("a.example", "a")]) }, now: now)
    store.ensure
    store.stop
    expect(store.manifest).to be_nil
    expect(store.stale?).to be(false)
    expect(store.refresh("x", force: true)).to be_nil
  end

  it "never raises out of ensure on a first failure" do
    store = described_class.new(-> { raise "boom" }, now: now)
    expect(store.ensure).to be_nil
    expect(store.last_error).to be_a(RuntimeError)
  end

  # ── the conditional poll (PARITY §21.1 "Conditional poll") ────────────────
  # Driven by the CROSS-LANGUAGE fixture sdk/fixtures/intercept-store-conditional.json;
  # node (sdk/knoxcall-node/test/intercept-manifest-store.test.ts) is the reference.
  describe "conditional poll (shared fixtures)" do
    let(:fixture) do
      JSON.parse(File.read(File.expand_path("../../fixtures/intercept-store-conditional.json", __dir__)))
    end

    it "has the steps this suite walks" do
      expect(fixture["steps"].length).to be >= 4
      expect(fixture["steps"][0]["expect"]["fetch_if_none_match"]).to be_nil
      expect(fixture["steps"].any? { |s| s["respond"]["status"] == 304 }).to be(true)
      expect(fixture["steps"].any? { |s| s["forced"] }).to be(true)
    end

    it "walks every step: the held version rides on every poll after the first (lazy or forced); " \
       "a 304 keeps the manifest and fires no hook; a 200 with a new version replaces it and fires the diff" do
      sent = []
      respond = nil
      refreshes = []
      fetch = lambda do |if_none_match: nil|
        sent << if_none_match
        next nil if respond["status"] == 304

        fixture["manifests"][respond["manifest"]]
      end
      store = described_class.new(fetch, on_refresh: ->(info) { refreshes << info }, now: now)

      fixture["steps"].each_with_index do |step, i|
        respond = step["respond"]
        refreshes.clear
        if i.zero?
          store.ensure
        elsif step["forced"]
          store.refresh("route_refused", force: true)
        else
          clock[0] += 61 # one TTL after the previous answer
          expect(store.stale?).to be(true), step["name"]
          store.ensure
        end
        expect(sent.length).to eq(i + 1), step["name"]
        expect(sent[i]).to eq(step["expect"]["fetch_if_none_match"]), step["name"]
        expect(store.version).to eq(step["expect"]["version"]), step["name"]
        expect(store.manifest&.dig("version")).to eq(step["expect"]["version"]), step["name"]
        expect(store.last_error).to be_nil, step["name"]
        expect(store.stale?).to be(false), step["name"] # every answer, a 304 included, restarts the clock
        if step["expect"]["refresh_fired"]
          expect(refreshes.length).to eq(1), step["name"]
          expect(refreshes[0][:version]).to eq(step["expect"]["version"]), step["name"]
          expect(refreshes[0][:added].map { |e| e["slug"] }).to eq(step["expect"]["added"]), step["name"]
          expect(refreshes[0][:removed].map { |e| e["slug"] }).to eq(step["expect"]["removed"]), step["name"]
        else
          expect(refreshes).to eq([]), step["name"]
        end
      end
    end

    it "clears the backoff a run of faults built up on a 304" do
      mode = :ok
      fetch = lambda do |if_none_match: nil|
        raise "boom" if mode == :fault
        next nil if mode == :not_modified

        manifest([entry("a.example", "a")])
      end
      store = described_class.new(fetch, now: now)
      store.ensure
      mode = :fault
      clock[0] += 61
      store.ensure # fault #1 → next at TTL
      clock[0] += 61
      store.ensure # fault #2 → next at 2×TTL
      clock[0] += 61
      expect(store.stale?).to be(false)
      clock[0] += 60
      mode = :not_modified
      store.ensure # a 304 after the 2×TTL wait
      expect(store.manifest["routes"].map { |r| r["slug"] }).to eq(["a"])
      expect(store.last_error).to be_nil
      clock[0] += 61 # back to one TTL, not 4×
      expect(store.stale?).to be(true)
    end

    it "polls unconditionally again after a permission refusal dropped the held version" do
      denied = false
      sent = []
      fetch = lambda do |if_none_match: nil|
        sent << if_none_match
        raise KnoxCall::PermissionDeniedError.new("insufficient scope", 403) if denied

        manifest([entry("a.example", "a")])
      end
      store = described_class.new(fetch, now: now)
      store.ensure
      denied = true
      store.refresh("manual", force: true)
      expect(sent).to eq([nil, "v:a"])
      expect(store.version).to be_nil
      denied = false
      store.refresh("manual", force: true)
      expect(sent[2]).to be_nil
      expect(store.version).to eq("v:a")
    end

    it "keeps polling unconditionally for a zero-argument fetch, and treats **rest as accepting the version" do
      calls = 0
      store = described_class.new(-> { calls += 1; manifest([entry("a.example", "a")]) }, now: now)
      store.ensure
      clock[0] += 61
      store.ensure
      expect(calls).to eq(2)
      expect(store.version).to eq("v:a")

      seen = []
      fetch = ->(**kw) { seen << kw; kw[:if_none_match] == "v:a" ? nil : manifest([entry("a.example", "a")]) }
      store2 = described_class.new(fetch, now: now)
      store2.ensure
      clock[0] += 61
      store2.ensure
      expect(seen).to eq([{}, { if_none_match: "v:a" }])
      expect(store2.version).to eq("v:a")
    end
  end
end
