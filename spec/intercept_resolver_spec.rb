# The route-aware decision table, driven by the CROSS-LANGUAGE fixtures in
# sdk/fixtures/intercept-resolver.json (route-aware-interception-plan.md §2.2,
# PARITY §21.1). Node is the reference; this is the Ruby mirror running the
# same cases unchanged. A missing fixture FAILS rather than skips — a skipped
# contract test reads as a pass.

require "json"
require "set"

RSpec.describe KnoxCall::InterceptResolver do
  fixture_path = File.expand_path("../../fixtures/intercept-resolver.json", __dir__)
  raise "the shared resolver fixture must exist at #{fixture_path}" unless File.exist?(fixture_path)

  fixture = JSON.parse(File.read(fixture_path))
  cases = fixture.fetch("cases")

  def host_set(hosts)
    Set.new(hosts.map { |h| KnoxCall::WrapTransport.normalize_host(h) })
  end

  it "runs a non-trivial fixture" do
    expect(cases.length).to be > 15
    expect(fixture.dig("manifest", "routes").length).to be > 3
  end

  cases.each do |c|
    it c.fetch("name") do
      manifest = c.key?("manifest") ? c["manifest"] : fixture["manifest"]
      hosts = c["hosts"] == "all" ? :all : host_set(c["hosts"])
      d = described_class.resolve(
        url: c["url"], method: c["method"], hosts: hosts, manifest: manifest,
        own_hosts: host_set(fixture["own_hosts"]),
        route_around: KnoxCall::WrapTransport::DEFAULT_ROUTE_AROUND,
        kill_switch: c["kill_switch"], require_context: c["require_context"], in_context: c["in_context"]
      )
      exp = c.fetch("expect")
      expect(d.mode.to_s).to eq(exp["mode"]), "#{c['url']}: mode #{d.mode} (reason #{d.reason})"
      expect(d.reason.to_s).to eq(exp["reason"]), "#{c['url']}: reason #{d.reason}"
      expect(d.slug).to eq(exp["slug"]) if exp.key?("slug")
      expect(d.path).to eq(exp["path"]) if exp.key?("path")
      if d.mode == :route
        expect(d.entry).not_to be_nil
        expect(d.entry["slug"]).to eq(d.slug)
      else
        expect([d.slug, d.path, d.entry]).to eq([nil, nil, nil])
      end
    end
  end

  describe ".rebase_path" do
    it "is segment-aware" do
      expect(described_class.rebase_path("/crm/v3/objects", "/crm/v3")).to eq("/objects")
      expect(described_class.rebase_path("/crm/v3", "/crm/v3")).to eq("/")
      expect(described_class.rebase_path("/crm/v30/x", "/crm/v3")).to be_nil
      expect(described_class.rebase_path("/anything", "/")).to eq("/anything")
      expect(described_class.rebase_path("", "/")).to eq("/")
      expect(described_class.rebase_path("x", "/")).to eq("/x")
      expect(described_class.rebase_path("/other", "/crm/v3")).to be_nil
    end
  end

  describe "WrapTransport.normalize_host (PARITY §21 contract)" do
    it "lower-cases, strips whitespace, brackets and a trailing dot" do
      expect(KnoxCall::WrapTransport.normalize_host(" API.Example. ")).to eq("api.example")
      expect(KnoxCall::WrapTransport.normalize_host("[::1]")).to eq("::1")
      expect(KnoxCall::WrapTransport.normalize_host(nil)).to eq("")
    end
  end

  describe ".platform_host?" do
    it "covers knoxcall.com and every subdomain, never look-alikes" do
      expect(described_class.platform_host?("knoxcall.com")).to be(true)
      expect(described_class.platform_host?("acme.knoxcall.com")).to be(true)
      expect(described_class.platform_host?("x.wrap.knoxcall.com")).to be(true)
      expect(described_class.platform_host?("knoxcall.com.evil.example")).to be(false)
      expect(described_class.platform_host?("notknoxcall.com")).to be(false)
    end
  end

  describe ".entries_for_host" do
    it "orders longest base_path first, then slug, and normalises the entry host" do
      m = { "routes" => [
        { "host" => "h.example", "base_path" => "/", "slug" => "z" },
        { "host" => "h.example", "base_path" => "/a/b", "slug" => "deep" },
        { "host" => "H.EXAMPLE.", "base_path" => "/", "slug" => "a" },
        { "host" => "other.example", "base_path" => "/", "slug" => "o" }
      ] }
      expect(described_class.entries_for_host(m, "h.example").map { |e| e["slug"] }).to eq(%w[deep a z])
      expect(described_class.entries_for_host(nil, "h.example")).to eq([])
    end
  end

  it "never lets a port in the request URL affect the host match" do
    m = { "routes" => [{ "host" => "h.example", "base_path" => "/", "slug" => "h" }] }
    d = described_class.resolve(url: "https://h.example:8443/x?y=1", method: "GET", hosts: Set.new, manifest: m,
                                own_hosts: Set.new, route_around: [])
    expect([d.mode, d.slug, d.path]).to eq([:route, "h", "/x?y=1"])
  end

  describe ".kill_switch?" do
    around do |example|
      previous = ENV["KNOXCALL_INTERCEPT"]
      example.run
    ensure
      previous.nil? ? ENV.delete("KNOXCALL_INTERCEPT") : ENV["KNOXCALL_INTERCEPT"] = previous
    end

    it "reads off / 0 / false, case-insensitively" do
      { "off" => true, "OFF" => true, " 0 " => true, "false" => true, "on" => false, "" => false, "1" => false }.each do |v, want|
        ENV["KNOXCALL_INTERCEPT"] = v
        expect(described_class.kill_switch?).to be(want), "KNOXCALL_INTERCEPT=#{v.inspect}"
      end
    end
  end
end
