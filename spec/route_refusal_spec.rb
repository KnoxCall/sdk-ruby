# The route-mode refusal predicate, driven by the CROSS-LANGUAGE fixtures in
# sdk/fixtures/route-refusal.json (PARITY §21.1, "Refusal-driven refresh").
# Node is the reference; this spec consumes the same cases unchanged.

require "json"
require "net/http"

RSpec.describe KnoxCall::RouteRefusal do
  fixture_path = File.expand_path("../../fixtures/route-refusal.json", __dir__)
  fixture = JSON.parse(File.read(fixture_path))
  cases = fixture.fetch("cases")

  it "has cases in both directions, so a predicate stuck on one answer cannot pass" do
    expect(cases.map { |c| c.dig("expect", "refusal") }.uniq.sort_by(&:to_s)).to eq([false, true])
    expect(cases.length).to be >= 10
  end

  cases.each do |c|
    it c.fetch("name") do
      expect(described_class.refusal?(status: c.fetch("status"), headers: c.fetch("headers"), body: c.fetch("body")))
        .to be(c.dig("expect", "refusal"))
    end
  end

  it "reads a real Net::HTTPResponse the way the pipeline hands it over (to_hash: lower-cased keys, array values)" do
    resp = Net::HTTPNotFound.new("1.1", "404", "Not Found")
    resp["X-Knox-Origin"] = "knoxcall"
    resp["X-Knox-Error"] = "route_not_found"
    resp.instance_variable_set(:@read, true)
    resp.instance_variable_set(:@body, '{"error":{"type":"route_not_found","message":"x","request_id":"r"}}')
    expect(described_class.refusal?(status: resp.code.to_i, headers: resp.to_hash, body: resp.body)).to be(true)

    resp["X-Knox-Upstream-Status"] = "404"
    expect(described_class.refusal?(status: resp.code.to_i, headers: resp.to_hash, body: resp.body)).to be(false)
  end
end
