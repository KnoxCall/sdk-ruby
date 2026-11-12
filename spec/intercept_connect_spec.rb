# frozen_string_literal: true

# wrap.intercept! must not connect to the real upstream for a request it is
# about to reroute (route-aware-interception-plan.md PR8; CI smoke on #1000).
#
# Net::HTTP connects in +start+, BEFORE +request+ — the method the seam
# prepends — so the first cut opened a TCP connection to the real host and
# then rerouted the request. Harmless while the host answers; fatal when it
# does not: the CI smoke runs each SDK in a container where the echo's address
# is the container's own loopback, and +Net::HTTP.get_response+ died with
# +ECONNREFUSED+ in +connect+ before KnoxCall was ever asked.
#
# WebMock could never show this: its Net::HTTP replacement defers the
# connection itself, which is exactly the behaviour the seam now has. So these
# examples run against the ORIGINAL Net::HTTP with a real closed port.
require "socket"

RSpec.describe "wrap.intercept! defers the real connection" do
  around do |example|
    WebMock.disable!
    begin
      example.run
    ensure
      WebMock.enable!
    end
  end

  let(:knox) do
    KnoxCall::Client.new(
      tenant: "acme", base_url: "https://api.example.test", proxy_base_url: "https://acme.example.test",
      api_key: "kc_live_x", retry_base_delay: 0.001
    )
  end
  let(:handles) { [] }
  after { handles.each(&:uninstall) }

  # A loopback port nothing listens on: bind, read, release.
  def closed_port
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    server.close
    port
  end

  def install(**opts)
    knox.wrap.intercept!(routes: :off, **opts).tap { |h| handles << h }
  end

  def fake_response
    Net::HTTPOK.new("1.1", "200", "OK").tap { |r| r.instance_variable_set(:@read, true) }
  end

  it "never connects to a host it reroutes: a listed host on a closed port is answered by the pipeline" do
    handle = install(hosts: ["127.0.0.1"])
    port = closed_port
    resp = fake_response
    sent = []
    allow(handle.pipeline).to receive(:send) { |decision, **kw| sent << [decision, kw]; resp }

    got = Net::HTTP.get_response(URI("http://127.0.0.1:#{port}/objects?probe=1"))

    expect(got).to be(resp)
    expect(sent.size).to eq(1)
    expect(sent.first.first).to be_ephemeral
    expect(sent.first.last[:url]).to eq("http://127.0.0.1:#{port}/objects?probe=1")
  end

  it "still connects for a direct decision: an unlisted host on a closed port refuses as it always did" do
    install(hosts: ["api.other.example"])
    port = closed_port

    expect { Net::HTTP.get_response(URI("http://127.0.0.1:#{port}/x")) }.to raise_error(Errno::ECONNREFUSED)
  end

  it "connects at that moment when the pipeline hands the request back (the unavailable: :direct fallback)" do
    handle = install(hosts: ["127.0.0.1"])
    port = closed_port
    allow(handle.pipeline).to receive(:send).and_return(KnoxCall::InterceptPipeline::DIRECT)

    expect { Net::HTTP.get_response(URI("http://127.0.0.1:#{port}/x")) }.to raise_error(Errno::ECONNREFUSED)
  end

  it "connects when the seam is uninstalled between start and request" do
    handle = install(hosts: ["127.0.0.1"])
    port = closed_port
    http = Net::HTTP.new("127.0.0.1", port)
    http.start # deferred: nothing listens, and nothing raised
    handle.uninstall

    expect { http.request(Net::HTTP::Get.new("/x")) }.to raise_error(Errno::ECONNREFUSED)
  ensure
    http&.finish if http&.started?
  end
end
