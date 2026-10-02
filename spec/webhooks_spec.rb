# construct_event — verify-and-parse for incoming webhook deliveries
# (PARITY §12). Signatures are produced exactly the way the server's
# src/webhooks/hmac-formats.ts does, then verified round-trip.

RSpec.describe "KnoxCall webhook event construction" do
  WH_SECRET = "whsec_test_do_not_leak".freeze

  # A realistic delivery envelope with a fresh ISO-8601 timestamp.
  def body_for(event: "request.success", timestamp: nil)
    JSON.generate(
      event: event,
      timestamp: timestamp || Time.now.utc.iso8601,
      webhook_id: "wh_123",
      webhook_name: "orders-hook",
      data: {
        route_id: "r_1",
        route_name: "orders",
        environment: "production",
        request: { method: "POST", path: "/v1/orders", ip: "203.0.113.9" },
        response: { status: 201, latency_ms: 42 }
      }
    )
  end

  def legacy_sign(body, key = WH_SECRET)
    "sha256=#{OpenSSL::HMAC.hexdigest('SHA256', key, body)}"
  end

  # -- legacy ----------------------------------------------------------------------

  it "verifies and parses a legacy event into typed fields" do
    body = body_for
    event = KnoxCall::Client.construct_event(body, {
      "X-Webhook-Signature" => legacy_sign(body),
      "X-Webhook-ID" => "wh_123",
      "X-Webhook-Event" => "request.success"
    }, WH_SECRET)

    expect(event["event"]).to eq("request.success")
    expect(event["webhook_id"]).to eq("wh_123")
    expect(event["webhook_name"]).to eq("orders-hook")
    expect(event["data"]["route_name"]).to eq("orders")
    expect(event["data"]["response"]["status"]).to eq(201)
  end

  it "looks headers up case-insensitively and takes the first of multi-values" do
    body = body_for
    event = KnoxCall::Client.construct_event(
      body, { "x-webhook-signature" => [legacy_sign(body), "sha256=bogus"] }, WH_SECRET
    )
    expect(event["event"]).to eq("request.success")
  end

  it "raises the typed error on a wrong secret without echoing signature or secret" do
    body = body_for
    expect {
      KnoxCall::Client.construct_event(
        body, { "X-Webhook-Signature" => legacy_sign(body, "whsec_other") }, WH_SECRET
      )
    }.to raise_error(KnoxCall::WebhookSignatureVerificationError) { |e|
      expect(e).to be_a(KnoxCall::Error) # inside the SDK hierarchy
      expect(e.message).not_to include(WH_SECRET)
      expect(e.message).not_to include(OpenSSL::HMAC.hexdigest("SHA256", "whsec_other", body))
    }
  end

  it "raises the typed error when the signature header is missing" do
    expect {
      KnoxCall::Client.construct_event(body_for, { "Content-Type" => "application/json" }, WH_SECRET)
    }.to raise_error(KnoxCall::WebhookSignatureVerificationError, /missing signature header/)
  end

  it "rejects a stale envelope timestamp for legacy, unless tolerance is disabled" do
    body = body_for(timestamp: (Time.now.utc - 3600).iso8601)
    headers = { "X-Webhook-Signature" => legacy_sign(body) }

    expect { KnoxCall::Client.construct_event(body, headers, WH_SECRET) }
      .to raise_error(KnoxCall::WebhookSignatureVerificationError, /tolerance/)

    # Explicitly disabling the tolerance skips the replay check.
    event = KnoxCall::Client.construct_event(body, headers, WH_SECRET, tolerance_seconds: nil)
    expect(event["event"]).to eq("request.success")
  end

  # -- stripe ----------------------------------------------------------------------

  it "round-trips the stripe format" do
    body = body_for
    ts = Time.now.to_i
    sig = OpenSSL::HMAC.hexdigest("SHA256", WH_SECRET, "#{ts}.#{body}")

    event = KnoxCall::Client.construct_event(
      body, { "Stripe-Signature" => "t=#{ts},v1=#{sig}" }, WH_SECRET, format: "stripe"
    )
    expect(event["event"]).to eq("request.success")
  end

  it "rejects a stale stripe header timestamp" do
    body = body_for
    ts = Time.now.to_i - 4000 # outside the default 300s window
    sig = OpenSSL::HMAC.hexdigest("SHA256", WH_SECRET, "#{ts}.#{body}")

    expect {
      KnoxCall::Client.construct_event(
        body, { "Stripe-Signature" => "t=#{ts},v1=#{sig}" }, WH_SECRET, format: "stripe"
      )
    }.to raise_error(KnoxCall::WebhookSignatureVerificationError, /tolerance/)
  end

  it "rejects a non-numeric stripe header timestamp (never silently NaN)" do
    body = body_for
    sig = OpenSSL::HMAC.hexdigest("SHA256", WH_SECRET, "not-a-number.#{body}")

    expect {
      KnoxCall::Client.construct_event(
        body, { "Stripe-Signature" => "t=not-a-number,v1=#{sig}" }, WH_SECRET, format: "stripe"
      )
    }.to raise_error(KnoxCall::WebhookSignatureVerificationError, /malformed Stripe-Signature/)
  end

  it "rejects a non-numeric stripe timestamp even when tolerance is disabled" do
    body = body_for
    sig = OpenSSL::HMAC.hexdigest("SHA256", WH_SECRET, "not-a-number.#{body}")

    expect {
      KnoxCall::Client.construct_event(
        body, { "Stripe-Signature" => "t=not-a-number,v1=#{sig}" }, WH_SECRET,
        format: "stripe", tolerance_seconds: nil
      )
    }.to raise_error(KnoxCall::WebhookSignatureVerificationError, /malformed Stripe-Signature/)
  end

  it "accepts multiple stripe v1 entries when any one matches" do
    # Mirrors Stripe's own behavior during secret rotation.
    body = body_for
    ts = Time.now.to_i
    good = OpenSSL::HMAC.hexdigest("SHA256", WH_SECRET, "#{ts}.#{body}")
    bad = OpenSSL::HMAC.hexdigest("SHA256", "whsec_rotated_out", "#{ts}.#{body}")

    event = KnoxCall::Client.construct_event(
      body, { "Stripe-Signature" => "t=#{ts},v1=#{bad},v1=#{good}" }, WH_SECRET, format: "stripe"
    )
    expect(event["event"]).to eq("request.success")

    expect {
      KnoxCall::Client.construct_event(
        body, { "Stripe-Signature" => "t=#{ts},v1=#{bad}" }, WH_SECRET, format: "stripe"
      )
    }.to raise_error(KnoxCall::WebhookSignatureVerificationError, /mismatch/)
  end

  # -- slack -----------------------------------------------------------------------

  it "round-trips the slack format" do
    body = body_for
    ts = Time.now.to_i.to_s
    sig = "v0=#{OpenSSL::HMAC.hexdigest('SHA256', WH_SECRET, "v0:#{ts}:#{body}")}"

    event = KnoxCall::Client.construct_event(
      body, { "X-Slack-Signature" => sig, "X-Slack-Request-Timestamp" => ts },
      WH_SECRET, format: "slack"
    )
    expect(event["event"]).to eq("request.success")
  end

  it "rejects a stale slack timestamp" do
    body = body_for
    ts = (Time.now.to_i - 4000).to_s
    sig = "v0=#{OpenSSL::HMAC.hexdigest('SHA256', WH_SECRET, "v0:#{ts}:#{body}")}"

    expect {
      KnoxCall::Client.construct_event(
        body, { "X-Slack-Signature" => sig, "X-Slack-Request-Timestamp" => ts },
        WH_SECRET, format: "slack"
      )
    }.to raise_error(KnoxCall::WebhookSignatureVerificationError, /tolerance/)
  end

  it "rejects a non-numeric slack request timestamp (never silently NaN)" do
    body = body_for
    ts = "not-a-number"
    sig = "v0=#{OpenSSL::HMAC.hexdigest('SHA256', WH_SECRET, "v0:#{ts}:#{body}")}"

    expect {
      KnoxCall::Client.construct_event(
        body, { "X-Slack-Signature" => sig, "X-Slack-Request-Timestamp" => ts },
        WH_SECRET, format: "slack"
      )
    }.to raise_error(KnoxCall::WebhookSignatureVerificationError, /malformed X-Slack-Request-Timestamp/)
  end

  # -- github / aws-sns / custom -----------------------------------------------------

  it "verifies the github format" do
    body = body_for
    event = KnoxCall::Client.construct_event(
      body, { "X-Hub-Signature-256" => legacy_sign(body) }, WH_SECRET, format: "github"
    )
    expect(event["event"]).to eq("request.success")
  end

  it "verifies the aws-sns base64 format" do
    body = body_for
    sig = [OpenSSL::HMAC.digest("SHA256", WH_SECRET, body)].pack("m0")

    event = KnoxCall::Client.construct_event(
      body, { "x-amz-sns-signature" => sig }, WH_SECRET, format: "aws-sns"
    )
    expect(event["event"]).to eq("request.success")
  end

  it "verifies a custom header name" do
    body = body_for
    event = KnoxCall::Client.construct_event(
      body, { "X-Acme-Signature" => legacy_sign(body) },
      WH_SECRET, format: "custom", header_name: "X-Acme-Signature"
    )
    expect(event["event"]).to eq("request.success")
  end

  it "requires header_name for the custom format" do
    expect {
      KnoxCall::Client.construct_event(body_for, {}, WH_SECRET, format: "custom")
    }.to raise_error(ArgumentError, /header_name/)
  end

  it "rejects an unknown format" do
    expect {
      KnoxCall::Client.construct_event(body_for, {}, WH_SECRET, format: "md5")
    }.to raise_error(ArgumentError, /format/)
  end

  # -- parsing ------------------------------------------------------------------------

  it "raises the typed error when the body is not JSON" do
    body = "not json at all"
    expect {
      KnoxCall::Client.construct_event(body, { "X-Webhook-Signature" => legacy_sign(body) }, WH_SECRET)
    }.to raise_error(KnoxCall::WebhookSignatureVerificationError, /not a JSON object/)
  end

  it "still parses unknown event types (the list is open)" do
    body = body_for(event: "lease.expiring_soon")
    event = KnoxCall::Client.construct_event(
      body, { "X-Webhook-Signature" => legacy_sign(body) }, WH_SECRET
    )
    expect(event["event"]).to eq("lease.expiring_soon")
  end

  it "parses the audit.event shape (no webhook_id/webhook_name)" do
    body = JSON.generate(
      event: "audit.event",
      timestamp: Time.now.utc.iso8601,
      data: {
        id: "al_1", action: "route.create", resource_type: "route",
        resource_id: "r_1", details: { name: "orders" }, ip_address: "203.0.113.9"
      }
    )
    event = KnoxCall::Client.construct_event(
      body, { "X-Webhook-Signature" => legacy_sign(body) }, WH_SECRET
    )

    expect(event["event"]).to eq("audit.event")
    expect(event).not_to have_key("webhook_id")
    expect(event["data"]["action"]).to eq("route.create")
  end

  # -- placement + implementation properties -------------------------------------------

  it "delegates from the instance method and the webhooks resource without HTTP" do
    # WebMock is active with no stubs: any HTTP attempt would raise.
    client = KnoxCall::Client.new(tenant: "acme", api_key: "kc_live_x")

    body = body_for
    headers = { "X-Webhook-Signature" => legacy_sign(body) }
    expect(client.construct_event(body, headers, WH_SECRET)["event"]).to eq("request.success")
    expect(client.webhooks.construct_event(body, headers, WH_SECRET)["event"]).to eq("request.success")
  end

  it "routes every signature comparison through a constant-time compare" do
    # Assert via the implementation (not timing): every comparison inside
    # construct_event goes through OpenSSL.secure_compare.
    path, start_line = KnoxCall::Client.method(:construct_event).source_location
    snippet = +""
    File.readlines(path)[start_line..].each do |line| # from the line after `def`
      break if line.match?(/^    (def |private\b)/)
      snippet << line
    end

    expect(snippet).to include("OpenSSL.secure_compare")
    # No direct equality on a computed HMAC anywhere in the method.
    expect(snippet).not_to include("==")
  end

  it "keeps the boolean verify_signature helper unchanged (compat)" do
    body = body_for
    ts = Time.now.to_i
    sig = OpenSSL::HMAC.hexdigest("SHA256", WH_SECRET, "#{ts}.#{body}")

    expect(KnoxCall::Client.verify_signature(body, "t=#{ts},v1=#{sig}", WH_SECRET, timestamp: ts)).to be(true)
    expect(KnoxCall::Client.verify_signature(body, "t=#{ts},v1=deadbeef", WH_SECRET, timestamp: ts)).to be(false)
  end
end
