# frozen_string_literal: true

# AIGW-163 — the AI DATA plane's typed refusal.
#
# The SDK deliberately does not make the data-plane call for you: you point an
# existing provider client at the agent's +agent_url+. So what the SDK owes you
# is the ability to TYPE what that client hands back — a
# {error, error_description, code} body, which is NOT the Management API's
# {"error" => {"type", "message", "request_id"}} and must not be mistaken for it.

require "spec_helper"

RSpec.describe "KnoxCall.ai_gateway_error_from" do
  let(:refusal) do
    {
      "error" => "budget_exceeded",
      "error_description" => "Daily budget exceeded: $50.0031 >= $50",
      "code" => "budget_exceeded",
      "utilization_pct" => 100.006
    }
  end

  it "returns the typed class carrying code, description and Retry-After" do
    err = KnoxCall.ai_gateway_error_from(429, refusal, {
                                           "Retry-After" => "3600",
                                           "X-Request-Id" => "0d5b2a9e-1f3c-4a7d-8e2b-6c9a1f4d7e35"
                                         })
    expect(err).to be_a(KnoxCall::AIGatewayError)
    expect(err.code).to eq("budget_exceeded")
    expect(err.status_code).to eq(429)
    expect(err.error_description).to eq("Daily budget exceeded: $50.0031 >= $50")
    expect(err.retry_after).to eq(3600)
    expect(err.request_id).to eq("0d5b2a9e-1f3c-4a7d-8e2b-6c9a1f4d7e35")
  end

  it "is an APIError, so an existing rescue still catches it" do
    # PARITY §1: every new typed error is re-parented into the hierarchy.
    err = KnoxCall.ai_gateway_error_from(403, {
                                           "error" => "model_not_allowed",
                                           "error_description" => "not on the allowlist",
                                           "code" => "model_not_allowed"
                                         })
    expect(err).to be_a(KnoxCall::APIError)
    expect(err).to be_a(KnoxCall::Error)
  end

  it "leaves retry_after nil when the header is absent or not whole seconds" do
    # Absence is meaningful: the gateway sends no header rather than a guess, so
    # nil must not become 0 (an immediate retry against a spent cap).
    expect(KnoxCall.ai_gateway_error_from(429, refusal).retry_after).to be_nil
    expect(KnoxCall.ai_gateway_error_from(429, refusal, { "Retry-After" => "" }).retry_after).to be_nil
    # An HTTP-date Retry-After is legal but is not delta-seconds.
    expect(
      KnoxCall.ai_gateway_error_from(429, refusal,
                                     { "Retry-After" => "Wed, 09 Sep 2026 00:00:00 GMT" }).retry_after
    ).to be_nil
  end

  it "returns nil for the MANAGEMENT envelope, which is a different contract" do
    expect(
      KnoxCall.ai_gateway_error_from(404, { "error" => { "type" => "not_found", "message" => "Gateway not found." } })
    ).to be_nil
  end

  it "returns nil for an RFC 6749 OAuth error, which carries no code" do
    expect(
      KnoxCall.ai_gateway_error_from(400, { "error" => "invalid_grant", "error_description" => "bad subject token" })
    ).to be_nil
  end

  it "returns nil when error and code disagree" do
    # The pre-AIGW-163 auth shape. Quietly accepting it would make #code mean
    # two things again.
    expect(
      KnoxCall.ai_gateway_error_from(401,
                                     { "error" => "Unauthorized", "code" => "expired",
                                       "reason" => "Token has expired" })
    ).to be_nil
  end

  it "returns nil for a non-Hash body" do
    expect(KnoxCall.ai_gateway_error_from(502, "<html>502 Bad Gateway</html>")).to be_nil
    expect(KnoxCall.ai_gateway_error_from(502, nil)).to be_nil
  end

  it "keeps the raw body for anything the typed fields do not carry" do
    expect(KnoxCall.ai_gateway_error_from(429, refusal).body["utilization_pct"]).to eq(100.006)
  end

  it "exposes the discriminator on its own" do
    expect(KnoxCall.ai_gateway_error_body?(refusal)).to be(true)
    expect(KnoxCall.ai_gateway_error_body?({ "error" => "x", "code" => "x" })).to be(false)
    expect(KnoxCall.ai_gateway_error_body?({ "error" => "x", "error_description" => "y" })).to be(false)
  end
end
