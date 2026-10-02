# KnoxCall.signup / KnoxCall.claim_signup — the credential-less
# headless-signup helpers (PARITY §11). Module-level: no constructed client
# required.
#
# Rewritten 2026-08-28 for the F-25 contract (wave-2 row 2-561): signup no
# longer has a 201 and never returns a credential. All three success shapes are
# covered — the signup 202, the claim's pending 202 (a SUCCESS, not an error)
# and the claim's ready 200.

RSpec.describe "KnoxCall.signup" do
  def accepted_response
    {
      data: {
        status: "pending",
        claim_handle: "sck_Yy3n0Rz1qF8mKpX2sVb7dH9tLwQ4eJ6uA1cN5gZ8kT0",
        claim_path: "/v1/signup/claim",
        poll_after_seconds: 5,
        expires_at: "2026-08-29T09:14:22.117Z",
        message: "If this email can be registered, a sign-in link has been sent.",
        documentation: "https://docs.knoxcall.com"
      },
      meta: { request_id: "req-signup" }
    }
  end

  it "POSTs to the public endpoint without credentials and unwraps data" do
    seen = {}
    stub_request(:post, "https://api.knoxcall.com/v1/signup")
      .with { |req|
        seen[:headers] = req.headers.transform_keys(&:downcase)
        seen[:body] = JSON.parse(req.body)
        true
      }
      .to_return(status: 202, body: JSON.generate(accepted_response),
                 headers: { "Content-Type" => "application/json" })

    accepted = KnoxCall.signup({ email: "dev@example.com", tenant_name: "Acme Inc" })

    expect(seen[:headers]).not_to have_key("authorization") # credential-less
    expect(seen[:headers]["content-type"]).to eq("application/json")
    expect(seen[:body]).to eq("email" => "dev@example.com", "tenant_name" => "Acme Inc")

    # Unwrapped, and carrying a handle rather than a credential.
    expect(accepted["status"]).to eq("pending")
    expect(accepted["claim_handle"]).to start_with("sck_")
    expect(accepted["poll_after_seconds"]).to eq(5)
    expect(accepted).not_to have_key("data")
    # The contract row 2-561 exists to enforce.
    expect(JSON.generate(accepted)).not_to include("tk_")
    expect(accepted).not_to have_key("starter")
  end

  it "answers an already-registered address identically (no enumeration signal)" do
    stub_request(:post, "https://api.knoxcall.com/v1/signup")
      .to_return(status: 202, body: JSON.generate(accepted_response))

    out = KnoxCall.signup({ email: "known@example.com", tenant_name: "Acme" })
    expect(out["status"]).to eq("pending")
    expect(out).not_to have_key("starter")
  end

  it "honors a custom base_url" do
    staging = stub_request(:post, "https://api-staging.knoxcall.com/v1/signup")
              .to_return(status: 202, body: JSON.generate(accepted_response))

    KnoxCall.signup({ email: "dev@example.com", tenant_name: "Acme Inc" },
                    base_url: "https://api-staging.knoxcall.com/")

    expect(staging).to have_been_requested.once
  end

  it "raises SignupError (inside the SDK hierarchy) with the server's error fields" do
    stub_request(:post, "https://api.knoxcall.com/v1/signup").to_return(
      status: 409,
      body: '{"error":{"type":"slug_taken","message":"That slug is taken.","request_id":"req-c9"}}'
    )

    expect {
      KnoxCall.signup({ email: "dev@example.com", tenant_name: "Acme", tenant_slug: "acme" })
    }.to raise_error(KnoxCall::SignupError) { |e|
      expect(e).to be_a(KnoxCall::Error) # part of the SDK hierarchy, not a bare error
      expect(e.message).to include("That slug is taken.")
      expect(e.status_code).to eq(409)
      expect(e.error_type).to eq("slug_taken")
      expect(e.request_id).to eq("req-c9")
    }
  end

  it "raises SignupError on an unexpected (non-envelope) body" do
    stub_request(:post, "https://api.knoxcall.com/v1/signup").to_return(
      status: 200, body: "<html>edge proxy</html>"
    )

    expect {
      KnoxCall.signup({ email: "dev@example.com", tenant_name: "Acme" })
    }.to raise_error(KnoxCall::SignupError) { |e| expect(e.status_code).to eq(200) }
  end

  it "maps transport failures to the SDK connection errors" do
    stub_request(:post, "https://api.knoxcall.com/v1/signup").to_raise(Errno::ECONNREFUSED)

    expect {
      KnoxCall.signup({ email: "dev@example.com", tenant_name: "Acme" })
    }.to raise_error(KnoxCall::NetworkError)
  end
end

RSpec.describe "KnoxCall.claim_signup" do
  def ready_response
    {
      data: {
        status: "ready",
        tenant: { id: "tn_1", slug: "acme", name: "Acme Inc", region: "us", plan: "free" },
        starter: {
          route: { id: "r_1", name: "getting-started", target_base_url: "https://httpbin.org" },
          api_key: { id: "k_1", key_id: "key_1", api_key: "tk_test_once",
                     key_prefix: "tk_test_", key_type: "test" },
          sandbox_host: "sandbox-acme.knoxcall.com",
          curl: "curl ..."
        },
        sandbox: { management_api: "https://sandbox.knoxcall.com/v1",
                   proxy_host: "sandbox-acme.knoxcall.com", note: "Test mode" },
        documentation: "https://docs.knoxcall.com"
      },
      meta: { request_id: "req-claim" }
    }
  end

  it "treats the pending 202 as a SUCCESS and sends the handle in the body" do
    seen = {}
    stub_request(:post, "https://api.knoxcall.com/v1/signup/claim")
      .with { |req|
        seen[:body] = JSON.parse(req.body)
        seen[:headers] = req.headers.transform_keys(&:downcase)
        true
      }
      .to_return(status: 202, body: '{"data":{"status":"pending","message":"Not ready yet.",' \
                                    '"poll_after_seconds":5,"expires_at":"2026-08-29T09:14:22.117Z"},"meta":{}}')

    out = KnoxCall.claim_signup("sck_handle")

    expect(seen[:headers]).not_to have_key("authorization") # credential-less
    expect(seen[:body]).to eq("claim_handle" => "sck_handle")
    expect(out["status"]).to eq("pending")
    expect(out).not_to have_key("starter")
  end

  it "returns the one-time starter key once the link has been clicked" do
    stub_request(:post, "https://api.knoxcall.com/v1/signup/claim")
      .to_return(status: 200, body: JSON.generate(ready_response))

    out = KnoxCall.claim_signup("sck_handle")

    expect(out["status"]).to eq("ready")
    expect(out["tenant"]["slug"]).to eq("acme")
    expect(out["starter"]["api_key"]["api_key"]).to eq("tk_test_once")
    expect(out["starter"]["api_key"]["key_type"]).to eq("test")
  end

  it "raises SignupError when the handle was already collected" do
    stub_request(:post, "https://api.knoxcall.com/v1/signup/claim").to_return(
      status: 409,
      body: '{"error":{"type":"claim_already_collected","message":"Already collected.","request_id":"req-c9"}}'
    )

    expect {
      KnoxCall.claim_signup("sck_handle")
    }.to raise_error(KnoxCall::SignupError) { |e|
      expect(e).to be_a(KnoxCall::Error)
      expect(e.status_code).to eq(409)
      expect(e.error_type).to eq("claim_already_collected")
    }
  end

  it "raises SignupError for an unknown or expired handle" do
    stub_request(:post, "https://api.knoxcall.com/v1/signup/claim").to_return(
      status: 404,
      body: '{"error":{"type":"invalid_claim","message":"That claim handle is not valid, or it has expired."}}'
    )

    expect {
      KnoxCall.claim_signup("sck_nope")
    }.to raise_error(KnoxCall::SignupError) { |e| expect(e.status_code).to eq(404) }
  end

  it "maps transport failures to the SDK connection errors" do
    stub_request(:post, "https://api.knoxcall.com/v1/signup/claim").to_raise(Errno::ECONNREFUSED)

    expect {
      KnoxCall.claim_signup("sck_handle")
    }.to raise_error(KnoxCall::NetworkError)
  end
end
