# Pure transport-helper unit tests for the wrap Faraday transport
# (KnoxCall::WrapTransport). These carry NO Faraday dependency — they load with
# the base SDK and pin the client-side security decisions (route-around
# matching, both-must-agree Test/Live, header dropping) independently of the
# adapter. The end-to-end adapter behaviour lives in wrap_faraday_spec.rb.

RSpec.describe KnoxCall::WrapTransport do
  describe ".match_route_around" do
    let(:rules) { KnoxCall::WrapTransport::DEFAULT_ROUTE_AROUND }

    it "matches a default raw-card endpoint by host + path prefix" do
      r = described_class.match_route_around("https://api.stripe.com/v1/tokens", rules)
      expect(r).not_to be_nil
      expect(r[:reason]).to match(/raw-card/)
    end

    it "does NOT match a normal endpoint on the same host" do
      expect(described_class.match_route_around("https://api.stripe.com/v1/charges", rules)).to be_nil
    end

    it "matches despite a trailing-dot FQDN (host normalized both sides)" do
      expect(described_class.match_route_around("https://api.stripe.com./v1/tokens", rules)).not_to be_nil
    end

    it "matches case-insensitively on host" do
      expect(described_class.match_route_around("https://API.STRIPE.COM/v1/sources", rules)).not_to be_nil
    end

    it "honours a caller rule with no path prefix (whole host)" do
      extra = [{ host: "files.stripe.com", reason: "multipart upload" }]
      expect(described_class.match_route_around("https://files.stripe.com/v1/files", extra)).not_to be_nil
    end

    it "tolerates string-keyed rules" do
      extra = [{ "host" => "files.stripe.com", "reason" => "multipart" }]
      expect(described_class.match_route_around("https://files.stripe.com/anything", extra)).not_to be_nil
    end

    it "returns nil for an unparseable URL rather than raising" do
      expect(described_class.match_route_around("::::not a url", rules)).to be_nil
    end
  end

  describe ".assert_route_around_rules" do
    it "accepts a bare DNS hostname" do
      expect { described_class.assert_route_around_rules([{ host: "files.stripe.com", reason: "x" }]) }
        .not_to raise_error
    end

    it "rejects a host carrying a scheme (would silently never match)" do
      expect { described_class.assert_route_around_rules([{ host: "https://api.stripe.com", reason: "x" }]) }
        .to raise_error(KnoxCall::WrapSandboxMismatchError)
    end

    it "rejects a host carrying a path" do
      expect { described_class.assert_route_around_rules([{ host: "api.stripe.com/v1", reason: "x" }]) }
        .to raise_error(KnoxCall::WrapSandboxMismatchError)
    end

    it "rejects an empty host" do
      expect { described_class.assert_route_around_rules([{ host: "", reason: "x" }]) }
        .to raise_error(KnoxCall::WrapSandboxMismatchError)
    end
  end

  describe ".assert_key_matches_sandbox" do
    it "no-ops when there is no authorization value" do
      expect { described_class.assert_key_matches_sandbox(nil, false) }.not_to raise_error
      expect { described_class.assert_key_matches_sandbox("", true) }.not_to raise_error
    end

    it "passes a live secret key on a live client" do
      expect { described_class.assert_key_matches_sandbox("Bearer sk_live_x", false) }.not_to raise_error
    end

    it "passes a test secret key on a sandbox client" do
      expect { described_class.assert_key_matches_sandbox("Bearer sk_test_x", true) }.not_to raise_error
    end

    it "passes a restricted key matching the flag" do
      expect { described_class.assert_key_matches_sandbox("Bearer rk_live_x", false) }.not_to raise_error
    end

    it "rejects a test key on a live client" do
      expect { described_class.assert_key_matches_sandbox("Bearer sk_test_x", false) }
        .to raise_error(KnoxCall::WrapSandboxMismatchError, /TEST key/)
    end

    it "rejects a live key on a sandbox client" do
      expect { described_class.assert_key_matches_sandbox("Bearer sk_live_x", true) }
        .to raise_error(KnoxCall::WrapSandboxMismatchError, /LIVE key/)
    end

    it "rejects a publishable key outright" do
      expect { described_class.assert_key_matches_sandbox("Bearer pk_live_x", false) }
        .to raise_error(KnoxCall::WrapSandboxMismatchError, /publishable/)
    end

    it "is not bypassed by a leading space before Bearer (regression #1)" do
      expect { described_class.assert_key_matches_sandbox(" Bearer sk_live_x", true) }
        .to raise_error(KnoxCall::WrapSandboxMismatchError)
    end

    it "leaves an unclassifiable non-Stripe scheme alone" do
      expect { described_class.assert_key_matches_sandbox("Bearer some_other_token", false) }.not_to raise_error
    end
  end

  describe ".forwardable_headers" do
    it "drops authorization, host and content-length (case-insensitively) and keeps the rest" do
      out = described_class.forwardable_headers(
        "Authorization" => "Bearer sk_live_x",
        "Host" => "api.stripe.com",
        "Content-Length" => "12",
        "Content-Type" => "application/json",
        "Idempotency-Key" => "idem-1"
      )
      expect(out.keys.map(&:downcase)).to contain_exactly("content-type", "idempotency-key")
      expect(out["Idempotency-Key"]).to eq("idem-1")
    end
  end
end
