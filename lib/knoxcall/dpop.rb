require "openssl"
require "securerandom"
require "json"

module KnoxCall
  # DPoP proof generation (RFC 9449) — client side. Ruby port of
  # knoxcall-node/src/auth/dpop.ts (see ../../PARITY.md §7).
  #
  # Generates an ES256 (P-256) keypair and signs a fresh proof JWT per
  # request (new jti/iat every call, htu stripped of query and fragment,
  # ath bound to the access token when one is presented). Uses the openssl
  # stdlib already required by the client — no new gem. The private key
  # never leaves the process.
  class DpopKeyPair
    attr_reader :public_jwk

    def self.generate
      new(OpenSSL::PKey::EC.generate("prime256v1"))
    end

    def initialize(key)
      @key = key
      point = key.public_key.to_bn.to_s(2) # uncompressed: 0x04 || X || Y
      unless point.bytesize == 65 && point.getbyte(0) == 4
        raise Error, "unexpected EC public key encoding"
      end
      # Member order crv, kty, x, y matches the RFC 7638 canonical order, so
      # the same hash serves both the proof header and the thumbprint input.
      @public_jwk = {
        "crv" => "P-256",
        "kty" => "EC",
        "x" => self.class.b64url(point.byteslice(1, 32)),
        "y" => self.class.b64url(point.byteslice(33, 32))
      }.freeze
    end

    # Sign a DPoP proof JWT for one request (RFC 9449 §4.2). The signature is
    # ECDSA P-256 + SHA-256 in JOSE P1363 form (r||s, 64 bytes), matching the
    # server verifier in src/lib/dpop-verifier.ts.
    def sign(method, url, access_token: nil, nonce: nil)
      htu = url.split("#", 2).first.split("?", 2).first
      header = { "alg" => "ES256", "typ" => "dpop+jwt", "jwk" => @public_jwk }
      payload = {
        "htm" => method.to_s.upcase,
        "htu" => htu,
        "iat" => Time.now.to_i,
        "jti" => self.class.b64url(SecureRandom.random_bytes(16))
      }
      if access_token && !access_token.empty?
        payload["ath"] = self.class.b64url(OpenSSL::Digest::SHA256.digest(access_token))
      end
      payload["nonce"] = nonce if nonce && !nonce.to_s.empty?

      signing_input = "#{self.class.b64url(JSON.generate(header))}.#{self.class.b64url(JSON.generate(payload))}"
      der = @key.sign(OpenSSL::Digest.new("SHA256"), signing_input)
      "#{signing_input}.#{self.class.b64url(self.class.der_to_p1363(der))}"
    end

    # RFC 7638 JWK thumbprint of the public key — the value the server binds
    # tokens to as cnf.jkt.
    def thumbprint
      self.class.b64url(OpenSSL::Digest::SHA256.digest(JSON.generate(@public_jwk)))
    end

    # Unpadded base64url via pack, not the base64 gem — base64 left the
    # stdlib default set in Ruby 3.4, and the README promises stdlib only.
    def self.b64url(bytes)
      [bytes].pack("m0").tr("+/", "-_").delete("=")
    end

    # Convert an ASN.1/DER ECDSA signature to JOSE P1363 (r||s, 64 bytes).
    def self.der_to_p1363(der)
      seq = OpenSSL::ASN1.decode(der)
      r, s = seq.value.map { |int| int.value.to_s(2) } # BN → big-endian binary, no leading zeros
      raise Error, "invalid DER signature" if r.bytesize > 32 || s.bytesize > 32
      r.rjust(32, "\0") + s.rjust(32, "\0")
    end
  end
end
