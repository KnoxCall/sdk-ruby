Gem::Specification.new do |spec|
  spec.name          = "knoxcall"
  spec.version       = "1.1.0"
  spec.summary       = "Official Ruby SDK for the KnoxCall API"
  spec.description   = "Ruby client for the KnoxCall multi-tenant API gateway and " \
                       "secrets platform: OAuth 2.1 + DPoP auth, route proxying, " \
                       "secrets, vaults, PKI, crypto, AI Gateway, and webhook verification."
  spec.authors       = ["KnoxCall"]
  spec.homepage      = "https://docs.knoxcall.com/api-reference"
  spec.license       = "Apache-2.0"
  spec.required_ruby_version = ">= 3.1"

  spec.files         = Dir["lib/**/*.rb", "exe/*", "README.md", "LICENSE"]
  spec.require_paths = ["lib"]
  spec.bindir        = "exe"
  spec.executables   = ["knoxcall"]

  spec.metadata = {
    "homepage_uri"          => "https://docs.knoxcall.com/api-reference",
    "source_code_uri"       => "https://github.com/knoxcall/sdk-ruby",
    "changelog_uri"         => "https://github.com/knoxcall/sdk-ruby/blob/main/CHANGELOG.md",
    "rubygems_mfa_required" => "true",
  }
end
