$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "bigdecimal"
require "tmpdir"
require "knoxcall"
require "webmock/rspec"

RSpec.configure do |config|
  config.order = :random
  config.disable_monkey_patching!
  config.expect_with(:rspec) { |c| c.syntax = :expect }

  # The credentials-file provider sits in the zero-arg construction chain, so
  # a developer's real ~/.knoxcall/credentials.json would otherwise leak into
  # any spec that builds a client. Point the override at a path that never
  # exists; specs that exercise the provider set their own tmpdir value.
  config.around do |example|
    had = ENV.key?("KNOXCALL_CREDENTIALS_FILE")
    previous = ENV["KNOXCALL_CREDENTIALS_FILE"]
    ENV["KNOXCALL_CREDENTIALS_FILE"] =
      File.join(Dir.tmpdir, "knoxcall-ruby-specs-no-creds", "credentials.json")
    example.run
  ensure
    had ? ENV["KNOXCALL_CREDENTIALS_FILE"] = previous : ENV.delete("KNOXCALL_CREDENTIALS_FILE")
  end
end
