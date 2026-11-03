# The KNOXCALL_INTERCEPT off-grammar, driven by the CROSS-LANGUAGE fixture
# sdk/fixtures/intercept-kill-switch.json (PARITY §21.1).
#
# Five SDKs hand-write this predicate and already agree character for
# character. A sixth spelling accepted here would be a kill switch that works
# in four SDKs and silently does nothing in the fifth — the worst shape a kill
# switch can have, because the operator believes interception is off.
#
# A missing fixture FAILS rather than skips — a skipped contract test reads as
# a pass.

require "json"

RSpec.describe "KNOXCALL_INTERCEPT off-grammar" do
  fixture_path = File.expand_path("../../fixtures/intercept-kill-switch.json", __dir__)
  raise "the shared kill-switch fixture must exist at #{fixture_path}" unless File.exist?(fixture_path)

  fixture = JSON.parse(File.read(fixture_path))
  cases = fixture.fetch("cases")

  around do |example|
    saved = ENV.fetch("KNOXCALL_INTERCEPT", nil)
    example.run
  ensure
    if saved.nil?
      ENV.delete("KNOXCALL_INTERCEPT")
    else
      ENV["KNOXCALL_INTERCEPT"] = saved
    end
  end

  cases.each do |c|
    it "#{c.fetch('name')} -> #{c.fetch('expect')}" do
      value = c.fetch("value")
      if value.nil?
        ENV.delete("KNOXCALL_INTERCEPT")
      else
        ENV["KNOXCALL_INTERCEPT"] = value
      end
      expect(KnoxCall::InterceptResolver.kill_switch?).to eq(c.fetch("expect"))
    end
  end

  it "the fixture is not vacuous" do
    expect(cases.map { |c| c.fetch("expect") }.uniq.sort_by(&:to_s)).to eq([false, true])
  end
end
