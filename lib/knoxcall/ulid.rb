require "securerandom"

module KnoxCall
  # ULID generator (Crockford base32: 48-bit timestamp + 80 bits of
  # randomness). Used for X-Idempotency-Key — generated once per logical
  # mutating request and stable across retries.
  module ULID
    ENCODING = "0123456789ABCDEFGHJKMNPQRSTVWXYZ".freeze

    def self.generate(time = Time.now)
      ms = (time.to_f * 1000).to_i
      out = +""
      9.downto(0) { |i| out << ENCODING[(ms >> (i * 5)) & 0x1F] }
      rand = SecureRandom.random_number(2**80)
      15.downto(0) { |i| out << ENCODING[(rand >> (i * 5)) & 0x1F] }
      out
    end
  end
end
