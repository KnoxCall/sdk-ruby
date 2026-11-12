require "uri"

module KnoxCall
  # One-time, deduplicated warnings for security-relevant misconfigurations
  # (plaintext transport, world-readable credentials file). Cross-SDK parity
  # with node's warn.ts (PARITY §15): each distinct code fires at most once per
  # process, and the warning is NON-BLOCKING — it never raises and never
  # changes behavior. Messages go to $stderr via Kernel#warn, so they honor
  # `-W0` / a replaced `$stderr` and are trivial to capture in tests.
  module Warnings
    # Per-process dedup of already-emitted warning codes. A Mutex guards the
    # check-then-set so concurrent client construction across threads can never
    # double-warn (or lose a warning).
    @warned = {}
    @warned_mutex = Mutex.new

    module_function

    # Test-only: clear the once-per-process dedup so warnings can be re-asserted.
    def _reset_for_tests
      @warned_mutex.synchronize { @warned.clear }
    end

    # Emit +message+ to $stderr at most once per distinct +code+ per process.
    # The Kernel#warn call happens OUTSIDE the mutex (no I/O under the lock) and
    # is wrapped so a warning can never throw into the caller's path.
    def warn_once(code, message)
      @warned_mutex.synchronize do
        return if @warned.key?(code)
        @warned[code] = true
      end
      begin
        warn(message)
      rescue StandardError
        # A misconfiguration warning must never break construction or a read.
      end
    end

    # True for a URL whose scheme is plaintext http:// and whose host is NOT
    # loopback. Loopback (localhost, *.localhost, 127.0.0.0/8, ::1, 0.0.0.0) is
    # the normal local-dev case and must NOT warn; every other host over plain
    # http:// sends credentials/tokens in the clear.
    def insecure_remote_url?(url)
      return false unless url.is_a?(String) && url.match?(%r{\Ahttp://}i)
      host = begin
        URI.parse(url).host
      rescue URI::InvalidURIError
        nil
      end
      return false if host.nil? || host.empty?
      host = host.downcase
      # URI#host keeps an IPv6 literal bracketed ("[::1]") — strip for the match.
      host = host[1..-2] if host.start_with?("[") && host.end_with?("]")
      loopback =
        host == "localhost" ||
        host.end_with?(".localhost") ||
        host == "0.0.0.0" ||
        host == "::1" ||
        host.match?(/\A127\./)
      !loopback
    end
  end
end
