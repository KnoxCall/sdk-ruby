require "json"
require "time"
require "fileutils"
require "net/http"
require "uri"
require "openssl"
require "securerandom"
require "rbconfig"

module KnoxCall
  # Shared credentials file (+~/.knoxcall/credentials.json+) — read, write,
  # lock, refresh.
  #
  # The file is written by `knoxcall login` and consumed by every SDK through
  # the StoredCredentials bootstrap. Format, lock protocol, and refresh rules
  # are cross-SDK identical (PARITY §2). The server's refresh tokens are
  # SINGLE-USE with family revocation on reuse, so any refresh MUST:
  #
  # 1. hold the sibling +credentials.json.lock+ file (exclusive-create, 100ms
  #    retry up to 10s; a lock older than the stale window is broken by atomic
  #    rename and retried once — ownership-aware so a peer's live lock is never
  #    deleted, and the window stays above the bounded refresh timeout),
  # 2. RE-READ the file after acquiring the lock (another process may have
  #    already refreshed), and
  # 3. atomically (temp file + rename) write back the rotated refresh token
  #    before releasing the lock.
  module CredentialsFile
    DEFAULT_PROFILE = "default"

    # A stored access token is "fresh" while it has more than this much
    # validity left; below the threshold the provider refreshes under the
    # file lock.
    FRESH_WINDOW_SECONDS = 60.0

    # The locked refresh HTTP call is bounded so the lock is provably released
    # well within the lock's stale window (Lock#stale_after) — otherwise a slow
    # token endpoint could hold the lock long enough for a peer to break it and
    # double-refresh the single-use token. Stays below STALE_AFTER_SECONDS.
    REFRESH_TIMEOUT_SECONDS = 30.0

    RELOGIN_MESSAGE =
      "stored CLI credentials are no longer valid — run `knoxcall login` again"

    module_function

    # -- Path / profile resolution ------------------------------------------------

    # Credentials file path: explicit override > KNOXCALL_CREDENTIALS_FILE > default.
    def resolve_path(override = nil)
      return override.to_s if override && !override.to_s.empty?
      env = ENV["KNOXCALL_CREDENTIALS_FILE"]
      return env if env && !env.empty?
      File.join(Dir.home, ".knoxcall", "credentials.json")
    end

    # Profile name: explicit override > KNOXCALL_PROFILE > "default".
    def resolve_profile(override = nil)
      value = override || ENV["KNOXCALL_PROFILE"]
      value && !value.to_s.empty? ? value.to_s : DEFAULT_PROFILE
    end

    # -- File primitives (atomic writes, tolerant reads) ---------------------------

    # Parse the whole file; nil on missing/malformed/unexpected shape.
    def read_document(path)
      warn_if_loose_permissions(path)
      doc = JSON.parse(File.read(path, encoding: "utf-8"))
      return nil unless doc.is_a?(Hash) && doc["profiles"].is_a?(Hash)
      doc
    rescue SystemCallError, IOError, JSON::ParserError, EncodingError
      nil
    end

    # Warn (once) if the credentials file — which holds a single-use refresh
    # token — is readable by group/other. POSIX only: on Windows the mode bits
    # are advisory and confidentiality rests on the %USERPROFILE% ACL, so the
    # check is skipped. Never raises; a missing/unreadable file is a no-op (the
    # read below handles absence).
    def warn_if_loose_permissions(path)
      return if windows_platform?
      mode = begin
        File.stat(path).mode
      rescue SystemCallError
        return # missing/unreadable — nothing to warn about
      end
      return if (mode & 0o077).zero?
      Warnings.warn_once(
        "KNOXCALL_CREDENTIALS_FILE_PERMS",
        "KnoxCall credentials file #{path} is accessible to group/other " \
        "(mode #{format('%03o', mode & 0o777)}) and holds a refresh token. " \
        "Restrict it: chmod 600 #{path}"
      )
    end

    def windows_platform?
      Gem.win_platform? ||
        (RbConfig::CONFIG["host_os"] =~ /mswin|mingw|cygwin/i ? true : false)
    end

    # One profile's record, or nil (missing file, malformed JSON, unknown profile).
    def read_profile(path, profile)
      doc = read_document(path)
      return nil unless doc
      record = doc["profiles"][profile]
      record.is_a?(Hash) ? record.dup : nil
    end

    # Atomic write: temp file in the same directory → fsync → rename over the
    # target. The directory is created 0700 and the file written 0600
    # (best-effort — the mode bits are advisory on Windows).
    def write_document(path, doc)
      directory = File.dirname(path)
      FileUtils.mkdir_p(directory, mode: 0o700)
      tmp_path = File.join(
        directory, ".credentials-#{Process.pid}-#{format('%08x', rand(2**32))}.tmp"
      )
      begin
        File.open(tmp_path, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |f|
          f.write(JSON.pretty_generate(doc) + "\n")
          f.flush
          f.fsync
        end
        begin
          File.chmod(0o600, tmp_path)
        rescue SystemCallError
          # best-effort on platforms without POSIX modes
        end
        File.rename(tmp_path, path)
      rescue Exception
        begin
          File.unlink(tmp_path)
        rescue SystemCallError
          # already gone / never created
        end
        raise
      end
      nil
    end

    # Merge one profile into the file (other profiles untouched), atomically.
    def write_profile(path, profile, record)
      doc = read_document(path) || { "version" => 1, "profiles" => {} }
      doc["version"] ||= 1
      doc["profiles"][profile.to_s] = record.reject { |_k, v| v.nil? }
      write_document(path, doc)
    end

    # Remove one profile; delete the file when it was the last one.
    def remove_profile(path, profile)
      doc = read_document(path)
      return false unless doc && doc["profiles"].key?(profile)
      doc["profiles"].delete(profile)
      if doc["profiles"].empty?
        begin
          File.unlink(path)
        rescue SystemCallError
          # already gone
        end
      else
        write_document(path, doc)
      end
      true
    end

    # Auto-detect presence check: file exists AND the selected profile parses.
    def profile_available?(path, profile)
      !read_profile(path, profile).nil?
    end

    # Chain-slot check for zero-arg construction: anything missing/malformed
    # (including an unresolvable home directory) skips the provider silently.
    def available?
      profile_available?(resolve_path, resolve_profile)
    rescue StandardError
      false
    end

    # -- Expiry formatting ----------------------------------------------------------

    def format_expiry(time)
      time.getutc.strftime("%Y-%m-%dT%H:%M:%SZ")
    end

    def parse_expiry(value)
      return nil unless value.is_a?(String) && !value.empty?
      Time.iso8601(value)
    rescue ArgumentError
      nil
    end

    # -- Cross-process lock ----------------------------------------------------------

    # Sibling +.lock+ file held by exclusive-create (O_CREAT|O_EXCL).
    #
    # Protocol (identical in every SDK): retry every 100ms up to 10s; a lock
    # file older than the stale window is broken and retried once.
    #
    # Ownership-aware break/release: the lock file carries a unique owner tag
    # (+pid time nonce+) written at acquire. A stale lock is broken by ATOMIC
    # RENAME (only one racer wins the rename, so a competitor's freshly-created
    # lock can never be deleted by path), and release only unlinks a lock whose
    # on-disk content still matches what this instance wrote. This closes the
    # double-acquire -> double-refresh race that would replay the single-use
    # refresh token and trip server-side family revocation. The stale window is
    # also kept safely above the bounded refresh HTTP timeout
    # (REFRESH_TIMEOUT_SECONDS) so a live-but-slow refresh is never mistaken for
    # a dead holder.
    class Lock
      # Must exceed the bounded refresh HTTP timeout (REFRESH_TIMEOUT_SECONDS)
      # so a legitimately in-flight refresh is never broken as "stale".
      STALE_AFTER_SECONDS = 60.0

      attr_reader :lock_path

      def initialize(target, timeout: 10.0, retry_interval: 0.1, stale_after: STALE_AFTER_SECONDS)
        @lock_path = "#{target}.lock"
        @timeout = timeout
        @retry_interval = retry_interval
        @stale_after = stale_after
        @held = false
        @own_content = nil
      end

      def acquire
        deadline = monotonic_now + @timeout
        stale_broken = false
        loop do
          return if try_acquire
          if !stale_broken && break_stale
            stale_broken = true
            return if try_acquire
          end
          if monotonic_now >= deadline
            raise Error, "timed out waiting for the credentials file lock (#{@lock_path})"
          end
          sleep @retry_interval
        end
      end

      def release
        return unless @held
        @held = false
        own = @own_content
        @own_content = nil
        begin
          # Only remove the lock if it is still OURS — if our lock was broken as
          # stale and re-taken by another process while we were suspended,
          # unlink by path would delete their live lock.
          if own && File.read(@lock_path) == own
            File.unlink(@lock_path)
          end
        rescue SystemCallError
          # already gone or unreadable
        end
      end

      def with_lock
        acquire
        begin
          yield
        ensure
          release
        end
      end

      private

      def monotonic_now
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      def try_acquire
        # Unique owner tag (pid time nonce) so break/release can prove ownership.
        content = "#{Process.pid} #{Time.now.to_f.round(3)} #{SecureRandom.hex(8)}\n"
        File.open(@lock_path, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |f|
          f.write(content)
        end
        @own_content = content
        @held = true
        true
      rescue SystemCallError
        false
      end

      # Break a stale lock via ATOMIC RENAME, so a competing process's fresh
      # lock is never removed by path. True when a retry is worthwhile now.
      def break_stale
        age = Time.now - File.mtime(@lock_path)
        return false if age <= @stale_after
        # Claim the break atomically: rename() has exactly one winner, so if a
        # competitor already broke-and-recreated the lock, our rename fails
        # (source gone) and we never touch their live lock.
        graveyard = "#{@lock_path}.stale-#{Process.pid}-#{SecureRandom.hex(6)}"
        begin
          File.rename(@lock_path, graveyard)
          File.unlink(graveyard)
        rescue SystemCallError
          # someone else already broke it (or it vanished) — just retry
        end
        true
      rescue SystemCallError
        true # lock vanished between attempts — retry immediately
      end
    end

    # -- Token fetch (fast path + locked refresh) -------------------------------------

    # Produce a usable token hash (the Client token-cache shape) from the
    # credentials file.
    #
    # Fast path: stored access token with >60s validity, no HTTP. Otherwise
    # lock → re-read → re-check → refresh-token grant → atomic write-back.
    # The caller's in-process token mutex (Client#token) wraps this whole
    # method, so the file lock is only ever contended across processes.
    def fetch_stored_token(path:, profile:, token_endpoint:, timeout: 30)
      record = read_profile(path, profile)
      # Detection saw the profile but it has since vanished/corrupted.
      raise relogin_error unless record
      cached = cached_from_record(record)
      return cached if cached

      Lock.new(path).with_lock do
        record = read_profile(path, profile)
        raise relogin_error unless record
        cached = cached_from_record(record)
        # another process refreshed while we waited
        return cached if cached
        refresh_and_write_back(record, path: path, profile: profile,
                                       token_endpoint: token_endpoint, timeout: timeout)
      end
    end

    def relogin_error(status = 401, headers: nil, body: nil)
      AuthenticationError.new(RELOGIN_MESSAGE, status, headers: headers, body: body)
    end

    # The fresh-token fast path: use the stored access token while >60s valid.
    #
    # No :refresh_token in the returned hash on purpose — the file is the sole
    # refresh authority, so no in-process fallback can ever replay a consumed
    # (rotated) refresh token. No :lifetime either: the Client's refresh-ahead
    # window then falls back to its 300s default, and re-entering this method
    # inside that window just re-reads the file (still no HTTP until <60s).
    def cached_from_record(record)
      token = record["access_token"]
      expires_at = parse_expiry(record["access_token_expires_at"])
      return nil unless token.is_a?(String) && !token.empty? && expires_at
      return nil if expires_at - Time.now <= FRESH_WINDOW_SECONDS
      {
        access_token: token,
        token_type: "Bearer",
        expires_at: expires_at,
        lifetime: nil,
        tenant: presence(record["tenant"])
      }
    end

    def refresh_and_write_back(record, path:, profile:, token_endpoint:, timeout:)
      refresh_token = presence(record["refresh_token"])
      client_id = presence(record["client_id"])
      raise relogin_error unless refresh_token && client_id

      uri = URI.parse(token_endpoint)
      req = Net::HTTP::Post.new(uri)
      req["Content-Type"] = "application/x-www-form-urlencoded"
      req["Accept"] = "application/json"
      req["User-Agent"] = SDK_VERSION
      req.body = URI.encode_www_form(
        grant_type: "refresh_token",
        refresh_token: refresh_token,
        client_id: client_id # the tenant's real CLI client (public, no secret)
      )

      # Bound the refresh call so the lock is provably released within the
      # stale window: never wait longer than REFRESH_TIMEOUT_SECONDS even if the
      # caller configured a larger client timeout (a smaller one still wins).
      refresh_timeout = [timeout, REFRESH_TIMEOUT_SECONDS].min
      resp = begin
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"
        http.open_timeout = refresh_timeout
        http.read_timeout = refresh_timeout
        http.start { |h| h.request(req) }
      rescue Net::OpenTimeout, Net::ReadTimeout => e
        raise ConnectionTimeoutError, "token refresh timed out: #{e.message}"
      rescue OpenSSL::SSL::SSLError, EOFError, SocketError, SystemCallError, IOError => e
        raise NetworkError, "token refresh failed: #{e.class}: #{e.message}"
      end

      data = begin
        JSON.parse(resp.body.to_s)
      rescue JSON::ParserError
        nil
      end

      if resp.code.to_i >= 400
        if data.is_a?(Hash) && data["error"] == "invalid_grant"
          # Revoked family or expired refresh token — unrecoverable here.
          headers = {}
          resp.each_header { |k, v| headers[k.downcase] = v }
          raise relogin_error(resp.code.to_i, headers: headers, body: data)
        end
        raise KnoxCall.error_from_response(resp)
      end
      unless data.is_a?(Hash) && data["access_token"].is_a?(String) && !data["access_token"].empty?
        # e.g. an HTML page from an edge proxy with a 200 status
        raise TokenError, "token endpoint returned an unexpected response (status #{resp.code})"
      end

      lifetime = begin
        Float(data["expires_in"] || 3600)
      rescue ArgumentError, TypeError
        3600.0
      end
      now = Time.now

      # Write back the rotated refresh token BEFORE releasing the lock (the
      # caller holds it) — the old one is already consumed server-side.
      updated = record.dup
      updated["access_token"] = data["access_token"]
      updated["access_token_expires_at"] = format_expiry(now + lifetime)
      updated["refresh_token"] = data["refresh_token"] if presence(data["refresh_token"])
      updated["scope"] = data["scope"] if presence(data["scope"])
      # extension members (RFC 6749 §5.1): tenant slug + the real per-tenant CLI client id
      updated["tenant"] = data["tenant"] if presence(data["tenant"])
      updated["client_id"] = data["client_id"] if presence(data["client_id"])
      write_profile(path, profile, updated)

      {
        access_token: data["access_token"],
        token_type: "Bearer",
        expires_at: now + lifetime,
        lifetime: lifetime,
        tenant: presence(updated["tenant"])
      }
    end

    def presence(value)
      value.is_a?(String) && !value.empty? ? value : nil
    end
  end
end
