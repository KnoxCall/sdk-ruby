module KnoxCall
  module CLI
    # `knoxcall logout` — best-effort revoke, then remove the stored profile.
    module Logout
      module_function

      def run(options)
        path = CredentialsFile.resolve_path
        profile = CredentialsFile.resolve_profile(options[:profile])
        record = CredentialsFile.read_profile(path, profile)
        if record.nil?
          puts "No stored credentials for profile '#{profile}' — nothing to do."
          return 0
        end

        refresh_token = CredentialsFile.presence(record["refresh_token"])
        base_url = record["base_url"].to_s.chomp("/")
        if refresh_token && !base_url.empty?
          begin
            Common.post_form(
              "#{base_url}/oauth/revoke",
              {
                "token" => refresh_token,
                "token_type_hint" => "refresh_token",
                "client_id" => CredentialsFile.presence(record["client_id"]) || CLI_CLIENT_ID
              }
            )
          rescue Error
            # best-effort: removal proceeds even when revocation is unreachable
          end
        end

        CredentialsFile::Lock.new(path).with_lock do
          CredentialsFile.remove_profile(path, profile)
        end
        puts "Logged out — removed profile '#{profile}' from #{path}."
        0
      end
    end
  end
end
