module KnoxCall
  module CLI
    # `knoxcall whoami` — show the signed-in tenant via the SDK client.
    module Whoami
      module_function

      def run(options)
        path = CredentialsFile.resolve_path
        profile = CredentialsFile.resolve_profile(options[:profile])
        if CredentialsFile.read_profile(path, profile).nil?
          raise Error, "not logged in (profile '#{profile}') — run `knoxcall login`"
        end

        client = Client.new(bootstrap: StoredCredentials.new(path: path, profile: profile))
        account = client.account.get || {}

        slug = account["slug"].to_s
        name = (account["name"] || account["company_name"]).to_s
        plan = (account["plan"] || account["subscription_plan"]).to_s
        tenant = name.empty? ? slug : name
        puts "Tenant: #{tenant.empty? ? '(unknown)' : tenant}"
        puts "Slug:   #{slug}" unless slug.empty?
        puts "Plan:   #{plan}" unless plan.empty?
        puts "Profile: #{profile} (#{path})"
        0
      end
    end
  end
end
