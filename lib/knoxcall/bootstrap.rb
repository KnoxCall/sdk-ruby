module KnoxCall
  # Bootstrap credential types. The +type+ discriminator defaults per class,
  # so callers never need to spell it out. Secret fields are excluded from
  # #inspect so a logged client or captured exception context never prints
  # the secret (Object#to_s is already safe — it shows only class + object id).

  class AccessToken
    attr_reader :type

    def initialize(access_token:)
      @access_token = access_token
      @type = "access_token"
    end

    def access_token = @access_token

    def inspect = "#<KnoxCall::AccessToken access_token=[REDACTED]>"
  end

  class OIDCTokenExchange
    attr_reader :issuer, :type

    def initialize(subject_token:, issuer:)
      @subject_token = subject_token
      @issuer = issuer
      @type = "oidc_token_exchange"
    end

    def subject_token = @subject_token

    def inspect = "#<KnoxCall::OIDCTokenExchange issuer=#{@issuer.inspect} subject_token=[REDACTED]>"
  end

  class ClientCredentials
    attr_reader :client_id, :type

    def initialize(client_id:, client_secret:)
      @client_id = client_id
      @client_secret = client_secret
      @type = "client_credentials"
    end

    def client_secret = @client_secret

    def inspect = "#<KnoxCall::ClientCredentials client_id=#{@client_id.inspect} client_secret=[REDACTED]>"
  end

  # Credentials file written by `knoxcall login` (PARITY §2).
  #
  # Holds no secrets itself — tokens are read from the file (path/profile
  # resolved from KNOXCALL_CREDENTIALS_FILE / KNOXCALL_PROFILE when not
  # given) at token-fetch time, so #inspect stays safe by construction.
  class StoredCredentials
    attr_reader :path, :profile, :type

    def initialize(path: nil, profile: nil)
      @path = path
      @profile = profile
      @type = "stored_credentials"
    end

    def inspect = "#<KnoxCall::StoredCredentials path=#{@path.inspect} profile=#{@profile.inspect}>"
  end

  # Deprecated aliases — the pre-release *Bootstrap names used by the other
  # KnoxCall SDKs. Remove before 2.0.
  AccessTokenBootstrap = AccessToken
  OidcTokenExchangeBootstrap = OIDCTokenExchange
  ClientCredentialsBootstrap = ClientCredentials
end
