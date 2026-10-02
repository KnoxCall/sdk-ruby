module KnoxCall
  module Resources
    class Account
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      def get = unwrap(@client.request("GET", "/v1/account"))
      def get_usage = unwrap(@client.request("GET", "/v1/account/usage"))
    end
  end
end
