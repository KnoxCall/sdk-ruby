module KnoxCall
  module Resources
    class Pki
      include UnwrapsEnvelope

      def initialize(client) = @client = client

      # Bare array of CA roots — no pagination.
      def list_roots = unwrap(@client.request("GET", "/v1/pki/roots"))
      # Returns {"root" => CARoot, "intermediate_not_after" => ISO string}.
      def create_root(name, subject) = unwrap(@client.request("POST", "/v1/pki/roots", body: { name: name, subject: subject }))
      # Raw PEM text (text/x-pem-file) — no JSON wrapper.
      def get_root_cert(name) = raw_text(@client.request("GET", "/v1/pki/roots/#{encode(name)}/cert"), "CA certificate")
      # Returns {"intermediate_id", "not_after"}.
      def rotate_intermediate(name) = unwrap(@client.request("POST", "/v1/pki/roots/#{encode(name)}/rotate-intermediate", body: {}))
      # Raw CRL text — no JSON wrapper.
      def get_crl(name) = raw_text(@client.request("GET", "/v1/pki/roots/#{encode(name)}/crl"), "CRL")
      # Bare array of roles — no pagination.
      def list_roles(root_name) = unwrap(@client.request("GET", "/v1/pki/roots/#{encode(root_name)}/roles"))
      def create_role(root_name, **input) = unwrap(@client.request("POST", "/v1/pki/roots/#{encode(root_name)}/roles", body: input))
      # Issue a leaf certificate under a role. The "private_key_pem" is shown
      # exactly once — store it now. Returns {"serial_hex", "cert_pem",
      # "private_key_pem", "ca_chain_pem", "not_before", "not_after"}.
      def issue_cert(root_name, role, **input) = unwrap(@client.request("POST", "/v1/pki/roots/#{encode(root_name)}/issue/#{encode(role)}", body: input))
      # Returns {"revoked" => Boolean}.
      def revoke_cert(root_name, serial_hex, reason: nil)
        body = { serial_hex: serial_hex }
        body[:reason] = reason if reason
        unwrap(@client.request("POST", "/v1/pki/roots/#{encode(root_name)}/revoke", body: body))
      end

      private

      # The cert/CRL endpoints return raw text, not the JSON envelope.
      def raw_text(response, what)
        raise Error, "expected raw #{what} text but got a JSON response" unless response.is_a?(String)
        response
      end
    end
  end
end
