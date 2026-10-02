# frozen_string_literal: true

require "json"

module KnoxCall
  # The route-mode REFUSAL predicate (PARITY §21.1, "Refusal-driven refresh";
  # the cross-language contract is sdk/fixtures/route-refusal.json).
  #
  # A KnoxCall-origin refusal on the route data plane is the one response the
  # pipeline answers by refreshing its manifest ONCE and re-deciding ONCE:
  #
  #   - a 401 with no upstream stamp — the credential was refused, or the caller
  #     is not authenticated for the route it named. +call+ has already spent its
  #     one re-mint by the time we see this.
  #   - a 404 whose envelope +error.type+ is +route_not_found+ — since the
  #     founder's 2026-09-26 decision an AUTHENTICATED key gets a real 404 for a
  #     route that does not resolve, and a stale manifest naming a Route deleted
  #     since the poll is exactly this. The +environment_*+ types are refused
  #     as-is: a refresh cannot fix an environment.
  #
  # Any response carrying +X-Knox-Upstream-Status+ (the route data plane's
  # response block) or +X-Knox-Destination-Status+ (the ephemeral proxy's older
  # spelling) is the UPSTREAM's answer, whatever its status or body, and never a
  # refusal.
  module RouteRefusal
    module_function

    # @param status [Integer]
    # @param headers [Hash] raw response headers, any casing; values may be
    #   strings or arrays (Net::HTTPResponse#to_hash yields arrays)
    # @param body [String, nil]
    def refusal?(status:, headers:, body:)
      return false if header(headers, "X-Knox-Upstream-Status") || header(headers, "X-Knox-Destination-Status")
      return true if status == 401
      return false unless status == 404

      envelope_type(body) == "route_not_found"
    end

    # The envelope's +error.type+ on a 404, or nil for anything that is not the
    # Shape-A envelope +{"error":{"type","message","request_id"}}+.
    def envelope_type(body)
      return nil if body.nil? || body.empty?

      parsed = JSON.parse(body)
      return nil unless parsed.is_a?(Hash)

      error = parsed["error"]
      return nil unless error.is_a?(Hash)

      type = error["type"]
      type.is_a?(String) ? type : nil
    rescue JSON::ParserError
      nil
    end

    def header(headers, name)
      pair = headers.find { |k, _| k.to_s.casecmp(name).zero? }
      return nil unless pair

      v = pair.last
      v = v.first if v.is_a?(Array)
      v = v.to_s
      v.empty? ? nil : v
    end
  end
end
