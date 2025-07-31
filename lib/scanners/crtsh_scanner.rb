require 'httparty'

module Scanners
  class CRTSHScanner
    API_URL = 'https://crt.sh/?output=json'.freeze

    def initialize(domain)
      @domain = domain
    end

    def scan
      response = HTTParty.get(API_URL, query: query_params)
      parse_response(response)
    rescue StandardError => e
      { error: "CRT.sh API error: #{e.message}" }
    end

    private

    def query_params
      { 
        q: "%.%.#{@domain}" 
      }
    end

    def parse_response(response)
      return [] unless response.success?

      json = JSON.parse(response.body)
      json.map { |entry| entry['name_value'] }
          .flat_map { |names| names.split("\n") }
          .grep(/\.#{Regexp.escape(@domain)}$/i)
          .map(&:strip)
          .map(&:downcase)
          .uniq
          .sort
    end
  end
end