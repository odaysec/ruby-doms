#!/usr/bin/env ruby

require 'httparty'
require 'json'
require 'uri'
require 'set'

class SubdomainScanner
  attr_reader :target, :results

  def initialize(target)
    @target = target
    @results = Set.new
  end

  def run
    puts "[*] Scanning subdomains for: #{@target}"
    fetch_from_crtsh
    fetch_from_bufferover
    fetch_from_hackertarget

    puts "[+] Total unique subdomains found: #{@results.size}"
    save_results
  end

  private

  def fetch_from_crtsh
    puts "[*] Querying crt.sh..."
    url = "https://crt.sh/?q=%25.#{@target}&output=json"
    response = HTTParty.get(url, headers: { "User-Agent" => "RubyScanner/1.0" })

    if response.code == 200
      begin
        json = JSON.parse(response.body)
        json.each do |entry|
          name = entry["name_value"]
          name.split("\n").each do |sub|
            @results.add(sub.strip.downcase) if sub.strip.end_with?(@target)
          end
      rescue JSON::ParserError => e
        puts "[!] Failed to parse crt.sh response"
      end
    else
      puts "[!] crt.sh query failed (#{response.code})"
    end
  end

  def fetch_from_bufferover
    puts "[*] Querying dns.bufferover.run..."
    url = "https://dns.bufferover.run/dns?q=#{@target}"
    response = HTTParty.get(url)

    if response.code == 200
      begin
        json = JSON.parse(response.body)
        if json["FDNS_A"]
          json["FDNS_A"].each do |record|
            sub = record.split(',').last.strip.downcase
            @results.add(sub) if sub.end_with?(@target)
          end
        end
      rescue JSON::ParserError
        puts "[!] Failed to parse bufferover response"
      end
    else
      puts "[!] bufferover query failed (#{response.code})"
    end
  end

  def fetch_from_hackertarget
    puts "[*] Querying hackertarget.com..."
    url = "https://api.hackertarget.com/hostsearch/?q=#{@target}"
    response = HTTParty.get(url)

    if response.code == 200
      lines = response.body.split("\n")
      lines.each do |line|
        sub = line.split(',').first.strip.downcase
        @results.add(sub) if sub.end_with?(@target)
      end
    else
      puts "[!] hackertarget query failed (#{response.code})"
    end
  end

  def save_results
    file = "subdomains_#{@target.gsub('.', '_')}.txt"
    File.open(file, 'w') do |f|
      @results.each { |sub| f.puts sub }
    end
    puts "[+] Results saved to #{file}"
  end
end

# CLI Execution
if __FILE__ == $0
  if ARGV.empty?
    puts "Usage: ruby subdomain_scanner.rb <target_domain>"
    exit
  end

  domain = ARGV[0].strip.downcase
  scanner = SubdomainScanner.new(domain)
  scanner.run
end
