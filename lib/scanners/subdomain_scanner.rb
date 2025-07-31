require_relative 'scanners/crtsh_scanner'

class SubdomainScanner
  def initialize(domain)
    @domain = domain
    @scanners = [Scanners::CRTSHScanner.new(domain)]
  end

  def run
    puts "Scanning subdomains for #{@domain}...".colorize(:green)
    
    results = {}
    @scanners.each do |scanner|
      scanner_name = scanner.class.name.split('::').last
      puts "\n[+] Using #{scanner_name}".colorize(:blue)
      
      subdomains = scanner.scan
      
      if subdomains.is_a?(Hash) && subdomains[:error]
        puts "Error: #{subdomains[:error]}".colorize(:red)
        next
      end
      
      results[scanner_name] = subdomains
      display_results(subdomains)
    end

    results
  end

  private

  def display_results(subdomains)
    if subdomains.empty?
      puts "No subdomains found".colorize(:yellow)
      return
    end

    puts "Found #{subdomains.size} subdomains:".colorize(:green)
    subdomains.each do |subdomain|
      puts "  • #{subdomain}"
    end
  end
end