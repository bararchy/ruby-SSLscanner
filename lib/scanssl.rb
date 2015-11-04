require 'colorize'
require 'getoptlong'
require 'openssl'
require 'socket'
require 'webrick'
require 'prawn'

require 'scanssl/version'
require 'scanssl/settings'
require 'scanssl/certInfo'
require 'scanssl/fileExport'
require 'scanssl/scanHost'

module ScanSSL
  class Command
    def self.call(options = {})
      @server = options[:server]
      @port = options[:port]

      # Get Certiticate Information
      if options[:check_cert] == true
        a = ScanSSL::CertInfo.new(@server, @port)
        # Not sure yet if we need to have an access to one of those
        # datas so right now I'm returning each of them.
        # We can convert it to hash or array.
        colorOutputCert(a.valid?,
                        a.valid_from, 
                        a.valid_until, 
                        a.issuer, 
                        a.subject, 
                        a.algorithm, 
                        a.key_size, 
                        a.public_key)
      end

      if options[:check_cert] == nil
        run = ScanSSL::ScanHost.new
        puts run.scan(@server, @port)
      end
    end

    def self.colorOutputCert(cValid, cFrom, cUntil, cIssuer, cSubject, cAlgorithm, cKey, cPublic)
      puts "== Certificate Information ==".bold
      puts "domain: #{@server}"
      puts "port: #{@port}"
      puts "----------------"
      puts "valid: #{cValid}"
      puts "valid from:#{cFrom}"
      puts "valid until: #{cUntil}"
      puts "issuer: #{cIssuer}"
      puts "subject: #{cSubject}"
      puts "algorithm: #{cAlgorithm}"
      puts "key size: #{cKey}"
      puts "public key:"
      puts "#{cPublic}"
    end
  end
end
