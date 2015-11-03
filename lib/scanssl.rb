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
  class Command < Certificate
    def initialize(options = {})
      @server       = options[:server]
      @port         = options[:port]
      @debug        = options[:debug]
      @check_cert   = options[:check_cert]
      @filename     = options[:filename]
      @filetype     = options[:filetype]
      @threads      = []
    end

    def call
      puts @server
      puts @port
      
      PROTOCOLS.each { |x| puts x }
    end
  end
end
