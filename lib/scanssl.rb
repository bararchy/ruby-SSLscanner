require 'colorize'
require 'getoptlong'
require 'openssl'
require 'socket'
require 'webrick'
require 'prawn'

require 'scanssl/version'

module ScanSSL
  class Help
    def self.show
      puts "Usage:"
      puts "  scanssl [options]"
      puts ""
      puts "  Options:"
      puts "    -v          # show version"
      puts "    -h          # show help"
      puts "    -s [host]		# set hostname"
      puts "    -p [port]		# set port"
      puts ""
      puts "  Example:"
      puts "    scanssl -s google.com -p 443"
    end
  end
end
