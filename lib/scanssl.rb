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
      # Here we are going to call some methods.
      puts @server
      puts @port
     
      # This is just for test :-)
      PROTOCOLS.each { |x| puts x }

      # In this method I guess we can simply have a kind
      # of queue for all commands. We can call methods,
      # get the output and send to colorizeOutput :-)
    end

    def colorizeOutput(output)
      # Each method inside the scanssl/ will need to return
      # something (using return), and here we are going to
      # create a nice output using those data
      puts "Here we are going to colorize the output."
    end
  end
end
