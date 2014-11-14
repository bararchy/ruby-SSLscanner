#!/usr/bin/env ruby

require 'colorize'
require 'getoptlong'
require 'openssl'
require 'socket'

USAGE = "Usage: #{File.basename($0)}: [-s <server hostname/ip>] [-p <port>] [-d <debug>] [-c <certificate information>]"

# SSL Scanner by Bar Hofesh (bararchy) bar.hofesh@gmail.com

class Scanner
    NO_SSLV2      = 16777216
    NO_SSLV3      = 33554432
    NO_TLSV1      = 67108864
    NO_TLSV1_1    = 268435456
    NO_TLSV1_2    = 134217728

    SSLV2         = NO_SSLV3 + NO_TLSV1 + NO_TLSV1_1 + NO_TLSV1_2
    SSLV3         = NO_SSLV2 + NO_TLSV1 + NO_TLSV1_1 + NO_TLSV1_2
    TLSV1         = NO_SSLV2 + NO_SSLV3 + NO_TLSV1_1 + NO_TLSV1_2
    TLSV1_1       = NO_SSLV2 + NO_SSLV3 + NO_TLSV1   + NO_TLSV1_2
    TLSV1_2       = NO_SSLV2 + NO_SSLV3 + NO_TLSV1   + NO_TLSV1_1

    PROTOCOLS     = [SSLV2, SSLV3, TLSV1, TLSV1_1, TLSV1_2]
    CIPHERS       = 'ALL::HIGH::MEDIUM::LOW::SSL23'
    PROTOCOL_NAME = { 
      SSLV2   => 'SSLv2',
      SSLV3   => 'SSLv3',
      TLSV1   => 'TLSv1',
      TLSV1_1 => 'TLSv1.1',
      TLSV1_2 => 'TLSv1.2'
    }


    def ssl_scan

        # Index by color
        printf "\nScanning, results will be presented by the following colors [%s / %s / %s]\n\n" % ["strong".colorize(:green), "weak".colorize(:yellow), "vulnerable".colorize(:red)]
        printf "%-15s %-15s %-19s %-14s %s\n" % ["", "Version", "Cipher", "   Bits", "Vulnerability"]
        
        # fork do 
        #     '-\|/'.each_char.cycle { |char| print char; sleep 0.5; print "\r"}
        #     exit 0
        # end
        scan
        if @check_cert == true
          puts get_certificate_information
        end
     end

    def scan
        p = 0
        c = []
        PROTOCOLS.each do |protocol|
            p = protocol
            ssl_context = OpenSSL::SSL::SSLContext.new
            ssl_context.ciphers = CIPHERS
            ssl_context.options = protocol

            ssl_context.ciphers.each do |cipher|
              begin
                c = cipher
                sleep 0
                ssl_context = OpenSSL::SSL::SSLContext.new
                ssl_context.options = protocol
                ssl_context.ciphers = cipher[0].to_s
                begin
                    tcp_socket = TCPSocket.new("#{@server}", @port)
                rescue => e
                    puts e.message
                    exit 1
                end
                socket_destination = OpenSSL::SSL::SSLSocket.new tcp_socket, ssl_context
                socket_destination.connect
                if protocol == SSLV3
                    printf parse(cipher[0], cipher[3], p)
                else
                    printf parse(cipher[0], cipher[2], p)
                end
                rescue => e
                if @debug
                    puts e.message
                    puts e.backtrace.join "\n"
                    case p
                    when SSLV2
                        puts "Server Don't Supports: SSLv2 #{c[0]} #{c[2]} bits"
                    when SSLV3
                        puts "Server Don't Supports: SSLv3 #{c[0]} #{c[3]} bits"
                    when TLSV1
                        puts "Server Don't Supports: TLSv1 #{c[0]} #{c[2]} bits"
                    when TLSV1_1
                        puts "Server Don't Supports: TLSv1.1 #{c[0]} #{c[2]} bits"
                    when TLSV1_2
                        puts "Server Don't Supports: TLSv1.2 #{c[0]} #{c[2]} bits"
                    end
                end
                ensure
                    socket_destination.close if socket_destination
                    tcp_socket.close if tcp_socket
                end
            end
        end
  end

  def get_certificate_information
    ssl_context = OpenSSL::SSL::SSLContext.new
    cert_store = OpenSSL::X509::Store.new
    cert_store.set_default_paths
    ssl_context.cert_store = cert_store

    tcp_socket = TCPSocket.new("#{@server}", @port)
    socket_destination = OpenSSL::SSL::SSLSocket.new tcp_socket, ssl_context
    socket_destination.connect

    cert = OpenSSL::X509::Certificate.new(socket_destination.peer_cert)
    certprops = OpenSSL::X509::Name.new(cert.issuer).to_a

    issuer = certprops.select { |name, data, type| name == "O" }.first[1]

    results = ["\r\n== Certificate Information ==".bold,
               "valid: #{(socket_destination.verify_result == 0)}",
               "valid from: #{cert.not_before}",
               "valid until: #{cert.not_after}",
               "issuer: #{issuer}",
               "subject: #{cert.subject}",
               "public key:\r\n#{cert.public_key}"].join("\r\n")	
    return results
    rescue
    ensure
        socket_destination.close if socket_destination
        tcp_socket.close         if tcp_socket
    end


    def parse(cipher_name, cipher_bits, protocol)
        if protocol == SSLV2
            ssl_version = "SSLv2".colorize(:red)
        elsif protocol == SSLV3
            ssl_version = "SSLv3".colorize(:yellow)
        elsif protocol == TLSV1
            ssl_version = "TLSv1".bold
        elsif protocol == TLSV1_1
            ssl_version = "TLSv1.1".bold
        elsif protocol == TLSV1_2
            ssl_version = "TLSv1.2".bold
        end

        if cipher_name.match(/RC4/i)
            cipher = "#{cipher_name}".colorize(:yellow)
        elsif cipher_name.match(/RC2/i)
            cipher = "#{cipher_name}".colorize(:red)
        elsif cipher_name.match(/MD5/i)
            cipher = "#{cipher_name}".colorize(:yellow)
        else
            cipher = "#{cipher_name}".colorize(:green)
        end

        if cipher_bits == 40
            bits = "#{cipher_bits}".colorize(:red)
        elsif cipher_bits == 56
            bits = "#{cipher_bits}".colorize(:red)
        else
            bits = "#{cipher_bits}".colorize(:green)
        end

        return detect_vulnerabilites(ssl_version, cipher, bits)
    end

    def detect_vulnerabilites(ssl_version, cipher, bits)

        if ssl_version.match(/SSLv3/).to_s != "" && cipher.match(/RC/i).to_s == ""
            return "Server supports: %-22s %-42s %-10s %s\n"%[ssl_version, cipher, bits, "     POODLE (CVE-2014-3566)".colorize(:red)]
        elsif cipher.match(/RC2/i)
            return "Server supports: %-22s %-42s %-10s %s\n"%[ssl_version, cipher, bits, "     Chosen-plaintext attack".colorize(:red)]
        elsif cipher.match(/EXP/i)
            return "Server supports: %-22s %-42s %-10s %s\n"%[ssl_version, cipher, bits, "     Weak EXPORT based cipher".colorize(:red)]
        #elsif cipher_name.match(/(?<!3)DES/i)   
        else
            return "Server supports: %-22s %-42s %-10s\n"%[ssl_version, cipher, bits]
        end
    end

    def initialize(options = {})
        @server     = options[:server]
        @port       = options[:port]
        @debug      = options[:debug]
        @check_cert = options[:check_cert]
    end
end


opts = GetoptLong.new(
    ['-s', GetoptLong::REQUIRED_ARGUMENT],
    ['-p', GetoptLong::REQUIRED_ARGUMENT],
    ['-d', GetoptLong::NO_ARGUMENT],
    ['-c', GetoptLong::NO_ARGUMENT]
)

options = {debug: false, check_cert: false}

opts.each do |opt, arg|
    case opt
    when '-s'
    options[:server] = arg
    when '-p'
    options[:port] = arg.to_i
    when '-d'
    options[:debug] = true
    when '-c'
    options[:check_cert] = true
    end
end

if options.keys.length <= 2
    p ARGV
    p options
    puts USAGE
    exit 0
end

if options[:server].empty? || options[:port] == 0
    $stderr.puts 'Missing required fields'
    puts USAGE
    exit 0
end

trap("INT") do
    puts "Exiting..."
    exit
end

scanner = Scanner.new(options)
scanner.ssl_scan
