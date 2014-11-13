#!/usr/bin/env ruby

require 'getoptlong'
require 'openssl'
require 'socket'

# SSL Scanner by Bar Hofesh (bararchy) bar.hofesh@gmail.com

class Scanner
    NO_SSLV2   = 16777216
    NO_SSLV3   = 33554432
    NO_TLSV1   = 67108864
    NO_TLSV1_1 = 268435456
    NO_TLSV1_2 = 134217728

    SSLV2      = NO_SSLV3 + NO_TLSV1 + NO_TLSV1_1 + NO_TLSV1_2
    SSLV3      = NO_SSLV2 + NO_TLSV1 + NO_TLSV1_1 + NO_TLSV1_2
    TLSV1      = NO_SSLV2 + NO_SSLV3 + NO_TLSV1_1 + NO_TLSV1_2
    TLSV1_1    = NO_SSLV2 + NO_SSLV3 + NO_TLSV1   + NO_TLSV1_2
    TLSV1_2    = NO_SSLV2 + NO_SSLV3 + NO_TLSV1   + NO_TLSV1_1

    PROTOCOLS  = [SSLV2, SSLV3, TLSV1, TLSV1_1, TLSV1_2]
    CIPERS     = 'ALL::HIGH::MEDIUM::LOW::SSL23'


  def ssl_scan

    usage = ("Usage: #{File.basename($0)}: [-s <server hostname/ip>] [-p <port>] [-d <debug>] [-c <certificate information>]")
    @debug = false
    check_cert = false
    begin
      loop { case ARGV[0]
      when '-s' then  ARGV.shift; @server = ARGV.shift
      when '-p' then  ARGV.shift; @port = ARGV.shift
      when '-d' then 	ARGV.shift; @debug = true
      when '-c' then  ARGV.shift; check_cert = true		    		
      when /^-/ then  usage("Unknown option: #{ARGV[0].inspect}")
      else break
      end; }
    rescue Exception => e
      puts usage
      exit 0
    end


    if @server.to_s == "" || @port.to_s == ""
      puts usage
      exit 0
    end
    ssl_ciphers # Setup OpenSSL ciphers per protocol

    # Index by color
    puts "\e[0;32mstrong\033[0m -- \e[0;33mweak\033[0m -- \033[1;31mvulnerable\033[0m\r\n\r\n"

    if scan == "exit"
      exit 1
    end
    if check_cert == true
      puts get_certificate_information
    end
  end


  def scan
    trap("INT") do
      puts "Exiting..."
      return "exit"
      exit
    end
    for protocol in @protocols
      ssl_context = OpenSSL::SSL::SSLContext.new
      ssl_context.ciphers = @ciphers
      ssl_context.options = protocol
      for cipher in ssl_context.ciphers
        begin
          @delay
          ssl_context = OpenSSL::SSL::SSLContext.new
          ssl_context.options = protocol
          ssl_context.ciphers = cipher[0].to_s
          begin
            tcp_socket = TCPSocket.new("#{@server}", @port.to_i)
          rescue Exception => e
            puts "#{e}"
            exit 1
          end
          socket_destination = OpenSSL::SSL::SSLSocket.new tcp_socket, ssl_context
          socket_destination.connect
          if protocol == @SSLv3
            puts parse(cipher[0].to_s, cipher[3], protocol)
          else
            puts parse(cipher[0].to_s, cipher[2], protocol)
          end
        rescue Exception => e
          if @debug == true
            puts e
            if protocol == @SSLv2
              puts "Server Don't Supports: SSLv2 #{cipher[0]} #{cipher[2]} bits"
            elsif protocol == @SSLv3
              puts "Server Don't Supports: SSLv3 #{cipher[0]} #{cipher[3]} bits"
            elsif protocol == @TLSv1
              puts "Server Don't Supports: TLSv1 #{cipher[0]} #{cipher[2]} bits"
            elsif protocol == @TLSv1_1
              puts "Server Don't Supports: TLSv1.1 #{cipher[0]} #{cipher[2]} bits"
            elsif protocol == @TLSv1_2
              puts "Server Don't Supports: TLSv1.2 #{cipher[0]} #{cipher[2]} bits"
            end	
          end
        ensure
          socket_destination.close
        end
      end
    end
  end

  def get_certificate_information
    begin
      ssl_context = OpenSSL::SSL::SSLContext.new
      cert_store = OpenSSL::X509::Store.new
      cert_store.set_default_paths
      ssl_context.cert_store = cert_store
      tcp_socket = TCPSocket.new("#{@server}", @port.to_i)
      socket_destination = OpenSSL::SSL::SSLSocket.new tcp_socket, ssl_context
      socket_destination.connect
      cert = OpenSSL::X509::Certificate.new(socket_destination.peer_cert)
      certprops = OpenSSL::X509::Name.new(cert.issuer).to_a
      issuer = certprops.select { |name, data, type| name == "O" }.first[1]
    rescue Exception => e   		
    end
    begin
      results = ["\r\n\033[1m== Certificate Information ==\033[0m",
                 "valid: #{(socket_destination.verify_result == 0)}",
                 "valid from: #{cert.not_before}",
                 "valid until: #{cert.not_after}",
                 "issuer: #{issuer}",
                 "subject: #{cert.subject}",
                 "public key:\r\n#{cert.public_key}"].join("\r\n")	
    rescue Exception => e
    ensure
      socket_destination.close
      tcp_socket.close
    end
    return results
  end


  def parse(cipher_name, cipher_bits, protocol)
    if protocol == @SSLv2
      ssl_version = "\033[1;31mSSLv2\033[0m"
    elsif protocol == @SSLv3
      ssl_version = "\e[0;33mSSLv3\033[0m"
    elsif protocol == @TLSv1
      ssl_version = "\033[1mTLSv1\033[0m"
    elsif protocol == @TLSv1_1
      ssl_version = "\033[1mTLSv1.1\033[0m"
    elsif protocol == @TLSv1_2
      ssl_version = "\033[1mTLSv1.2\033[0m"
    end

    if cipher_name.match(/RC4/i)
      cipher = "\e[0;33m#{cipher_name}\033[0m"
    elsif cipher_name.match(/RC2/i)
      cipher = "\033[1;31m#{cipher_name}\033[0m"
    elsif cipher_name.match(/MD5/i)
      cipher = "\e[0;33m#{cipher_name}\033[0m"
    else
      cipher = "\e[0;32m#{cipher_name}\033[0m"
    end

    if cipher_bits == 40
      bits = "\033[1;31m#{cipher_bits}\033[0m"
    elsif cipher_bits == 56
      bits = "\033[1;31m#{cipher_bits}\033[0m"
    else
      bits = "\e[0;32m#{cipher_bits}\033[0m"
    end
    if protocol == @SSLv3 && cipher_name.match(/RC/i).to_s == ""
      return "Server Supports #{ssl_version} #{cipher} #{bits} \033[1;31m -- POODLE (CVE-2014-3566)\033[0m"
    else
      return "Server Supports #{ssl_version} #{cipher} #{bits}"
    end
  end

end

scanner = Scanner.new
scanner.ssl_scan
