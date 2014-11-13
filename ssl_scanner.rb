#!/usr/bin/env ruby
require 'openssl'
require 'socket'

# SSL Configurations

class Scanner
	
	def self.ssl_scan

		@delay = sleep 0
		usage = ("Usage: #{File.basename($0)}: [-s <server hostname/ip>] [-p <port>] [-d <debug>")
		@debug = false
		begin
			loop { case ARGV[0]
		    	when '-s' then  ARGV.shift; @server = ARGV.shift
		    	when '-p' then  ARGV.shift; @port = ARGV.shift
		    	when '-d' then 	ARGV.shift; @debug = true
		    	when /^-/ then  usage("Unknown option: #{ARGV[0].inspect}")
		    	else break
			end; }
		rescue Exception => e
			puts usage
		end


		if @server.to_s == "" || @port.to_s == ""
			puts usage
			exit 0
		end
		ssl_ciphers # Setup OpenSSL ciphers per protocol

		# Index by color
		puts "\e[0;32mstrong\033[0m -- \e[0;33mweak\033[0m -- \033[1;31mvulnerable\033[0m\r\n\r\n"
		
		scan_sslv2
		scan_sslv3
		scan_tlsv1
		scan_tlsv1_1
		scan_tlsv1_2
		puts get_certificate_information
	end


	def self.scan_sslv2
		trap("INT") do
	  		puts "Exiting..."
	  		break
	  		exit 1
		end
		ssl_context = OpenSSL::SSL::SSLContext.new
		ssl_context.ciphers = @ciphers
		ssl_context.options = @SSLv2
		for cipher in ssl_context.ciphers
			begin
    			@delay
    			ssl_context = OpenSSL::SSL::SSLContext.new
    			ssl_context.options = @SSLv2
    			ssl_context.ciphers = cipher[0].to_s
				tcp_socket = TCPSocket.new("#{@server}", @port.to_i)
    			socket_destination = OpenSSL::SSL::SSLSocket.new tcp_socket, ssl_context
    			socket_destination.connect
    			puts "Server Supports: \033[1;31m SSLv2 #{cipher[0]} #{cipher[2]}\033[0m bits"
    			socket_destination.close
    		rescue Exception => e
    			if @debug == true	
	    			puts "Server Don't Supports: SSLv2 #{cipher[0]} #{cipher[2]} bits"
    			end
    		end
		end
	end
	def self.scan_sslv3
		trap("INT") do
	  		puts "Exiting..."
	  		break
	  		exit 1
		end
		ssl_context = OpenSSL::SSL::SSLContext.new
		ssl_context.ciphers = @ciphers
		ssl_context.options = @SSLv3
		for cipher in ssl_context.ciphers
			begin
    			@delay
    			ssl_context = OpenSSL::SSL::SSLContext.new
    			ssl_context.options = @SSLv3
    			ssl_context.ciphers = cipher[0].to_s
				tcp_socket = TCPSocket.new("#{@server}", @port.to_i)
    			socket_destination = OpenSSL::SSL::SSLSocket.new tcp_socket, ssl_context
    			socket_destination.connect
    			if cipher[0].match(/RC/i).to_s == ""
    				puts "Server Supports: \033[1mSSLv3 \033[0m \033[1;31m#{cipher[0]} #{cipher[2]}\033[0m bits -- \033[1;31mPOODLE\033[0m"
    			else
    				puts "Server Supports: \033[1mSSLv3 \033[0m #{color_issues(cipher[0])} #{color_issues(cipher[3])} bits"
    			end
    			socket_destination.close
    		rescue Exception => e
    			if @debug == true	
	    			puts "Server Don't Supports: #{cipher[0]} #{cipher[3]} bits"
    			end
    		ensure
    			socket_destination.close
    		end
		end
	end
	def self.scan_tlsv1
		trap("INT") do
	  		puts "Exiting..."
	  		break
	  		exit 1
		end
		ssl_context = OpenSSL::SSL::SSLContext.new
		ssl_context.ciphers = @ciphers
		ssl_context.options = @TLSv1
		for cipher in ssl_context.ciphers
			begin
    			@delay
    			ssl_context = OpenSSL::SSL::SSLContext.new
    			ssl_context.options = @TLSv1
    			ssl_context.ciphers = cipher[0].to_s
				tcp_socket = TCPSocket.new("#{@server}", @port.to_i)
    			socket_destination = OpenSSL::SSL::SSLSocket.new tcp_socket, ssl_context
    			socket_destination.connect
    			puts "Server Supports: \033[1mTLSv1 \033[0m #{color_issues(cipher[0])} #{color_issues(cipher[2])} bits"
    			socket_destination.close
    		rescue Exception => e
    			if @debug == true	
	    			puts "Server Don't Supports: \033[1mTLSv1 \033[0m #{cipher[0]} #{cipher[2]} bits"
    			end
    		ensure
    			socket_destination.close
    		end
		end
	end
		def self.scan_tlsv1_1
		trap("INT") do
	  		puts "Exiting..."
	  		break
	  		exit 1
		end
		ssl_context = OpenSSL::SSL::SSLContext.new
		ssl_context.ciphers = @ciphers
		ssl_context.options = @TLSv1_1
		for cipher in ssl_context.ciphers
			begin
    			@delay
    			ssl_context = OpenSSL::SSL::SSLContext.new
    			ssl_context.options = @TLSv1_1
    			ssl_context.ciphers = cipher[0].to_s
				tcp_socket = TCPSocket.new("#{@server}", @port.to_i)
    			socket_destination = OpenSSL::SSL::SSLSocket.new tcp_socket, ssl_context
    			socket_destination.connect
    			puts "Server Supports: \033[1mTLSv1.1 \033[0m #{color_issues(cipher[0])} #{color_issues(cipher[2])} bits"
    			socket_destination.close
    		rescue Exception => e
    			if @debug == true	
	    			puts "Server Don't Supports: \033[1mTLSv1.1 \033[0m #{cipher[0]} #{cipher[2]} bits"
    			end
    		ensure
    			socket_destination.close
    		end
		end
	end
		def self.scan_tlsv1_2
		trap("INT") do
	  		puts "Exiting..."
	  		break
	  		exit 1
		end
		ssl_context = OpenSSL::SSL::SSLContext.new
		ssl_context.ciphers = @ciphers
		ssl_context.options = @TLSv1_2
		for cipher in ssl_context.ciphers
			begin
    			@delay
    			ssl_context = OpenSSL::SSL::SSLContext.new
    			ssl_context.options = @TLSv1_2
    			ssl_context.ciphers = cipher[0].to_s
				tcp_socket = TCPSocket.new("#{@server}", @port.to_i)
    			socket_destination = OpenSSL::SSL::SSLSocket.new tcp_socket, ssl_context
    			socket_destination.connect
    			puts "Server Supports: \033[1mTLSv1.2 \033[0m #{color_issues(cipher[0])} #{color_issues(cipher[2])} bits"
    			socket_destination.close
    		rescue Exception => e
    			if @debug == true	
	    			puts "Server Don't Supports: \033[1mTLSv1.2 \033[0m #{cipher[0]} #{cipher[2]} bits"
    			end
    		ensure
    			socket_destination.close
    		end
		end
	end


    def self.get_certificate_information
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
		           "public key: #{cert.public_key}"].join("\r\n")	
		socket_destination.connect
		rescue Exception => e
		end
		return results
	end


    def self.color_issues(data)

    	if data.to_s.match(/RC4/i)
    		return "\e[0;33m#{data}\033[0m"
    	elsif data.to_s.match(/RC2/i)
    		return "\033[1;31m#{data}\033[0m"
    	elsif data == 40
    		return "\033[1;31m#{data}\033[0m"
    	elsif data == 56
    		return "\033[1;31m#{data}\033[0m"		
    	elsif data.to_s.match(/MD5/i)
    		return "\e[0;33m#{data}\033[0m"
    	else
    		return "\e[0;32m#{data}\033[0m"
    	end
    end

    def self.ssl_ciphers

    	no_SSLv2 = 16777216
        no_SSLv3 = 33554432
        no_TLSv1 = 67108864
        no_TLSv1_1 = 268435456
        no_TLSv1_2 = 134217728

        @SSLv2 = no_SSLv3 + no_TLSv1 + no_TLSv1_1 + no_TLSv1_2
        @SSLv3 = no_SSLv2 + no_TLSv1 + no_TLSv1_1 + no_TLSv1_2
        @TLSv1 = no_SSLv2 + no_SSLv3 + no_TLSv1_1 + no_TLSv1_2
        @TLSv1_1 = no_SSLv2 + no_SSLv3 + no_TLSv1 + no_TLSv1_2
        @TLSv1_2 = no_SSLv2 + no_SSLv3 + no_TLSv1 + no_TLSv1_1
        @ciphers = "ALL::HIGH::MEDIUM::LOW::SSL23"
    end 
end

Scanner.ssl_scan
