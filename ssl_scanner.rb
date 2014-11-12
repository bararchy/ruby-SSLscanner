#!/usr/bin/env ruby
require 'openssl'
require 'socket'

# SSL Configurations

class Scanner
	
	def self.ssl_scan
	
	    @NO_SSLv2 = 16777216
        @NO_SSLv3 = 33554432
        @NO_TLSv1 = 67108864
        @NO_TLSv1_1 = 268435456
        @NO_TLSv1_2 = 134217728
		# Check version for compatibility  
		puts "\e[0;32mstrong\033[0m -- \e[0;33mweak\033[0m -- \033[1;31mvulnerable\033[0m"
		puts "\r\n\033[1mTesting SSLv2: \033[0m"
		scan_loop(@NO_SSLv3 + @NO_TLSv1 + @NO_TLSv1_1 + @NO_TLSv1_2)
		puts "\r\n\033[1mTesting SSLv3: \033[0m"
		scan_loop(@NO_SSLv2 + @NO_TLSv1 + @NO_TLSv1_1 + @NO_TLSv1_2)
		puts "\r\n\033[1mTesting TLSv1: \033[0m"
		scan_loop(@NO_SSLv2 + @NO_SSLv3 + @NO_TLSv1_1 + @NO_TLSv1_2)
		puts "\r\n\033[1mTesting TLSv1.1: \033[0m"
		scan_loop(@NO_SSLv2 + @NO_SSLv3 + @NO_TLSv1 + @NO_TLSv1_2)
		puts "\r\n\033[1mTesting TLSv1.2: \033[0m"
		scan_loop(@NO_SSLv2 + @NO_SSLv3 + @NO_TLSv1 + @NO_TLSv1_1)

		puts get_certificate_information
	end


	def self.scan_sslv2
		trap("INT") do
	  		puts "Exiting..."
	  		break
	  		exit 1
		end
		ssl_context = OpenSSL::SSL::SSLContext.new
		ssl_context.ciphers = "ALL::HIGH::MEDIUM::LOW::SSL23"
		ssl_context.options = @NO_SSLv3 + @NO_TLSv1 + @NO_TLSv1_1 + @NO_TLSv1_2

	end

	def self.scan_loop(options)
		trap("INT") do
	  		puts "Exiting..."
	  		break
	  		exit 1
		end
		ssl_context = OpenSSL::SSL::SSLContext.new
		ssl_context.ciphers = "ALL::HIGH::MEDIUM::LOW::SSL23"
		if options != "test_all"
			ssl_context.options = options
    	end
    	for cipher in ssl_context.ciphers
    		begin
    			sleep 0.1
    			ssl_context = OpenSSL::SSL::SSLContext.new
    			ssl_context.ciphers = "ALL::HIGH::MEDIUM::LOW::SSL23"
    			if options != "test_all"
					ssl_context.options = options
    			end
				ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE	
				tcp_socket = TCPSocket.new("#{ARGV[0]}", ARGV[1].to_i)
    			ssl_context.ciphers = cipher[0].to_s
    			socket_destination = OpenSSL::SSL::SSLSocket.new tcp_socket, ssl_context
    			socket_destination.connect
    			if options != "test_all"
    				puts "Server Supports: #{color_issues(cipher[0])} #{color_issues(cipher[2])}".chomp
    			else
    				puts "Server Supports: #{color_issues(cipher[0])} #{color_issues(cipher[1])} #{color_issues(cipher[2])}".chomp
    			end
    			socket_destination.close
    		rescue Exception => e
    			if e.to_s.match(/unsupported protocol/)
    				puts "No Support for protocol"
    				break
    			end
    			if ARGV[2] == "--no-error"
    			else	
	    			if options != "test_all"
	    				puts "Server Don't Supports: #{cipher[0]} #{cipher[2]}".chomp
	    			else
	    				puts "Server Don't Supports: #{cipher[0]} #{cipher[1]} #{cipher[2]}".chomp
	    			end
    			end
    		end
    	end
    end

    def self.get_certificate_information
    	begin
    		ssl_context = OpenSSL::SSL::SSLContext.new
			ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
			cert_store = OpenSSL::X509::Store.new
			cert_store.set_default_paths
			ssl_context.cert_store = cert_store
			tcp_socket = TCPSocket.new("#{ARGV[0]}", ARGV[1].to_i)
			socket_destination = OpenSSL::SSL::SSLSocket.new tcp_socket, ssl_context
			socket_destination.connect
			cert = OpenSSL::X509::Certificate.new(socket_destination.peer_cert)
			certprops = OpenSSL::X509::Name.new(cert.issuer).to_a
			issuer = certprops.select { |name, data, type| name == "O" }.first[1]
    	rescue Exception => e
    		
    	end
		results = ["\r\n== Certificate Information ==",
				   "valid: #{(socket_destination.verify_result == 0)}",
				   "valid from: #{cert.not_before}",
		           "valid until: #{cert.not_after}",
		           "issuer: #{issuer}",
		           "subject: #{cert.subject}",
		           "public key: #{cert.public_key}"].join("\r\n")

		begin
			socket_destination.connect
		rescue Exception => e

		end
		return results
	end


    def self.color_issues(data)

    	case data
    	when (/RC4/i)
    		return "\e[0;33m#{data}\033[0m"
    	when (/40/)
    		return "\033[1;31m#{data}\033[0m"
    	when (/^56^/)
    		return "\033[1;31m#{data}\033[0m"		
    	when (/MD5/i)
    		return "\e[0;33m#{data}\033[0m"
    	else
    		return "\e[0;32m#{data}\033[0m"
    	end
    end
end

Scanner.ssl_scan
