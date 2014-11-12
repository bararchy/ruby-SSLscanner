#!/usr/bin/env ruby
require 'openssl'
require 'socket'

# SSL Configurations

class Scanner


	def self.ssl_scan
	
		# Check version for compatibility 
		version = RUBY_VERSION 
		if version.match(/1.9/) || version.match(/1.8/)
			puts "Starting in compatibility mode\r\n"
			scan_loop("test_all")
		else
			puts "\r\nTesting SSLv2"
			scan_loop(OpenSSL::SSL::OP_NO_SSLv3 + OpenSSL::SSL::OP_NO_TLSv1 + OpenSSL::SSL::OP_NO_TLSv1_1 + OpenSSL::SSL::OP_NO_TLSv1_2)
			puts "\r\nTesting SSLv3"
			scan_loop(OpenSSL::SSL::OP_NO_SSLv2 + OpenSSL::SSL::OP_NO_TLSv1 + OpenSSL::SSL::OP_NO_TLSv1_1 + OpenSSL::SSL::OP_NO_TLSv1_2)
			puts "\r\nTesting TLSv1"
			scan_loop(OpenSSL::SSL::OP_NO_SSLv2 + OpenSSL::SSL::OP_NO_SSLv3 + OpenSSL::SSL::OP_NO_TLSv1_1 + OpenSSL::SSL::OP_NO_TLSv1_2)
			puts "\r\nTesting TLSv1.1"
			scan_loop(OpenSSL::SSL::OP_NO_SSLv2 + OpenSSL::SSL::OP_NO_SSLv3 + OpenSSL::SSL::OP_NO_TLSv1 + OpenSSL::SSL::OP_NO_TLSv1_2)
			puts "\r\nTesting TLSv1.2"
			scan_loop(OpenSSL::SSL::OP_NO_SSLv2 + OpenSSL::SSL::OP_NO_SSLv3 + OpenSSL::SSL::OP_NO_TLSv1 + OpenSSL::SSL::OP_NO_TLSv1_1)
		end

		puts get_certificate_information
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
    				puts "\e[0;32mServer Supports: #{cipher[0]} #{cipher[2]}\033[0m"
    			else
    				puts "\e[0;32mServer Supports: #{cipher[0]} #{cipher[1]} #{cipher[2]}\033[0m"
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
	    				puts "\e[0;32mServer Supports: #{cipher[0]} #{cipher[2]}\033[0m"
	    			else
	    				puts "\e[0;32mServer Supports: #{cipher[0]} #{cipher[1]} #{cipher[2]}\033[0m"
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
    	rescue Exception => e
    		
    	end
    	
    	  
		certprops = OpenSSL::X509::Name.new(cert.issuer).to_a
		issuer = certprops.select { |name, data, type| name == "O" }.first[1]
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


    def self.known_vulunrabilties(data)

    end
end

Scanner.ssl_scan
