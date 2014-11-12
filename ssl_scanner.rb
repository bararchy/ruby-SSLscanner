require 'openssl'
require 'thread'
require 'socket'

# SSL Configurations

class Scanner

	def self.ssl_scan
		trap("INT") do
	  		puts "Exiting..."
	  		break
	  		exit 1
		end
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


	def self.scan_loop(options)
		trap("INT") do
	  		puts "Exiting..."
	  		break
	  		exit 1
		end
		ssl_context = OpenSSL::SSL::SSLContext.new
		ssl_context.options = options
    	for cipher in ssl_context.ciphers
    		begin
    			sleep 0.1
    			ssl_context = OpenSSL::SSL::SSLContext.new
    			ssl_context.options = options
				ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE	
				tcp_socket = TCPSocket.new("#{ARGV[0]}", ARGV[1].to_i)
    			ssl_context.ciphers = cipher[0].to_s
    			socket_destination = OpenSSL::SSL::SSLSocket.new tcp_socket, ssl_context
    			socket_destination.connect
    			puts "\e[0;32mServer supports #{cipher[0]} #{cipher[2]}\033[0m"
    			socket_destination.close
    		rescue Exception => e
    			if e.to_s.match(/unsupported protocol/)
    				puts "No Support for protocol"
    				break
    			end
    			if ARGV[2] == "--no-error"
    			else
    				puts "\033[1;31mNo support for #{cipher[0]} #{cipher[2]}\033[0m #{e}"
    			end
    		end
    	end
    end
end

Scanner.ssl_scan
