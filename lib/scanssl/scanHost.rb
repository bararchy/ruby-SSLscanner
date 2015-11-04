module ScanSSL
  # I think the best will be to put the result to the hash or array
  # and return it to ScanSLL::Command so we can send it to Colorize method
  # and sort.
  #
  class ScanHost < Certificate
    def scan(server, port)
      ssl2_array = []
      ssl3_array = []
      tls1_array = []
      tls1_1_array = []
      tls1_2_array = []
      threads = []

      c = []
        PROTOCOLS.each do |protocol|
          ssl_context = OpenSSL::SSL::SSLContext.new
          ssl_context.ciphers = CIPHERS
          ssl_context.options = protocol
          threads << Thread.new do
            ssl_context.ciphers.each do |cipher|
            begin
              ssl_context = OpenSSL::SSL::SSLContext.new
              ssl_context.options = protocol
              ssl_context.ciphers = cipher[0].to_s
              begin
                tcp_socket = WEBrick::Utils.timeout(5){
                  TCPSocket.new(server, port)
                }
              rescue => e
                puts e.message
                exit 1
              end
              socket_destination = OpenSSL::SSL::SSLSocket.new tcp_socket, ssl_context
              WEBrick::Utils.timeout(5) {
                socket_destination.connect
              }
              if protocol == SSLV3
                ssl_version, cipher, bits, vulnerability = result_parse(cipher[0], cipher[3], protocol)
                result = "Server supports: %-22s %-42s %-10s %s\n"%[ssl_version, cipher, bits, vulnerability]
                ssl3_array << result
              elsif protocol == TLSV1
                ssl_version, cipher, bits, vulnerability = result_parse(cipher[0], cipher[2], protocol)
                result = "Server supports: %-22s %-42s %-10s %s\n"%[ssl_version, cipher, bits, vulnerability]
                tls1_array << result
              elsif protocol == TLSV1_1
                ssl_version, cipher, bits, vulnerability = result_parse(cipher[0], cipher[2], protocol)
                result = "Server supports: %-22s %-42s %-10s %s\n"%[ssl_version, cipher, bits, vulnerability]
                tls1_1_array << result
              elsif protocol == TLSV1_2
                ssl_version, cipher, bits, vulnerability = result_parse(cipher[0], cipher[2], protocol)
                result = "Server supports: %-22s %-42s %-10s %s\n"%[ssl_version, cipher, bits, vulnerability]
                tls1_2_array << result
              elsif protocol == SSLV2
                ssl_version, cipher, bits, vulnerability = result_parse(cipher[0], cipher[2], protocol)
                result = "Server supports: %-22s %-42s %-10s %s\n"%[ssl_version, cipher, bits, vulnerability]
                ssl2_array << result
              end

            rescue Exception => e
              if @debug
                puts e.message
                puts e.backtrace.join "\n"
                if protocol == SSLV2
                  puts "Server Don't Supports: SSLv2 #{c[0]} #{c[2]} bits"
                elsif protocol == SSLV3
                  puts "Server Don't Supports: SSLv3 #{c[0]} #{c[3]} bits"
                elsif protocol == TLSV1
                  puts "Server Don't Supports: TLSv1 #{c[0]} #{c[2]} bits"
                elsif protocol == TLSV1_1
                  puts "Server Don't Supports: TLSv1.1 #{c[0]} #{c[2]} bits"
                elsif protocol == TLSV1_2
                  puts "Server Don't Supports: TLSv1.2 #{c[0]} #{c[2]} bits"
                end
              end
            ensure
              socket_destination.close if socket_destination rescue nil
              tcp_socket.close if tcp_socket rescue nil
            end
          end
        end
    end
      begin    
        threads.map(&:join)
      rescue Interrupt
      end
      return ssl3_array, ssl2_array, tls1_array, tls1_1_array, tls1_2_array
    end

    def result_parse(cipher_name, cipher_bits, protocol)
      ssl_version = PROTOCOL_COLOR_NAME[protocol]
      cipher = case cipher_name
        when /^(RC4|MD5)/
          cipher_name.colorize(:yellow)
        when /^RC2/
          cipher_name.colorize(:red)
        when /^EXP/
          cipher_name.colorize(:red)
        else
          cipher_name.colorize(:gree)
        end

      bits = case cipher_bits
        when 48, 56, 40
          cipher_bits.to_s.colorize(:red)
        when 112
          cipher_bits.to_s.colorize(:yellow)
        else
          cipher_bits.to_s.colorize(:green)
        end
      detect_vulnerabilites(ssl_version, cipher, bits)
    end

    def detect_vulnerabilites(ssl_version, cipher, bits)
      if ssl_version.match(/SSLv3/).to_s != "" && cipher.match(/RC/i).to_s == ""
        return ssl_version, cipher, bits, "     POODLE (CVE-2014-3566)".colorize(:red)
      elsif cipher.match(/RC2/i)
        return ssl_version, cipher, bits, "     Chosen-Plaintext Attack".colorize(:red)
      elsif cipher.match(/EXP/i)
        return ssl_version, cipher, bits, "     FREAK (CVE-2015-0204)".colorize(:red)
      elsif cipher.match(/RC4/i)
        return ssl_version, cipher, bits, "     Bar-Mitzvah Attack".colorize(:yellow)
      else
        return ssl_version, cipher, bits, ''
      end
    end
  end
end
