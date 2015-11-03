module ScanSSL
  # Will finish it tomorrow :P
  #

  class CertInfo < Certificate
    def initialize(server, port)
      @ssl_context = OpenSSL::SSL::SSLContext.new
      @cert_store = OpenSSL::X509::Store.new
      @cert_store.set_default_paths
      @ssl_context.cert_store = @cert_store
      @tcp_socket = TCPSocket.new(server, port)
      @socket_destination = OpenSSL::SSL::SSLSocket.new @tcp_socket, @ssl_context
      @socket_destination.connect
      @cert = OpenSSL::X509::Certificate.new(@socket_destination.peer_cert)
      @certprops = OpenSSL::X509::Name.new(@cert.issuer).to_a
    end

    def get_certificate_information
      begin
        
        issuer = @certprops.select { |name, data, type| name == "O" }.first[1]
        if Time.now.utc > @cert.not_after
            is_expired = @cert.not_after.to_s.colorize(:red)
        else 
            is_expired = @cert.not_after.to_s.colorize(:green)
        end
        
        results = ["\r\n== Certificate Information ==".bold,
                 'valid: ' + TRUTH_TABLE[(@socket_destination.verify_result == 0)],
                 "valid from: #{@cert.not_before}",
                 "valid until: #{is_expired}",
                 "issuer: #{issuer}",
                 "subject: #{@cert.subject}",
                 "algorithm: #{algorithm?}",
                 "key size: #{key_size?}",
                 "public key:\r\n#{@cert.public_key}"].join("\r\n")
        return results
      rescue Exception => e
        puts e.message, e.backtrace
      ensure
        @socket_destination.close if @socket_destination rescue nil
        tcp_socket.close         if tcp_socket rescue nil
      end
    end

    def algorithm?
      return @cert.signature_algorithm
    end

    def key_size?
      begin
        key_size = OpenSSL::PKey::RSA.new(@cert.public_key).to_text.match(/Public-Key: \((.*) bit/).to_a[1].strip.to_i
        if key_size.between?(1000, 2000)
          key_size = $1
        elsif key_size > 2000
          key_size = $1
        else
          key_size = $1
        end
        return key_size
      end
    rescue
      return "Problem with key_size"
    end
  end
end
