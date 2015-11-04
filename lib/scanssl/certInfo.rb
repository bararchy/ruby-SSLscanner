module ScanSSL
  class CertInfo < Certificate
    def initialize(server, port)
      @ssl_context = OpenSSL::SSL::SSLContext.new
      @cert_store = OpenSSL::X509::Store.new
      @cert_store.set_default_paths
      @ssl_context.cert_store = @cert_store
      @tcp_socket = TCPSocket.new(server, port)
      @socket_destination = OpenSSL::SSL::SSLSocket.new @tcp_socket, @ssl_context
      @socket_destination.connect
    end

    def valid?
      return TRUTH_TABLE[(@socket_destination.verify_result == 0)]
    end

    def valid_from
      return cert.not_before
    end

    def valid_until
      return cert.not_after
    end

    def issuer
      return certprops.select { |name, data, type| name == "O" }.first[1]
    end

    def subject
      return cert.subject
    end

    def algorithm
      return cert.signature_algorithm
    end

    def key_size
      begin
        key_size = OpenSSL::PKey::RSA.new(cert.public_key).to_text.match(/Public-Key: \((.*) bit/).to_a[1].strip.to_i
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

    def public_key
      return cert.public_key
    end

    def cert
      return OpenSSL::X509::Certificate.new(@socket_destination.peer_cert)
    end

    def certprops
      return OpenSSL::X509::Name.new(cert.issuer).to_a
    end
  end
end
