module ScanSSL
  class Certificate
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
    CIPHERS       = 'ALL::COMPLEMENTOFDEFAULT::COMPLEMENTOFALL'
    
    PROTOCOL_COLOR_NAME = {
      SSLV2   => 'SSLv2',
      SSLV3   => 'SSLv3',
      TLSV1   => 'TLSv1',
      TLSV1_1 => 'TLSv1.1',
      TLSV1_2 => 'TLSv1.2'
    }

    TRUTH_TABLE = { true => 'true', false => 'false' }
  end
end
