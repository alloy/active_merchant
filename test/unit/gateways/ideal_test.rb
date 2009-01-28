require File.dirname(__FILE__) + '/../../test_helper'

module IdealTestCases
  DEFAULT_IDEAL_OPTIONS = {
    :merchant => "123456789",
    :private_key => "PRIVATE_KEY",
    :private_certificate => "PRIVATE_CERT",
    :ideal_certificate => "IDEAL_CERT",
    :password => "PASSWORD"
  }

  class ActiveMerchant::Billing::IdealGateway
    self.test_url = "https://idealtest.example.com:443/ideal/iDeal"
    self.live_url = "https://ideal.example.com:443/ideal/iDeal"
  end

  class GeneralTest < Test::Unit::TestCase
    def setup
      @gateway = IdealGateway.new(DEFAULT_IDEAL_OPTIONS)
    end

    def test_optional_initialization_options
      assert_equal 0, IdealGateway.new(DEFAULT_IDEAL_OPTIONS).sub_id
      assert_equal 1, IdealGateway.new(DEFAULT_IDEAL_OPTIONS.merge(:sub_id => 1)).sub_id
    end

    def test_returns_the_test_url_when_in_the_test_env
      @gateway.stubs(:test?).returns(true)
      assert_equal IdealGateway.test_url, @gateway.send(:acquirer_url)
    end

    def test_returns_the_live_url_when_not_in_the_test_env
      @gateway.stubs(:test?).returns(false)
      assert_equal IdealGateway.live_url, @gateway.send(:acquirer_url)
    end

    def test_returns_created_at_timestamp
      timestamp = '2001-12-17T09:30:47.000Z'
      Time.any_instance.stubs(:gmtime).returns(DateTime.parse(timestamp))

      assert_equal timestamp, @gateway.send(:created_at_timestamp)
    end

    def test_pretty_to_ugly_keys_conversion
      keys = [
        [:acquirer_transaction_request, 'AcquirerTrxReq'],
        [:created_at,                   'createDateTimeStamp'],
        [:issuer,                       'Issuer'],
        [:merchant,                     'Merchant'],
        [:transaction,                  'Transaction'],
        [:issuer_id,                    'issuerID'],
        [:merchant_id,                  'merchantID'],
        [:sub_id,                       'subID'],
        [:token_code,                   'tokenCode'],
        [:merchant_return_url,          'merchantReturnURL'],
        [:purchase_id,                  'purchaseID'],
        [:expiration_period,            'expirationPeriod'],
        [:entrance_code,                'entranceCode']
      ]

      keys.each do |key, expected_key|
        assert_equal expected_key, @gateway.send(:uglify_key, key)
      end
    end

    def test_does_not_convert_unknown_key_to_ugly_key
      assert_equal 'not_a_registered_key', @gateway.send(:uglify_key, :not_a_registered_key)
    end

    def test_token_generation
      File.expects(:read).with(@gateway.private_certificate).returns(CERTIFICATE)

      expected_token = Digest::SHA1.hexdigest(OpenSSL::X509::Certificate.new(CERTIFICATE).to_der).upcase
      assert_equal expected_token, @gateway.send(:token)
    end

    def test_token_code_generation
      message = "Top\tsecret\tman.\nI could tell you, but then I'd have to kill you…"
      stripped_message = message.gsub(/\s/m, '')

      sha1 = OpenSSL::Digest::SHA1.new
      OpenSSL::Digest::SHA1.stubs(:new).returns(sha1)

      File.expects(:read).with(@gateway.private_key).returns(PRIVATE_KEY)

      key = OpenSSL::PKey::RSA.new(PRIVATE_KEY, @gateway.password)
      signature = key.sign(sha1, stripped_message)
      encoded_signature = Base64.encode64(signature).strip

      assert_equal encoded_signature, @gateway.send(:token_code, message)
    end
  end

  class XMLBuildingTest < Test::Unit::TestCase
    def setup
      @gateway = IdealGateway.new(DEFAULT_IDEAL_OPTIONS)
    end

    def test_contains_correct_info_in_root_node
      expected_xml = Builder::XmlMarkup.new
      expected_xml.instruct!
      expected_xml.tag!('AcquirerTrxReq', 'xmlns' => IdealGateway::XML_NAMESPACE, 'version' => IdealGateway::API_VERSION) {}

      assert_equal expected_xml.target!, @gateway.send(:xml_for, :acquirer_transaction_request, {})
    end

    def test_creates_correct_xml_from_hash_with_ugly_keys
      expected_xml = Builder::XmlMarkup.new
      expected_xml.instruct!
      expected_xml.tag!('AcquirerTrxReq', 'xmlns' => IdealGateway::XML_NAMESPACE, 'version' => IdealGateway::API_VERSION) do
        expected_xml.tag!('a_parent') do
          expected_xml.tag!('createDateTimeStamp', '2009-01-26')
        end
      end

      assert_equal expected_xml.target!, @gateway.send(:xml_for, :acquirer_transaction_request, :a_parent => { :created_at => '2009-01-26' })
    end
  end

  class AcquirerTest < Test::Unit::TestCase
    def setup
      @gateway = IdealGateway.new(DEFAULT_IDEAL_OPTIONS)

      @valid_options = {
        :issuer_id         => '0001',
        :expiration_period => 'PT10M',
        :return_url        => 'http://return_to.example.com',
        :order_id          => '1234567890123456',
        :currency          => 'EUR',
        :description       => 'A classic Dutch windmill for in the garden',
        :entrance_code     => '1234'
      }
    end

    def test_valid_with_required_options
      @gateway.stubs(:token)
      @gateway.stubs(:token_code)

      assert_nothing_raised(ArgumentError) do
        @gateway.send(:build_transaction_request_body, 100, @valid_options)
      end
    end

    def test_raises_ArgumentError_without_required_options
      @valid_options.keys.each do |key|
        @valid_options.delete(key)

        assert_raise(ArgumentError) do
          @gateway.send(:build_transaction_request_body, 100, @valid_options)
        end
      end
    end

    def test_builds_a_transaction_request_body
      @gateway.stubs(:created_at_timestamp).returns('created_at_timestamp')
      @gateway.stubs(:token).returns('the_token')

      money = 4321

      message = 'created_at_timestamp' +
                @valid_options[:issuer_id] +
                @gateway.merchant +
                @gateway.sub_id.to_s +
                @valid_options[:return_url] +
                @valid_options[:order_id] +
                money.to_s +
                @valid_options[:currency] +
                IdealGateway::LANGUAGE +
                @valid_options[:description] +
                @valid_options[:entrance_code]

      @gateway.expects(:token_code).with(message).returns('the_token_code')

      @gateway.expects(:xml_for).with(:acquirer_transaction_request, {
        :created_at => 'created_at_timestamp',
        :issuer => { :issuer_id => @valid_options[:issuer_id] },

        :merchant => {
          :merchant_id =>         @gateway.merchant,
          :sub_id =>              @gateway.sub_id,
          :authentication =>      IdealGateway::AUTHENTICATION_TYPE,
          :token =>               'the_token',
          :token_code =>          'the_token_code',
          :merchant_return_url => @valid_options[:return_url]
        },

        :transaction => {
          :purchase_id =>       @valid_options[:order_id],
          :amount =>            money,
          :currency =>          @valid_options[:currency],
          :expiration_period => @valid_options[:expiration_period],
          :language =>          IdealGateway::LANGUAGE,
          :description =>       @valid_options[:description],
          :entrance_code =>     @valid_options[:entrance_code]
        }
      })

      @gateway.send(:build_transaction_request_body, money, @valid_options)
    end

    def test_builds_a_directory_request_body
      @gateway.stubs(:created_at_timestamp).returns('created_at_timestamp')
      @gateway.stubs(:token).returns('the_token')

      message = 'created_at_timestamp' + @gateway.merchant + @gateway.sub_id.to_s
      @gateway.expects(:token_code).with(message).returns('the_token_code')

      @gateway.expects(:xml_for).with(:directory_request, {
        :created_at => 'created_at_timestamp',
        :merchant => {
          :merchant_id =>    @gateway.merchant,
          :sub_id =>         @gateway.sub_id,
          :authentication => IdealGateway::AUTHENTICATION_TYPE,
          :token =>          'the_token',
          :token_code =>     'the_token_code'
        }
      })

      @gateway.send(:build_directory_request_body)
    end
  end

  CERTIFICATE = %{-----BEGIN CERTIFICATE----- 
MIIEAzCCA3CgAwIBAgIQMIEnzk1UPrPDLOY9dc2cUjANBgkqhkiG9w0BAQUFADBf
MQswCQYDVQQGEwJVUzEgMB4GA1UEChMXUlNBIERhdGEgU2VjdXJpdHksIEluYy4x
LjAsBgNVBAsTJVNlY3VyZSBTZXJ2ZXIgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkw
HhcNMDQwNjA4MDAwMDAwWhcNMDUwNjA4MjM1OTU5WjCBvDELMAkGA1UEBhMCTkwx
FjAUBgNVBAgTDU5vb3JkLUhvbGxhbmQxEjAQBgNVBAcUCUFtc3RlcmRhbTEbMBkG
A1UEChQSQUJOIEFNUk8gQmFuayBOLlYuMRYwFAYDVQQLFA1JTi9OUy9FLUlORlJB
MTMwMQYDVQQLFCpUZXJtcyBvZiB1c2UgYXQgd3d3LnZlcmlzaWduLmNvbS9ycGEg
KGMpMDAxFzAVBgNVBAMUDnd3dy5hYm5hbXJvLm5sMIGfMA0GCSqGSIb3DQEBAQUA
A4GNADCBiQKBgQD1hPZlFD01ZdQu0GVLkUQ7tOwtVw/jmZ1Axu8v+3bxrjKX9Qi1
0w6EIadCXScDMmhCstExVptaTEQ5hG3DedV2IpMcwe93B1lfyviNYlmc/XIol1B7
PM70mI9XUTYAoJpquEv8AaupRO+hgxQlz3FACHINJxEIMgdxa1iyoJfCKwIDAQAB
o4IBZDCCAWAwCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAwPAYDVR0fBDUwMzAxoC+g
LYYraHR0cDovL2NybC52ZXJpc2lnbi5jb20vUlNBU2VjdXJlU2VydmVyLmNybDBE
BgNVHSAEPTA7MDkGC2CGSAGG+EUBBxcDMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8v
d3d3LnZlcmlzaWduLmNvbS9ycGEwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF
BwMCMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AudmVy
aXNpZ24uY29tMG0GCCsGAQUFBwEMBGEwX6FdoFswWTBXMFUWCWltYWdlL2dpZjAh
MB8wBwYFKw4DAhoEFI/l0xqGrI2Oa8PPgGrUSBgsexkuMCUWI2h0dHA6Ly9sb2dv
LnZlcmlzaWduLmNvbS92c2xvZ28uZ2lmMA0GCSqGSIb3DQEBBQUAA34AY7BYsNvj
i5fjnEHPlGOd2yxseCHU54HDPPCZOoP9a9kVWGX8tuj2b1oeiOsIbI1viIo+O4eQ
ilZjTJIlLOkXk6uE8vQGjZy0BUnjNPkXOQGkTyj4jDxZ2z+z9Vy8BwfothdcYbZK
48ZOp3u74DdEfQejNxBeqLODzrxQTV4=
-----END CERTIFICATE-----}

  PRIVATE_KEY = %{-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQEAxlbbntcogdQ6QZ5DzNpWSMafzf06pn4jzB+6iE5w27UdjAMP
jMsJz+/uabts0jXIc8Cs2ZjLh8/UY39PNW47bs4otSjT/l4U9NeXBCEilxXadTdi
OhAgHDheTxLv7wISwgwgV8iPhWiKeQak4ZQIeMwrTAc8fsWv1Zw3ZJanaQtTMXMI
mCLnTtL7v4cnSz5fq2lv0b2X42UPvf3ziyH2Em0T0LafUATQitm7KKst+PdUzaxL
Kg0cFMhdfyd5P9zMloEGsHg9dFp1U8nhTIDC7wgsE+a0ZUxctmo9V1UFsExpatX9
dr+e/9BhkEh/nKSMxw0blP0Hm8FUbg2/j0YgBQIBIwKCAQEAr6wEWXy9ek5COh52
kN6kMdR+6aXGO7GNa6cS7cHRrKe7FZxPmfWpmup0FIFvA1Q1M1LiPRJN3rDDbhGs
jmjyz9srXqCBQGH1TeOFwdQ0lHJxCLwGizLanKb0cewzmS2418GY/Us9SkamiHOZ
WhVmluC4omzPLnSUbL2QJeSFpi0ICuU2NsKRgywEl45Dt+A9wPytAqO9oCQwThY9
AQ08nFn9AiEIbksnBrFpsgpX31+ia4hU+j8fYvcc8+PyFwOpn6l/WWsspoC5/KEd
ZBdpgnD0JP5Tu9lwfPQg4c8LmFL7s2IAM0Fcm42dhfs4Ms1vtjZlN7Iji1hvnynN
ystRSwKBgQD+YvhroBouKO2jBhQ/2b0K4GXbz6loF46wvbwKZQJ+aTRp4qJV4Crr
+XMGGEUZH7X1a1z3th2qRvcncrewNoo/rQfqDTkALOGE9u3vva1uxuQ9cA2uRsO8
z601Y4uuyYhrZBkaO/GMqz7emYBPyf/MksTGBNCgFYSAbhyBZpkD8QKBgQDHmOMu
NhRGaIIZu8HERxCK8SAa/xlA7b4HbknV0lrYZAze2yjMTio0YI3i5EnjL6PZjhA9
1UUUj6FwMuIKSi1iC+tKyq12OOeaP6HpJhO8ADkMipjZISfGD1bST64HvupuPDV3
phjr1n4CqdXXmUkxj9lfKAAu4Kduv9rRrxHhVQKBgF58iCf5o1L5QlJ+mc6Ss+4Y
1WBF0TVKlBXC0NCpLM/d7uWAEGkKHpIpc92xPjyIHwNiZFwB0IETC1fLhg5AJLiQ
ucv2SF8mnOg+daIwgj8WrIvZKachmSjfbDhmzXtvbS8zzs861g+tUd2muqFLBz1b
FeMmXB4z4MH9A0YBiUqbAoGAERu7s4D6bG9bm85Dzv7G51Z/GEHAVgW/1MBPeLpC
TQ/j2JZxNhVUEx44DCIyOAtl0NGpnuZlAcMrGD7gLMSHjA+mdCAAPVVVriK2G0xo
F227vz8UamHtd2Bmhw4k3Betsa1jqyt+ep1bQg6OrBRz/O8SocGZnZ46PLFb5hZR
/V8CgYBh4NTzB/ZuUsaNfgJVYqje1Q87cc8RfeYKuLzXxRGcxKtM8JlS3WPZ7Xc9
NQLHCf/L1gBj/VxVwwL7yjvYDVeBcDI6Pz7XrbJupqDL408UazzHdK4Y28OdDsHj
F9W/Kcx2+xEaZ0Xbb4ZCd9cj9cBtmUqb51CwhZkYxIP+9pCPeA==
-----END RSA PRIVATE KEY-----}
end