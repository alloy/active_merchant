require File.dirname(__FILE__) + '/../../test_helper'

module IdealTestCases
  DEFAULT_IDEAL_OPTIONS = {
    :merchant => "123456789",
    :private_key => "PRIVATE_KEY",
    :private_cert => "PRIVATE_CERT",
    :ideal_cert => "IDEAL_CERT",
    :password => "PASSWORD"
  }

  class GeneralTest < Test::Unit::TestCase
    def setup
      @gateway = IdealGateway.new(DEFAULT_IDEAL_OPTIONS)
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
        :description       => 'A description',
        :entrance_code     => '1234'
      }
    end

    def test_valid_with_required_options
      assert_nothing_raised(ArgumentError) do
        @gateway.build_transaction_request_body 100, @valid_options
      end
    end

    def test_raises_ArgumentError_without_required_options
      @valid_options.keys.each do |key|
        @valid_options.delete(key)

        assert_raise(ArgumentError) do
          @gateway.build_transaction_request_body 100, @valid_options
        end
      end
    end

    # def test_builds_a_transaction_request_body
    #   @gateway.stubs(:created_at_timestamp).returns('timestamp')
    #   
    #   @gateway.expects(:xml_for).with('AcquirerTrxReq', {
    #     :created_at => 'timestamp',
    #     :issuer => { :issuer_id => '0001' },
    #     :merchant => {
    #       :merchant_id => '',
    #       :sub_id => '',
    #       :authentication => '',
    #       :token => '',
    #       :token_code => ''
    #       :merchant_return_url => ''
    #     },
    #     :transaction => {
    #       :purchase_id => '',
    #       :amount => '',
    #       :currency => 'EUR',
    #       :expiration_period => '',
    #       :language => 'nl',
    #       :description => '',
    #       :entrance_code => ''
    #     }
    #   })
    # end
  end
end

# class IdealTest < Test::Unit::TestCase
# 
#   DEFAULT_IDEAL_OPTIONS = {
#     :merchant => "123456789",
#     :private_key => "PRIVATE_KEY",
#     :private_cert => "PRIVATE_CERT",
#     :ideal_cert => "IDEAL_CERT",
#     :password => "PASSWORD"
#   }
# 
#   def setup
#     @gateway = ActiveMerchant::Billing::Base.gateway(:ideal).new DEFAULT_IDEAL_OPTIONS 
# 
#     # stub security methods, so we can run tests without PEM files
#     @stubbed_time_stamp = "2007-07-02T10:03:18.000Z"
#     @gateway.stubs(:token).returns("TOKEN")
#     @gateway.stubs(:sign_message).returns("TOKEN_CODE")
#     @gateway.stubs(:create_time_stamp).returns(@stubbed_time_stamp)
# 
#     @transaction_options = {:issuer_id=>'0001', :expiration_period=>'PT10M', 
#       :return_url =>'http://www.return.url', :order_id=>'1234567890123456', :currency=>'EUR', 
#       :description => 'A description', :entrance_code => '1234'}
#   end
# 
#   # First test outgoing messages
#   
#   def test_build_transaction_request
#     request = @gateway.build_transaction_request(100, @transaction_options)  
# 
#     xml_request = REXML::Document.new(request)
# 
#     assert_ideal_message xml_request, 'AcquirerTrxReq' 
#     assert_merchant_elements xml_request
#         
#     assert_equal @transaction_options[:issuer_id], xml_request.root.elements['Issuer/issuerID'].text, 'Should map to an issuerID element.'
#     assert_equal @transaction_options[:return_url], xml_request.root.elements['Merchant/merchantReturnURL'].text, 'Should map to a merchantReturnURL element.'
#     assert_equal @transaction_options[:order_id], xml_request.root.elements['Transaction/purchaseID'].text, 'Should map to a purchaseID element.'
#     assert_equal '100', xml_request.root.elements['Transaction/amount'].text, 'Should map to an amount element.'
#     assert_equal @transaction_options[:currency], xml_request.root.elements['Transaction/currency'].text, 'Should map to a currency element.'
#     assert_equal @transaction_options[:expiration_period], xml_request.root.elements['Transaction/expirationPeriod'].text, 'Should map to an expirationPeriod element.'
#     assert_equal 'nl', xml_request.root.elements['Transaction/language'].text, 'Should map to a language element.'
#     assert_equal @transaction_options[:description], xml_request.root.elements['Transaction/description'].text, 'Should map to a description element.'
#     assert_equal @transaction_options[:entrance_code], xml_request.root.elements['Transaction/entranceCode'].text, 'Should map to an entranceCode element.'
# 
#   end
#   
#   def test_build_status_request
#     request = @gateway.build_status_request(:transaction_id =>'1234')  
#     xml_request = REXML::Document.new(request)
# 
#     assert_ideal_message xml_request, 'AcquirerStatusReq'    
#     assert_merchant_elements xml_request  
# 
#     assert_equal '1234', xml_request.root.elements['Transaction/transactionID'].text, 'Should map to a transactionID element.'     
#   end
# 
#   def test_build_directory_request
#     request = @gateway.build_directory_request
#     xml_request = REXML::Document.new(request)
# 
#     assert_ideal_message xml_request, 'DirectoryReq'
#     assert_merchant_elements xml_request  
#   end
#   
#   def assert_ideal_message xml_request, message_name
#     assert_equal '1.0', xml_request.version, "Should be version 1.0 of the xml specification"
#     assert_equal 'UTF-8', xml_request.encoding, "Should be UTF-8 encoding"
#     assert_equal 'http://www.idealdesk.com/Message', xml_request.root.namespace, "Should have a valid namespace"
#     assert_equal message_name, xml_request.root.name, "Root should match messagename"
#     assert_equal '1.1.0', xml_request.root.attribute('version',nil).value, "Should have a ideal version number"
#     assert_equal @stubbed_time_stamp, xml_request.root.elements['createDateTimeStamp'].text, 'Should have a time stamp.'
#   end
# 
#   def assert_merchant_elements xml_request
#     assert_equal DEFAULT_IDEAL_OPTIONS[:merchant], xml_request.root.elements['Merchant/merchantID'].text, 'Should map to an merchantID element.'
#     assert_equal '0', xml_request.root.elements['Merchant/subID'].text, 'Should map to an subID element.'
#     assert_equal 'SHA1_RSA', xml_request.root.elements['Merchant/authentication'].text, 'Should map to an authentication element.'
#     assert_equal 'TOKEN', xml_request.root.elements['Merchant/token'].text, 'Should map to a token element.'
#     assert_equal 'TOKEN_CODE', xml_request.root.elements['Merchant/tokenCode'].text, 'Should map to a tokenCode element.'
#   end
# 
#   # test incoming messages
#   
#   def test_setup_purchase_successful
#     @gateway.expects(:ssl_post).returns(successful_transaction_response)
#     response = @gateway.setup_purchase(100,@transaction_options)
#     assert response.success?, "Transaction request should be succesful"
#     transaction = response.transaction
#     assert_equal '0050000002797923', transaction['transactionID'], 'Should map to transaction_id'
#     assert_equal '9459897270157938', transaction['purchaseID'], 'Should map to purchase_id'
#     assert_equal '0050', response.params['AcquirerTrxRes']['Acquirer']['acquirerID'], 'Should map to acquirer_id'
#     assert_equal 'https://issuer.url/action?trxid=0050000002797923', response.service_url, "Response should have an issuer url"
#   end
#   
#   def test_error_response
#     @gateway.expects(:ssl_post).returns(failed_transaction_response)
#     response = @gateway.setup_purchase(100,@transaction_options)
#     assert !response.success?, "Transaction request should fail"
#     assert_equal 'ErrorRes', response.message, 'Should return error response'          
#     error = response.error
#     assert_equal "BR1210", error['errorCode'], "Should return an error code"    
#     assert_equal "Field generating error: Parameter \'25.99\' is not a natural(or \'-\') format", error['errorDetail'], "Should return an error detail"    
#     assert_equal "Value contains non-permitted character", error['errorMessage'], "Should return an error message"    
#     assert_equal "Betalen met iDEAL is nu niet mogelijk. Probeer het later nogmaals of betaal op een andere manier.", error['consumerMessage'], "Should return consumer message"
#   end
#     
#   def test_capture
#     @gateway.expects(:ssl_post).returns(successful_status_response)
#     @gateway.expects(:verify_message).with('IDEAL_CERT', '2007-07-02T10:03:18.000Z0050000002807474SuccessP001234567', 
#     'LONGSTRING').returns(true)
#     
#     response = @gateway.capture(:transaction_id =>'0050000002807474')  
#     assert response.success?, "Transaction should be succesful"
#     transaction = response.transaction
#     assert_equal '0050000002807474', transaction['transactionID'], 'Should map to transaction_id'
#     assert_equal 'C M Bröcker-Meijer en M Bröcker', transaction['consumerName']
#     assert_equal 'P001234567', transaction['consumerAccountNumber']
#     assert_equal 'DEN HAAG', transaction['consumerCity']
#     assert_equal 'Success', transaction['status'], 'Should map to status'    
#   end
# 
#   # make sure the gateway does not crash if issuer 'forgets' consumerAcountNumber
#   def test_capture_with_missing_account_number
#     @gateway.expects(:ssl_post).returns(successful_status_response_with_missing_fields)
#     @gateway.expects(:verify_message).with('IDEAL_CERT', '2007-07-02T10:03:18.000Z0050000002807474Success', 
#     'LONGSTRING').returns(true)
#     
#     response = @gateway.capture(:transaction_id =>'0050000002807474')  
#     assert response.success?, "Transaction should be succesful"
#     transaction = response.transaction
#     assert_equal '0050000002807474', transaction['transactionID'], 'Should map to transaction_id'
#     assert_nil transaction['consumerAccountNumber']
#     assert_equal 'Success', transaction['status'], 'Should map to status'    
#   end
# 
#   def test_payment_cancelled
#     @gateway.expects(:ssl_post).returns(cancelled_status_response)
#     @gateway.expects(:verify_message).with('IDEAL_CERT', '2007-07-02T10:03:18.000Z0050000002807474Cancelled', 
#     'LONGSTRING').returns(true)
#     
#     response = @gateway.capture(:transaction_id =>'0050000002807474')  
#     assert !response.success?, "Transaction should not be succesful"
#     transaction = response.transaction
#     assert_equal '0050000002807474', transaction['transactionID'], 'Should map to transaction_id'
#     assert_equal 'Cancelled', transaction['status'], 'Should map to status'
#   end
# 
#   def test_issuers_multiple
#     @gateway.expects(:ssl_post).returns(directory_request_response)
#     response = @gateway.issuers
#     assert response.success?, "Request should be succesful"
#     list = response.issuer_list
#     assert_equal 4, list.size, "Should return multiple issuers"
#     assert_equal '0031', list[0]['issuerID'], "Should return an issuerID"
#   end
# 
#   def test_issuers_one_issuer
#     @gateway.expects(:ssl_post).returns(directory_request_response_one_issuer)
#     response = @gateway.issuers
#     assert response.success?, "Request should be succesful"
#     list = response.issuer_list
#     assert_equal 1, list.size, "Should return one issuer"
#     assert_equal '0031', list[0]['issuerID'], "Should return an issuerID"
#   end
# 
#   def test_acquirer_url
#     IdealGateway.live_url = "http://production.url"
#     IdealGateway.test_url = "http://test.url"  
#     assert_equal "http://test.url", @gateway.acquirer_url, "Should return the test url"
#     
#     ActiveMerchant::Billing::Base.mode = :live
#     assert_equal "http://production.url", @gateway.acquirer_url, "Should return the production url"
#   end
# 
#   #For this test we use the certificate and fingerprint from the iDeal documentation
#   def test_fingerprint
#     assert_equal "500A0D42D111413B5363D567B9C7979290427DA3", 
#       @gateway.create_fingerprint(certificate)
#   end
# 
#   def certificate
#       <<-CERTIFICATE
# -----BEGIN CERTIFICATE----- 
# MIIEAzCCA3CgAwIBAgIQMIEnzk1UPrPDLOY9dc2cUjANBgkqhkiG9w0BAQUFADBf 
# MQswCQYDVQQGEwJVUzEgMB4GA1UEChMXUlNBIERhdGEgU2VjdXJpdHksIEluYy4x 
# LjAsBgNVBAsTJVNlY3VyZSBTZXJ2ZXIgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkw 
# HhcNMDQwNjA4MDAwMDAwWhcNMDUwNjA4MjM1OTU5WjCBvDELMAkGA1UEBhMCTkwx 
# FjAUBgNVBAgTDU5vb3JkLUhvbGxhbmQxEjAQBgNVBAcUCUFtc3RlcmRhbTEbMBkG 
# A1UEChQSQUJOIEFNUk8gQmFuayBOLlYuMRYwFAYDVQQLFA1JTi9OUy9FLUlORlJB 
# MTMwMQYDVQQLFCpUZXJtcyBvZiB1c2UgYXQgd3d3LnZlcmlzaWduLmNvbS9ycGEg 
# KGMpMDAxFzAVBgNVBAMUDnd3dy5hYm5hbXJvLm5sMIGfMA0GCSqGSIb3DQEBAQUA 
# A4GNADCBiQKBgQD1hPZlFD01ZdQu0GVLkUQ7tOwtVw/jmZ1Axu8v+3bxrjKX9Qi1 
# 0w6EIadCXScDMmhCstExVptaTEQ5hG3DedV2IpMcwe93B1lfyviNYlmc/XIol1B7 
# PM70mI9XUTYAoJpquEv8AaupRO+hgxQlz3FACHINJxEIMgdxa1iyoJfCKwIDAQAB 
# o4IBZDCCAWAwCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAwPAYDVR0fBDUwMzAxoC+g 
# LYYraHR0cDovL2NybC52ZXJpc2lnbi5jb20vUlNBU2VjdXJlU2VydmVyLmNybDBE 
# BgNVHSAEPTA7MDkGC2CGSAGG+EUBBxcDMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8v 
# d3d3LnZlcmlzaWduLmNvbS9ycGEwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF 
# BwMCMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AudmVy 
# aXNpZ24uY29tMG0GCCsGAQUFBwEMBGEwX6FdoFswWTBXMFUWCWltYWdlL2dpZjAh 
# MB8wBwYFKw4DAhoEFI/l0xqGrI2Oa8PPgGrUSBgsexkuMCUWI2h0dHA6Ly9sb2dv 
# LnZlcmlzaWduLmNvbS92c2xvZ28uZ2lmMA0GCSqGSIb3DQEBBQUAA34AY7BYsNvj 
# i5fjnEHPlGOd2yxseCHU54HDPPCZOoP9a9kVWGX8tuj2b1oeiOsIbI1viIo+O4eQ 
# ilZjTJIlLOkXk6uE8vQGjZy0BUnjNPkXOQGkTyj4jDxZ2z+z9Vy8BwfothdcYbZK 
# 48ZOp3u74DdEfQejNxBeqLODzrxQTV4= 
# -----END CERTIFICATE-----
#      CERTIFICATE
#   end  
#       
#   def successful_transaction_response
#     <<-RESPONSE  
# <?xml version='1.0' encoding='UTF-8'?>
# <AcquirerTrxRes version='1.1.0' xmlns='http://www.idealdesk.com/Message'>
#     <createDateTimeStamp>2007-07-02T10:03:18.000Z</createDateTimeStamp>
#     <Acquirer>
#       <acquirerID>0050</acquirerID>
#     </Acquirer>
#     <Issuer>
#       <issuerAuthenticationURL>https://issuer.url/action?trxid=0050000002797923</issuerAuthenticationURL>
#     </Issuer>
#     <Transaction>
#       <transactionID>0050000002797923</transactionID>
#       <purchaseID>9459897270157938</purchaseID>
#     </Transaction>
# </AcquirerTrxRes>
#     RESPONSE
#   end
# 
#   def failed_transaction_response
#     <<-RESPONSE 
# <?xml version='1.0' encoding='UTF-8'?>
#   <ErrorRes version='1.1.0' xmlns='http://www.idealdesk.com/Message'>
#   <createDateTimeStamp>2007-07-02T10:03:18.000Z</createDateTimeStamp>
#     <Error>
#       <errorCode>BR1210</errorCode>
#       <errorMessage>Value contains non-permitted character</errorMessage>
#       <errorDetail>Field generating error: Parameter &apos;25.99&apos; is not a natural(or &apos;-&apos;) format</errorDetail>
#       <consumerMessage>Betalen met iDEAL is nu niet mogelijk. Probeer het later nogmaals of betaal op een andere manier.</consumerMessage>
#     </Error>
# </ErrorRes>   
#     RESPONSE
#   end
# 
#   def successful_status_response
#     <<-RESPONSE
# ?xml version='1.0' encoding='UTF-8'?>
# <AcquirerStatusRes version='1.1.0' xmlns='http://www.idealdesk.com/Message'>
#   <createDateTimeStamp>2007-07-02T10:03:18.000Z</createDateTimeStamp>
# <Acquirer>
#   <acquirerID>0050</acquirerID>
# </Acquirer>
# <Transaction>
#   <transactionID>0050000002807474</transactionID>
#   <status>Success</status>
#   <consumerName>C M Bröcker-Meijer en M Bröcker</consumerName>
#   <consumerAccountNumber>P001234567</consumerAccountNumber>
#   <consumerCity>DEN HAAG</consumerCity>
# </Transaction>
# <Signature>
#   <signatureValue>LONGSTRING</signatureValue>
#   <fingerprint>FINGERPRINT</fingerprint>
# </Signature>
# </AcquirerStatusRes>
#     RESPONSE
#   end
# 
#   def successful_status_response_with_missing_fields
#     <<-RESPONSE
# ?xml version='1.0' encoding='UTF-8'?>
# <AcquirerStatusRes version='1.1.0' xmlns='http://www.idealdesk.com/Message'>
#   <createDateTimeStamp>2007-07-02T10:03:18.000Z</createDateTimeStamp>
# <Acquirer>
#   <acquirerID>0050</acquirerID>
# </Acquirer>
# <Transaction>
#   <transactionID>0050000002807474</transactionID>
#   <status>Success</status>
# </Transaction>
# <Signature>
#   <signatureValue>LONGSTRING</signatureValue>
#   <fingerprint>FINGERPRINT</fingerprint>
# </Signature>
# </AcquirerStatusRes>
#     RESPONSE
#   end
# 
#   def cancelled_status_response
#     <<-RESPONSE
# <?xml version='1.0' encoding='UTF-8'?>
# <AcquirerStatusRes version='1.1.0' xmlns='http://www.idealdesk.com/Message'>
#   <createDateTimeStamp>2007-07-02T10:03:18.000Z</createDateTimeStamp>
# <Acquirer>
#   <acquirerID>0050</acquirerID>
# </Acquirer>
# <Transaction>
#   <transactionID>0050000002807474</transactionID>
#   <status>Cancelled</status>
# </Transaction>
# <Signature>
#   <signatureValue>LONGSTRING</signatureValue>
#   <fingerprint>FINGERPRINT</fingerprint>
# </Signature>
# </AcquirerStatusRes>
#     RESPONSE
#   end
# 
#   def directory_request_response
#     <<-RESPONSE  
# <?xml version='1.0' encoding='UTF-8'?>
# <DirectoryRes version='1.1.0' xmlns='http://www.idealdesk.com/Message'>
# <createDateTimeStamp>2007-07-02T10:03:18.000Z</createDateTimeStamp> 
# <Acquirer>
#   <acquirerID>0050</acquirerID>
# </Acquirer>
# <Directory>
#   <directoryDateTimeStamp>2007-07-02T10:03:18.000Z</directoryDateTimeStamp>
#   <Issuer>
#     <issuerID>0031</issuerID>
#     <issuerName>ABN Amro Bank</issuerName>
#     <issuerList>Short</issuerList>
#   </Issuer>
#   <Issuer>
#     <issuerID>0721</issuerID>
#     <issuerName>Postbank</issuerName>
#     <issuerList>Short</issuerList>
#   </Issuer>
#   <Issuer>
#     <issuerID>0021</issuerID>
#     <issuerName>Rabobank</issuerName>
#     <issuerList>Short</issuerList>
#   </Issuer>
#   <Issuer>
#     <issuerID>0751</issuerID>
#     <issuerName>SNS Bank</issuerName>
#     <issuerList>Short</issuerList>
#   </Issuer>
# </Directory>
# </DirectoryRes>  
#    RESPONSE
#   end
# 
#   def directory_request_response_one_issuer
#       <<-RESPONSE  
# <?xml version='1.0' encoding='UTF-8'?>
# <DirectoryRes version='1.1.0' xmlns='http://www.idealdesk.com/Message'>
# <createDateTimeStamp>2007-07-02T10:03:18.000Z</createDateTimeStamp> 
# <Acquirer>
#   <acquirerID>0050</acquirerID>
# </Acquirer>
# <Directory>
#   <directoryDateTimeStamp>2007-07-02T10:03:18.000Z</directoryDateTimeStamp>
#   <Issuer>
#     <issuerID>0031</issuerID>
#     <issuerName>ABN Amro Bank</issuerName>
#     <issuerList>Short</issuerList>
#   </Issuer>
# </Directory>
# </DirectoryRes>  
#      RESPONSE
#   end
#     
# end
# 
