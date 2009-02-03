require File.dirname(__FILE__) + '/../../test_helper'

# Creation of the necessary certificate (OSX):
#
#   $ /usr/bin/openssl genrsa -des3 -out private_key.pem -passout pass:the_passphrase 1024
#   $ /usr/bin/openssl req -x509 -new -key private_key.pem -passin pass:the_passphrase -days 3650 -out private_certificate.cer

KEY_ROOT = File.expand_path('../../../../REMOTE_TEST_KEYS', __FILE__)

class IdealTest < Test::Unit::TestCase
  class ActiveMerchant::Billing::IdealGateway
    self.merchant_id = '005043502'

    self.passphrase = 'the_passphrase'
    self.private_key_file = File.join(KEY_ROOT, 'private_key.pem')
    self.private_certificate_file = File.join(KEY_ROOT, 'private_certificate.cer')
    self.ideal_certificate_file = File.join(KEY_ROOT, 'iDEAL.cer')

    self.test_url = "https://idealtest.secure-ing.com:443/ideal/iDeal"
    self.live_url = nil
  end
  
  # DEFAULT_IDEAL_OPTIONS = {
  #   :merchant => "123456789",
  #   :private_key => File.dirname(__FILE__) + "/../../../../../config/ideal/merchantprivatekey.pem",
  #   :private_cert => File.dirname(__FILE__) + "/../../../../../config/ideal/merchantprivatecert.cer",
  #   :ideal_cert => File.dirname(__FILE__) + "/../../../../../config/ideal/ideal.cer",
  #   :password => "passsword",
  #   :expiration_period => "PT10M"
  # }
  
  def setup
    Base.gateway_mode = :test

    @gateway = Base.gateway(:ideal).new

    # @options = {
    #   :issuer_id=>'0151', 
    #   :expiration_period=>'PT10M', 
    #   :return_url =>'http://www.return.url', 
    #   :order_id=>'1234567890123456', 
    #   :currency=>'EUR', 
    #   :description => 'A description', 
    #   :entrance_code => '1234'
    # }
  end
  
  def test_issuers
    response = @gateway.issuers
    list = response.list
  
    assert_equal 1, list.length
    assert_equal "Issuer Simulator", list[0][ "issuerName" ]
    assert_equal "0151", list[0]["issuerID"]
    assert_equal "Short", list[0]["issuerList"]
  end

  # def test_set_purchase
  #   response = @gateway.setup_purchase(550, @options)
  #   assert response.success?
  #   assert response.test?
  #   assert_nil response.error, "Response should not have an error"
  # end  
  # 
  # def test_return_errors    
  #   response = @gateway.setup_purchase(0.5, @options)
  #   assert !response.success?, "Should fail"
  #   assert_equal "BR1210", response.error[ 'errorCode']
  #   assert_not_nil response.error[ 'errorMessage'],  "Response should contain an Error message"
  #   assert_not_nil response.error[ 'errorDetail'],   "Response should contain an Error Detail message" 
  #   assert_not_nil response.error['consumerMessage'],"Response should contain an Consumer Error message"    
  # end
  # 
  # # default payment should succeed
  # def test_purchase_successful
  #   # first setup the payment
  #   response = @gateway.setup_purchase(2599, @options)
  #   
  #   assert response.success?, "Setup should succeed."
  # 
  #   assert_equal "1234567890123456", response.transaction['purchaseID']
  #   assert_equal "0050", response.params['AcquirerTrxRes']['Acquirer'][ 'acquirerID']    
  #   assert_not_nil response.service_url, "Response should contain a service url for payment"
  #       
  #   # now authorize the payment, issuer simulator has completed the payment 
  #   response = @gateway.capture(:transaction_id => response.transaction['transactionID'])
  # 
  #   assert response.success?, 'Transaction should succeed'
  #   assert_equal "Success", response.transaction['status']
  #   assert_equal "DEN HAAG", response.transaction['consumerCity']
  #   assert_equal "C M Bröcker-Meijer en M Bröcker", response.transaction['consumerName'] 
  # end
  # 
  # # payment of 200 should cancel
  # def test_purchase_cancel
  #   # first setup the payment
  #   response = @gateway.setup_purchase(200, @options)
  #   
  #   assert response.success?, "Setup should succeed."    
  #   # now try to authorize the payment, issuer simulator has cancelled the payment 
  #   response = @gateway.capture(:transaction_id => response.transaction['transactionID'])
  # 
  #   assert !response.success?, 'Transaction should cancel'
  #   assert_equal "Cancelled", response.transaction['status'], 'Transaction should cancel'
  # end
  # 
  # # payment of 300 should expire  
  # def test_transaction_expired       
  #   # first setup the payment
  #   response = @gateway.setup_purchase(300, @options)
  # 
  #   # now try to authorize the payment, issuer simulator let the payment expire
  #   response = @gateway.capture(:transaction_id => response.transaction['transactionID'])
  #   
  #   assert !response.success?, 'Transaction should expire'
  #   assert_equal "Expired", response.transaction['status'], 'Transaction should expire'    
  # end
  # 
  # # payment of 400 should remain open
  # def test_transaction_expired       
  #   # first setup the payment
  #   response = @gateway.setup_purchase(400, @options)
  # 
  #   # now try to authorize the payment, issuer simulator keeps the payment open
  #   response = @gateway.capture(:transaction_id => response.transaction['transactionID'])
  #   
  #   assert !response.success?, 'Transaction should remain open'
  #   assert_equal "Open", response.transaction['status'], 'Transaction should remain open'    
  # end
  # 
  # # payment of 500 should fail at issuer
  # def test_transaction_expired       
  #   # first setup the payment
  #   response = @gateway.setup_purchase(500, @options)
  # 
  #   # now try to authorize the payment, issuer simulator lets the payment fail
  #   response = @gateway.capture(:transaction_id => response.transaction['transactionID'])
  #   assert !response.success?, 'Transaction should fail'
  #   assert_equal "Failure", response.transaction['status'], 'Transaction should fail'
  # end
  # 
  # # payment of 700 should be unknown at issuer
  # def test_transaction_expired       
  #   # first setup the payment
  #   response = @gateway.setup_purchase(700, @options)
  # 
  #   # now try to authorize the payment, issuer simulator lets the payment fail
  #   response = @gateway.capture(:transaction_id => response.transaction['transactionID'])
  # 
  #   assert !response.success?, 'Transaction should fail'
  #   assert_equal "SO1000", response.error[ 'errorCode'], 'ErrorCode should be correct'
  # end
  
  
end 