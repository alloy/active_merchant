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

  def setup
    Base.gateway_mode = :test
    @gateway = Base.gateway(:ideal).new

    @valid_options = {
      :issuer_id         => '0151',
      :expiration_period => 'PT10M',
      :return_url        => 'http://return_to.example.com',
      :order_id          => '123456789012',
      :currency          => 'EUR',
      :description       => 'A classic Dutch windmill',
      :entrance_code     => '1234'
    }
  end

  def test_making_test_requests
    assert @gateway.issuers.test?
  end

  def test_setup_purchase_with_valid_options
    response = @gateway.setup_purchase(550, @valid_options)

    assert_success response
    assert_not_nil response.service_url
    assert_not_nil response.transaction_id
    assert_equal @valid_options[:order_id], response.purchase_id
  end

  def test_setup_purchase_with_invalid_amount
    response = @gateway.setup_purchase(0.5, @valid_options)

    assert_failure response
    assert_equal "BR1210", response.error_code
    assert_not_nil response.error_message[:system]
    assert_not_nil response.error_message[:human]
  end

  ###
  #
  # These are the 7 integration tests of ING which need to be ran sucessfuly
  # _before_ you'll get access to the live environment.
  #
  # See test_transaction_id for info on how the remote tests are ran.
  #

  def test_retrieval_of_issuers
    assert_equal [{ :id => '0151', :name => 'Issuer Simulator' }], @gateway.issuers.list
  end

  def test_successful_transaction
    assert_success capture_transaction(:success)
  end

  def test_cancelled_transaction
    captured_response = capture_transaction(:cancelled)

    assert_failure captured_response
    assert_equal 'Cancelled', captured_response.status
  end

  def test_expired_transaction
    captured_response = capture_transaction(:expired)

    assert_failure captured_response
    assert_equal 'Expired', captured_response.status
  end

  def test_still_open_transaction
    captured_response = capture_transaction(:open)

    assert_failure captured_response
    assert_equal 'Open', captured_response.status
  end

  def test_failed_transaction
    captured_response = capture_transaction(:failure)

    assert_failure captured_response
    assert_equal 'Failure', captured_response.status
  end

  def test_internal_server_error
    captured_response = capture_transaction(:server_error)

    assert_failure captured_response
    assert_equal 'SO1000', captured_response.error_code
  end

  private

  # Shortcut method which does a #setup_purchase through #test_transaction and
  # captures the resulting transaction and returns the capture response.
  def capture_transaction(type)
    @gateway.capture test_transaction(type).transaction_id
  end

  # Calls #setup_purchase with the amount corresponding to the named test and
  # returns the response. Before returning an assertion will be ran to test
  # whether or not the transaction was successful.
  def test_transaction(type)
    amount = case type
    when :success      then 100
    when :cancelled    then 200
    when :expired      then 300
    when :open         then 400
    when :failure      then 500
    when :server_error then 700
    end

    response = @gateway.setup_purchase(amount, @valid_options)
    assert response.success?
    response
  end
end 