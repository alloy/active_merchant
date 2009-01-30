require 'openssl'
require 'base64'

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    # The base class for all iDEAL response classes.
    class IdealResponse < Response
      def initialize(response_body)
        @params = Hash.from_xml(response_body)
        @success = !error_occured?
      end

      # Returns a hash containging the :system error message which is the
      # technical version, whereas the :human error message is a human readable
      # version of the error message. At least that's what the documentation
      # says, however, sources tell me it really isn't that readable, so it
      # might be preferable to provide your own.
      def error_message
        unless success?
          error = @params['ErrorRes']['Error']
          { :system => error['errorMessage'], :human => error['consumerMessage'] }
        end
      end

      private

      def error_occured?
        @params.keys.first == 'ErrorRes'
      end
    end

    # An instance of IdealTransactionResponse is returned from
    # IdealGateway#setup_purchase which returns the service_url to where the
    # user should be redirected to perform the transaction _and_ the
    # transaction & purchase IDs.
    #
    # See section 4.3.2 for which data a user should see.
    class IdealTransactionResponse < IdealResponse
      # Returns the url to where the user should be redirected to perform the
      # transaction.
      def service_url
        @params['AcquirerTrxRes']['Issuer']['issuerAuthenticationURL']
      end

      # Returns the transaction ID which is needed for requesting the status
      # of a transaction.
      def transaction_id
        transaction['transactionID']
      end

      # Returns the purchase ID for this transaction.
      def purchase_id
        transaction['purchaseID']
      end

      private

      def transaction
        @params['AcquirerTrxRes']['Transaction']
      end
    end

    # An instance of IdealStatusResponse is returned from IdealGateway#capture
    # which returns whether or not the transaction that was started with
    # IdealGateway#setup_purchase was successful.
    class IdealStatusResponse < IdealResponse
      def initialize(response_body)
        super
        @success = transaction_successful?
      end

      private

      def transaction_successful?
        return false if error_occured?
        status == 'Success' && response_verified?
      end

      def transaction
        @params['AcquirerStatusRes']['Transaction']
      end

      def status
        transaction['status']
      end

      def message
        message = @params['AcquirerStatusRes']['createDateTimeStamp'] + transaction['transactionID'] + status
        message += transaction['consumerAccountNumber'] if transaction['consumerAccountNumber']
        message
      end

      def signature
        Base64.decode64(@params['AcquirerStatusRes']['Signature']['signatureValue'])
      end

      # Verifies that the signature matches the IdealGateway.ideal_certificate.
      def response_verified?
        IdealGateway.ideal_certificate.public_key.verify(OpenSSL::Digest::SHA1.new, signature, message)
      end
    end

    # An instance of IdealDirectoryResponse is returned from
    # IdealGateway#issuers which returns the list of issuers available at the
    # acquirer.
    class IdealDirectoryResponse < IdealResponse
      # Returns a list of issuers available at the acquirer.
      #
      #   gateway.issuers.list # => [{ :id => '1006', :name => 'ABN AMRO Bank' }]
      def list
        @params['DirectoryRes']['Directory']['Issuer'].map do |issuer|
          { :id => issuer['issuerID'], :name => issuer['issuerName'] }
        end
      end
    end
  end
end