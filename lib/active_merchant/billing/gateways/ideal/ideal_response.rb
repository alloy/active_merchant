module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class IdealResponse < Response
      def initialize(response_body)
        @params = Hash.from_xml(response_body)
        @success = @params.keys.first != 'ErrorRes'
      end

      def error_message
        unless success?
          error = @params['ErrorRes']['Error']
          { :system => error['errorMessage'], :human => error['consumerMessage'] }
        end
      end
    end

    class IdealTransactionResponse < IdealResponse
      def service_url
        @params['AcquirerTrxRes']['Issuer']['issuerAuthenticationURL']
      end

      def transaction_id
        transaction['transactionID']
      end

      def purchase_id
        transaction['purchaseID']
      end

      private

      def transaction
        @params['AcquirerTrxRes']['Transaction']
      end
    end

    class IdealDirectoryResponse < IdealResponse
      def list
        @params['DirectoryRes']['Directory']['Issuer'].map do |issuer|
          { :id => issuer['issuerID'], :name => issuer['issuerName'] }
        end
      end
    end
  end
end