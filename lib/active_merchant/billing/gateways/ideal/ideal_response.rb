require 'openssl'
require 'base64'

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class IdealResponse < Response
      def initialize(response_body)
        @params = Hash.from_xml(response_body)
        @success = !error_occured?
      end

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

    # See section 4.3.2 for which data a user should see.
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

    class IdealStatusResponse < IdealResponse
      def initialize(response_body)
        super
        @success = transaction_successful?
      end

      private

      def transaction_successful?
        return false if error_occured?
        @params['AcquirerStatusRes']['Transaction']['status'] == 'Success'
      end
      
      
      # TODO:
      #
      #       def verify_message(cert_file, data, signature)
      #         pub_key = OpenSSL::X509::Certificate.new(File.read(cert_file)).public_key
      #         return pub_key.verify(OpenSSL::Digest::SHA1.new, Base64.decode64(signature), data)
      #       end
      #       
      #       def status_response_verified?(response)
      #         transaction = response['AcquirerStatusRes']['Transaction']
      #         message = response['AcquirerStatusRes']["createDateTimeStamp" ] + transaction["transactionID" ] + transaction["status"] 
      #         message = message + transaction['consumerAccountNumber'] unless transaction['consumerAccountNumber'].nil?
      #         verify_message(@options[:ideal_cert],message,response['AcquirerStatusRes']["Signature"]["signatureValue"])
      #       end
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