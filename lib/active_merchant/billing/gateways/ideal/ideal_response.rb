module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class IdealResponse < Response
      def initialize(response_body)
        @params = Hash.from_xml(response_body)

        case @params.keys.first
        when 'ErrorRes'
          @success = false
        end

        @success = true if @success.nil?
      end
      
      # def service_url
      #   @params.values[0]['Issuer']['issuerAuthenticationURL']
      # end
      # 
      # def transaction
      #   @params.values[0]['Transaction']
      # end
      # 
      # def error
      #   @params.values[0]['Error']
      # end
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