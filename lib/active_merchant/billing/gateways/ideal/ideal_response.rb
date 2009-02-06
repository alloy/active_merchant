require 'openssl'
require 'base64'

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    # The base class for all iDEAL response classes.
    #
    # Note that if the iDEAL system is under load it will _not_ allow more
    # then two retries per request.
    class IdealResponse < Response
      def initialize(response_body, options = {})
        @params = Hash.from_xml(response_body)
        @success = !error_occured?
        @test = options[:test]
      end

      # Returns a hash containing the <tt>:system</tt> error message which is
      # the technical version, whereas the <tt>:human</tt> error message is a
      # human readable version of the error message.
      def error_message
        unless success?
          error = @params['error_res']['error']
          { :system => error['error_message'], :human => error['consumer_message'] }
        end
      end

      # Returns an error type inflected from the first two characters of the
      # error code. See error_code for a full list of errors.
      #
      # Error code to type mappings:
      #
      # * +IX+ - <tt>:xml</tt>
      # * +SO+ - <tt>:system</tt>
      # * +SE+ - <tt>:security</tt>
      # * +BR+ - <tt>:value</tt>
      # * +AP+ - <tt>:application</tt>
      def error_type
        unless success?
          case error_code[0,2]
          when 'IX' then :xml
          when 'SO' then :system
          when 'SE' then :security
          when 'BR' then :value
          when 'AP' then :application
          end
        end
      end

      # Returns the code of the error that occured.
      #
      # === Codes
      #
      # ==== IX: Invalid XML and all related problems
      #
      # Such as incorrect encoding, invalid version, or otherwise unreadable:
      #
      # * <tt>IX1000</tt> - Received XML not well-formed.
      # * <tt>IX1100</tt> - Received XML not valid.
      # * <tt>IX1200</tt> - Encoding type not UTF-8.
      # * <tt>IX1300</tt> - XML version number invalid.
      # * <tt>IX1400</tt> - Unknown message.
      # * <tt>IX1500</tt> - Mandatory main value missing. (Merchant ID ?)
      # * <tt>IX1600</tt> - Mandatory value missing.
      #
      # ==== SO: System maintenance or failure
      #
      # The errors that are communicated in the event of system maintenance or
      # system failure. Also covers the situation where new requests are no
      # longer being accepted but requests already submitted will be dealt with
      # (until a certain time):
      #
      # * <tt>SO1000</tt> - Failure in system.
      # * <tt>SO1200</tt> - System busy. Try again later.
      # * <tt>SO1400</tt> - Unavailable due to maintenance.
      #
      # ==== SE: Security and authentication errors
      #
      # Incorrect authentication methods and expired certificates:
      #
      # * <tt>SE2000</tt> - Authentication error.
      # * <tt>SE2100</tt> - Authentication method not supported.
      # * <tt>SE2700</tt> - Invalid electronic signature.
      #
      # ==== BR: Field errors
      #
      # Extra information on incorrect fields:
      #
      # * <tt>BR1200</tt> - iDEAL version number invalid.
      # * <tt>BR1210</tt> - Value contains non-permitted character.
      # * <tt>BR1220</tt> - Value too long.
      # * <tt>BR1230</tt> - Value too short.
      # * <tt>BR1240</tt> - Value too high.
      # * <tt>BR1250</tt> - Value too low.
      # * <tt>BR1250</tt> - Unknown entry in list.
      # * <tt>BR1270</tt> - Invalid date/time.
      # * <tt>BR1280</tt> - Invalid URL.
      #
      # ==== AP: Application errors
      #
      # Errors relating to IDs, account numbers, time zones, transactions:
      #
      # * <tt>AP1000</tt> - Acquirer ID unknown.
      # * <tt>AP1100</tt> - Merchant ID unknown.
      # * <tt>AP1200</tt> - Issuer ID unknown.
      # * <tt>AP1300</tt> - Sub ID unknown.
      # * <tt>AP1500</tt> - Merchant ID not active.
      # * <tt>AP2600</tt> - Transaction does not exist.
      # * <tt>AP2620</tt> - Transaction already submitted.
      # * <tt>AP2700</tt> - Bank account number not 11-proof.
      # * <tt>AP2900</tt> - Selected currency not supported.
      # * <tt>AP2910</tt> - Maximum amount exceeded. (Detailed record states the maximum amount).
      # * <tt>AP2915</tt> - Amount too low. (Detailed record states the minimum amount).
      # * <tt>AP2920</tt> - Please adjust expiration period. See suggested expiration period.
      def error_code
        @params['error_res']['error']['error_code'] unless success?
      end

      private

      def error_occured?
        @params.keys.first == 'error_res'
      end
    end

    # An instance of IdealTransactionResponse is returned from
    # IdealGateway#setup_purchase which returns the service_url to where the
    # user should be redirected to perform the transaction _and_ the
    # transaction ID.
    class IdealTransactionResponse < IdealResponse
      # Returns the URL to the issuer’s page where the consumer should be
      # redirected to in order to perform the payment.
      def service_url
        @params['acquirer_trx_res']['issuer']['issuer_authentication_url']
      end

      # Returns the transaction ID which is needed for requesting the status
      # of a transaction. See IdealGateway#capture.
      def transaction_id
        transaction['transaction_id']
      end

      # Returns the <tt>:order_id</tt> for this transaction.
      def order_id
        transaction['purchase_id']
      end

      private

      def transaction
        @params['acquirer_trx_res']['transaction']
      end
    end

    # An instance of IdealStatusResponse is returned from IdealGateway#capture
    # which returns whether or not the transaction that was started with
    # IdealGateway#setup_purchase was successful.
    #
    # It takes care of checking if the message was authentic by verifying the
    # the message and its signature against the iDEAL certificate.
    class IdealStatusResponse < IdealResponse
      def initialize(response_body, options = {})
        super
        @success = transaction_successful?
      end

      # Returns the status message, which is one of: <tt>:success</tt>,
      # <tt>:cancelled</tt>, <tt>:expired</tt>, <tt>:open</tt>, or
      # <tt>:failure</tt>.
      def status
        transaction['status'].downcase.to_sym
      end

      # Returns whether or not the authenticity of the message could be
      # verified.
      def verified?
        @verified ||= IdealGateway.ideal_certificate.public_key.
                        verify(OpenSSL::Digest::SHA1.new, signature, message)
      end

      private

      # Checks if no errors occured _and_ if the message was authentic.
      def transaction_successful?
        !error_occured? && status == :success && verified?
      end

      def transaction
        @params['acquirer_status_res']['transaction']
      end

      def message
        message = @params['acquirer_status_res']['create_date_time_stamp'] + transaction['transaction_id'] + transaction['status']
        message += transaction['consumer_account_number'] #if transaction['consumer_account_number']
        message
      end

      def signature
        Base64.decode64(@params['acquirer_status_res']['signature']['signature_value'])
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
        issuers = @params['directory_res']['directory']['issuer']
        issuers = [issuers] unless issuers.is_a?(Array)

        issuers.map do |issuer|
          { :id => issuer['issuer_id'], :name => issuer['issuer_name'] }
        end
      end
    end
  end
end