require File.dirname(__FILE__) + '/ideal/ideal_response'

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class IdealGateway < Gateway
      AUTHENTICATION_TYPE = 'SHA1_RSA'
      LANGUAGE = 'nl'
      API_VERSION = '1.1.0'
      XML_NAMESPACE = 'http://www.idealdesk.com/Message'

      OPTIONS = [:password, :ideal_certificate, :private_certificate, :private_key, :merchant, :sub_id]
      OPTIONS.each { |option| attr_reader option }

      def initialize(options = {})
        options = { :sub_id => 0 }.merge(options)
        requires!(options, *OPTIONS)
        OPTIONS.each { |option_name| instance_variable_set("@#{option_name}", options[option_name]) }
        super
      end

      def build_transaction_request_body(money, options)
        requires!(options, :issuer_id, :expiration_period, :return_url, :order_id, :currency, :description, :entrance_code)

        xml_for(:acquirer_transaction_request, {
          :created_at => 'created_at_timestamp',
          :issuer => { :issuer_id => '0001' },

          :merchant => {
            :merchant_id =>         @merchant,
            :sub_id =>              @sub_id,
            :authentication =>      AUTHENTICATION_TYPE,
            :token =>               token,
            :token_code =>          token_code,
            :merchant_return_url => options[:return_url]
          },

          :transaction => {
            :purchase_id =>         options[:order_id],
            :amount =>              money,
            :currency =>            options[:currency],
            :expiration_period =>   options[:expiration_period],
            :language =>            LANGUAGE,
            :description =>         options[:description],
            :entrance_code =>       options[:entrance_code]
          }
        })
      end
      
      private

      # Returns a string containing the current UTC time, formatted as per the
      # iDeal specifications, except we don't use miliseconds.
      def created_at_timestamp
        Time.now.gmtime.strftime("%Y-%m-%dT%H:%M:%S.000Z")
      end

      # iDeal doesn't really seem to care about nice looking keys in their XML.
      # And since there doesn't seem to be any method in this madness, I could
      # not come up with a better name than uglify_key…
      def uglify_key(key)
        key = key.to_s
        case key
        when 'acquirer_transaction_request'
          'AcquirerTrxReq'
        when 'issuer', 'merchant', 'transaction'
          key.capitalize
        when 'created_at'
          'createDateTimeStamp'
        when 'merchant_return_url'
          'merchantReturnURL'
        when 'token_code', 'expiration_period', 'entrance_code'
          key[0,1] + key.camelize[1..-1]
        when /^(\w+)_id$/
          "#{$1}ID"
        else
          key
        end
      end

      def xml_for(name, tags_and_values)
        xml = Builder::XmlMarkup.new
        xml.instruct!
        xml.tag!(uglify_key(name), 'xmlns' => XML_NAMESPACE, 'version' => API_VERSION) do
          xml_from_hash(xml, tags_and_values)
        end
        xml.target!
      end

      def xml_from_hash(builder, tags_and_values)
        tags_and_values.each do |tag, value|
          tag = uglify_key(tag)

          if value.is_a?(Hash)
            builder.tag!(tag) do
              xml_from_hash(builder, value)
            end
          else
            builder.tag!(tag, value)
          end
        end
      end
    end
  end
end

# module ActiveMerchant #:nodoc:
#   module Billing #:nodoc:
#     # First, make sure you have everything setup correctly and all of your dependencies in place with:
#     # 
#     #   require 'rubygems'
#     #   require 'active_merchant'
#     #
#     # ActiveMerchant expects the amounts to be given as an Integer in cents. In this case, 10 EUR becomes 1000.
#     #
#     # Configure the gateway using your Ideal account info and security settings:
#     #
#     # ActiveMerchant::Billing::IdealGateway.test_url = "https://idealtest.secure-ing.com:443/ideal/iDeal"
#     # ActiveMerchant::Billing::IdealGateway.live_url = "https://ideal.secure-ing.com:443/ideal/iDeal"    
#     # 
#     # DEFAULT_IDEAL_OPTIONS = {
#     #   :merchant => "123456789",
#     #   :private_key => File.dirname(__FILE__) + "/../ideal/merchantprivatekey.pem",
#     #   :private_cert => File.dirname(__FILE__) + "/../ideal/merchantprivatecert.cer",
#     #   :ideal_cert => File.dirname(__FILE__) + "/../ideal/ideal.cer",
#     #   :password => "password"
#     # }
#     #
#     # Create gateway:
#     # gateway = ActiveMerchant::Billing::Base.gateway(:ideal).new DEFAULT_IDEAL_OPTIONS 
#     #
#     #
#     # Get list of issuers to fill selection list on your payment form:
#     # response = gateway.issuers
#     # list = response.issuer_list
#     #
#     # Request transaction:
#     #
#     # options = {
#     #    :issuer_id=>'0001', 
#     #    :expiration_period=>'PT10M', 
#     #    :return_url =>'http://www.return.url', 
#     #    :order_id=>'1234567890123456', 
#     #    :currency=>'EUR', 
#     #    :description => 'Een omschrijving', 
#     #    :entrance_code => '1234'
#     # }    
#     #
#     # response = gateway.setup_purchase(amount, options)
#     # transaction_id = response.transaction['transactionID']
#     # redirect_url = response.service_url
#     #   
#     # Mandatory status request will confirm transaction:
#     # response = gateway.capture(:transaction_id => transaction_id)
#     #
#     # Implementation contains some simplifications
#     # - does not support multiple subID per merchant
#     # - language is fixed to 'nl'
#     class IdealGateway < Gateway
#       require 'openssl'
#       require 'net/https'
#       require 'base64'
#       require 'digest/sha1'
# 
#       class_inheritable_accessor :test_url, :live_url
# 
      # # These constants will never change for most users
      # AUTHENTICATION_TYPE = 'SHA1_RSA'
      # LANGUAGE = 'nl'
      # SUB_ID = '0'
      # API_VERSION = '1.1.0'
# 
#       def initialize(options = {})
#         requires!(options, :password, :ideal_cert, :private_cert, :private_key, :merchant)
#         @options = options
#         super
#       end
# 
#       def token
#         if @token.nil?
#           @token = create_fingerprint(File.read(@options[:private_cert])) 
#         end
#         @token
#       end
# 
#       # Setup transaction. Get redirect_url from response.service_url
#       def setup_purchase(money, options = {})
#         requires!(options, :issuer_id, :expiration_period, :return_url, :order_id, :currency, :description, :entrance_code)
#         commit(build_transaction_request(money, options))
#       end
# 
#       # Check status of transaction and confirm payment
#       # transaction_id must be a valid transaction_id from a prior setup.
#       def capture(options = {})
#         requires!(options, :transaction_id)
#         commit(build_status_request(options))
#       end
# 
#       # Get list of issuers from response.issuer_list
#       def issuers
#         commit(build_directory_request)
#       end
# 
#       def acquirer_url
#         test? ? IdealGateway.test_url : IdealGateway.live_url
#       end
# 
#       # <?xml version="1.0" encoding="UTF-8"?>
#       # <AcquirerTrxReq xmlns="http://www.idealdesk.com/Message" version="1.1.0">
#       #  <createDateTimeStamp>2001-12-17T09:30:47.0Z</createDateTimeStamp>
#       #  <Issuer>
#       #   <issuerID>1003</issuerID>
#       #  </Issuer>
#       #   <Merchant> 
#       #     <merchantID>000123456</merchantID> 
#       #     <subID>0</subID> 
#       #     <authentication>passkey</authentication> 
#       #     <token>1</token> 
#       #     <tokenCode>3823ad872eff23</tokenCode> 
#       #     <merchantReturnURL>https://www.mijnwinkel.nl/betaalafhandeling
#       #      </merchantReturnURL> 
#       #   </Merchant> 
#       #   <Transaction> 
#       #     <purchaseID>iDEAL-aankoop 21</purchaseID> 
#       #     <amount>5999</amount> 
#       #     <currency>EUR</currency> 
#       #     <expirationPeriod>PT3M30S</expirationPeriod> 
#       #     <language>nl</language>                  
#       #     <description>Documentensuite</description> 
#       #     <entranceCode>D67tyx6rw9IhY71</entranceCode> 
#       #   </Transaction> 
#       # </AcquirerTrxReq>          
#       def build_transaction_request(money, options)
#         requires!(options, :issuer_id, :expiration_period, :return_url, :order_id, :currency, :description, :entrance_code)
#         
#         date_time_stamp = create_time_stamp
#         message  = date_time_stamp +
#                    options[:issuer_id] +
#                    @options[:merchant] +
#                    SUB_ID +
#                    options[:return_url] +
#                    options[:order_id] +
#                    money.to_s +
#                    options[:currency] +
#                    LANGUAGE +
#                    options[:description] +
#                    options[:entrance_code]
#         token_code = sign_message(@options[:private_key], @options[:password], message)
#         
#         xml = Builder::XmlMarkup.new :indent => 2
#         xml.instruct!
#         xml.tag! 'AcquirerTrxReq', 'xmlns' => "http://www.idealdesk.com/Message", 'version' => API_VERSION do
#           xml.tag! 'createDateTimeStamp', date_time_stamp
#           xml.tag! 'Issuer' do
#             xml.tag! 'issuerID', options[:issuer_id]
#           end
#           xml.tag! 'Merchant' do
#             xml.tag! 'merchantID', @options[:merchant]
#             xml.tag! 'subID', SUB_ID
#             xml.tag! 'authentication', AUTHENTICATION_TYPE
#             xml.tag! 'token', token
#             xml.tag! 'tokenCode', token_code
#             xml.tag! 'merchantReturnURL', options[:return_url]
#           end
#           xml.tag! 'Transaction' do
#             xml.tag! 'purchaseID', options[:order_id]
#             xml.tag! 'amount', money
#             xml.tag! 'currency', options[:currency]
#             xml.tag! 'expirationPeriod', options[:expiration_period]
#             xml.tag! 'language', LANGUAGE
#             xml.tag! 'description', options[:description]
#             xml.tag! 'entranceCode', options[:entrance_code]
#           end
#           xml.target!
#         end
#       end
#       
#       # <?xml version="1.0" encoding="UTF-8"?> 
#       # <AcquirerStatusReq xmlns="http://www.idealdesk.com/Message" version="1.1.0"> 
#       #  <createDateTimeStamp>2001-12-17T09:30:47.0Z</createDateTimeStamp> 
#       #  <Merchant> 
#       #   <merchantID>000123456</merchantID> 
#       #   <subID>0</subID> 
#       #   <authentication>keyed hash</authentication> 
#       #   <token>1</token> 
#       #   <tokenCode>3823ad872eff23</tokenCode> 
#       #  </Merchant> 
#       #  <Transaction> 
#       #   <transactionID>0001023456789112</transactionID> 
#       #  </Transaction> 
#       # </AcquirerStatusReq>       
#       def build_status_request(options)
#         datetimestamp = create_time_stamp
#         message = datetimestamp + @options[:merchant] + SUB_ID + options[:transaction_id]
#         tokenCode = sign_message(@options[:private_key], @options[:password], message)
# 
#         xml = Builder::XmlMarkup.new :indent => 2
#         xml.instruct!
#         xml.tag! 'AcquirerStatusReq', 'xmlns' => "http://www.idealdesk.com/Message", 'version' => API_VERSION do
#           xml.tag! 'createDateTimeStamp', datetimestamp
#           xml.tag! 'Merchant' do
#             xml.tag! 'merchantID', @options[:merchant]
#             xml.tag! 'subID', SUB_ID
#             xml.tag! 'authentication' , AUTHENTICATION_TYPE
#             xml.tag! 'token', token
#             xml.tag! 'tokenCode', tokenCode
#           end
#           xml.tag! 'Transaction' do
#             xml.tag! 'transactionID', options[:transaction_id]
#           end
#         end
#         xml.target!
#       end
# 
#       # <?xml version="1.0" encoding="UTF-8"?> 
#       # <DirectoryReq xmlns="http://www.idealdesk.com/Message" version="1.1.0"> 
#       #  <createDateTimeStamp>2001-12-17T09:30:47.0Z</createDateTimeStamp> 
#       #  <Merchant> 
#       #   <merchantID>000000001</merchantID> 
#       #   <subID>0</subID> 
#       #   <authentication>1</authentication> 
#       #   <token>hashkey</token> 
#       #   <tokenCode>WajqV1a3nDen0be2r196g9FGFF=</tokenCode> 
#       #  </Merchant> 
#       # </DirectoryReq>      
#       def build_directory_request
#         datetimestamp = create_time_stamp
#         message = datetimestamp + @options[:merchant] + SUB_ID
#         tokenCode = sign_message(@options[:private_key], @options[:password], message)
# 
#         xml = Builder::XmlMarkup.new :indent => 2
#         xml.instruct!
#         xml.tag! 'DirectoryReq', 'xmlns' => "http://www.idealdesk.com/Message", 'version' => API_VERSION do
#           xml.tag! 'createDateTimeStamp', datetimestamp
#           xml.tag! 'Merchant' do
#             xml.tag! 'merchantID', @options[:merchant]
#             xml.tag! 'subID', SUB_ID
#             xml.tag! 'authentication', AUTHENTICATION_TYPE
#             xml.tag! 'token', token
#             xml.tag! 'tokenCode', tokenCode
#           end
#         end
#         xml.target!
#       end
# 
#       def commit(request)
#         raw_response = ssl_post(acquirer_url, request)
#         response = Hash.from_xml(raw_response.to_s)
#         response_type = response.keys[0]
# 
#         case response_type
#           when 'AcquirerTrxRes', 'DirectoryRes'
#             success = true
#           when 'ErrorRes'
#             success = false
#           when 'AcquirerStatusRes'       
#             raise SecurityError, "Message verification failed.", caller unless status_response_verified? response
#             success = (response['AcquirerStatusRes']['Transaction']['status'] =="Success")
#           else
#             raise ArgumentError, "Unknown response type.", caller
#         end
#         
#         return IdealResponse.new(success, response.keys[0] , response, :test => test?)        
#       end
# 
#       def create_fingerprint(cert_data)
#         Digest::SHA1.hexdigest(
#           OpenSSL::X509::Certificate.new(cert_data).to_der
#         ).upcase        
#       end
# 
#       def sign_message(privatekey_file, password, data)
#         privatekey  = OpenSSL::PKey::RSA.new(File.read(privatekey_file), password)
#         signature   = privatekey.sign( OpenSSL::Digest::SHA1.new, data.gsub(/ /, '').gsub(/\t/, '').gsub(/\n/, '') )
#         return Base64.encode64(signature).gsub(/\n/, "")
#       end
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
# 
#       # def create_time_stamp
#       #   Time.now.gmtime.strftime("%Y-%m-%dT%H:%M:%S.000Z")
#       # end
# 
#     end
#     
#   end
# end
