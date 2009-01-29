require File.dirname(__FILE__) + '/ideal/ideal_response'

require 'openssl'
require 'net/https'
require 'base64'
require 'digest/sha1'

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

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class IdealGateway < Gateway
      AUTHENTICATION_TYPE = 'SHA1_RSA'
      LANGUAGE = 'nl'
      API_VERSION = '1.1.0'
      XML_NAMESPACE = 'http://www.idealdesk.com/Message'

      # Assign the test and production urls for your iDeal acquirer.
      #
      # For instance, for ING:
      #
      #   ActiveMerchant::Billing::IdealGateway.test_url = "https://idealtest.secure-ing.com:443/ideal/iDeal"
      #   ActiveMerchant::Billing::IdealGateway.live_url = "https://ideal.secure-ing.com:443/ideal/iDeal"
      class_inheritable_accessor :test_url, :live_url

      OPTIONS = [:password, :ideal_certificate, :private_certificate, :private_key, :merchant, :sub_id]
      attr_reader *OPTIONS

      def initialize(options = {})
        options = { :sub_id => 0 }.merge(options)
        requires!(options, *OPTIONS)
        OPTIONS.each { |option_name| instance_variable_set("@#{option_name}", options[option_name]) }
        super
      end

      # Returns the url of the according matching the current environment. When
      # #test? returns +true+ the IdealGateway.test_url is used, otherwise the
      # IdealGateway.live_url is used.
      def acquirer_url
        test? ? self.class.test_url : self.class.live_url
      end

      def issuers
        IdealDirectoryResponse.new post_data(build_directory_request_body)
      end

      def setup_purchase(money, options)
        IdealTransactionResponse.new post_data(build_transaction_request_body(money, options))
      end

      def capture(transaction_id)
        IdealStatusResponse.new post_data(build_status_request_body(:transaction_id => transaction_id))
      end

      private

      def post_data(data)
        ssl_post(acquirer_url, data)
      end

      def build_directory_request_body
        timestamp = created_at_timestamp

        xml_for(:directory_request, {
          :created_at => timestamp,
          :merchant => {
            :merchant_id =>    @merchant,
            :sub_id =>         @sub_id,
            :authentication => AUTHENTICATION_TYPE,
            :token =>          token,
            :token_code =>     token_code("#{timestamp}#{@merchant}#{@sub_id}")
          }
        })
      end

      def build_transaction_request_body(money, options)
        requires!(options, :issuer_id, :expiration_period, :return_url, :order_id, :currency, :description, :entrance_code)

        timestamp = created_at_timestamp
        message = timestamp +
                  options[:issuer_id] +
                  @merchant +
                  @sub_id.to_s +
                  options[:return_url] +
                  options[:order_id] +
                  money.to_s +
                  options[:currency] +
                  LANGUAGE +
                  options[:description] +
                  options[:entrance_code]

        xml_for(:acquirer_transaction_request, {
          :created_at => timestamp,
          :issuer => { :issuer_id => options[:issuer_id] },

          :merchant => {
            :merchant_id =>         @merchant,
            :sub_id =>              @sub_id,
            :authentication =>      AUTHENTICATION_TYPE,
            :token =>               token,
            :token_code =>          token_code(message),
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

      def build_status_request_body(options)
        requires!(options, :transaction_id)

        timestamp = created_at_timestamp
        message = "#{timestamp}#{@merchant}#{@sub_id}#{options[:transaction_id]}"

        xml_for(:acquirer_status_request, {
          :created_at =>       timestamp,
          :merchant => {
            :merchant_id =>    @merchant,
            :sub_id =>         @sub_id,
            :authentication => AUTHENTICATION_TYPE,
            :token =>          token,
            :token_code =>     token_code(message)
          },
          :transaction => {
            :transaction_id => options[:transaction_id]
          }
        })
      end

      # Returns the +token+ as specified in section 2.8.4 of the iDeal specs.
      def token
        certificate = OpenSSL::X509::Certificate.new(File.read(@private_certificate))
        Digest::SHA1.hexdigest(certificate.to_der).upcase
      end

      # Creates a +tokenCode+ from the specified +message+.
      def token_code(message)
        key = OpenSSL::PKey::RSA.new(File.read(@private_key), @password)
        signature = key.sign(OpenSSL::Digest::SHA1.new, message.gsub(/\s/m, ''))
        Base64.encode64(signature).strip
      end

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
        when 'acquirer_status_request'
          'AcquirerStatusReq'
        when 'directory_request'
          'DirectoryReq'
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

      # Creates xml with a given hash of tag-value pairs according to the iDeal
      # requirements.
      def xml_for(name, tags_and_values)
        xml = Builder::XmlMarkup.new
        xml.instruct!
        xml.tag!(uglify_key(name), 'xmlns' => XML_NAMESPACE, 'version' => API_VERSION) { xml_from_hash(xml, tags_and_values) }
        xml.target!
      end

      # Recursively creates xml for a given hash of tag-value pair. Uses
      # uglify_key on the tags to create the tags needed by iDeal.
      def xml_from_hash(builder, tags_and_values)
        tags_and_values.each do |tag, value|
          tag = uglify_key(tag)
          if value.is_a?(Hash)
            builder.tag!(tag) { xml_from_hash(builder, value) }
          else
            builder.tag!(tag, value)
          end
        end
      end
    end
  end
end