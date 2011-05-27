require "net/http"
require "net/https"
require "openssl"

class AlwaysVerifySSLCertificates
  class << self
    attr_accessor :ca_file, :ca_path

    #
    # disable peer verification in 1.8 this is the default in 1.9 this means before connecting verify_mode is set to OpenSSL::SSL::VERIFY_NONE
    #
    def off!
      Net::HTTP.class_eval do
        private

        undef connect

        def connect
          # we're off in 1.9 that means verify_mode = OpenSSL::SSL::VERIFY_NONE
          self.verify_mode = OpenSSL::SSL::VERIFY_NONE if self.respond_to?(:verify_mode)
          default_connect
        end
      end
    end

    #
    # Use the defaults on AlwaysVerifySSLCertificates, this means use OpenSSL::SSL::VERIFY_PEER and ca_file/ca_path if provided
    #
    def on!
      Net::HTTP.class_eval do
        private
        private

        undef connect

        def connect
          self.verify_mode = OpenSSL::SSL::VERIFY_PEER if self.respond_to?(:verify_mode)
          self.ca_file     = AlwaysVerifySSLCertificates.ca_file if self.respond_to?(:ca_file) && AlwaysVerifySSLCertificates.ca_file
          self.ca_path     = AlwaysVerifySSLCertificates.ca_path if self.respond_to?(:ca_path) && AlwaysVerifySSLCertificates.ca_path
          default_connect
        end

      end
    end
  end
end

# save the original connect method
Net::HTTP.class_eval do
  private
  alias default_connect connect
end

AlwaysVerifySSLCertificates.on!
