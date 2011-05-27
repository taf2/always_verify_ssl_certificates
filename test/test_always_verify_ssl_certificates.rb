require 'helper'

class TestAlwaysVerifySslCertificates < Test::Unit::TestCase

  should "verify the peer even if it's not set on Net/HTTP" do
    begin
      AlwaysVerifySSLCertificates.ca_file = File.expand_path(File.join(File.dirname(__FILE__), '/../lib/cacert.pem'))
      url = URI.parse('https://google.com/')
      http = Net::HTTP.new(url.host, url.port)
      http.use_ssl = true
      res = http.get("/", {})
    rescue => e
    #  puts e.message
    #  puts e.backtrace.join("\n")
      assert_equal OpenSSL::SSL::SSLError, e.class
      assert_equal "hostname was not match with the server certificate", e.message
    end
  end

  should "be able to disable verification" do
    2.times do
    AlwaysVerifySSLCertificates.off!
    AlwaysVerifySSLCertificates.ca_file = File.expand_path(File.join(File.dirname(__FILE__), '/../lib/cacert.pem'))
    url = URI.parse('https://google.com/')
    http = Net::HTTP.new(url.host, url.port)
    http.use_ssl = true
    res = http.get("/", {})
    assert_equal Net::HTTPMovedPermanently, res.class
    AlwaysVerifySSLCertificates.on!
    begin
      AlwaysVerifySSLCertificates.ca_file = File.expand_path(File.join(File.dirname(__FILE__), '/../lib/cacert.pem'))
      url = URI.parse('https://google.com/')
      http = Net::HTTP.new(url.host, url.port)
      http.use_ssl = true
      res = http.get("/", {})
    rescue => e
      #puts e.message
      #puts e.backtrace.join("\n")
      assert_equal OpenSSL::SSL::SSLError, e.class
      assert_equal "hostname was not match with the server certificate", e.message
    end
    end
  end

end
