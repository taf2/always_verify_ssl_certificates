require 'uri'
require 'net/http'
require 'net/https'

$:.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$:.unshift(File.dirname(__FILE__))
require 'always_verify_ssl_certificates'

require 'rubygems'
require 'test/unit'
require 'shoulda'


class Test::Unit::TestCase
end
