require "net/http"
require "net/https"
require "net/protocol"

class AlwaysVerifySSLCertificates
  class << self
    attr_accessor :ca_file, :ca_path

    def off!
      Net::HTTP.class_eval do
        private

        undef connect

        def connect
          default_connect
        end
      end
    end

    def on!
      Net::HTTP.class_eval do
        private

        # mix in our new connect
        if RUBY_VERSION.match(/^1.8/)
          include OverrideConnect18
        elsif RUBY_VERSION.match(/^1.9/)
          include OverrideConnect19
        end
      end
    end
  end
end

module OverrideConnect19
  def connect_and_verify
    D "opening connection to #{conn_address()}..."
    s = timeout(@open_timeout) { TCPSocket.open(conn_address(), conn_port()) }
    D "opened"
    if use_ssl?
      ssl_parameters = Hash.new
      iv_list = instance_variables
      SSL_ATTRIBUTES.each do |name|
        ivname = "@#{name}".intern
        if iv_list.include?(ivname) and
           value = instance_variable_get(ivname)
          ssl_parameters[name] = value
        end
      end
      @ssl_context = OpenSSL::SSL::SSLContext.new
      @ssl_context.set_params(ssl_parameters)
      s = OpenSSL::SSL::SSLSocket.new(s, @ssl_context)
      s.sync_close = true
    end
    @socket = Net::BufferedIO.new(s)
    @socket.read_timeout = @read_timeout
    @socket.debug_output = @debug_output
    if use_ssl?
      if proxy?
        @socket.writeline sprintf('CONNECT %s:%s HTTP/%s',
                                  @address, @port, HTTPVersion)
        @socket.writeline "Host: #{@address}:#{@port}"
        if proxy_user
          credential = ["#{proxy_user}:#{proxy_pass}"].pack('m')
          credential.delete!("\r\n")
          @socket.writeline "Proxy-Authorization: Basic #{credential}"
        end
        @socket.writeline ''
        HTTPResponse.read_new(@socket).value
      end
      s.connect
      if @ssl_context.verify_mode != OpenSSL::SSL::VERIFY_NONE
        s.post_connection_check(@address)
      end
    end
    on_connect
  end

  def self.included(base)
    base.class_eval do
      undef connect
      def connect
        connect_and_verify
      end
    end
  end
end

module OverrideConnect18
  def connect_and_verify
    D "opening connection to #{conn_address()}..."
    s = timeout(@open_timeout) { TCPSocket.open(conn_address(), conn_port()) }
    D "opened"
    if use_ssl?
      @ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
      @ssl_context.ca_file     = AlwaysVerifySSLCertificates.ca_file if AlwaysVerifySSLCertificates.ca_file
      @ssl_context.ca_path     = AlwaysVerifySSLCertificates.ca_path if AlwaysVerifySSLCertificates.ca_path
      s = OpenSSL::SSL::SSLSocket.new(s, @ssl_context)
      s.sync_close = true
    end
    @socket = Net::BufferedIO.new(s)
    @socket.read_timeout = @read_timeout
    @socket.debug_output = @debug_output
    if use_ssl?
      if proxy?
        @socket.writeline sprintf('CONNECT %s:%s HTTP/%s',
                                  @address, @port, HTTPVersion)
        @socket.writeline "Host: #{@address}:#{@port}"
        if proxy_user
          credential = ["#{proxy_user}:#{proxy_pass}"].pack('m')
          credential.delete!("\r\n")
          @socket.writeline "Proxy-Authorization: Basic #{credential}"
        end
        @socket.writeline ''
        HTTPResponse.read_new(@socket).value
      end
      s.connect
      if @ssl_context.verify_mode != OpenSSL::SSL::VERIFY_NONE
        s.post_connection_check(@address)
      end
    end
    on_connect
  end

  def self.included(base)
    base.class_eval do
      undef connect
      def connect
        connect_and_verify
      end
    end
  end
end

Net::HTTP.class_eval do
  private
  # save the original connect
  alias default_connect connect
end
AlwaysVerifySSLCertificates.on!
