require "net/http"
require "net/https"

class AlwaysVerifySSLCertificates
  class << self
    attr_accessor :ca_file, :ca_path
  end
end

module OverrideConnect19
  def connect
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
    @socket = BufferedIO.new(s)
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
end

module OverrideConnect18
  def connect
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
    @socket = BufferedIO.new(s)
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
end

module Net
  class HTTP
    private
    if RUBY_VERSION.match(/^1.8/)
      include OverrideConnect18
    elsif RUBY_VERSION.match(/^1.9/)
      include OverrideConnect19
    end

  end
end
