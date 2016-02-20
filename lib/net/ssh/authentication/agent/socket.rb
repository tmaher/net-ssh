require 'net/ssh/transport/server_version'

# Only load pageant on Windows
if Net::SSH::Authentication::PLATFORM == :win32
  require 'net/ssh/authentication/pageant'
end

module Net; module SSH; module Authentication

  # This class implements a simple client for the ssh-agent protocol. It
  # does not implement any specific protocol, but instead copies the
  # behavior of the ssh-agent functions in the OpenSSH library (3.8).
  #
  # This means that although it behaves like a SSH1 client, it also has
  # some SSH2 functionality (like signing data).
  class Agent
    include Net::SSH::Authentication::AgentProtocolConstants
    include Loggable
    @default_key_opts = {:comment => "", :confirm => false, :lifetime => 0}

    # A simple module for extending keys, to allow comments to be specified
    # for them.
    module Comment
      attr_accessor :comment
    end

    # The underlying socket being used to communicate with the SSH agent.
    attr_reader :socket

    # Instantiates a new agent object, connects to a running SSH agent,
    # negotiates the agent protocol version, and returns the agent object.
    def self.connect(logger=nil)
      agent = new(logger)
      agent.connect!
      agent.negotiate!
      agent
    end

    # Creates a new Agent object, using the optional logger instance to
    # report status.
    def initialize(logger=nil)
      self.logger = logger
    end

    # Connect to the agent process using the socket factory and socket name
    # given by the attribute writers. If the agent on the other end of the
    # socket reports that it is an SSH2-compatible agent, this will fail
    # (it only supports the ssh-agent distributed by OpenSSH).
    def connect!
      begin
        debug { "connecting to ssh-agent" }
        @socket = agent_socket_factory.open(ENV['SSH_AUTH_SOCK'])
      rescue
        error { "could not connect to ssh-agent" }
        raise AgentNotAvailable, $!.message
      end
    end

    # Attempts to negotiate the SSH agent protocol version. Raises an error
    # if the version could not be negotiated successfully.
    def negotiate!
      # determine what type of agent we're communicating with
      type, body = send_and_wait(SSH_AGENTC_REQUEST_RSA_IDENTITIES, :string, Transport::ServerVersion::PROTO_VERSION)

      if type == SSH2_AGENT_VERSION_RESPONSE
        raise AgentNotAvailable, "SSH2 agents are not yet supported"
      elsif type == SSH2_AGENT_FAILURE
        debug { "Unexpected response type==#{type}, this will be ignored" }
      elsif type != SSH_AGENT_RSA_IDENTITIES_ANSWER && type != SSH_AGENT_FAILURE
        raise AgentNotAvailable, "unknown response from agent: #{type}, #{body.to_s.inspect}"
      end
    end

    # Return an array of all identities (public keys) known to the agent.
    # Each key returned is augmented with a +comment+ property which is set
    # to the comment returned by the agent for that key.
    def identities
      type, body = send_and_wait(SSH2_AGENTC_REQUEST_IDENTITIES)
      raise AgentError, "could not get identity count" if agent_failed(type)
      raise AgentError, "bad authentication reply: #{type}" if type != SSH2_AGENT_IDENTITIES_ANSWER

      identities = []
      body.read_long.times do
        key_str = body.read_string
        comment_str = body.read_string
        begin
          key = Buffer.new(key_str).read_key
          key.extend(Comment)
          key.comment = comment_str
          identities.push key
        rescue NotImplementedError => e
          error { "ignoring unimplemented key:#{e.message} #{comment_str}" }
        end
      end

      return identities
    end

    # Closes this socket. This agent reference is no longer able to
    # query the agent.
    def close
      @socket.close
    end

    # Using the agent and the given public key, sign the given data. The
    # signature is returned in SSH2 format.
    def sign(key, data)
      type, reply = send_and_wait(SSH2_AGENTC_SIGN_REQUEST, :string, Buffer.from(:key, key), :string, data, :long, 0)

      if agent_failed(type)
        raise AgentError, "agent could not sign data with requested identity"
      elsif type != SSH2_AGENT_SIGN_RESPONSE
        raise AgentError, "bad authentication response #{type}"
      end

      return reply.read_string
    end

    def add_key(key, opt=@default_key_opts)
      type, reply = nil, nil

      case key.class.to_s
      when "OpenSSL::PKey::RSA"
        type, reply = add_rsa_key key, opt
      else
        raise NotImplementedError, "Only RSA keys are supported, not #{key.class}"
      end
      type
    end

    def add_rsa_key(rsa_key, opt=@default_key_opts)
      p = rsa_key.params
      send_and_wait(SSH2_AGENTC_ADD_IDENTITY,
        :string, "ssh-rsa",
        :bignum, p['n'],
        :bignum, p['e'],
        :bignum, p['d'],
        :bignum, p['iqmp'],
        :bignum, p['p'],
        :bignum, p['q'],
        :string, opt[:comment]
      )
    end

    private

    # Returns the agent socket factory to use.
    def agent_socket_factory
      if Net::SSH::Authentication::PLATFORM == :win32
        Pageant::Socket
      else
        UNIXSocket
      end
    end

    # Send a new packet of the given type, with the associated data.
    def send_packet(type, *args)
      buffer = Buffer.from(*args)
      data = [buffer.length + 1, type.to_i, buffer.to_s].pack("NCA*")
      debug { "sending agent request #{type} len #{buffer.length}" }
      @socket.send data, 0
    end

    # Read the next packet from the agent. This will return a two-part
    # tuple consisting of the packet type, and the packet's body (which
    # is returned as a Net::SSH::Buffer).
    def read_packet
      buffer = Net::SSH::Buffer.new(@socket.read(4))
      buffer.append(@socket.read(buffer.read_long))
      type = buffer.read_byte
      debug { "received agent packet #{type} len #{buffer.length-4}" }
      return type, buffer
    end

    # Send the given packet and return the subsequent reply from the agent.
    # (See #send_packet and #read_packet).
    def send_and_wait(type, *args)
      send_packet(type, *args)
      read_packet
    end

    # Returns +true+ if the parameter indicates a "failure" response from
    # the agent, and +false+ otherwise.
    def agent_failed(type)
      type == SSH_AGENT_FAILURE ||
        type == SSH2_AGENT_FAILURE ||
        type == SSH_COM_AGENT2_FAILURE
    end
  end

end; end; end
