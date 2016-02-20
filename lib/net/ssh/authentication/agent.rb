require 'net/ssh/buffer'
require 'net/ssh/errors'
require 'net/ssh/loggable'

module Net; module SSH; module Authentication
  PLATFORM = File::ALT_SEPARATOR \
    ? RUBY_PLATFORM =~ /java/ ? :java_win32 : :win32 \
    : RUBY_PLATFORM =~ /java/ ? :java : :unix

  # Taken from Section 3 of
  # https://github.com/openssh/openssh-portable/blob/4e636cf/PROTOCOL.agent
  # These only apply to the socket agent, but tests need them too
  module AgentProtocolConstants
    SSH2_AGENT_REQUEST_VERSION    = 1
    SSH2_AGENT_REQUEST_IDENTITIES = 11
    SSH2_AGENT_IDENTITIES_ANSWER  = 12
    SSH2_AGENT_SIGN_REQUEST       = 13
    SSH2_AGENT_SIGN_RESPONSE      = 14
    SSH2_AGENT_FAILURE            = 30
    SSH2_AGENT_VERSION_RESPONSE   = 103

    SSH_COM_AGENT2_FAILURE        = 102

    SSH_AGENT_REQUEST_RSA_IDENTITIES = 1
    SSH_AGENT_RSA_IDENTITIES_ANSWER  = 2
    SSH_AGENT_RSA_IDENTITIES_ANSWER1 = 2
    SSH_AGENT_RSA_IDENTITIES_ANSWER2 = 5
    SSH_AGENT_FAILURE                = 5

    # 3.1 Requests from client to agent for protocol 1 key operations
    SSH_AGENT_REQUEST_RSA_IDENTITIES        = 1
    SSH_AGENT_RSA_CHALLENGE                 = 3
    SSH_AGENT_ADD_RSA_IDENTITY              = 7
    SSH_AGENT_REMOVE_RSA_IDENTITY           = 8
    SSH_AGENT_REMOVE_ALL_RSA_IDENTITIES     = 9
    SSH_AGENT_ADD_RSA_ID_CONSTRAINED        = 24

    # 3.2 Requests from client to agent for protocol 2 key operations
    SSH2_AGENT_REQUEST_IDENTITIES           = 11
    SSH2_AGENT_SIGN_REQUEST                 = 13
    SSH2_AGENT_ADD_IDENTITY                 = 17
    SSH2_AGENT_REMOVE_IDENTITY              = 18
    SSH2_AGENT_REMOVE_ALL_IDENTITIES        = 19
    SSH2_AGENT_ADD_ID_CONSTRAINED           = 25

    # 3.3 Key-type independent requests from client to agent
    SSH_AGENT_ADD_SMARTCARD_KEY             = 20
    SSH_AGENT_REMOVE_SMARTCARD_KEY          = 21
    SSH_AGENT_LOCK                          = 22
    SSH_AGENT_UNLOCK                        = 23
    SSH_AGENT_ADD_SMARTCARD_KEY_CONSTRAINED = 26

    # 3.4 Generic replies from agent to client
    SSH_AGENT_FAILURE                       = 5
    SSH_AGENT_SUCCESS                       = 6

    # 3.5 Replies from agent to client for protocol 1 key operations
    SSH_AGENT_RSA_IDENTITIES_ANSWER         = 2
    SSH_AGENT_RSA_RESPONSE                  = 4

    # 3.6 Replies from agent to client for protocol 2 key operations
    SSH2_AGENT_IDENTITIES_ANSWER            = 12
    SSH2_AGENT_SIGN_RESPONSE                = 14

    # 3.7 Key constraint identifiers
    SSH_AGENT_CONSTRAIN_LIFETIME            = 1
    SSH_AGENT_CONSTRAIN_CONFIRM             = 2

  end

  # A trivial exception class for representing agent-specific errors.
  class AgentError < Net::SSH::Exception; end

  # An exception for indicating that the SSH agent is not available.
  class AgentNotAvailable < AgentError; end
end; end; end

case Net::SSH::Authentication::PLATFORM
when :java_win32
  # Java pageant requires whole different agent.
  require 'net/ssh/authentication/agent/java_pageant'
else
  require 'net/ssh/authentication/agent/socket'
end
