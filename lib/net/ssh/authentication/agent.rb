require 'net/ssh/buffer'
require 'net/ssh/errors'
require 'net/ssh/loggable'

module Net; module SSH; module Authentication
  PLATFORM = File::ALT_SEPARATOR \
    ? RUBY_PLATFORM =~ /java/ ? :java_win32 : :win32 \
    : RUBY_PLATFORM =~ /java/ ? :java : :unix

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
