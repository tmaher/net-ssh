require 'net/ssh/buffer'
require 'net/ssh/errors'
require 'net/ssh/loggable'

module Net; module SSH; module Authentication
  PLATFORM = File::ALT_SEPARATOR \
    ? RUBY_PLATFORM =~ /java/ ? :java_win32 : :win32 \
    : RUBY_PLATFORM =~ /java/ ? :java : :unix

  # https://github.com/openssh/openssh-portable/blob/76c9fbb/authfd.h
  # These only apply to the socket agent, but tests need them too
  module AgentProtocolConstants
    # Messages for the authentication agent connection.
    SSH_AGENTC_REQUEST_RSA_IDENTITIES	= 1
    SSH_AGENT_RSA_IDENTITIES_ANSWER = 2
    SSH_AGENTC_RSA_CHALLENGE = 3
    SSH_AGENT_RSA_RESPONSE = 4
    SSH_AGENT_FAILURE = 5
    SSH_AGENT_SUCCESS = 6
    SSH_AGENTC_ADD_RSA_IDENTITY = 7
    SSH_AGENTC_REMOVE_RSA_IDENTITY = 8
    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES = 9

    # private OpenSSH extensions for SSH2
    SSH2_AGENTC_REQUEST_IDENTITIES = 11
    SSH2_AGENT_IDENTITIES_ANSWER = 12
    SSH2_AGENTC_SIGN_REQUEST = 13
    SSH2_AGENT_SIGN_RESPONSE = 14
    SSH2_AGENTC_ADD_IDENTITY = 17
    SSH2_AGENTC_REMOVE_IDENTITY = 18
    SSH2_AGENTC_REMOVE_ALL_IDENTITIES	= 19

    # smartcard
    SSH_AGENTC_ADD_SMARTCARD_KEY = 20
    SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21

    # lock/unlock the agent
    SSH_AGENTC_LOCK = 22
    SSH_AGENTC_UNLOCK = 23

    # add key with constraints
    SSH_AGENTC_ADD_RSA_ID_CONSTRAINED	= 24
    SSH2_AGENTC_ADD_ID_CONSTRAINED = 25
    SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26

    SSH_AGENT_CONSTRAIN_LIFETIME = 1
    SSH_AGENT_CONSTRAIN_CONFIRM = 2

    # extended failure messages
    SSH2_AGENT_FAILURE = 30

    # additional error code for ssh.com's ssh-agent2
    SSH_COM_AGENT2_FAILURE = 102
    SSH2_AGENT_VERSION_RESPONSE   = 103

    SSH_AGENT_OLD_SIGNATURE = 0x01
    SSH_AGENT_RSA_SHA2_256 = 0x02
    SSH_AGENT_RSA_SHA2_512 = 0x04
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
