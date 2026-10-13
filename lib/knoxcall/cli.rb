require "optparse"

require "knoxcall"
require "knoxcall/cli/common"
require "knoxcall/cli/login"
require "knoxcall/cli/logout"
require "knoxcall/cli/whoami"
require "knoxcall/cli/init"
require "knoxcall/cli/ai"
require "knoxcall/cli/ai_control"

module KnoxCall
  # KnoxCall CLI — `knoxcall login` / `logout` / `whoami` / `init` / `ai`.
  #
  # Shipped as the gem executable (`exe/knoxcall`); `KnoxCall::CLI.run(argv)`
  # is the testable entry point. Credentials are stored in the cross-SDK
  # ~/.knoxcall/credentials.json file and picked up automatically by every
  # KnoxCall SDK (auto-detect slot 2). The command surface, messages, and exit
  # codes mirror the python reference implementation (PARITY §13).
  module CLI
    PROGRAM = "knoxcall"
    COMMANDS = %w[login logout whoami init ai].freeze
    # `ai` is the only command with a sub-command of its own.
    #
    # AIGW-162. `exchange` is the data-plane door and needs no login; the rest
    # are the control plane and act as the signed-in tenant. Both live under
    # `ai` because they are one surface to a user, and the golden path crosses
    # between them: create-agent -> mint -> a real call.
    #
    # Every one of these takes FLAGS ONLY, no positionals — four of the five SDK
    # CLIs hand-roll their parser and reject positionals outright (only python
    # gets them free from argparse), so an id as a positional would be a surface
    # that is the same in all five except in shape.
    AI_COMMANDS = %w[exchange gateways agents create-agent mint usage].freeze
    AI_COMMAND_SUMMARIES = {
      "exchange" => "exchange a CI OIDC token for a capability token (no login needed)",
      "gateways" => "list AI gateways",
      "agents" => "list a gateway's agents",
      "create-agent" => "create an agent with its upstream credential",
      "mint" => "mint a capability token (shown once)",
      "usage" => "cost + token usage by model"
    }.freeze
    USAGE = "usage: #{PROGRAM} [-h] {#{COMMANDS.join(',')}} ..."
    DESCRIPTION =
      "KnoxCall command-line interface — sign in once, every SDK on this machine picks it up."
    COMMAND_SUMMARIES = {
      "login" => "sign in with your browser and store credentials locally",
      "logout" => "revoke and remove stored credentials",
      "whoami" => "show the signed-in tenant",
      "init" => "get started wrapping a provider SDK (escrow a key)",
      "ai" => "AI gateway operations"
    }.freeze
    PROFILE_HELP = "credentials profile name (default: KNOXCALL_PROFILE or 'default')"

    module_function

    # Run the CLI: 0 on success, 1 on expected failure/interrupt ("error: …" /
    # "aborted" on stderr, never a backtrace), 2 on usage errors.
    def run(argv = ARGV)
      parsed = parse(Array(argv).map(&:to_s))
      return parsed if parsed.is_a?(Integer) # help printed (0) or usage error (2)

      command, options = parsed
      begin
        execute(command, options)
      rescue Error, KnoxCall::Error => e
        warn "error: #{e.message}"
        1
      rescue Interrupt
        warn "aborted"
        1
      end
    end

    def execute(command, options)
      case command
      when "login" then Login.run(options)
      when "logout" then Logout.run(options)
      when "whoami" then Whoami.run(options)
      when "init" then Init.run(options)
      when "ai" then execute_ai(options)
      end
    end

    # `ai` fans out to its own sub-commands. `exchange` is the data-plane door
    # (no login); the other five are the control plane and act as the
    # signed-in tenant.
    def execute_ai(options)
      case options[:ai_command]
      when "exchange" then Ai.run(options)
      when "gateways" then AiControl.gateways(options)
      when "agents" then AiControl.agents(options)
      when "create-agent" then AiControl.create_agent(options)
      when "mint" then AiControl.mint(options)
      when "usage" then AiControl.usage(options)
      end
    end

    # Parse argv into [command, options]. Help and usage errors are handled
    # here: help prints to stdout and returns 0; a usage error prints to
    # stderr and returns 2 (matching the python reference's argparse).
    def parse(argv)
      if argv.empty?
        warn USAGE
        warn "#{PROGRAM}: error: a command is required (choose from #{COMMANDS.join(', ')})"
        return 2
      end
      if %w[-h --help].include?(argv.first)
        puts root_help
        return 0
      end
      command = argv.first
      unless COMMANDS.include?(command)
        warn USAGE
        warn "#{PROGRAM}: error: invalid choice: '#{command}' (choose from #{COMMANDS.join(', ')})"
        return 2
      end

      options = {}
      rest_argv = argv[1..]
      ai_command = nil

      # `ai` carries a sub-command. Consume it here, then fall through to the
      # same OptionParser path with argv advanced past it — one parser, not two.
      if command == "ai"
        sub = rest_argv.first
        if sub.nil?
          warn ai_usage
          warn "#{PROGRAM} ai: error: a sub-command is required (choose from #{AI_COMMANDS.join(', ')})"
          return 2
        end
        if %w[-h --help].include?(sub)
          puts ai_help
          return 0
        end
        unless AI_COMMANDS.include?(sub)
          warn ai_usage
          warn "#{PROGRAM} ai: error: invalid choice: '#{sub}' (choose from #{AI_COMMANDS.join(', ')})"
          return 2
        end
        ai_command = sub
        options[:ai_command] = sub
        rest_argv = rest_argv[1..]
      end

      label = ai_command ? "#{command} #{ai_command}" : command
      help_requested = false
      parser = build_parser(command, options, ai_command)
      parser.on("-h", "--help", "show this help message and exit") { help_requested = true }
      begin
        rest = parser.parse(rest_argv)
      rescue OptionParser::ParseError => e
        warn parser.banner
        warn "#{PROGRAM} #{label}: error: #{e.message}"
        return 2
      end
      if help_requested
        puts parser
        return 0
      end
      unless rest.empty?
        warn parser.banner
        warn "#{PROGRAM} #{label}: error: unrecognized arguments: #{rest.join(' ')}"
        return 2
      end
      [command, options]
    end

    def ai_usage
      "usage: #{PROGRAM} ai [-h] {#{AI_COMMANDS.join(',')}} ..."
    end

    def ai_help
      <<~HELP
        #{ai_usage}

        AI-gateway operations.

        From a tenant with nothing in it to a real streamed call, in two commands:

            export ANTHROPIC_API_KEY=sk-ant-...
            knoxcall ai create-agent --name copilot --slug copilot \\
                --provider anthropic --secret-from-env ANTHROPIC_API_KEY
            knoxcall ai mint --agent <id>

        sub-commands:
        #{AI_COMMANDS.map { |c| format('  %-14s %s', c, AI_COMMAND_SUMMARIES[c]) }.join("\n")}

        options:
          -h, --help  show this help message and exit
      HELP
    end

    def root_help
      <<~HELP
        #{USAGE}

        #{DESCRIPTION}

        commands:
        #{COMMANDS.map { |c| format('  %-8s %s', c, COMMAND_SUMMARIES[c]) }.join("\n")}

        options:
          -h, --help  show this help message and exit
      HELP
    end

    def build_parser(command, options, ai_command = nil)
      OptionParser.new do |o|
        o.banner = "usage: #{PROGRAM} #{command} [options]"
        o.summary_width = 18
        case command
        when "login"
          o.on("--tenant SLUG", "tenant slug hint for the sign-in page") do |v|
            options[:tenant] = v
          end
          o.on("--base-url URL",
               "management API base URL (default https://api.knoxcall.com, or KNOXCALL_BASE_URL)") do |v|
            options[:base_url] = v
          end
          o.on("--sandbox", "log in against the sandbox environment") do
            options[:sandbox] = true
          end
          o.on("--profile NAME", PROFILE_HELP) { |v| options[:profile] = v }
          o.on("--device", "use the device-code flow (headless/SSH machines)") do
            options[:device] = true
          end
          o.on("--no-browser", "never open a browser (implies the device-code flow)") do
            options[:no_browser] = true
          end
        when "logout", "whoami"
          o.on("--profile NAME", PROFILE_HELP) { |v| options[:profile] = v }
        when "init"
          o.on("--profile NAME", PROFILE_HELP) { |v| options[:profile] = v }
          o.on("--base-url URL",
               "management API base URL (default https://api.knoxcall.com)") do |v|
            options[:base_url] = v
          end
          o.on("--sandbox", "operate against the sandbox environment") do
            options[:sandbox] = true
          end
          o.on("--provider PROVIDER", "provider to escrow a key for (e.g. stripe); enables escrow mode") do |v|
            options[:provider] = v
          end
          o.on("--secret-name NAME", "name for the escrowed credential (required with --provider)") do |v|
            options[:secret_name] = v
          end
          o.on("--host HOST", "upstream host to pin the credential to (required with --provider)") do |v|
            options[:host] = v
          end
        when "ai"
          o.banner = "usage: #{PROGRAM} ai #{ai_command} [options]"
          build_ai_parser(o, options, ai_command)
        end
      end
    end

    # The `ai` flag table is keyed by SUB-command, not by `ai`.
    #
    # A single shared table would accept `ai exchange --period 30d` and silently
    # ignore it — the opposite of what every other command here does with an
    # unknown flag (usage error, exit 2). It also has to be per-sub-command for
    # `--secret-value` to be REJECTED on create-agent: an unknown flag is only
    # unknown if the table it is checked against is the one for that command.
    def build_ai_parser(opt, options, ai_command)
      case ai_command
      when "exchange"
        opt.on("--tenant SLUG", "tenant slug; the data-plane host is https://{tenant}.knoxcall.com") do |v|
          options[:tenant] = v
        end
        opt.on("--sandbox", "use the Test data space (sandbox-{tenant}.knoxcall.com)") do
          options[:sandbox] = true
        end
        opt.on("--base-url URL", "full data-plane origin; overrides --tenant") do |v|
          options[:base_url] = v
        end
        # Assigned even when empty: the key's PRESENCE is what says the
        # caller asked for a resource, and an empty one is a server refusal
        # rather than "no resource".
        opt.on("--resource URI",
               "RFC 8707 resource indicator (an MCP server's `resource`); narrows the token to that one MCP server") do |v|
          options[:resource] = v
        end
        opt.on("--audience AUDIENCE", "defaults to knoxcall:gateway") do |v|
          options[:audience] = v
        end
      when "gateways"
        ai_common_options(opt, options)
      when "agents"
        opt.on("--gateway ID", "gateway id") { |v| options[:gateway] = v }
        ai_common_options(opt, options)
      when "create-agent"
        # Printed by `--help` only — OptionParser#banner, which is what a usage
        # error echoes, stays the single usage line.
        ai_create_agent_preamble(opt)
        opt.on("--slug SLUG", "url slug; the agent is served at /v1/ai/{slug}") do |v|
          options[:slug] = v
        end
        opt.on("--provider PROVIDER",
               "provider id (anthropic, openai, bedrock, …); catalog is server-side") do |v|
          options[:provider] = v
        end
        opt.on("--secret ID", "id of an existing KnoxCall secret holding the key") do |v|
          options[:secret] = v
        end
        # The key is read from the NAMED ENVIRONMENT VARIABLE, never from a
        # flag value: an argv value lands in shell history, ps output and the
        # CI log line that echoes the command.
        opt.on("--secret-from-env VAR",
               "env var holding the key; escrows it, reusing a same-named secret") do |v|
          options[:secret_from_env] = v
        end
        opt.on("--name NAME", "display name (defaults to --slug)") { |v| options[:name] = v }
        opt.on("--gateway ID", "gateway id or slug to create under") { |v| options[:gateway] = v }
        opt.on("--model MODEL", "default model (required for openai-compatible)") do |v|
          options[:model] = v
        end
        opt.on("--upstream URL",
               "upstream base URL; required for azure-openai, ollama, " \
               "bedrock and openai-compatible") do |v|
          options[:upstream] = v
        end
        ai_common_options(opt, options)
      when "mint"
        opt.separator ""
        opt.separator "Mint a capability token for an agent. The plaintext is returned ONCE and is"
        opt.separator "the only thing on stdout, so it can be captured:"
        opt.separator "    TOKEN=\"$(knoxcall ai mint --agent ag_123)\""
        opt.separator ""
        opt.separator "options:"
        opt.on("--agent ID", "agent id") { |v| options[:agent] = v }
        opt.on("--kind KIND", "agent | read | tool | oneshot (default agent)") { |v| options[:kind] = v }
        opt.on("--name NAME", "label for the token") { |v| options[:name] = v }
        ai_common_options(opt, options)
      when "usage"
        opt.on("--period PERIOD", "7d | 30d | 90d (default 30d)") { |v| options[:period] = v }
        opt.on("--agent ID", "scope to one agent") { |v| options[:agent] = v }
        ai_common_options(opt, options)
      end
    end

    # The three rules `create-agent` exists to enforce, printed by `--help`.
    # Separators land in the summary only, so a usage error still echoes the
    # one-line banner rather than nine lines of prose.
    def ai_create_agent_preamble(opt)
      opt.separator ""
      opt.separator "Create an agent wired to a provider credential, and print the command that"
      opt.separator "follows. Works on a tenant with nothing in it: with no --gateway it uses your"
      opt.separator "only gateway, or creates one when you have none. With several it refuses and"
      opt.separator "lists them rather than picking one for you."
      opt.separator ""
      opt.separator "The provider key is read from the environment named by --secret-from-env,"
      opt.separator "never from a flag — an argv value lands in shell history, ps output and the"
      opt.separator "CI log. There is deliberately no --secret-value."
      opt.separator ""
      opt.separator "--provider and a credential are both required: the API accepts an agent with"
      opt.separator "neither and stores one whose first data-plane call 502s."
      opt.separator ""
      opt.separator "Only the agent id goes to stdout, so it can be captured:"
      opt.separator "    AGENT=\"$(knoxcall ai create-agent --slug copilot --provider anthropic \\"
      opt.separator "        --secret-from-env ANTHROPIC_API_KEY)\""
      opt.separator ""
      opt.separator "options:"
    end

    # Accepted by every control-plane sub-command: they select WHICH tenant and
    # WHICH stored login is acting. `exchange` takes none of them — it needs no
    # login at all.
    def ai_common_options(opt, options)
      opt.on("--profile NAME", PROFILE_HELP) { |v| options[:profile] = v }
      opt.on("--base-url URL", "management API base URL (default https://api.knoxcall.com)") do |v|
        options[:base_url] = v
      end
      opt.on("--sandbox", "operate against the Test data space") { options[:sandbox] = true }
    end
  end
end
