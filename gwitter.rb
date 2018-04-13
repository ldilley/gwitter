# Gwitter - GitHub to Twitter hook glue
# Copyright (C) 2018 Lloyd Dilley
# http://www.dilley.me/
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# Check Ruby version
if RUBY_VERSION < '2.2'
  puts 'Gwitter requires Ruby >=2.2!'
  exit!
end

# Dependencies
require 'json'
require 'openssl'
require 'sinatra/base'
require 'twitter'
require 'webrick'
require 'webrick/https'
require 'yaml'

# Constants and globals (many globals are set in parse_config())
GWITTER_VERSION = '1.0'
TWEET_LIMIT = 280 # chars
$log_dir = 'logs'
$log_name = 'gwitter.log'
$config_name = 'config.yml'

# Reads $config_name and stores options in globals
def parse_config
  begin
    config_file = YAML.load_file($config_name)
  rescue => error_msg
    puts "Unable to open config.yml file: #{error_msg}"
    exit!
  end

  # Map options to values
  $listen_host = config_file['listen_host']
  $listen_port = config_file['listen_port']
  $use_ssl = config_file['use_ssl']
  $github_secret = config_file['github_secret']
  $consumer_key = config_file['consumer_key']
  $consumer_secret = config_file['consumer_secret']
  $access_token = config_file['access_token']
  $access_secret = config_file['access_secret']
  $become_daemon = config_file['become_daemon']
  $debug_mode = config_file['debug_mode']

  validate_config
end

# Validates values read from parse_config()
def validate_config
  if $listen_host.nil?
    $listen_host = '0.0.0.0'
  else
    unless valid_hostname?($listen_host) || valid_address?($listen_host)
      puts 'listen_host value is not a valid hostname or IP address!'
      exit!
    end
  end

  if $listen_port.nil?
    puts 'Unable to read listen_port value from config.yml file!'
    exit!
  end

  if $listen_port <= 0 || $listen_port >= 65_536
    puts 'listen_port value is out of range!'
    exit!
  end

  if $consumer_key.nil?
    puts 'Unable to read consumer_key value from config.yml file!'
    exit!
  end

  if $consumer_secret.nil?
    puts 'Unable to read consumer_secret value from config.yml file!'
    exit!
  end

  if $access_token.nil?
    puts 'Unable to read access_token value from config.yml file!'
    exit!
  end

  if $access_secret.nil?
    puts 'Unable to read access_secret value from config.yml file!'
    exit!
  end

  $use_ssl = false if $use_ssl.nil?
  $become_daemon = false if $become_daemon.nil?
  $debug_mode = false if $debug_mode.nil?

  if $use_ssl.to_s != 'true' && $use_ssl.to_s != 'false'
    puts 'use_ssl value should be set to either \'true\' or \'false\'.'
    exit!
  end

  if $become_daemon.to_s != 'true' && $become_daemon.to_s != 'false'
    puts 'become_daemon value should be set to either \'true\' or \'false\'.'
    exit!
  end

  if $debug_mode.to_s != 'true' && $debug_mode.to_s != 'false'
    puts 'debug_mode value should be set to either \'true\' or \'false\'.'
    exit!
  end
end

# Validates hostnames
# @param hostname [string] the hostname to validate
# @return [true] if hostname is valid
# @return [false] if hostname is invalid
def valid_hostname?(hostname)
  if hostname =~ /^(?:[a-zA-Z0-9]+(?:\-*[a-zA-Z0-9])*\.)+[a-zA-Z]{2,6}$/i
    return true
  else
    return false
  end
end

# Validates IP addresses
# @param address [string] the IP address to validate
# @return [true] if address is valid
# @return [false] if address is invalid
def valid_address?(address)
  # IPv4
  if address =~ /^\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$/
    return true
  # IPv6
  elsif address =~ /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:    \
                   [0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:       \
                   [0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(: \
                   [0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)   \
                   |fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1     \
                   {0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:   \
                   ((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/
    return true
  else
    return false
  end
end

# Logs text entry to $log_dir/$log_name
# @param text [string] text entry to log to file
def log_write(text)
  Dir.mkdir($log_dir) unless File.exists?($log_dir)
  log_file = File.open("#{$log_dir}/#{$log_name}", 'a')
  time_stamp = Time.now.strftime "[%m/%d/%Y %H:%M:%S]"
  log_file.puts "#{time_stamp} #{text}"
  log_file.close
  rescue
    puts 'Unable to write log file!'
end

# Verifies hook payload using hashing with $github_secret
# @param payload_body [string] body of hook payload to verify
# @return [string] HTTP error code 500 if signature does not match
def verify_signature(payload_body)
  signature = 'sha1=' + OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha1'), $github_secret, payload_body)
  unless Rack::Utils.secure_compare(signature, request.env['HTTP_X_HUB_SIGNATURE'])
    return halt 500, "Signature mismatch!"
    log_write 'Signature mismatch!'
  end
end

# Handles possible GitHub event types
# @param push_event [string] event data to grok
# @return [string] message to tweet
def handle_event push_event
  message = ""
  case
    # Release
    when push_event.key?('release')
      release_name = push_event['release']['name']
      release_tag = push_event['release']['tag_name']
      release_url = push_event['release']['html_url']
      release_body = push_event['release']['body']
      message += "#{release_name} #{release_tag}\r\n"
      message += "#{release_url}\r\n"
      message += "#{release_body}"
    # Pull request (merge only)
    when push_event.key?('pull_request') && push_event['action'] == 'closed' && push_event['merged'] == 'true'
      pr_title = push_event['pull_request']['title']
      pr_url = push_event['pull_request']['html_url']
      pr_body = push_event['pull_request']['body']
      message += "#{pr_title}\r\n"
      message += "#{pr_url}\r\n"
      message += "#{pr_body}"
    # ToDo: Handle more events and make them configurable
    # Unhandled event
    else
      message = nil
      log_write('Unhandled event encountered.')
  end
  return message
end

# Tweets a message
# @param message [string] message to tweet
def tweet(message)
  # Configure Twitter client auth
  client = Twitter::REST::Client.new do |config|
    config.consumer_key        = $consumer_key
    config.consumer_secret     = $consumer_secret
    config.access_token        = $access_token
    config.access_token_secret = $access_secret
  end

  # Links should automagically be shortened by the t.co service
  # Acquiring the shortened link maximum length is rate limited:
  # https://developer.twitter.com/en/docs/developer-utilities/configuration/api-reference/get-help-configuration
  client_conf = client.configuration

  # If one particular shortened link maximum length (HTTP versus HTTPS) is higher, use the higher value to be safe.
  link_limit = client_conf.short_url_length <= client_conf.short_url_length_https ? client_conf.short_url_length : client_conf.short_url_length_https

  # Truncate message if it exceeds limit
  if (message.length - link_limit) > TWEET_LIMIT
    message = message[0..(TWEET_LIMIT - link_limit)]
  end

  # Submit tweet
  client.update(message)
end

# Main
puts "Gwitter #{GWITTER_VERSION}"
log_write "Gwitter #{GWITTER_VERSION}"
puts 'Parsing config.yml...'
log_write 'Parsing config.yml...'
parse_config
puts 'config.yml successfully parsed.'
log_write 'config.yml successfully parsed.'
Thread.abort_on_exception = true if $debug_mode.to_s == 'true'
puts 'Starting web service...'
log_write 'Starting web service...'

# This class is where all the magic happens
class Gwitter < Sinatra::Base
  post '/payload' do
    #request.body.rewind
    log_write "Connection received from #{request.ip} for: #{request.path}"
    payload_body = request.body.read
    verify_signature(payload_body) unless $github_secret.nil?
    push_event = JSON.parse(payload_body)
    #push_event = JSON.parse(params[:payload])
    log_write "Payload contents: #{push_event.inspect}"
    message = handle_event push_event
    tweet(message) unless message.nil?
  end
end

# Configure WEBrick logging
access_log = File.new("#{$log_dir}/#{$log_name}", 'a')
logger = WEBrick::Log::new(access_log, WEBrick::Log::DEBUG)
logger.time_format = "[%m/%d/%Y %H:%M:%S]"
access_log.sync = true # Write logs immediately to disk. Otherwise, logs may be buffered until program terminates.

# Set PID file
pid_file = 'gwitter.pid'

# Check if JRuby is being used and $become_daemon is set
if RUBY_PLATFORM == 'java' && $become_daemon.to_s == 'true'
  puts 'JRuby does not support fork! Running in foreground...'
  log_write 'JRuby does not support fork! Running in foreground...'
  $become_daemon = false
end

# Use a CA certificate if available
ca_file = 'ca.crt' if File.exists?('ca.crt')

# Use TLS, disable weak ciphers, prevent CRIME (CVE-2012-4929), etc.
ssl_options = OpenSSL::SSL::OP_NO_SSLv3 + OpenSSL::SSL::OP_NO_SSLv2

# OpenSSL::SSL::OP_NO_COMPRESSION does not seem to be defined in JRuby 9.1.16.0 hence the check below.
ssl_options += OpenSSL::SSL::OP_NO_COMPRESSION if defined?(OpenSSL::SSL::OP_NO_COMPRESSION)
ssl_ciphers = 'TLSv1.2:!aNULL:!eNULL:!AES128'

# BindAddress does not work as expected, so use Host too.
if $use_ssl
  webrick_options = {
    :BindAddress          => $listen_host,
    :Host                 => $listen_host,
    :Port                 => $listen_port,
    :Logger               => logger,
    :AccessLog            => [[logger, WEBrick::AccessLog::COMBINED_LOG_FORMAT]],
    :DocumentRoot         => 'payload',
    :SSLEnable            => true,
    #:SSLVerifyClient      => OpenSSL::SSL::VERIFY_NONE,
    :SSLCertificate       => OpenSSL::X509::Certificate.new(File.open('server.crt').read),
    :SSLPrivateKey        => OpenSSL::PKey::RSA.new(File.open('server.key').read),
    :SSLCACertificateFile => ca_file,
    :SSLCertName          => [['CN',WEBrick::Utils::getservername]],
    :SSLOptions           => ssl_options,
    :SSLCiphers           => ssl_ciphers,
    :SSLVersion           => :TLSv1_2,
    :daemonize            => $become_daemon,
    :pid                  => File.expand_path(pid_file),
    :app                  => Gwitter
  }
else
  webrick_options = {
    :BindAddress          => $listen_host,
    :Host                 => $listen_host,
    :Port                 => $listen_port,
    :Logger               => logger,
    :AccessLog            => [[logger, WEBrick::AccessLog::COMBINED_LOG_FORMAT]],
    :DocumentRoot         => 'payload',
    :SSLEnable            => false,
    :daemonize            => $become_daemon,
    :pid                  => File.expand_path(pid_file),
    :app                  => Gwitter
  }
end

Rack::Server.start webrick_options
