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

require 'json'
require 'openssl'
require 'sinatra'
require 'twitter'
require 'webrick'
require 'webrick/https'
require 'yaml'

GWITTER_VERSION = '1.0'

def parse_config
  begin
    config_file = YAML.load_file('config.yml')
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
  $debug_mode = config_file['debug_mode']

  # Validate values
  unless $listen_host.nil?
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
  $debug_mode = false if $debug_mode.nil?

  if $use_ssl.to_s != 'true' && $use_ssl.to_s != 'false'
    puts 'use_ssl value should be set to either \'true\' or \'false\'.'
    exit!
  end

  if $debug_mode.to_s != 'true' && $debug_mode.to_s != 'false'
    puts 'debug_mode value should be set to either \'true\' or \'false\'.'
    exit!
  end
end

def valid_hostname?(hostname)
  if hostname =~ /^(?:[a-zA-Z0-9]+(?:\-*[a-zA-Z0-9])*\.)+[a-zA-Z]{2,6}$/i
    return true
  else
    return false
  end
end

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

def log_write(text)
  log_dir = 'logs'
  Dir.mkdir(log_dir) unless File.exists?(log_dir)
  log_file = File.open("#{log_dir}/gwitter.log", 'a')
  log_file.puts "#{Time.now.asctime} - #{text}"
  log_file.close
  rescue
    puts 'Unable to write log file!'
end

puts "Gwitter #{GWITTER_VERSION}"
log_write "Gwitter #{GWITTER_VERSION}"
puts 'Parsing config.yml...'
log_write 'Parsing config.yml...'
parse_config
puts 'config.yml successfully parsed.'
log_write 'config.yml successfully parsed.'
puts 'Starting web service...'
log_write 'Starting web service...'

set :bind, $listen_host unless $listen_host.nil?
set :port, $listen_port

post '/payload' do
  #request.body.rewind
  payload_body = request.body.read
  verify_signature(payload_body) unless $github_secret.nil?
  push = JSON.parse(payload_body)
  #push = JSON.parse(params[:payload])
  puts push.inspect
  # ToDo: Continue to grok payload here and formulate Twitter post accordingly based on event(s)
  # Also use WEBrick and OpenSSL to read in certs and handle SSL connections
end

def verify_signature(payload_body)
  signature = 'sha1=' + OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha1'), $github_secret, payload_body)
  return halt 500, "Signatures didn't match!" unless Rack::Utils.secure_compare(signature, request.env['HTTP_X_HUB_SIGNATURE'])
end
