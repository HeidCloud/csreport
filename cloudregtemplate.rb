#!/usr/bin/env ruby 
#
# CloudStack template register
# A script from Rightscale Services
# Questions:
# Brett@rightscale.com 
# Ove@rightscale.com
#
# Uses CloudStack API for Registration of new template from an exising image download url
#
#

require 'rubygems'
require 'nokogiri'
require 'openssl'
require 'base64'
require 'cgi'
require 'yaml'
require 'uri'

begin
config = YAML::parse(File.open("reg.yml")).transform
rescue
puts "Can't find reg.yml file - Please create first"
exit
end

# Credentials & Endpoint are read from ./creds.yml
@CLOUD = Hash.new
@CLOUD.merge!(config)

# API calls that will get executed against the endpoint
# Some of these commands require you to have DOMAIN ADMIN priviledges!

api_calls = "#{@CLOUD['command']}" + "&name=#{@CLOUD['name']}" + "&displaytext=#{@CLOUD['displaytext']}" + "&url=#{@CLOUD['url']}" + "&checksum=#{@CLOUD['checksum']}" + "&zoneid=#{@CLOUD['zoneid']}" + "&ostypeid=#{@CLOUD['ostypeid']}" + "&hypervisor=#{@CLOUD['hypervisor']}" + "&format=#{@CLOUD['format']}"

puts api_calls

# XML Template
@XML_TEMPLATE = File.dirname(__FILE__) + "/cloudstack.xslt"

# Build a CloudStack query string and sign it.
#
def query(string)
  api_param = "apiKey=#{@CLOUD['api_key']}"
  cmd_param = "command=#{string}"

  sorted_array = []

  "#{api_param}&#{cmd_param}".split('&').sort.each do |arg|
    (cmd, value) = arg.split('=')
    puts "cmd:|#{cmd}|, value:|#{value}|"
    enc = URI.escape(value, Regexp.new("[^#{URI::PATTERN::UNRESERVED}]"))
    sorted_array << "#{cmd}=#{enc}"
  end

  final_string = sorted_array.join('&')
  puts "final: |#{final_string}|"

  sign(@CLOUD['api_secret'], final_string)
end

# Return Signature
#
def sign(secret,string)
  CGI.escape(Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, secret, string.downcase)).chomp)
end

def callapi(command)
  # TODO: Send command & check for success response.  Add retry?
  cmd="#{@CLOUD['api_endpoint']}" + "command=#{command}" +
    "&apiKey=#{@CLOUD['api_key']}" + "&signature=#{query(command)}"
  puts cmd
  #res_code=`curl -sw %{http_code} '#{cmd}'`
  #res_code unless res_code.match("does not exist")
  puts `curl -vv '#{cmd}' 2>&1`
end

def dumpxml(command)
  rawxml = callapi(command)
  xml = Nokogiri::XML(rawxml)
  xml.xpath("//listcapabilitiesresponse/capability").each do |node|
    reportdate = Time.now.strftime("%m-%d-%Y %H:%M:%S")
    node.add_child "<apiname>#{@CLOUD['api_name']}</apiname>" if @CLOUD['api_name']
    node.add_child "<cloudapiendpoint>#{@CLOUD['api_endpoint']}</cloudapiendpoint>"
    node.add_child "<reportdate>#{reportdate}</reportdate>"

  end
  xslt = Nokogiri::XSLT(File.read(@XML_TEMPLATE))
  puts xslt.transform(xml)
end


# Cycle through each of the API calls.
# Build a properly formatted API string, sign it, call it & transform the results.

dumpxml(api_calls)
