require 'rest_client'
require 'nokogiri'
require 'date'

module Memento

  class Call
    attr_reader :to_uri, :to_name, :from_uri, :from_name, :answered, :outgoing, :start_time, :answered_time, :end_time

    def initialize xmlnode
      @to_uri = xmlnode.xpath('//to/URI').text
      @to_name = xmlnode.xpath('//to/name').text
      @from_uri = xmlnode.xpath('//from/URI').text
      @from_name = xmlnode.xpath('//from/name').text
      @answered = (xmlnode.xpath('//answered').text == "1") or (xmlnode.xpath('//answered').text == "true")
      @outgoing = (xmlnode.xpath('//outgoing').text == "1") or (xmlnode.xpath('//answered').text == "true")
      @start_string = DateTime.parse(xmlnode.xpath('//start-time').text)
      @start_time = DateTime.parse(xmlnode.xpath('//start-time').text).to_time
      @answered_time = DateTime.parse(xmlnode.xpath('//answer-time').text).to_time if @answered
      @end_time = DateTime.parse(xmlnode.xpath('//end-time').text).to_time if @answered
    end

    def ringing_time
      if @answered_time
        @answered_time - @start_time
      else
        0
      end
    end

    def duration
      if @end_time
        @end_time - @answered_time
      else
        0
      end
    end

    def to_s
      if @answered and @outgoing
        "Call to #{to_name} (#{to_uri}) made at #{@start_string} and lasting #{duration}"
      elsif @answered and not @outgoing
        "Call from #{from_name} (#{from_uri}) received at #{@start_string} and lasting #{duration}"
      elsif @outgoing
        "Unanswered call to #{to_name} (#{to_uri}) made at #{@start_string}"
      else
        "Unanswered call from #{from_name} (#{from_uri}) received at #{@start_string}"
      end
    end
  end

  class CallList
    def initialize xmlnode
      @calls = xmlnode.xpath("//calls/call").collect { |call_xml| Call.new call_xml }
    end

    def [](n)
      @calls[n]
    end

    def size
      @calls.size
    end

    def to_s
      if @calls.empty?
        "No calls"
      else
        @calls.collect { |call| call.to_s }.join("\n")
      end
    end
  end


  class Client
    def initialize schema_path, memento_server, sip_uri, username, password
      @@schema = Nokogiri::XML::RelaxNG(File.open(schema_path))
      @resource = RestClient::Resource.new "https://#{memento_server}/org.projectclearwater.call-list/users/#{sip_uri}/call-list.xml", :verify_ssl => false, :user => username, :password => password
    end

    def get_call_list debug=false
      response = @resource.get "Accept-Encoding" => "gzip"
      puts response.headers if debug
      puts response.body if debug
      xml = Nokogiri.XML(response.body, nil, nil, Nokogiri::XML::ParseOptions::PEDANTIC)
      fail xml.errors.to_s unless xml.errors.empty?
      fail @@schema.validate(xml).to_s unless @@schema.valid? xml
      fail "Response is not gzip-encoded!" if (response.headers[:content_encoding] != "gzip")
      fail "Content-Type is #{response.headers[:content_type]}, not 'application/vnd.projectclearwater.call-list+xml'" unless (response.headers[:content_type] == "application/vnd.projectclearwater.call-list+xml")
      CallList.new xml
    end
  end
end

