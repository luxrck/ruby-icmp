#!/usr/bin/ruby

require "socket"


class ICMP
  def initialize
    @connection = Socket.new(Socket::PF_INET, Socket::SOCK_RAW, Socket::IPPROTO_ICMP)
    @iseq = 1
  end


  def self.echo(host, msg)
    Packet.parse(ICMP.send(host, Packet.new(type: :ping, msg:msg, iseq:0).serialize))
  end

  def echo(host, msg)
    Packet.parse(self.send(host, Packet.new(type: :ping, msg:msg, iseq:@iseq).serialize))
  end


  def self.timestamp(host)
    Packet.parse(ICMP.send(host, Packet.new(type: :timestamp, iseq:0).serialize))
  end

  def timestamp(host)
    Packet.parse(self.send(host, Packet.new(type: :timestamp, iseq:@iseq).serialize))
  end


  # Obsolete: This message type is specified in [RFC0950] and was meant to provide
  # a means to obtain the subnet mask.  However, other mechanisms (such
  # as DHCP [RFC2131]) have superseded this message type for the purpose
  # of host configuration.
  # https://tools.ietf.org/html/rfc6918#section-2.4
  def self.netmask(host)
    Packet.parse(ICMP.send(host, Packet.new(type: :netmask, iseq:0).serialize))
  end

  def netmask(host)
    Packet.parse(ICMP.send(host, Packet.new(type: :netmask, iseq:@iseq).serialize))
  end


  def self.send(host, msg, connection=nil)
    connection = Socket.new(Socket::PF_INET, Socket::SOCK_RAW, Socket::IPPROTO_ICMP) unless connection
    connection.send(msg, 0, Socket.sockaddr_in(0, host))
    resp = connection.recvfrom(1500).first
    connection.close unless connection.closed?
    resp
  end

  def send(host, msg)
    ICMP.send(host, msg, @connection)
  end


  class Packet
    attr_accessor :typeid, :type, :code, :cksm, :idnt, :iseq
    attr_accessor :msg
    attr_accessor :tnow, :trec, :tttl
    attr_accessor :mask

    def initialize(**kw)
      typetb = {
        :ping => 8, :pong => 0,
        :timestamp => 13, :timestamp_resp => 14,
        :netmask => 17, :netmask_resp => 18
        }
      raise TypeError unless kw[:type]
      self.type = kw[:type]
      self.typeid = typetb[self.type]
      self.code = kw[:code] || 0
      self.cksm = kw[:cksm] || 0
      self.idnt = kw[:idnt] || Process.pid & 0xffff
      self.iseq = kw[:iseq] || 0

      self.msg = kw[:msg] || ""

      self.tnow = kw[:tnow] || 0
      self.trec = kw[:trec] || 0
      self.tttl = kw[:tttl] || 0

      self.mask = kw[:mask] || 0
    end


    def serialize
      header = [self.typeid, self.code, self.cksm, self.idnt, self.iseq].pack("C2 S3")
      case self.type
      when :ping, :pong
        body = [self.msg].pack("A*")
      when :timestamp, :timestamp_resp
        tnow = Time.now.to_i
        trec = 0
        tttl = 0
        body = [tnow, trec, tttl].pack("N3")
      when :netmask, :netmask_resp
        mask = 0
        body = [mask].pack("N1")
      end

      self.cksm = Packet.checksum(header + body)
      header = [self.typeid, self.code, self.cksm, self.idnt, self.iseq].pack("C2 S3")
      return header + body
    end


    def self.parse(data)
      typetb = {
        8 => :ping, 0 => :pong,
        13 => :timestamp, 14 => :timestamp_resp,
        17 => :netmask, 18 => :netmask_resp
        }

      # Skip IP Header
      data = data[20..-1]

      typeid = data.unpack("C")[0]

      type = typetb[typeid]
      raise TypeError unless type
      typeid, code, cksm, idnt, iseq = data.unpack("C2 S3")
      m = Packet.new type:type, code:code, cksm:cksm, idnt:idnt, iseq:iseq

      data = data[8..-1]
      case m.type
      when :ping, :pong
        m.msg, = data.unpack("A*")
      when :timestamp, :timestamp_resp
        m.tnow, mtrec, m.tttl = data.unpack("N3")
      when :netmask, :netmask_resp
        m.mask, = data.unpack("N1")
      end
      m
    end


    def self.checksum(data)
      s = data.each_byte.each_slice(2).inject(0) do |r, a|
        r += a[0].ord + ((a.length == 2 ? a[1].ord : 0) << 8)
      end
      (~s - 1) & 0xffff
    end
  end
end
