/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router
{
  Buffer SimpleRouter::buildICMPPacket(uint8_t code, uint8_t type, const Buffer &IP_datagram)
  {
    Buffer output;
    //  |               IP datagram               |
    //  |   IP header   |        IP_payload       |
    //  |   20 bits     | ICMP header | content   |
    //                  |

    if (type == 0)
    {
      // Get ICMP packet
      std::copy(IP_datagram.begin() + sizeof(ip_hdr), IP_datagram.end(), output.begin());

      auto *icmp_hdr_ptr = (icmp_hdr *)output.data();

      // Set ICMP header
      icmp_hdr_ptr->icmp_code = code;
      icmp_hdr_ptr->icmp_type = type;
      icmp_hdr_ptr->icmp_sum = 0;
      icmp_hdr_ptr->icmp_sum = cksum((void *)output.data(), output.size());
    }
    else if (type == 3 || type == 11)
    {
      output = Buffer(sizeof(icmp_t3_hdr), 0);
      auto icmp_t3_hdr_ptr = (icmp_t3_hdr *)output.data();

      // Set ICMP header
      icmp_t3_hdr_ptr->icmp_code = code;
      icmp_t3_hdr_ptr->icmp_type = type;
      icmp_t3_hdr_ptr->icmp_sum = 0;

      // Copy IP header and 8 bytes of IP payload
      std::copy(IP_datagram.begin(), IP_datagram.begin() + sizeof(icmp_t3_hdr::data), icmp_t3_hdr_ptr->data);

      // Calculate checksum
      icmp_t3_hdr_ptr->icmp_sum = cksum((void *)output.data(), output.size());
    }
    else
    {
      std::cerr << "Sending wrong type of ICMP packet!" << std::endl;
    }
    return output;
  }

  void SimpleRouter::buildIPPacket()
  {
  }

  void SimpleRouter::buildARPPacket()
  {
  }

  void SimpleRouter::handleARPPacket(const Buffer &packet, const std::string &iface)
  {
  }

  void SimpleRouter::handleIPPacket(const Buffer &packet, const std::string &iface)
  {
    // Verify
    if (packet.size() < sizeof(ip_hdr))
    {
      std::cerr << "Received bad IPv4 packet!" << std::endl;
      return;
    }

    // Get header and payload
    auto ip_hdr_ptr = (ip_hdr *)packet.data();
    auto ip_payload = Buffer(packet.begin() + sizeof(ip_hdr), packet.end());

    // Verify IP packet size
    auto ip_packet_size = ntohs(ip_hdr_ptr->ip_len);
    if (ip_packet_size != packet.size())
    {
      std::cerr << "IPv4 packet size not match!" << std::endl;
      return;
    }

    // Verify checksum
    uint16_t checksum = cksum((void *)ip_hdr_ptr, sizeof(ip_hdr));
    if (checksum != 0XFFFF)
    {
      std::cerr << "IPv4 checksum miss detected!" << std::endl;
    }

    // Get destination interface
    auto dest_iface = findIfaceByIp(ntohl(ip_hdr_ptr->ip_dst));

    // Initialize output packet and interface
    Buffer output_ip_packet;

    // No TTL left
    if ((ip_hdr_ptr->ip_ttl == 0 && dest_iface) || (ip_hdr_ptr->ip_ttl == 1 && !dest_iface))
    {
      // Get ICMP packet
      Buffer output_icmp_packet = buildICMPPacket(0, 11, packet);

      // Set IP header
      Buffer output_ip_header(sizeof(ip_hdr), 0);
      auto output_ip_header_ptr = (ip_hdr *)output_ip_header.data();

      output_ip_header_ptr->ip_hl = 5;
      output_ip_header_ptr->ip_v = 4;
      output_ip_header_ptr->ip_tos = 0;
      output_ip_header_ptr->ip_len = htons(uint16_t(output_ip_header.size() + output_icmp_packet.size()));
      output_ip_header_ptr->ip_id = htons(uint16_t(rand()));
      output_ip_header_ptr->ip_off = htons(IP_DF);
      output_ip_header_ptr->ip_ttl = 64;
      output_ip_header_ptr->ip_p = ip_protocol_icmp;
      output_ip_header_ptr->ip_src = htonl(findIfaceByName(iface)->ip);
      output_ip_header_ptr->ip_dst = ip_hdr_ptr->ip_src;
      output_ip_header_ptr->ip_sum = cksum((void *)output_ip_header_ptr, sizeof(ip_hdr));

      // Build IP packet to send
      output_ip_packet.insert(output_ip_packet.begin(), output_ip_header.begin(), output_ip_header.end());
      output_ip_packet.insert(output_ip_packet.begin(), output_icmp_packet.begin(), output_icmp_packet.end());
    }
    // Iface found
    else if (dest_iface)
    {
      // Handle ICMP echo packet
      if (ip_hdr_ptr->ip_p == ip_protocol_icmp)
      {
        auto icmp_packet_ptr = (icmp_hdr *)ip_payload.data();
        if (icmp_packet_ptr->icmp_code == 0 && icmp_packet_ptr->icmp_type == 8)
        {
          // Get ICMP packet
          Buffer output_icmp_packet = buildICMPPacket(0, 0, packet);

          // Set IP header
          Buffer output_ip_header(sizeof(ip_hdr), 0);
          auto output_ip_header_ptr = (ip_hdr *)output_ip_header.data();
          output_ip_header_ptr->ip_hl = 5;
          output_ip_header_ptr->ip_v = 4;
          output_ip_header_ptr->ip_tos = 0;
          output_ip_header_ptr->ip_len = htons(uint16_t(output_ip_header.size() + output_icmp_packet.size()));
          output_ip_header_ptr->ip_id = htons(uint16_t(rand()));
          output_ip_header_ptr->ip_off = htons(IP_DF);
          output_ip_header_ptr->ip_ttl = 64;
          output_ip_header_ptr->ip_p = ip_protocol_icmp;
          output_ip_header_ptr->ip_src = htonl(findIfaceByName(iface)->ip);
          output_ip_header_ptr->ip_dst = ip_hdr_ptr->ip_src;
          output_ip_header_ptr->ip_sum = cksum((void *)output_ip_header_ptr, sizeof(ip_hdr));

          // Build IP packet to send
          output_ip_packet.insert(output_ip_packet.begin(), output_ip_header.begin(), output_ip_header.end());
          output_ip_packet.insert(output_ip_packet.begin(), output_icmp_packet.begin(), output_icmp_packet.end());
        }
        else
        {
          std::cerr << "Wrong ICMP packet received ought to be a echo!" << std::endl;
          return;
        }
      }
      // Handle TCP/UDP packet
      else
      {
        // Get ICMP packet
        Buffer output_icmp_packet = buildICMPPacket(3, 3, packet);

        // Set IP header
        Buffer output_ip_header(sizeof(ip_hdr), 0);
        auto output_ip_header_ptr = (ip_hdr *)output_ip_header.data();
        output_ip_header_ptr->ip_hl = 5;
        output_ip_header_ptr->ip_v = 4;
        output_ip_header_ptr->ip_tos = 0;
        output_ip_header_ptr->ip_len = htons(uint16_t(output_ip_header.size() + output_icmp_packet.size()));
        output_ip_header_ptr->ip_id = htons(uint16_t(rand()));
        output_ip_header_ptr->ip_off = IP_DF;
        output_ip_header_ptr->ip_ttl = 64;
        output_ip_header_ptr->ip_p = ip_protocol_icmp;
        output_ip_header_ptr->ip_src = htonl(findIfaceByName(iface)->ip);
        output_ip_header_ptr->ip_dst = ip_hdr_ptr->ip_src;
        output_ip_header_ptr->ip_sum = cksum((void *)output_ip_header_ptr, sizeof(ip_hdr));

        // Build IP packet to send
        output_ip_packet.insert(output_ip_packet.begin(), output_ip_header.begin(), output_ip_header.end());
        output_ip_packet.insert(output_ip_packet.begin(), output_icmp_packet.begin(), output_icmp_packet.end());
      }
    }
    // Forward
    else
    {
      // Rebuild IP packet
      Buffer new_ip_package(packet);
      auto new_ip_header_ptr = (ip_hdr *)new_ip_package.data();

      new_ip_header_ptr->ip_ttl -= 1;
      new_ip_header_ptr->ip_sum = 0;

      // Calculate checksum
      new_ip_header_ptr->ip_sum = cksum((void *)new_ip_header_ptr, sizeof(ip_hdr));

      output_ip_packet = new_ip_package;
    }
  }

  bool SimpleRouter::isBroadcast(Buffer MAC_addr)
  {
    for (auto byte : MAC_addr)
    {
      if (byte != 0xFF)
      {
        return false;
      }
    }
    return true;
  }

  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////
  // IMPLEMENT THIS METHOD
  void SimpleRouter::handlePacket(const Buffer &packet, const std::string &inIface)
  {
    std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

    const Interface *iface = findIfaceByName(inIface);
    if (iface == nullptr)
    {
      std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
      return;
    }

    std::cerr << getRoutingTable() << std::endl;

    if (packet.size() < sizeof(ethernet_hdr))
    {
      std::cerr << "Received bad Ethernet Packet, ignoring" << std::endl;
      return;
    }

    // Handle ethernet packet
    auto ethernet_header_ptr = (ethernet_hdr *)packet.data();

    // Transform destination and source MAC to Buffer
    Buffer dest_mac = Buffer(ethernet_header_ptr->ether_dhost, ethernet_header_ptr->ether_dhost + ETHER_ADDR_LEN);
    auto dest_iface = findIfaceByMac(dest_mac);

    if (!isBroadcast(dest_mac) && !dest_iface)
    {
      std::cerr << "The ethernet packet destination not found!" << std::endl;
      return;
    }

    // Get packet type(uint16_t)
    auto packet_type = ethertype(packet.data());

    // Get packet inside
    auto ethernet_payload = Buffer(packet.begin() + sizeof(ethernet_hdr), packet.end());

    switch (packet_type)
    {
    case ethertype_arp:
      handleARPPacket(ethernet_payload, inIface);
      break;
    case ethertype_ip:
      handleIPPacket(ethernet_payload, inIface);
      break;
    default:
      std::cerr << "Received ethernet packet of unknown type " << packet_type << "!" << std::endl;
      return;
    }
  }
  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////

  // You should not need to touch the rest of this code.
  SimpleRouter::SimpleRouter()
      : m_arp(*this)
  {
  }

  void
  SimpleRouter::sendPacket(const Buffer &packet, const std::string &outIface)
  {
    m_pox->begin_sendPacket(packet, outIface);
  }

  bool
  SimpleRouter::loadRoutingTable(const std::string &rtConfig)
  {
    return m_routingTable.load(rtConfig);
  }

  void
  SimpleRouter::loadIfconfig(const std::string &ifconfig)
  {
    std::ifstream iff(ifconfig.c_str());
    std::string line;
    while (std::getline(iff, line))
    {
      std::istringstream ifLine(line);
      std::string iface, ip;
      ifLine >> iface >> ip;

      in_addr ip_addr;
      if (inet_aton(ip.c_str(), &ip_addr) == 0)
      {
        throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
      }

      m_ifNameToIpMap[iface] = ip_addr.s_addr;
    }
  }

  void
  SimpleRouter::printIfaces(std::ostream &os)
  {
    if (m_ifaces.empty())
    {
      os << " Interface list empty " << std::endl;
      return;
    }

    for (const auto &iface : m_ifaces)
    {
      os << iface << "\n";
    }
    os.flush();
  }

  const Interface *
  SimpleRouter::findIfaceByIp(uint32_t ip) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip](const Interface &iface)
                              { return iface.ip == ip; });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  const Interface *
  SimpleRouter::findIfaceByMac(const Buffer &mac) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac](const Interface &iface)
                              { return iface.addr == mac; });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  const Interface *
  SimpleRouter::findIfaceByName(const std::string &name) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name](const Interface &iface)
                              { return iface.name == name; });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  void
  SimpleRouter::reset(const pox::Ifaces &ports)
  {
    std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

    m_arp.clear();
    m_ifaces.clear();

    for (const auto &iface : ports)
    {
      auto ip = m_ifNameToIpMap.find(iface.name);
      if (ip == m_ifNameToIpMap.end())
      {
        std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
        continue;
      }

      m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
    }

    printIfaces(std::cerr);
  }

} // namespace simple_router {
