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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router
{

  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////
  // IMPLEMENT THIS METHOD
  void
  ArpCache::periodicCheckArpRequestsAndCacheEntries()
  {
    std::cerr << "Periodly checking ARP requests and cache entries" << std::endl;
    std::vector<std::shared_ptr<ArpRequest>> to_remove;
    std::vector<Buffer> to_send;

    std::cerr << m_arpRequests.size() << " requests in queue!" << std::endl;

    for (auto request : m_arpRequests)
    {
      if (request->nTimesSent >= 5)
      {
        std::cerr << "Discarding request, too many tries, IP address:" << ipToString(request->ip) << std::endl;
        for (auto pending_packet : request->packets)
        {
          if (pending_packet.iface == "")
          {
            std::cerr << "Discarding self source packet" << std::endl;
            continue;
          }
          auto ip_packet = Buffer(pending_packet.packet.begin() + sizeof(ethernet_hdr), pending_packet.packet.end());
          auto icmp_packet = m_router.buildICMPPacket(1, 3, ip_packet);

          auto iface = m_router.findIfaceByName(pending_packet.iface);
          if (iface == nullptr)
          {
            std::cerr << "Discarding packet, interface not found" << std::endl;
            continue;
          }
          // Form IP header
          auto output_ip_packet = Buffer(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
          auto ip_hdr_ptr = (ip_hdr *)output_ip_packet.data();

          auto origin_ip_hdr_ptr = (ip_hdr *)ip_packet.data();
          auto dst_ip_n = origin_ip_hdr_ptr->ip_src;

          ip_hdr_ptr->ip_hl = 5;
          ip_hdr_ptr->ip_v = 4;
          ip_hdr_ptr->ip_tos = 0;
          ip_hdr_ptr->ip_len = htons(output_ip_packet.size());
          ip_hdr_ptr->ip_id = htons(uint16_t(rand()));
          ip_hdr_ptr->ip_off = htons(IP_DF);
          ip_hdr_ptr->ip_ttl = 64;
          ip_hdr_ptr->ip_p = ip_protocol_icmp;
          ip_hdr_ptr->ip_src = iface->ip;
          ip_hdr_ptr->ip_dst = dst_ip_n;
          ip_hdr_ptr->ip_sum = 0;
          ip_hdr_ptr->ip_sum = cksum((void *)output_ip_packet.data(), sizeof(ip_hdr));

          to_remove.push_back(request);
        }
      }
      else
      {
        std::cerr << "Sending ARP request, IP address:" << ipToString(request->ip) << std::endl;
        request->nTimesSent++;
        // Send ARP request
        auto arp_header = Buffer(sizeof(arp_hdr));
        auto ethernet_header = Buffer(sizeof(ethernet_hdr));

        auto arp_hdr_ptr = (arp_hdr *)arp_header.data();
        auto ethernet_hdr_ptr = (ethernet_hdr *)ethernet_header.data();

        auto iface = m_router.findIfaceByName(request->packets.front().iface);

        // Set ARP header
        arp_hdr_ptr->arp_hrd = htons(arp_hrd_ethernet);
        arp_hdr_ptr->arp_pro = htons(ethertype_ip);
        arp_hdr_ptr->arp_op = htons(arp_op_request);
        arp_hdr_ptr->arp_hln = ETHER_ADDR_LEN;
        arp_hdr_ptr->arp_pln = 0x04;
        arp_hdr_ptr->arp_tip = request->ip;
        arp_hdr_ptr->arp_sip = iface->ip;
        memset(arp_hdr_ptr->arp_tha, 0, ETHER_ADDR_LEN);
        memcpy(arp_hdr_ptr->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);

        // Set Ethernet header
        ethernet_hdr_ptr->ether_type = htons(ethertype_arp);

        auto broadcast_addr = std::vector<uint8_t>(ETHER_ADDR_LEN, 0xff);
        memcpy(ethernet_hdr_ptr->ether_dhost, broadcast_addr.data(), ETHER_ADDR_LEN);
        memcpy(ethernet_hdr_ptr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);

        Buffer output_ethernet_packet;
        output_ethernet_packet.insert(output_ethernet_packet.end(), ethernet_header.begin(), ethernet_header.end());
        output_ethernet_packet.insert(output_ethernet_packet.end(), arp_header.begin(), arp_header.end());

        m_router.sendPacket(output_ethernet_packet, iface->name);
        std::cerr << "Sent ARP request, IP address:" << ipToString(request->ip) << std::endl;
        print_hdrs(output_ethernet_packet);
      }
    }

    for (auto request : to_remove)
    {
      m_arpRequests.remove(request);
    }

    std::vector<std::shared_ptr<ArpEntry>> to_remove_entries;
    // Refresh cache entries
    for (auto entry : m_cacheEntries)
    {
      if (!entry->isValid)
      {
        to_remove_entries.push_back(entry);
      }
    }
    for (auto entry : to_remove_entries)
    {
      m_cacheEntries.remove(entry);
    }

    // Send packets to send
    for (auto packet : to_send)
    {
      m_router.sendIPPacket(packet);
    }
  }
  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////

  // You should not need to touch the rest of this code.

  ArpCache::ArpCache(SimpleRouter &router)
      : m_router(router), m_shouldStop(false), m_tickerThread(std::bind(&ArpCache::ticker, this))
  {
  }

  ArpCache::~ArpCache()
  {
    m_shouldStop = true;
    m_tickerThread.join();
  }

  std::shared_ptr<ArpEntry>
  ArpCache::lookup(uint32_t ip)
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    for (const auto &entry : m_cacheEntries)
    {
      if (entry->isValid && entry->ip == ip)
      {
        return entry;
      }
    }

    return nullptr;
  }

  std::shared_ptr<ArpRequest>
  ArpCache::queueRequest(uint32_t ip, const Buffer &packet, const std::string &iface)
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                [ip](const std::shared_ptr<ArpRequest> &request)
                                {
                                  return (request->ip == ip);
                                });

    if (request == m_arpRequests.end())
    {
      request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
    }

    // Add the packet to the list of packets for this request
    (*request)->packets.push_back({packet, iface});
    return *request;
  }

  void
  ArpCache::removeRequest(const std::shared_ptr<ArpRequest> &entry)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_arpRequests.remove(entry);
  }

  std::shared_ptr<ArpRequest>
  ArpCache::insertArpEntry(const Buffer &mac, uint32_t ip)
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto entry = std::make_shared<ArpEntry>();
    entry->mac = mac;
    entry->ip = ip;
    entry->timeAdded = steady_clock::now();
    entry->isValid = true;
    m_cacheEntries.push_back(entry);

    auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                [ip](const std::shared_ptr<ArpRequest> &request)
                                {
                                  return (request->ip == ip);
                                });
    if (request != m_arpRequests.end())
    {
      return *request;
    }
    else
    {
      return nullptr;
    }
  }

  void
  ArpCache::clear()
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    m_cacheEntries.clear();
    m_arpRequests.clear();
  }

  void
  ArpCache::ticker()
  {
    while (!m_shouldStop)
    {
      // TODO: change to 1 seconds
      std::this_thread::sleep_for(std::chrono::seconds(1));

      {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto now = steady_clock::now();

        for (auto &entry : m_cacheEntries)
        {
          if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO))
          {
            entry->isValid = false;
          }
        }

        periodicCheckArpRequestsAndCacheEntries();
      }
    }
  }

  std::ostream &
  operator<<(std::ostream &os, const ArpCache &cache)
  {
    std::lock_guard<std::mutex> lock(cache.m_mutex);

    os << "\nMAC            IP         AGE                       VALID\n"
       << "-----------------------------------------------------------\n";

    auto now = steady_clock::now();
    for (const auto &entry : cache.m_cacheEntries)
    {

      os << macToString(entry->mac) << "   "
         << ipToString(entry->ip) << "   "
         << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
         << entry->isValid
         << "\n";
    }
    os << std::endl;
    return os;
  }

} // namespace simple_router
