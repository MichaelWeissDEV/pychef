Packets, PCAP, and PCAPNG
=========================

PyChef decodes common network layers into ordinary Python dictionaries without
requiring Wireshark, tshark, or a packet library at runtime. Unknown data remains
available as bytes so callers can inspect it themselves.

Read a capture
--------------

.. code-block:: python

   from pychef import read_capture

   capture = read_capture("challenge.pcap")
   print(capture["format"], len(capture["packets"]))

   for packet in capture["packets"]:
       print(packet["timestamp"], packet.get("decoded"))

``read_capture`` reads a path. ``parse_capture`` accepts bytes and auto-detects
classic PCAP and PCAPNG. ``parse_pcap`` and ``parse_pcapng`` select a format
explicitly.

Supported layers
----------------

The parsers currently understand:

* Ethernet, 802.1Q/802.1ad VLAN, Linux cooked v1/v2, loopback, and raw IP links;
* ARP, IPv4, IPv6, and common IPv6 extension headers;
* ICMP, TCP including options, and UDP;
* DNS wire messages including compressed names and common records;
* recognizable HTTP messages and TLS record headers.

An unsupported link type or application protocol is not guessed. Raw payload
bytes remain in the result.

Parse individual layers
-----------------------

Use the most specific parser when the input layer is known:

.. code-block:: python

   from pychef import parse_ethernet_frame, parse_ipv4_packet, parse_tcp_segment

   ethernet = parse_ethernet_frame(frame_bytes)
   ipv4 = parse_ipv4_packet(ip_packet_bytes)
   tcp = parse_tcp_segment(tcp_segment_bytes)

Available entry points include ``parse_packet``, ``parse_ethernet_frame``,
``parse_arp_packet``, ``parse_ipv4_packet``, ``parse_ipv6_packet``,
``parse_icmp_message``, ``parse_tcp_segment``, ``parse_udp_datagram``, and
``parse_dns_message``. Their exact signatures are in :doc:`api/packets`.

Use packet parsers in pipelines
-------------------------------

.. code-block:: python

   from pychef import Pipeline

   first_source = (
       Pipeline()
       .parse_capture()
       .select("packets", 0, "decoded", "network", "source")
   )
   print(first_source(pcap_bytes))

JSON output
-----------

Packet dictionaries deliberately retain bytes. Standard ``json.dumps`` cannot
serialize them. ``json_safe`` recursively converts every byte string into a
``{"hex": ..., "length": ...}`` object. ``packet_json`` returns formatted JSON.

.. code-block:: python

   from pychef import json_safe, packet_json

   serializable = json_safe(capture)
   document = packet_json(capture, indent=2)

Resource limits and malformed input
-----------------------------------

Capture readers enforce maximum file size, packet count, and packet size.
Lengths, offsets, DNS pointers, and capture blocks are validated. A per-packet
decode failure is retained with the captured bytes instead of discarding the
packet. Adjust limits only for trusted captures and only as far as necessary.
