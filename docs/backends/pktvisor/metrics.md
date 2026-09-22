# Pktvisor metrics

The metrics each handler produces, grouped by handler type. A handler emits a
metric only when the metric group it belongs to is enabled; see
[metric groups](handlers.md#pktvisor-handlers) for how to enable and disable them,
and each handler's own page for which groups it supports.

The Orb metrics currently provided come from the various supported pktvisor handlers and are listed here by handler.

For handlers that have metric groups, the metric groups that must be enabled for the metric to exist are listed in "Metric Groups" column. `any group*` means that the metric will exist for any valid metric groups that is enabled.

## DHCP Metrics
[Check how to activate dhcp metrics](handler_dhcp.md)

| Metric                                                                                   | Prometheus Name                |
|------------------------------------------------------------------------------------------|--------------------------------|
| Quantiles of all DHCP wire packets (combined ingress and egress) in packets per second   | dhcp_rates_total               |
| Total sum of all DHCP wire packets (combined ingress and egress) in packets per second   | dhcp_rates_total_sum           |
| Count of all DHCP wire packets (combined ingress and egress) in packets per second       | dhcp_rates_total_count         |
| Quantiles of all DHCP wire packets before filtering per second                           | dhcp_rates_events              |
| Total sum of all DHCP wire packets before filtering per second                           | dhcp_rates_events_sum          |
| Count of all DHCP wire packets before filtering per second                               | dhcp_rates_events_count        |
| Top DHCP servers                                                                         | dhcp_top_servers               |
| Top DHCP clients                                                                         | dhcp_top_clients               |
| Total DHCP packets with message type ACK                                                 | dhcp_wire_packets_ack          |
| Total DHCPv6 packets with message type ADVERTISE                                         | dhcp_wire_packets_advertise    |
| Total DHCP wire packets that were sampled for deep inspection                            | dhcp_wire_packets_deep_samples |
| Total DHCP packets with message type DISCOVER                                            | dhcp_wire_packets_discover     |
| Total DHCP wire packets events                                                           | dhcp_wire_packets_events       |
| Total DHCP/DHCPv6 wire packets seen that did not match the configured filter(s) (if any) | dhcp_wire_packets_filtered     |
| Total DHCP packets with message type OFFER                                               | dhcp_wire_packets_offer        |
| Total DHCPv6 packets with message type REPLY                                             | dhcp_wire_packets_reply        |
| Total DHCP packets with message type REQUEST                                             | dhcp_wire_packets_request      |
| Total DHCPv6 packets with message type REQUEST                                           | dhcp_wire_packets_request_v6   |
| Total DHCPv6 packets with message type SOLICIT                                           | dhcp_wire_packets_solicit      |
| DORA packet counts                                                                       | dhcp_wire_packets_total        |

## DNS Metrics
[Check how to activate/deactivate dns metrics](handler_dns.md)

| Metric                                                                                                                 | Prometheus Name                     | Metric Groups |
|------------------------------------------------------------------------------------------------------------------------|-------------------------------------|---------------|
| Quantiles of all DNS wire packets before filtering per second	                                                         | dns_rates_observed_pps              | any group*    |
| Count of all DNS wire packets before filtering per second		                                                            | dns_rates_observed_pps_count        | any group*    |
| Total sum of rates for DNS packets processed by policy	                                                                | dns_rates_observed_pps_sum          | any group*    |
| Total DNS transactions (query/reply pairs) with the AD flag set in the response                                        | dns_authenticated_data_xacts        | counters      |
| Total DNS transactions (query/reply pairs) with the AA flag set in the response                                        | dns_authoritative_answer_xacts      | counters      |
| Cardinality of unique QNAMES, both ingress and egress	                                                                 | dns_cardinality_qname               | cardinality   |
| Total DNS transactions (query/reply pairs) with the CD flag set in the query                                           | dns_checking_disabled_xacts         | counters      |
| Total DNS wire packets that were sampled for deep inspection                                                           | dns_deep_sampled_packets            | any group*    |
| Total DNS transactions (query/reply pairs) received over DNSCrypt over TCP                                             | dns_dnscrypt_tcp_xacts              | counters      |
| Total DNS transactions (query/reply pairs) received over DNSCrypt over UDP                                             | dns_dnscrypt_udp_xacts              | counters      |
| Total DNS transactions (query/reply pairs) received over DNS over HTTPS                                                | dns_doh_xacts                       | counters      |
| Total DNS transactions (query/reply pairs) received over DNS over QUIC                                                 | dns_doq_xacts                       | counters      |
| Total DNS transactions (query/reply pairs) received over DNS over TLS                                                  | dns_dot_xacts                       | counters      |
| Total DNS transactions (query/reply pairs) with the EDNS Client Subnet option set                                      | dns_ecs_xacts                       | counters      |
| Total DNS wire packets seen that did not match the configured filter(s) (if any)                                       | dns_filtered_packets                | counters      |
| Total DNS transactions (query/reply pairs) received over IPv4                                                          | dns_ipv4_xacts                      | counters      |
| Total DNS transactions (query/reply pairs) received over IPv6                                                          | dns_ipv6_xacts                      | counters      |
| Total DNS transactions (query/reply pairs) flagged as reply with response code NOERROR but with an empty answers section | dns_nodata_xacts                    | counters      |
| Total DNS transactions (query/reply pairs) flagged as reply with response code NOERROR                                   | dns_noerror_xacts                   | counters      |
| Total DNS transactions (query/reply pairs) flagged as reply with response code NXDOMAIN                                  | dns_nxdomain_xacts                  | counters      |
| Total DNS wire packets events                                                                                          | dns_observed_packets                | any group*    |
| Total number of DNS responses that do not have a corresponding query                                                   | dns_orphan_responses                | counters      |
| Total DNS transactions (query/reply pairs) flagged as reply with response code REFUSED                                   | dns_refused_xacts                   | counters      |
| Quantiles of ratio of packet sizes in a DNS transaction (reply/query)                                                  | dns_response_query_size_ratio       | top_size      |
| Count of ratio of packet sizes in a DNS transaction (reply/query)                                                      | dns_response_query_size_ratio_count | top_size      |
| Total sum of ratio of packet sizes in a DNS transaction (reply/query)                                                  | dns_response_query_size_ratio_sum   | top_size      |
| Total DNS transactions (query/reply pairs) flagged as reply with response code SRVFAIL                                   | dns_srvfail_xacts                   | counters      |
| Total DNS transactions (query/reply pairs) received over TCP                                                           | dns_tcp_xacts                       | counters      |
| Total number of DNS queries that timed out                                                                             | dns_timeout_queries                 | counters      |
| Top ASNs by ECS                                                                                                        | dns_top_asn_ecs_xacts               | top_ecs       |
| Top EDNS Client Subnet (ECS) observed in DNS transaction                                                               | dns_top_ecs_xacts                   | top_ecs       |
| 	     Top GeoIP ECS locations                                                                                          | dns_top_geo_loc_ecs_xacts           | top_ecs       |
| 	  Top QNAMES with result code NOERROR and empty answer section                                                        | dns_top_nodata_xacts                | top_rcodes    |
| Top QNAMES with result code NOERROR                                                                                    | dns_top_noerror_xacts               | top_rcodes    |
| 	    Top QNAMES with result code NXDOMAIN                                                                              | dns_top_nxdomain_xacts              | top_rcodes    |
| 	      Top QNAMES, aggregated at a depth of two labels                                                                 | dns_top_qname2_xacts                | top_qnames    |
| Top QNAMES, aggregated at a depth of three labels                                                                      | dns_top_qname3_xacts                | top_qnames    |
| Top QNAMES by response volume in bytes                                                                                 | dns_top_response_bytes              | top_size      |
| Top query types                                                                                                        | dns_top_qtype_xacts                 | top_qtypes    |
| 	    Top result codes                                                                                                  | dns_top_rcode_xacts                 | top_rcodes    |
| 	         Top QNAMES with result code REFUSED                                                                          | dns_top_refused_xacts               | top_rcodes    |
| Top QNAMES in transactions where host is the server and transaction speed is slower than p90                           | dns_top_slow_xacts                  | xact_times    |
| 	    Top QNAMES with result code SRVFAIL                                                                               | dns_top_srvfail_xacts               | top_rcodes    |
| 	     Top UDP source port on the query side of a transaction                                                           | dns_top_udp_ports_xacts             | top_ports     |
| Total DNS transactions (query/reply pairs) received over UDP                                                           | dns_udp_xacts                       | counters      |
| Cumulative counters of transaction timing (query/reply pairs) in microseconds                                          | dns_xact_histogram_us_bucket        | xact_times    |
| Counts of transaction timing (query/reply pairs) in microseconds                                                       | dns_xact_histogram_us_count         | xact_times    |
| Rate of all DNS transaction (reply/query) per second                                                                   | dns_xact_rates                      | quantiles     |
| Count of all DNS transaction (reply/query) per second                                                                  | dns_xact_rates_count                | quantiles     |
| Total sum of all DNS transaction (reply/query) per second                                                              | dns_xact_rates_sum                  | quantiles     |
| Quantiles of transaction timing (query/reply pairs) in microseconds                                                    | dns_xact_time_us                    | xact_times    |
| Count of transaction timing (query/reply pairs) in microseconds                                                        | dns_xact_time_us_count              | xact_times    |
| Total sum of transaction timing (query/reply pairs) in microseconds                                                    | dns_xact_time_us_sum                | xact_times    |
| Total DNS transactions (query/reply pairs)                                                                             | dns_xacts                           | counters      |

| Metric                                                                                                             | Prometheus Name                       | Metric Groups                   |
|--------------------------------------------------------------------------------------------------------------------|---------------------------------------|---------------------------------|
| Cardinality of unique QNAMES, both ingress and egress                                                              | dns_cardinality_qname               | cardinality                     |
| Quantiles of rates for DNS packets processed by policy                                                             | dns_rates_total                     | any group*                      |
| Total sum of rates for DNS packets processed by policy                                                             | dns_rates_total_sum                | any group*                      |
| Count of rates for DNS packets processed by policy                                                                 | dns_rates_total_count              | any group*                      |
| Quantiles of all DNS wire packets before filtering per second                                                      | dns_rates_events                    | any group*                      |
| Total sum of all DNS wire packets before filtering per second                                                      | dns_rates_events_sum               | any group*                      |
| Count of all DNS wire packets before filtering per second                                                          | dns_rates_events_count             | any group*                      |
| Top ECS ASNs                                                                                                       | dns_top_asn_ecs                    | top_ecs                         |
| Top ECS GeoIP locations                                                                                            | dns_top_geoLoc_ecs                 | top_ecs                         |
| Top QNAMES with response code NOERROR and no data in the response (NODATA)                                         | dns_top_nodata                      | top_qnames                      |
| Top QNAMES with response code NXDOMAIN                                                                             | dns_top_nxdomain                    | top_qnames                      |
| Top QNAMES by response volume                                                                                      | dns_top_qname_by_resp_bytes      | top_qnames_details + top_qnames |
| Top QNAMES with result code NOERROR                                                                                | dns_top_noerror                     | top_qname_details + top_qnames  |
| Top QNAMES aggregated at a depth of two labels                                                                     | dns_top_qname2                      | top_qnames                      |
| Top QNAMES aggregated at a depth of three labels                                                                   | dns_top_qname3                      | top_qnames                      |
| Top QTYPEs                                                                                                         | dns_top_qtype                       | any group*                      |
| Top EDNS Client Subnets (ECS)                                                                                      | dns_top_query_ecs                  | top_ecs                         |
| Top RCODEs                                                                                                         | dns_top_rcode                       | any group*                      |
| Top QNAMES with response code REFUSED                                                                              | dns_top_refused                     | top_qnames                      |
| Top QNAMES with response code SRVFAIL                                                                              | dns_top_srvfail                     | top_qnames                      |
| Top UDP source ports of DNS queries                                                                                | dns_top_udp_ports                  | top_ports                       |
| Total DNS wire packets sampled for deep inspection                                                                 | dns_wire_packets_deep_samples     | any group*                      |
| Count of DNS packets sent to policy                                                                                | dns_wire_packets_events            | any group*                      |
| Count of DNS packets filtered out by policy                                                                        | dns_wire_packets_filtered          | counters                        |
| Count of DNS packets received over IPv4                                                                            | dns_wire_packets_ipv4              | counters                        |
| Count of DNS packets received over IPv6                                                                            | dns_wire_packets_ipv6              | counters                        |
| Count of DNS packets flagged as reply and identified as NODATA                                                     | dns_wire_packets_nodata            | counters                        |
| Count of DNS packets flagged as reply with response code NOERROR                                                   | dns_wire_packets_noerror           | counters                        |
| Count of DNS packets flagged as reply with response code NXDOMAIN                                                  | dns_wire_packets_nxdomain          | counters                        |
| Count of DNS packets flagged as query                                                                              | dns_wire_packets_queries           | counters                        |
| Count of DNS packets with EDNS Client Subnet (ECS) option set                                                      | dns_wire_packets_query_ecs        | counters + top_ecs              |
| Count of DNS packets flagged as reply with response code REFUSED                                                   | dns_wire_packets_refused           | counters                        |
| Count of DNS packets flagged as reply                                                                              | dns_wire_packets_replies           | counters                        |
| Count of DNS packets flagged as reply with response code SRVFAIL                                                   | dns_wire_packets_srvfail           | counters                        |
| Count of DNS packets received over TCP                                                                             | dns_wire_packets_tcp               | counters                        |
| Count of DNS packets matched by policy                                                                             | dns_wire_packets_total             | counters                        |
| Count of DNS packets received over UDP                                                                             | dns_wire_packets_udp               | counters                        |
| Total DNS wire packets received over DNS over HTTPS                                                                | dns_wire_packets_doh               | counters (dnstap)               |
| Total DNS wire packets received over DNS over TLS                                                                  | dns_wire_packets_dot               | counters (dnstap)               |
| Total number of DNS transactions that timed out                                                                    | dns_xact_counts_timed_out         | dns_transaction                 |
| Total DNS transactions (query/reply pairs)                                                                         | dns_xact_counts_total              | dns_transaction                 |
| Cumulative counters for the buckets of transaction timing (query/reply pairs) when host is server, in microseconds | dns_xact_in_histogram_us_bucket  | dns_transaction + histograms                      |
| Count of transaction timing (query/reply pairs) when host is server, in microseconds                               | dns_xact_in_histogram_us_count   | dns_transaction + histograms                      |
| Cumulative counters for the buckets of transaction timing (query/reply pairs) when host is client, in microseconds | dns_xact_out_histogram_us_bucket | dns_transaction + histograms                      |
| Count of transaction timing (query/reply pairs) when host is client, in microseconds                               | dns_xact_out_histogram_us_count  | dns_transaction + histograms                      |
| Quantiles of transaction timing (query/reply pairs) when host is server, in microseconds                           | dns_xact_in_quantiles_us          | dns_transaction + quantiles                 |
| Total sum of transaction timing (query/reply pairs) when host is server, in microseconds                           | dns_xact_in_quantiles_us_sum     | dns_transaction + quantiles                |
| Count of transaction timing (query/reply pairs) when host is server, in microseconds                               | dns_xact_in_quantiles_us_count   | dns_transaction + quantiles                |
| Top QNAMES in transactions where host is the server and transaction speed is slower than p90                       | dns_xact_in_top_slow              | dns_transaction                 |
| Total ingress DNS transactions (host is server)                                                                    | dns_xact_in_total                  | dns_transaction                 |
| Quantiles of transaction timing (query/reply pairs) when host is client, in microseconds                           | dns_xact_out_quantiles_us         | dns_transaction + quantiles                |
| Total sum of transaction timing (query/reply pairs) when host is client, in microseconds                           | dns_xact_out_quantiles_us_sum    | dns_transaction + quantiles                |
| Count of transaction timing (query/reply pairs) when host is client, in microseconds                               | dns_xact_out_quantiles_us_count  | dns_transaction + quantiles                |
| Top QNAMES in transactions where host is the client and transaction speed is slower than p90                       | dns_xact_out_top_slow             | dns_transaction                 |
| Total egress DNS transactions (host is client)                                                                     | dns_xact_out_total                 | dns_transaction                 |
| Distribution of response/query size ratios                                                                         | dns_xact_ratio_quantiles           | dns_transaction + quantiles                |
| Total sum of response/query size ratios                                                                            | dns_xact_ratio_quantiles_sum      | dns_transaction + quantiles                |
| Count of response/query size ratios                                                                                | dns_xact_ratio_quantiles_count    | dns_transaction + quantiles                |

## Network Metrics
[Check how to activate/deactivate network metrics](handler_net.md)

| Metric                                                                  | Prometheus Name              | Metric Groups |
|-------------------------------------------------------------------------|------------------------------|---------------|
| IP cardinality                                                          | net_cardinality_ips          | cardinality   |
 | Total packets that were sampled for deep inspection                     | net_deep_sampled_packets     | any group*    |
 | Total packets seen that did not match the configured filter(s) (if any) | net_filtered_packets         | counters      |
 | Count of IPv4 packets                                                   | net_ipv4_packets             | counters      |
 | Count of IPv6 packets                                                   | net_ipv6_packets             | counters      |
 | Total packets events generated                                          | net_observed_packets         | any group*    |
 | Count of packets which are not UDP or TCP                               | net_other_l4_packets         | counters      |
 | Quantiles of payload sizes, in bytes                                    | net_payload_size_bytes       | quantiles     |
 | Count of payload sizes, in bytes                                        | net_payload_size_bytes_count | quantiles     |
 | Total sum of payload sizes, in bytes                                    | net_payload_size_bytes_sum   | quantiles     |
 | Data rate of bits per second                                            | net_rates_bps                | quantiles     |
 | Count of bits per second                                                | net_rates_bps_count          | quantiles     |
 | Total sum of bits per second                                            | net_rates_bps_sum            | quantiles     |
 | Rate of all packets before filtering per second                         | net_rates_observed_pps       | any group*    |
 | Count of all packets before filtering per second                        | net_rates_observed_pps_count | any group*    |
 | Total sum of all packets before filtering per second                    | net_rates_observed_pps_sum   | any group*    |
 | Rate of packets per second                                              | net_rates_pps                | quantiles     |
 | Count of packets per second                                             | net_rates_pps_count          | quantiles     |
 | Total sum of packets per second                                         | net_rates_pps_sum            | quantiles     |
 | Count of TCP packets                                                    | net_tcp_packets              | counters      |
 | Count of TCP SYN packets                                                | net_tcp_syn_packets          | counters      |
 | Top ASNs by IP                                                          | net_top_asn_packets          | top_geo       |
 | Top GeoIP locations                                                     | net_top_geo_loc_packets      | top_geo       |
 | Top IPv4 addresses                                                      | net_top_ipv4_packets         | top_ips       |
 | Top IPv6 addresses                                                      | net_top_ipv6_packets         | top_ips       |
 | Count of total packets matching the configured filter(s)                | net_total_packets            | counters      |
 | Count of UDP packets                                                    | net_udp_packets              | counters      |

| Metric                                                          | Prometheus Name                     | Metric Groups |
|-----------------------------------------------------------------|-------------------------------------|---------------|
| Destination IP cardinality                                      | packets_cardinality_dst_ips_out | cardinality   |
| Source IP cardinality                                           | packets_cardinality_src_ips_in  | cardinality   |
| Count of packets sampled for deep inspection                    | packets_deep_samples              | any group*    |
| Count of packets sent to policy                                 | packets_events                     | any group*    |
| Count of packets filtered out by policy                         | packets_filtered                   | counters      |
| Count of ingress packets                                        | packets_in                         | counters      |
| Count of IPv4 packets                                           | packets_ipv4                       | counters      |
| Count of IPv6 packets                                           | packets_ipv6                       | counters      |
| Count of packets not UDP or TCP                                 | packets_other_l4                  | counters      |
| Count of egress packets                                         | packets_out                        | counters      |
| Quantiles of packet payload sizes                               | packets_payload_size              | any group*    |
| Total sum of packet payload sizes                               | packets_payload_size_sum         | any group*    |
| Count of packet payload sizes                                   | packets_payload_size_count       | any group*    |
| Count of TCP packets with SYN flag set                          | packets_protocol_tcp_syn         | counters      |
| Quantiles of ingress data rates                                 | payload_rates_bytes_in           | any group*    |
| Total sum of ingress data rates                                 | payload_rates_bytes_in_sum      | any group*    |
| Count of ingress data rates                                     | payload_rates_bytes_in_count    | any group*    |
| Quantiles of egress data rates                                  | payload_rates_bytes_out          | any group*    |
| Total sum of egress data rates                                  | payload_rates_bytes_out_sum     | any group*    |
| Count of egress data rates                                      | payload_rates_bytes_out_count   | any group*    |
| Quantiles of total data rates                                   | payload_rates_bytes_total        | any group*    |
| Total sum of total data rates                                   | payload_rates_bytes_total_sum   | any group*    |
| Count of total data rates                                       | payload_rates_bytes_total_count | any group*    |
| Quantiles of all packets before filtering in packets per second | payload_rates_pps_events         | any group*    |
| Total sum of all packets before filtering in packets per second | payload_rates_pps_events_sum    | any group*    |
| Count of all packets before filtering in packets per second     | payload_rates_pps_events_count  | any group*    |
| Quantiles of ingress packet rates                               | payload_rates_pps_in             | any group*    |
| Total sum of ingress packet rates                               | payload_rates_pps_in_sum        | any group*    |
| Count of ingress packet rates                                   | payload_rates_pps_in_count      | any group*    |
| Quantiles of egress packet rates                                | payload_rates_pps_out            | any group*    |
| Total sum of egress packet rates                                | payload_rates_pps_out_sum       | any group*    |
| Count of egress packet rates                                    | payload_rates_pps_out_count     | any group*    |
| Quantiles of total packet rates                                 | payload_rates_pps_total          | any group*    |
| Total sum of total packet rates                                 | payload_rates_pps_total_sum     | any group*    |
| Count of total packet rates                                     | payload_rates_pps_total_count   | any group*    |
| Count of TCP packets                                            | packets_tcp                        | counters      |
| Top ASNs                                                        | packets_top_ASN                   | top_geo       |
| Top GeoIP locations                                             | packets_top_geoLoc                | top_geo       |
| Top IPv4 IP addresses                                           | packets_top_ipv4                  | top_ips       |
| Top IPv6 IP addresses                                           | packets_top_ipv6                  | top_ips       |
| Count of packets matched by policy                              | packets_total                      | counters      |
| Count of UDP packets                                            | packets_udp                        | counters      |
| Count of packets of unknown direction                           | packets_unknown_dir               | counters      |

## PCAP Metrics
[Check how to activate pcap metrics](handler_pcap.md)

| Metric                                        | Prometheus Name            |
|-----------------------------------------------|----------------------------|
| Total wire packets dropped by the interface   | pcap_if_drops              |
| Total wire packets dropped by the OS          | pcap_os_drops              |
| Total TCP wire packets that failed reassembly | pcap_tcp_reassembly_errors |

## BGP metrics
[Check how to activate bgp metrics](handler_bgp.md)

| Metric                                                                                | Prometheus Name               |
|---------------------------------------------------------------------------------------|-------------------------------|
| Quantiles of all BGP wire packets before filtering per second                         | bgp_rates_events              |
| Count of all BGP wire packets before filtering per second                             | bgp_rates_events_count        |
| Total sum of all BGP wire packets before filtering per second                         | bgp_rates_events_sum          |
| Quantiles of all BGP wire packets (combined ingress and egress) in packets per second | bgp_rates_total               |
| Count of all BGP wire packets (combined ingress and egress) in packets per second     | bgp_rates_total_count         |
| Total sum of all BGP wire packets (combined ingress and egress) in packets per second | bgp_rates_total_sum           |
| Total BGP wire packets that were sampled for deep inspection                          | bgp_wire_packets_deep_samples |
| Total BGP wire packets events                                                         | bgp_wire_packets_events       |
| Total BGP wire packets seen that did not match the configured filter(s) (if any)      | bgp_wire_packets_filtered     |
| Total BGP packets with message type KEEPALIVE                                         | bgp_wire_packets_keepalive    |
| Total BGP packets with message type NOTIFICATION                                      | bgp_wire_packets_notification |
| Total BGP packets with message type UPDATE                                            | bgp_wire_packets_update       |
| Total BGP packets with message type OPEN                                              | bgp_wire_packets_open         |
| Total BGP packets with message type ROUTEREFRESH                                      | bgp_wire_packets_routerefresh |
| Total BGP wire packets matching the configured filter(s)                              | bgp_wire_packets_total        |

## Flow metrics
[Check how to activate/deactivate flow metrics](handler_flow.md)

| Metric                                                                                 | Prometheus Name                   | Metric Groups               |
|----------------------------------------------------------------------------------------|-----------------------------------|-----------------------------|
| Conversations cardinality                                                              | flow_cardinality_conversations    | cardinality + conversations |
| Destination IP cardinality                                                             | flow_cardinality_dst_ips_out      | cardinality                 | ok
| Destination ports cardinality                                                          | flow_cardinality_dst_ports_out    | cardinality                 |
| Source IP cardinality                                                                  | flow_cardinality_src_ips_in       | cardinality                 | ok
| Source ports cardinality                                                               | flow_cardinality_src_ports_in     | cardinality                 |
| Count of in by bytes                                                                   | flow_in_bytes                     | counters + by_bytes         | ok
| Count of in IPv4 by bytes                                                              | flow_in_ipv4_bytes                | counters + by_bytes         |
| Count of in IPv4 by packets                                                            | flow_in_ipv4_packets              | counters + by_packets       |
| Count of in IPv6 by bytes                                                              | flow_in_ipv6_bytes                | counters + by_bytes         |
| Count of in IPv6 by packets                                                            | flow_in_ipv6_packets              | counters + by_packets       |
| Count of in by bytes which are not UDP or TCP                                          | flow_in_other_l4_bytes            | counters + by_bytes         |
| Count of in by packtes which are not UDP or TCP                                        | flow_in_other_l4_packets          | counters + by_packets       |
| Count of in by packets                                                                 | flow_in_packets                   | counters + by_packets       |
| Count of in TCP by bytes                                                               | flow_in_tcp_bytes                 | counters + by_bytes         |
| Count of in TCP by packets                                                             | flow_in_tcp_packets               | counters + by_packets       |
| Count of in UDP by bytes                                                               | flow_in_udp_bytes                 | counters + by_bytes         |
| Count of in UDP by packets                                                             | flow_in_udp_packets               | counters + by_packets       |
| Count of out by bytes                                                                  | flow_out_bytes                    | counters + by_bytes         | ok
| Count of out IPV4 by bytes                                                             | flow_out_ipv4_bytes               | counters + by_bytes         |
| Count of out IPV4 by packets                                                           | flow_out_ipv4_packets             | counters + by_packets       |
| Count of out IPV6 by bytes                                                             | flow_out_ipv6_bytes               | counters + by_bytes         |
| Count of out IPV6 by packets                                                           | flow_out_ipv6_packets             | counters + by_packets       |
| Count of out by bytes which are not UDP or TCP                                         | flow_out_other_l4_bytes           | counters + by_bytes         |
| Count of out by packets which are not UDP or TCP                                       | flow_out_other_l4_packets         | counters + by_packets       |
| Count of out by packets                                                                | flow_out_packets                  | counters + by_packets       |
| Count of out TCP by bytes                                                              | flow_out_tcp_bytes                | counters + by_bytes         |
| Count of out TCP by packets                                                            | flow_out_tcp_packets              | counters + by_packets       |
| Count of out UDP by bytes                                                              | flow_out_udp_bytes                | counters + by_bytes         |
| Count of out UDP by packets                                                            | flow_out_udp_packets              | counters + by_packets       |
| Count of total flows records seen that did not match the configured filter(s) (if any) | flow_records_filtered             | counters                    | ok
| Count of total flows records that match the configured filter(s) (if any)              | flow_records_flows                | counters                    | ok
| Top ASNs by IP by bytes                                                                | flow_top_asn_bytes                | top_geo + by_bytes          | ok
| Top ASNs by IP by packets                                                              | flow_top_asn_packets              | top_geo + by_packets        |
| Top source IP addresses and port by bytes                                              | flow_top_conversations_bytes      | conversations + by_bytes    |
| Top source IP addresses and port by packets                                            | flow_top_conversations_packets    | conversations + by_packets  |
| Top GeoIP locations by bytes                                                           | flow_top_geo_loc_bytes            | top_geo + by_bytes          | ok
| Top GeoIP locations by packets                                                         | flow_top_geo_loc_packets          | top_geo + by_packets        |
| Top in destination IP addresses and port by bytes                                      | flow_top_in_dst_ip_ports_bytes    | top_ips_ports + by_bytes    |
| Top in destination IP addresses and port by packets                                    | flow_top_in_dst_ip_ports_packets  | top_ips_ports + by_packets  |
| Top in destination IP addresses by bytes                                               | flow_top_in_dst_ips_bytes         | top_ips + by_bytes          | ok
| Top in destination IP addresses by packets                                             | flow_top_in_dst_ips_packets       | top_ips + by_packets        |
| Top in destination ports by bytes                                                      | flow_top_in_dst_ports_bytes       | top_ports + by_bytes        | ok
| Top in destination ports by packets                                                    | flow_top_in_dst_ports_packets     | top_ports + by_packets      |
| Top input interfaces by bytes                                                          | flow_top_in_interfaces_bytes      | top_interfaces + by_bytes   |
| Top input interfaces by packets                                                        | flow_top_in_interfaces_packets    | top_interfaces + by_packets |
| Top in source IP addresses and port by bytes                                           | flow_top_in_src_ip_ports_bytes    | top_ips_ports + by_bytes    |
| Top in source IP addresses and port by packets                                         | flow_top_in_src_ip_ports_packets  | top_ips_ports + by_packets  |
| Top in source IP addresses by bytes                                                    | flow_top_in_src_ips_bytes         | top_ips + by_bytes          | ok
| Top in source IP addresses by packets                                                  | flow_top_in_src_ips_packets       | top_ips + by_packets        |
| Top in source ports by bytes                                                           | flow_top_in_src_ports_bytes       | top_ports + by_bytes        | ok
| Top in source ports by packets                                                         | flow_top_in_src_ports_packets     | top_ports + by_packets      |
| Top out destination IP addresses and port by bytes                                     | flow_top_out_dst_ip_ports_bytes   | top_ips_ports + by_bytes    |
| Top out destination IP addresses and port by packets                                   | flow_top_out_dst_ip_ports_packets | top_ips_ports + by_packets  |
| Top out destination IP addresses by bytes                                              | flow_top_out_dst_ips_bytes        | top_ips + by_bytes          | ok
| Top out destination IP addresses by packets                                            | flow_top_out_dst_ips_packets      | top_ips + by_packets        |
| Top out destination ports by bytes                                                     | flow_top_out_dst_ports_bytes      | top_ports + by_bytes        | ok
| Top out destination ports by packets                                                   | flow_top_out_dst_ports_packets    | top_ports + by_packets      |
| Top output interfaces by bytes                                                         | flow_top_out_interfaces_bytes     | top_interfaces + by_bytes   |
| Top output interfaces by packets                                                       | flow_top_out_interfaces_packets   | top_interfaces + by_packets |
| Top out source IP addresses and port by bytes                                          | flow_top_out_src_ip_ports_bytes   | top_ips_ports + by_bytes    |
| Top out source IP addresses and port by packets                                        | flow_top_out_src_ip_ports_packets | top_ips_ports + by_packets  |
| Top out source IP addresses by bytes                                                   | flow_top_out_src_ips_bytes        | top_ips + by_bytes          | ok
| Top out source IP addresses by packets                                                 | flow_top_out_src_ips_packets      | top_ips + by_packets        |
| Top out source ports by bytes                                                          | flow_top_out_src_ports_bytes      | top_ports + by_bytes        | ok
| Top out source ports by packets                                                        | flow_top_out_src_ports_packets    | top_ports + by_packets      |
| Top in DSCP by bytes                                                                   | flow_top_in_dscp_bytes            | top_tos + by_bytes          | ok
| Top out DSCP by bytes                                                                  | flow_top_out_dscp_bytes           | top_tos + by_bytes          | ok
| Top in ECN by bytes                                                                    | flow_top_in_ecn_bytes             | top_tos + by_bytes          |
| Top out ECN by bytes                                                                   | flow_top_out_ecn_bytes            | top_tos + by_bytes          |
| Top in DSCP by packets                                                                 | flow_top_in_dscp_packets          | top_tos + by_packets        |
| Top out DSCP by packets                                                                | flow_top_out_dscp_packets         | top_tos + by_packets        |
| Top in ECN by packets                                                                  | flow_top_in_ecn_packets           | top_tos + by_packets        |
| Top out ECN by packets                                                                 | flow_top_out_ecn_packets          | top_tos + by_packets        |

## Netprobe Metrics
[Check how to activate/deactivate netprobe metrics](handler_netprobe.md)

| Metric                                                                     | Prometheus Name                       | Metric Groups                        |
|----------------------------------------------------------------------------|---------------------------------------|--------------------------------------|
| Quantiles of Net Probe quantile in microseconds                            | netprobe_response_quantiles_us        | quantiles                            |
| Total sum of Net Probe quantile in microseconds                            | netprobe_response_quantiles_us_sum    | quantiles                            |
| Count of Net Probe quantile in microseconds                                | netprobe_response_quantiles_us_count  | quantiles                            |
| Total Net Probe attempts                                                   | netprobe_attempts                     | counters                             |
| Total Net Probe failures when performed DNS lookup                         | netprobe_dns_lookup_failures          | counters                             |
| Total Net Probe failures when performing a TCP socket connection           | netprobe_connect_failures             | counters                             |
| Total Net Probe timeout transactions                                       | netprobe_packets_timeout              | counters                             |
| Maximum response time measured in the reporting interval                   | netprobe_response_max_us              | counters + (quantiles or histograms) |
| Minimum response time measured in the reporting interval                   | netprobe_response_min_us              | counters + (quantiles or histograms) |
| Total Net Probe successes                                                  | netprobe_successes                    | counters                             |
| Cumulative counters for the buckets of Net Probe histogram in microseconds | netprobe_response_histogram_us_bucket | histograms                           |
| Count of events of Net Probe histogram in microseconds                     | netprobe_response_histogram_us_count  | histograms                           |
