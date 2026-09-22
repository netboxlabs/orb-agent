# DNS handler (dns)

- [Example of policy](#example-of-policy-with-input-pcap-and-handler-dnsv2)
- [Metrics Group](#metrics-group-20)
- [Filters](#filters-20)
- [Configurations](#configurations)

## Example of policy with input pcap and handler DNS(v2)

``` yaml
handlers:
  window_config:
    deep_sample_rate: 100
    num_periods: 5
  modules:
    default_dns:
      type: dns
      require_version: "2.0"
      config:
        public_suffix_list: true
        topn_count: 25
        topn_percentile_threshold: 10
      filter:
        only_rcode: 0
        only_dnssec_response: true
        answer_count: 1
        only_qtype: [1, 2]
        only_qname_suffix: [".example.com", ".example.net"]
        geoloc_notfound: false
        asn_notfound: false
        dnstap_msg_type: "auth"
      metric_groups:
        enable:
          - cardinality
          - counters
          - quantiles
          - top_rcodes
          - top_qnames
          - top_qtypes
        disable:
          - top_size
          - top_ports
          - xact_times
          - top_ecs
input:
  input_type: pcap
  tap: default_pcap
  filter:
    bpf: udp port 53
  config:
    iface: wlo1
    host_spec: 192.168.1.167/24
    pcap_source: libpcap
    debug: true
config:
    merge_like_handlers: true
kind: collection
```

**Handler Type**: "dns"

## Metrics Group (2.0)

- [Check the dns metrics belonging to each group](metrics.md#dns-metrics)

| Metric Group  | Default  |
|:-------------:|:--------:|
|   `top_ecs`   | disabled |
|  `top_ports`  | disabled |
|  `top_size`   | disabled |
| `xact_times`  | disabled |
| `cardinality` | enabled  |
|  `counters`   | enabled  |
| `top_qnames`  | enabled  |
|  `quantiles`  | enabled  |
| `top_qtypes`  | enabled  |
| `top_rcodes`  | enabled  |

## Filters (2.0)

|                         Filter                          |  Type   | Input  |
|:-------------------------------------------------------:|:-------:|:------:|
|             [`only_rcode`](#only_rcode-v2)              | *str[]* |  PCAP  |
|        [`exclude_noerror`](#exclude_noerror-v2)         | *bool*  |  PCAP  |
|   [`only_dnssec_response`](#only_dnssec_response-v2)    | *bool*  |  PCAP  |
|           [`answer_count`](#answer_count-v2)            |  *int*  |  PCAP  |
|             [`only_qtype`](#only_qtype-v2)              | *str[]* |  PCAP  |
|             [`only_qname`](#only_qname-v2)              | *str[]* |  PCAP  |
|      [`only_qname_suffix`](#only_qname_suffix-v2)       | *str[]* |  PCAP  |
|        [`geoloc_notfound`](#geoloc_notfound-v2)         | *bool*  |  PCAP  |
|           [`asn_notfound`](#asn_notfound-v2)            | *bool*  |  PCAP  |
| [`only_xact_directions`](#only_xact_directions-v2) | *str[]* |  PCAP  |
|        [`dnstap_msg_type`](#dnstap_msg_type-v2)         |  *str*  | DNSTAP |

### only_rcode (v2)

Type: *str[]*

Input: PCAP

When a DNS server returns a response to a query made, one of the properties of the response is the "response code" (rcode), a code that describes what happened to the query that was made.

Most response codes indicate why the query failed and when the query succeeds, the return is an RCODE:0, whose name is NOERROR.

Supported types are in the table below (if you use any other code that is not in the table below, your policy will fail):

| DNS response code |      Name      |                                                                                                                          Description                                                                                                                          |                         Reference                         |
|:-----------------:|:--------------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:---------------------------------------------------------:|
|        `0`        |    NOERROR     |                                                                                                                      No error condition                                                                                                                       | [[RFC1035]](https://www.rfc-editor.org/rfc/rfc1035.html)  |
|        `1`        |    FORMERR     |                                                                                               Format error - The name server was unable to interpret the query.                                                                                               | [[RFC1035]](https://www.rfc-editor.org/rfc/rfc1035.html)  |
|        `2`        |    SERVFAIL     |                                                                           Server failure - The name server was unable to process this query due to a problem with the name server.                                                                            | [[RFC1035]](https://www.rfc-editor.org/rfc/rfc1035.html)  |
|        `3`        |    NXDOMAIN    |                                                Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.                                                 | [[RFC1035]](https://www.rfc-editor.org/rfc/rfc1035.html)  |
|        `4`        |     NOTIMP     |                                                                                        Not Implemented - The name server does not support the requested kind of query.                                                                                        | [[RFC1035]](https://www.rfc-editor.org/rfc/rfc1035.html)  |
|        `5`        |    REFUSED     | The name server refuses to perform the specified operation for  policy reasons.  For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone) | [[RFC1035]](https://www.rfc-editor.org/rfc/rfc1035.html)  |
|        `6`        |    YXDOMAIN    |                                                                                                            Name that should not exist, does exist                                                                                                             | [[RFC2136]](https://www.rfc-editor.org/rfc/rfc2136.html)  |
|        `7`        |    YXRRSET     |                                                                                                           RR set that should not exist, does exist                                                                                                            | [[RFC2136]](https://www.rfc-editor.org/rfc/rfc2136.html)  |
|        `8`        |    NXRRSET     |                                                                                                           RR Set that should exist, does not exist                                                                                                            | [[RFC2136]](https://www.rfc-editor.org/rfc/rfc2136.html)  |
|        `9`        |    NOTAUTH     |                                                                                                      Server Not Authoritative for zone or Not Authorized                                                                                                      | [[RFC2136]](https://www.rfc-editor.org/rfc/rfc2136.html)  |
|       `10`        |    NOTZONE     |                                                                                                                  Name not contained in zone                                                                                                                   | [[RFC2136]](https://www.rfc-editor.org/rfc/rfc2136.html)  |
|       `11`        |   DSOTYPENI    |                                                                                                                   DSO-TYPE Not Implemented                                                                                                                    |       [[RFC8490]](https://www.iana.org/go/rfc8490)        |
|       `16`        | BADVERS/BADSIG |                                                                                                           Bad OPT Version or TSIG Signature Failure                                                                                                           | [[RFC8945]](https://www.rfc-editor.org/rfc/rfc8945.html)  |
|       `17`        |     BADKEY     |                                                                                                                      Key not recognized                                                                                                                       | [[RFC8945]](https://www.rfc-editor.org/rfc/rfc8945.html)  |
|       `18`        |    BADTIME     |                                                                                                                 Signature out of time window                                                                                                                  | [[RFC8945]](https://www.rfc-editor.org/rfc/rfc8945.html)  |
|       `19`        |    BADMODE     |                                                                                                                         Bad TKEY Mode                                                                                                                         | [[RFC2930]](https://www.rfc-editor.org/rfc/rfc2930.html) |
|       `20`        |    BADNAME     |                                                                                                                      Duplicate key name                                                                                                                       | [[RFC2930]](https://www.rfc-editor.org/rfc/rfc2930.html) |
|       `21`        |     BADALG     |                                                                                                                    Algorithm not supported                                                                                                                    | [[RFC2930]](https://www.rfc-editor.org/rfc/rfc2930.html) |
|       `22`        |    BADTRUNC    |                                                                                                                        Bad Truncation                                                                                                                         | [[RFC8945]](https://www.rfc-editor.org/rfc/rfc8945.html)  |
|       `23`        |   BADCOOKIE    |                                                                                                                   Bad/missing Server Cookie                                                                                                                   | [[RFC7873]](https://www.rfc-editor.org/rfc/rfc7873.html)  |

The `only_rcode` filter usage syntax is:

```yaml
only_rcode:
  - str
  - str
```

with the `int` referring to the response code to be filtered, written as string.

Example:

If you want to filter only successful queries responses you should use (note that all that the query will be discarded and the result will be just the responses):

```yaml
only_rcode:
  - "NXDOMAIN"
  - "2"
```

Important information is that only one response code is possible for each handler. So, in order to have multiple filters on the same policy, multiple handlers must be created, each with a rcode type.

### exclude_noerror (v2)

Type: *bool*

Input: PCAP

You may still want to filter out only responses with any kind of error. For this, there is the `exclude_noerror` filter, which removes from its results all responses that did not return any type of error.
The `exclude_noerror` filter usage syntax is:

```yaml
exclude_noerror: true
```

Attention: the filter of `exclude_noerror` is dominant in relation to the filter of only_rcode, that is, if the filter of `exclude_noerror` is true, even if the filter of only_rcode is set, the results will be composed only by responses without any type of error (all type of errors will be kept).

### only_dnssec_response (v2)

Type: *bool*

Input: PCAP

When you make a DNS query, the response you get may have a DNSSEC signature, which authenticates that DNS records originate from an authorized sender, thus protecting DNS from falsified information.

To filter only responses signed by an authorized sender, use:
The `only_dnssec_response` filter usage syntax is:

```yaml
only_dnssec_response: true
```

### answer_count (v2)

Type: *int*

Input: PCAP

One of the properties present in the query message structure is `Answer RRs`, which is the count of entries in the responses section (RR stands for “resource record”).

The number of answers in the query is always zero, as a query message has only questions and no answers, and when the server sends the answer to that query, the value is set to the amount of entries in the answers section.

The `answer_count` filter usage syntax is:

```yaml
answer_count: int
```

with the `int` referring to the desired amount of answer.

Note that any value greater than zero that is defined will exclude queries from the results, since in queries the number of answers is always 0.

As the answers count of queries is 0, whenever the value set for the answer_count is 0, both queries and responses will compose the result.

A special case is the concept of `NODATA`, which is one of the possible returns to a query made to a DNS server is known as. This happens when the query is successful (so rcode:0), but there is no data as a response, so the number of answers is 0.

In this case, to have in the results only the cases of `NODATA`, that is, the responses, the filter must be used together with the filter `exclude_noerror`.

Important information is that only one answer_count is possible for each handler. So, in order to have multiple counts on the same policy, multiple handlers must be created, each with an amount of answers.

### only_qtype (v2)

Type: *str[]*

Input: PCAP

DNS record types are records that provide important information about a hostname or domain. Supported default types can be seen [here](https://github.com/netboxlabs/pktvisor/blob/develop/libs/visor_dns/dns.h#L30).

The `only_qtype` filter usage syntax is:

```yaml
only_qtype:
  - str
  - str
```

If you want to filter only IPV4 record types, for example, you should use:

```yaml
only_qtype:
  - "A"
```

or

```yaml
only_qtype:
  - 1
```

Multiple types are also supported and both queries and responses that have any of the values in the array will be considered.

```yaml
only_qtype:
  - 1
  - 2
  - "A"
```

### only_qname (v2)

Type: *str[]*

Input: PCAP

The `only_qname` filters dns packets based on queries and responses whose names exactly matches the strings present in the array.

The `only_qname` filter usage syntax is:

```yaml
only_qname:
  - str
  - str
```

Examples:

```yaml
only_qname:
  - www.example.com
  - .example.net
```

### only_qname_suffix (v2)

Type: *str[]*

Input: PCAP

The `only_qname_suffix` filters queries and responses whose endings (suffixes) of the names match the strings present in the array.

The `only_qname_suffix` filter usage syntax is:

```yaml
only_qname_suffix:
  - str
  - str
```

Examples:

```yaml
only_qname_suffix:
  - .example.com
```

or

```yaml
only_qname_suffix:
  - example.com
  - .example.net
```

### geoloc_notfound (v2)

Type: *bool*

Input: PCAP

Based on ECS (EDNS Client Subnet) information, it is possible to determine the geolocation of where the query is being made. When the Subnet refers to a region found in the standard databases, the city, state and country (approximated) are returned. However, when based on the subnet it is not possible to determine the geolocation, a `not found` is returned.

The `geoloc_notfound` filter only keeps responses whose geolocations were not found.

The `geoloc_notfound` filter usage syntax is:

```yaml
geoloc_notfound: true
```

### asn_notfound (v2)

Type: *bool*

Input: PCAP

Based on ECS (EDNS Client Subnet) information, it is possible to determine the ASN (Autonomous System Number). When the IP of the subnet belongs to some not known ASN in the standard databases, a `not found` is returned.

The `asn_notfound` filter only keeps responses whose asn were not found.

The `asn_notfound` filter usage syntax is:

```yaml
asn_notfound: true
```

### only_xact_directions (v2)

> **Not currently usable.** The 2.0 handler implements this filter but does not
> list it among its accepted keys, so a policy that sets it is rejected with
> `only_xact_directions is an invalid/unsupported config or filter`. Tracked
> against pktvisor; the filter is documented here for when that is corrected.

Type: *str[]*

Input: PCAP

Filters metrics according to the direction of the transaction. Options are: `in`, `out` and `unknown`.
```yaml
only_xact_directions:
  - str
  - str
```
Example:
```yaml
only_xact_directions:
- in
- unknown
```

### dnstap_msg_type (v2)

Type: *str*

Input: DNSTAP

With a dnstap protocol it is possible to know the type of message that must be resolved in the request to the server. This filter therefore allows you to filter by response types.
Supported message types are: `auth`, `resolver`, `client`, `forwarder`, `stub`, `tool` and `update`.

The `dnstap_msg_type` filter usage syntax is:

```yaml
dnstap_msg_type: str
```
Example:
```yaml
dnstap_msg_type: auth
```

## Example of policy with input pcap and handler DNS(v1)

``` yaml
handlers:
  window_config:
    deep_sample_rate: 100
    num_periods: 5
  modules:
    default_dns:
      type: dns
      config:
        public_suffix_list: true
        topn_count: 25
        topn_percentile_threshold: 10
      filter:
        only_rcode: 0
        only_dnssec_response: true
        answer_count: 1
        only_qtype: [1, 2]
        only_qname_suffix: [".example.com", ".example.net"]
        geoloc_notfound: false
        asn_notfound: false
        dnstap_msg_type: "auth"
      metric_groups:
        enable:
          - top_ecs
          - top_qnames_details
        disable:
          - histograms
          - quantiles
          - cardinality
          - counters
          - dns_transaction
          - top_qnames
          - top_ports
input:
  input_type: pcap
  tap: default_pcap
  filter:
    bpf: udp port 53
  config:
    iface: wlo1
    host_spec: 192.168.1.167/24
    pcap_source: libpcap
    debug: true
config:
    merge_like_handlers: true
kind: collection
```

**Handler Type**: "dns"

## Metrics Group (1.0)

- [Check the dns metrics belonging to each group](metrics.md#dns-metrics)

|     Metric Group     | Default  |
|:--------------------:|:--------:|
|      `top_ecs`       | disabled |
| `top_qnames_details` | disabled |
|     `histograms`     | disabled |
|    `cardinality`     | enabled  |
|      `counters`      | enabled  |
|  `dns_transaction`   | enabled  |
|     `top_qnames`     | enabled  |
|     `top_ports`      | enabled  |
|     `quantiles`      | enabled  |

## Filters (1.0)

|                       Filter                       |  Type   | Input  |
|:--------------------------------------------------:|:-------:|:------:|
|           [`only_rcode`](#only_rcode-v1)           | *str[]* |  PCAP  |
|      [`exclude_noerror`](#exclude_noerror-v1)      | *bool*  |  PCAP  |
| [`only_dnssec_response`](#only_dnssec_response-v1) | *bool*  |  PCAP  |
|         [`answer_count`](#answer_count-v1)         |  *int*  |  PCAP  |
|           [`only_qtype`](#only_qtype-v1)           | *str[]* |  PCAP  |
|           [`only_qname`](#only_qname-v1)           | *str[]* |  PCAP  |
|    [`only_qname_suffix`](#only_qname_suffix-v1)    | *str[]* |  PCAP  |
|      [`geoloc_notfound`](#geoloc_notfound-v1)      | *bool*  |  PCAP  |
|         [`asn_notfound`](#asn_notfound-v1)         | *bool*  |  PCAP  |
|         [`only_queries`](#only_queries-v1)         | *bool*  |  PCAP  |
|       [`only_responses`](#only_responses-v1)       | *bool*  |  PCAP  |
|      [`dnstap_msg_type`](#dnstap_msg_type-v1)      |  *str*  | DNSTAP |

### only_rcode (v1)

Type: *str[]*

Input: PCAP

When a DNS server returns a response to a query made, one of the properties of the response is the "response code" (rcode), a code that describes what happened to the query that was made.

Most response codes indicate why the query failed and when the query succeeds, the return is an RCODE:0, whose name is NOERROR.

Supported types are in the table below (if you use any other code that is not in the table below, your policy will fail):

| DNS response code |      Name      |                                                                                                                          Description                                                                                                                          |                         Reference                         |
|:-----------------:|:--------------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:---------------------------------------------------------:|
|        `0`        |    NOERROR     |                                                                                                                      No error condition                                                                                                                       | [[RFC1035]](https://www.rfc-editor.org/rfc/rfc1035.html)  |
|        `1`        |    FORMERR     |                                                                                               Format error - The name server was unable to interpret the query.                                                                                               | [[RFC1035]](https://www.rfc-editor.org/rfc/rfc1035.html)  |
|        `2`        |    SERVFAIL     |                                                                           Server failure - The name server was unable to process this query due to a problem with the name server.                                                                            | [[RFC1035]](https://www.rfc-editor.org/rfc/rfc1035.html)  |
|        `3`        |    NXDOMAIN    |                                                Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.                                                 | [[RFC1035]](https://www.rfc-editor.org/rfc/rfc1035.html)  |
|        `4`        |     NOTIMP     |                                                                                        Not Implemented - The name server does not support the requested kind of query.                                                                                        | [[RFC1035]](https://www.rfc-editor.org/rfc/rfc1035.html)  |
|        `5`        |    REFUSED     | The name server refuses to perform the specified operation for  policy reasons.  For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone) | [[RFC1035]](https://www.rfc-editor.org/rfc/rfc1035.html)  |
|        `6`        |    YXDOMAIN    |                                                                                                            Name that should not exist, does exist                                                                                                             | [[RFC2136]](https://www.rfc-editor.org/rfc/rfc2136.html)  |
|        `7`        |    YXRRSET     |                                                                                                           RR set that should not exist, does exist                                                                                                            | [[RFC2136]](https://www.rfc-editor.org/rfc/rfc2136.html)  |
|        `8`        |    NXRRSET     |                                                                                                           RR Set that should exist, does not exist                                                                                                            | [[RFC2136]](https://www.rfc-editor.org/rfc/rfc2136.html)  |
|        `9`        |    NOTAUTH     |                                                                                                      Server Not Authoritative for zone or Not Authorized                                                                                                      | [[RFC2136]](https://www.rfc-editor.org/rfc/rfc2136.html)  |
|       `10`        |    NOTZONE     |                                                                                                                  Name not contained in zone                                                                                                                   | [[RFC2136]](https://www.rfc-editor.org/rfc/rfc2136.html)  |
|       `11`        |   DSOTYPENI    |                                                                                                                   DSO-TYPE Not Implemented                                                                                                                    |       [[RFC8490]](https://www.iana.org/go/rfc8490)        |
|       `16`        | BADVERS/BADSIG |                                                                                                           Bad OPT Version or TSIG Signature Failure                                                                                                           | [[RFC8945]](https://www.rfc-editor.org/rfc/rfc8945.html)  |
|       `17`        |     BADKEY     |                                                                                                                      Key not recognized                                                                                                                       | [[RFC8945]](https://www.rfc-editor.org/rfc/rfc8945.html)  |
|       `18`        |    BADTIME     |                                                                                                                 Signature out of time window                                                                                                                  | [[RFC8945]](https://www.rfc-editor.org/rfc/rfc8945.html)  |
|       `19`        |    BADMODE     |                                                                                                                         Bad TKEY Mode                                                                                                                         | [[RFC2930]](https://www.rfc-editor.org/rfc/rfc2930.html) |
|       `20`        |    BADNAME     |                                                                                                                      Duplicate key name                                                                                                                       | [[RFC2930]](https://www.rfc-editor.org/rfc/rfc2930.html) |
|       `21`        |     BADALG     |                                                                                                                    Algorithm not supported                                                                                                                    | [[RFC2930]](https://www.rfc-editor.org/rfc/rfc2930.html) |
|       `22`        |    BADTRUNC    |                                                                                                                        Bad Truncation                                                                                                                         | [[RFC8945]](https://www.rfc-editor.org/rfc/rfc8945.html)  |
|       `23`        |   BADCOOKIE    |                                                                                                                   Bad/missing Server Cookie                                                                                                                   | [[RFC7873]](https://www.rfc-editor.org/rfc/rfc7873.html)  |

The `only_rcode` filter usage syntax is:

```yaml
only_rcode:
  - str
  - str
```

with the `int` referring to the response code to be filtered, written as string.

Example:

If you want to filter only successful queries responses you should use (note that all that the query will be discarded and the result will be just the responses):

```yaml
only_rcode:
  - "NXDOMAIN"
  - "2"
```

Important information is that only one response code is possible for each handler. So, in order to have multiple filters on the same policy, multiple handlers must be created, each with a rcode type.

### exclude_noerror (v1)

Type: *bool*

Input: PCAP

The `exclude_noerror` filter removes from its results all responses that did not return any type of error (RCODE=0)

The `exclude_noerror` filter usage syntax is:

```yaml
exclude_noerror: true
```

`exclude_noerror` takes precedence over the "only_rcode" filter. If exclude_noerror = True, then the results will be composed only of responses WITH an error, that is, responses with RCODE=0 will not be returned.

### only_dnssec_response (v1)

Type: *bool*

Input: PCAP

When you make a DNS query, the response you get may have a DNSSEC signature, which authenticates that DNS records originate from an authorized sender, thus protecting DNS from falsified information.

To filter only responses signed by an authorized sender, use:
The `only_dnssec_response` filter usage syntax is:

```yaml
only_dnssec_response: true
```

### answer_count (v1)

Type: *int*

Input: PCAP

One of the properties present in the query message structure is `Answer RRs`, which is the count of entries in the responses section (RR stands for “resource record”).

The number of answers in the query is always zero, as a query message has only questions and no answers, and when the server sends the answer to that query, the value is set to the amount of entries in the answers section.

The `answer_count` filter usage syntax is:

```yaml
answer_count: int
```

with the `int` referring to the desired amount of answer.

Note that any value greater than zero that is defined will exclude queries from the results, since in queries the number of answers is always 0.

As the answers count of queries is 0, whenever the value set for the answer_count is 0, both queries and responses will compose the result.

A special case is the concept of `NODATA`, which is one of the possible returns to a query made to a DNS server is known as. This happens when the query is successful (so rcode:0), but there is no data as a response, so the number of answers is 0.

In this case, to have in the results only the cases of `NODATA`, that is, the responses, the filter must be used together with the filter `exclude_noerror`.

Important information is that only one answer_count is possible for each handler. So, in order to have multiple counts on the same policy, multiple handlers must be created, each with an amount of answers.

### only_qtype (v1)

Type: *str[]*

Input: PCAP

DNS record types are records that provide important information about a hostname or domain. Supported default types can be seen [here](https://github.com/netboxlabs/pktvisor/blob/develop/libs/visor_dns/dns.h#L30).

The `only_qtype` filter usage syntax is:

```yaml
only_qtype:
  - str
  - str
```

If you want to filter only IPV4 record types, for example, you should use:

```yaml
only_qtype:
  - "A"
```

or

```yaml
only_qtype:
  - 1
```

Multiple types are also supported and both queries and responses that have any of the values in the array will be considered.

```yaml
only_qtype:
  - 1
  - 2
  - "A"
```

### only_qname (v1)

Type: *str[]*

Input: PCAP

The `only_qname` filters dns packets based on queries and responses whose names exactly matches the strings present in the array.

The `only_qname` filter usage syntax is:

```yaml
only_qname:
  - str
  - str
```

Examples:

```yaml
only_qname:
  - www.example.com
  - .example.net
```

### only_qname_suffix (v1)

Type: *str[]*

Input: PCAP

The `only_qname_suffix` filters queries and responses whose endings (suffixes) of the names match the strings present in the array.

The `only_qname_suffix` filter usage syntax is:

```yaml
only_qname_suffix:
  - str
  - str
```

Examples:

```yaml
only_qname_suffix:
  - .example.com
```

or

```yaml
only_qname_suffix:
  - example.com
  - .example.net
```

### geoloc_notfound (v1)

Type: *bool*

Input: PCAP

Based on ECS (EDNS Client Subnet) information, it is possible to determine the geolocation of where the query is being made. When the Subnet refers to a region found in the standard databases, the city, state and country (approximated) are returned. However, when based on the subnet it is not possible to determine the geolocation, a `not found` is returned.

The `geoloc_notfound` filter only keeps responses whose geolocations were not found.

The `geoloc_notfound` filter usage syntax is:

```yaml
geoloc_notfound: true
```

### asn_notfound (v1)

Type: *bool*

Input: PCAP

Based on ECS (EDNS Client Subnet) information, it is possible to determine the ASN (Autonomous System Number). When the IP of the subnet belongs to some not known ASN in the standard databases, a `not found` is returned.

The `asn_notfound` filter only keeps responses whose asn were not found.

The `asn_notfound` filter usage syntax is:

```yaml
asn_notfound: true
```

### only_queries (v1)

Type: *bool*

Input: PCAP

The `only_queries` filters out all dns response packets and its usage syntax is:

```yaml
only_queries: true
```

### only_responses (v1)

Type: *bool*

Input: PCAP

The `only_responses` filters out all dns queries packets and its usage syntax is:

```yaml
only_responses: true
```

### dnstap_msg_type (v1)

Type: *str*

Input: DNSTAP

With a dnstap protocol it is possible to know the type of message that must be resolved in the request to the server. This filter therefore allows you to filter by response types.
Supported message types are: `auth`, `resolver`, `client`, `forwarder`, `stub`, `tool` and `update`.

The `dnstap_msg_type` filter usage syntax is:

```yaml
dnstap_msg_type: str
```
Example:
```yaml
dnstap_msg_type: auth
```

## Configurations

- [public_suffix_list](#public_suffix_list): *bool*.
- [recorded_stream](#recorded_stream): *bool*.
- [xact_ttl_secs](#xact_ttl_ms-or-xact_ttl_secs): *int*.
- [xact_ttl_ms](#xact_ttl_ms-or-xact_ttl_secs): *int*.
- [Abstract configurations](handlers.md#abstract-configurations).

### public_suffix_list

Some names to be resolved by a dns server have public suffixes. These suffixes cause metrics to be generated considering non-relevant data.

The example below illustrates the benefit of using this type of configuration. The qnames consider each part of the name to be resolved. When a name has a public suffix, generic information is generated. Note that in the standard configuration, Qname2 and Qname3 are the same for both domains. With the public suffix setting `true` (which makes the entire public part be considered as a single part), Qname3 already displays relevant information about the name.

The list of suffixes considered public can be accessed [here](https://github.com/netboxlabs/pktvisor/blob/develop/libs/visor_dns/PublicSuffixList.h).

|            Name             | Qname2 Standard | Qname3 Standard | Qname2 Public Suffix | Qname3 Public Suffix |
|:---------------------------:|:---------------:|:---------------:|:--------------------:|:--------------------:|
|  `www.imagine.qname.co.uk`  |      co.uk      |   qname.co.uk   |     qname.co.uk      | imagine.qname.co.uk  |
| `other.example.qname.co.uk` |      co.uk      |   qname.co.uk   |     qname.co.uk      | example.qname.co.uk  |

The `public_suffix_list` configuration usage syntax is:

```yaml
public_suffix_list: true
```

### recorded_stream

This configuration is useful when a pcap_file is used in taps/input configuration. Set it to True when you want to load an offline traffic (from a pcap_file).

The `recorded_stream` configuration usage syntax is:

```yaml
recorded_stream: true
```

### xact_ttl_ms or xact_ttl_secs

Type: *int*

Both configurations have the same functionality, that is, defines the time to live of transactions, and only change the unit of measurement to be configured. This configuration causes the metrics to be generated for complete transactions (query and response) within the established time limit.

- xact_ttl_ms: Defines the time to live of transactions in milliseconds.
- xact_ttl_secs: Defines the time to live of transactions in seconds.

Note that `xact_ttl_ms` is dominant over `xact_ttl_secs`, that is, if `xact_ttl_ms` exists, even if `xact_ttl_secs` also exists, the value of `xact_ttl_ms` will be considered.

The `xact_ttl_ms` or `xact_ttl_secs` configuration usage syntax is:

```yaml
xact_ttl_ms: 5000
```

or

```yaml
xact_ttl_secs: 5
```
