import ../[config, utils, meta]
import winim
import winim/winstr

# proc dns_query(host: string, query_type: WORD): string =
#     var record: PDNS_RECORD
#     var api_servers: PIP4_ARRAY
#     if DnsQuery(+$host, query_type, DNS_QUERY_STANDARD, api_servers, &record, NULL) == 0:
#         dbg "[-] DNS query failed: " & $GetLastError()
#         return
#     defer: DnsRecordListFree(record, dnsFreeRecordList)

proc send_request_dns_get*(data: seq[byte]): seq[byte] =
    discard

proc send_request_dns_post*(data: seq[byte]): seq[byte] =
    discard
