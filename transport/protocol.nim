import ../[config, utils]
import ./[http, dns, smtp]

proc send_request*(data: seq[byte], output = false): seq[byte] =
    case config.protocol
    of "http://", "https://":
        if output: return send_request_http_post(data)
        else: return send_request_http_get(data)
    of "dns://":
        if output: return send_request_dns_post(data)
        else: return send_request_dns_get(data)
    else:
        dbg "[-] unknown protocol: " & config.protocol
        return
