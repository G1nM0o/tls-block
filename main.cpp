#include <pcap.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

using namespace std;

#pragma pack(push, 1)

struct PseudoHdr {
    uint32_t sip;
    uint32_t dip;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
};

#pragma pack(pop)

struct FlowKey {
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;

    bool operator<(const FlowKey& r) const
    {
        if (sip != r.sip) return sip < r.sip;
        if (dip != r.dip) return dip < r.dip;
        if (sport != r.sport) return sport < r.sport;
        return dport < r.dport;
    }
};

struct Ctx {
    pcap_t* handle;
    int raw_sock;
    string server_name;
    uint8_t my_mac[6];
    map<FlowKey, vector<uint8_t>> flows;
    set<FlowKey> blocked_flows;
};

enum TlsParseResult {
    TLS_INVALID,
    TLS_NEED_MORE,
    TLS_CLIENT_HELLO
};

uint16_t checksum(const void* data, size_t len)
{
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint32_t sum = 0;

    for (size_t i = 0; i + 1 < len; i += 2)
        sum += (p[i] << 8) | p[i + 1];

    if (len & 1)
        sum += p[len - 1] << 8;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return htons(static_cast<uint16_t>(~sum));
}

uint16_t tcp_checksum(const IpHdr* ip, const TcpHdr* tcp, size_t tcp_len)
{
    PseudoHdr ph{};
    ph.sip = ip->sip;
    ph.dip = ip->dip;
    ph.proto = IP_PROTO_TCP;
    ph.len = htons(static_cast<uint16_t>(tcp_len));

    vector<uint8_t> buf(sizeof(PseudoHdr) + tcp_len);
    memcpy(buf.data(), &ph, sizeof(PseudoHdr));
    memcpy(buf.data() + sizeof(PseudoHdr), tcp, tcp_len);

    return checksum(buf.data(), buf.size());
}

void get_my_mac(const char* ifname, uint8_t mac[6])
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifreq ifr{};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    close(fd);
}

bool pull_u8(const uint8_t*& p, const uint8_t* end, uint8_t& v)
{
    if (p + 1 > end)
        return false;
    v = *p++;
    return true;
}

bool pull_u16(const uint8_t*& p, const uint8_t* end, uint16_t& v)
{
    if (p + 2 > end)
        return false;
    v = static_cast<uint16_t>((p[0] << 8) | p[1]);
    p += 2;
    return true;
}

bool pull_u24(const uint8_t*& p, const uint8_t* end, uint32_t& v)
{
    if (p + 3 > end)
        return false;
    v = (p[0] << 16) | (p[1] << 8) | p[2];
    p += 3;
    return true;
}

bool skip_bytes(const uint8_t*& p, const uint8_t* end, size_t len)
{
    if (p + len > end)
        return false;
    p += len;
    return true;
}

FlowKey reverse_key(const FlowKey& key)
{
    return FlowKey{key.dip, key.sip, key.dport, key.sport};
}

bool match_server_name(const string& sni, const string& server_name)
{
    if (sni == server_name)
        return true;

    if (sni.size() <= server_name.size())
        return false;

    size_t pos = sni.size() - server_name.size();
    return sni[pos - 1] == '.' && sni.compare(pos, server_name.size(), server_name) == 0;
}

TlsParseResult parse_client_hello_sni(const vector<uint8_t>& buf, string& sni)
{
    const uint8_t* base = buf.data();
    const uint8_t* end = base + buf.size();
    const uint8_t* p = base;

    if (buf.size() < 5)
        return TLS_NEED_MORE;

    if (p[0] != 0x16 || p[1] != 0x03)
        return TLS_INVALID;

    uint16_t record_len = static_cast<uint16_t>((p[3] << 8) | p[4]);
    if (buf.size() < static_cast<size_t>(5 + record_len))
        return TLS_NEED_MORE;

    p += 5;
    end = p + record_len;

    uint8_t handshake_type;
    uint32_t handshake_len;
    if (!pull_u8(p, end, handshake_type) || !pull_u24(p, end, handshake_len))
        return TLS_INVALID;

    if (handshake_type != 0x01)
        return TLS_INVALID;

    if (p + handshake_len > end)
        return TLS_INVALID;

    end = p + handshake_len;

    if (!skip_bytes(p, end, 2 + 32))
        return TLS_INVALID;

    uint8_t session_id_len;
    if (!pull_u8(p, end, session_id_len) || !skip_bytes(p, end, session_id_len))
        return TLS_INVALID;

    uint16_t cipher_suites_len;
    if (!pull_u16(p, end, cipher_suites_len) || !skip_bytes(p, end, cipher_suites_len))
        return TLS_INVALID;

    uint8_t compression_methods_len;
    if (!pull_u8(p, end, compression_methods_len) || !skip_bytes(p, end, compression_methods_len))
        return TLS_INVALID;

    uint16_t extensions_len;
    if (!pull_u16(p, end, extensions_len))
        return TLS_INVALID;

    if (p + extensions_len > end)
        return TLS_INVALID;

    const uint8_t* ext_end = p + extensions_len;

    while (p + 4 <= ext_end)
    {
        uint16_t ext_type;
        uint16_t ext_len;
        if (!pull_u16(p, ext_end, ext_type) || !pull_u16(p, ext_end, ext_len))
            return TLS_INVALID;

        if (p + ext_len > ext_end)
            return TLS_INVALID;

        const uint8_t* ext_data = p;
        const uint8_t* ext_data_end = p + ext_len;
        p += ext_len;

        if (ext_type != 0x0000)
            continue;

        uint16_t list_len;
        if (!pull_u16(ext_data, ext_data_end, list_len) || ext_data + list_len > ext_data_end)
            return TLS_INVALID;

        const uint8_t* list_end = ext_data + list_len;
        while (ext_data + 3 <= list_end)
        {
            uint8_t name_type;
            uint16_t name_len;
            if (!pull_u8(ext_data, list_end, name_type) || !pull_u16(ext_data, list_end, name_len))
                return TLS_INVALID;

            if (ext_data + name_len > list_end)
                return TLS_INVALID;

            if (name_type == 0)
            {
                sni.assign(reinterpret_cast<const char*>(ext_data), name_len);
                return TLS_CLIENT_HELLO;
            }

            ext_data += name_len;
        }

        return TLS_INVALID;
    }

    return TLS_CLIENT_HELLO;
}

void send_forward_rst(Ctx* ctx, const EthHdr* org_eth, const IpHdr* org_ip, const TcpHdr* org_tcp, uint32_t tcp_data_size)
{
    vector<uint8_t> pkt(sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr));

    EthHdr* eth = reinterpret_cast<EthHdr*>(pkt.data());
    IpHdr* ip = reinterpret_cast<IpHdr*>(pkt.data() + sizeof(EthHdr));
    TcpHdr* tcp = reinterpret_cast<TcpHdr*>(pkt.data() + sizeof(EthHdr) + sizeof(IpHdr));

    memcpy(eth->dmac, org_eth->dmac, 6);
    memcpy(eth->smac, ctx->my_mac, 6);
    eth->type = htons(ETH_TYPE_IP);

    ip->vhl = 0x45;
    ip->tos = 0;
    ip->len = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    ip->id = 0;
    ip->off = 0;
    ip->ttl = org_ip->ttl;
    ip->proto = IP_PROTO_TCP;
    ip->sum = 0;
    ip->sip = org_ip->sip;
    ip->dip = org_ip->dip;
    ip->sum = checksum(ip, sizeof(IpHdr));

    tcp->sport = org_tcp->sport;
    tcp->dport = org_tcp->dport;
    tcp->seq = htonl(ntohl(org_tcp->seq) + tcp_data_size);
    tcp->ack = org_tcp->ack;
    tcp->off = 0x50;
    tcp->flags = TCP_RST | TCP_ACK;
    tcp->win = 0;
    tcp->sum = 0;
    tcp->urp = 0;
    tcp->sum = tcp_checksum(ip, tcp, sizeof(TcpHdr));

    pcap_sendpacket(ctx->handle, pkt.data(), static_cast<int>(pkt.size()));
}

void send_backward_rst(Ctx* ctx, const IpHdr* org_ip, const TcpHdr* org_tcp, uint32_t tcp_data_size)
{
    size_t ip_len = sizeof(IpHdr) + sizeof(TcpHdr);
    vector<uint8_t> pkt(ip_len);

    IpHdr* ip = reinterpret_cast<IpHdr*>(pkt.data());
    TcpHdr* tcp = reinterpret_cast<TcpHdr*>(pkt.data() + sizeof(IpHdr));

    ip->vhl = 0x45;
    ip->tos = 0;
    ip->len = htons(static_cast<uint16_t>(ip_len));
    ip->id = 0;
    ip->off = 0;
    ip->ttl = 128;
    ip->proto = IP_PROTO_TCP;
    ip->sum = 0;
    ip->sip = org_ip->dip;
    ip->dip = org_ip->sip;
    ip->sum = checksum(ip, sizeof(IpHdr));

    tcp->sport = org_tcp->dport;
    tcp->dport = org_tcp->sport;
    tcp->seq = org_tcp->ack;
    tcp->ack = htonl(ntohl(org_tcp->seq) + tcp_data_size);
    tcp->off = 0x50;
    tcp->flags = TCP_RST | TCP_ACK;
    tcp->win = 0;
    tcp->sum = 0;
    tcp->urp = 0;
    tcp->sum = tcp_checksum(ip, tcp, sizeof(TcpHdr));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip->dip;

    sendto(ctx->raw_sock, pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
}

void block_packet(Ctx* ctx, const EthHdr* eth, const IpHdr* ip, const TcpHdr* tcp, uint32_t tcp_data_size)
{
    for (int i = 0; i < 3; i++)
    {
        send_backward_rst(ctx, ip, tcp, tcp_data_size);
        send_forward_rst(ctx, eth, ip, tcp, tcp_data_size);
    }

    char sip[16];
    char dip[16];
    inet_ntop(AF_INET, &ip->sip, sip, sizeof(sip));
    inet_ntop(AF_INET, &ip->dip, dip, sizeof(dip));
    printf("blocked %s:%u -> %s:%u\n", sip, ntohs(tcp->sport), dip, ntohs(tcp->dport));
}

void on_packet(u_char* user, const pcap_pkthdr* h, const u_char* bytes)
{
    Ctx* ctx = reinterpret_cast<Ctx*>(user);

    if (h->caplen < sizeof(EthHdr) + sizeof(IpHdr))
        return;

    const EthHdr* eth = reinterpret_cast<const EthHdr*>(bytes);
    if (ntohs(eth->type) != ETH_TYPE_IP)
        return;

    const IpHdr* ip = reinterpret_cast<const IpHdr*>(bytes + sizeof(EthHdr));
    uint32_t ip_hlen = (ip->vhl & 0x0f) * 4;

    if ((ip->vhl >> 4) != 4 || ip->proto != IP_PROTO_TCP)
        return;

    if (h->caplen < sizeof(EthHdr) + ip_hlen + sizeof(TcpHdr))
        return;

    const TcpHdr* tcp = reinterpret_cast<const TcpHdr*>(bytes + sizeof(EthHdr) + ip_hlen);
    uint32_t tcp_hlen = (tcp->off >> 4) * 4;
    uint32_t ip_len = ntohs(ip->len);

    if (ip_len < ip_hlen + tcp_hlen)
        return;

    uint32_t tcp_data_size = ip_len - ip_hlen - tcp_hlen;
    FlowKey key{ip->sip, ip->dip, tcp->sport, tcp->dport};

    if (ctx->blocked_flows.find(key) != ctx->blocked_flows.end())
    {
        block_packet(ctx, eth, ip, tcp, tcp_data_size);
        return;
    }

    if (tcp_data_size == 0)
        return;

    if (h->caplen < sizeof(EthHdr) + ip_hlen + tcp_hlen + tcp_data_size)
        return;

    const uint8_t* payload = bytes + sizeof(EthHdr) + ip_hlen + tcp_hlen;
    vector<uint8_t>& buf = ctx->flows[key];

    if (buf.size() + tcp_data_size > 16384)
    {
        ctx->flows.erase(key);
        return;
    }

    buf.insert(buf.end(), payload, payload + tcp_data_size);

    string sni;
    TlsParseResult result = parse_client_hello_sni(buf, sni);
    if (result == TLS_NEED_MORE)
        return;

    ctx->flows.erase(key);

    if (result != TLS_CLIENT_HELLO || !match_server_name(sni, ctx->server_name))
        return;

    ctx->blocked_flows.insert(key);
    ctx->blocked_flows.insert(reverse_key(key));
    block_packet(ctx, eth, ip, tcp, tcp_data_size);
}

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        printf("syntax : %s <interface> <server name>\n", argv[0]);
        printf("sample : %s wlan0 naver.com\n", argv[0]);
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    Ctx ctx{};
    ctx.server_name = argv[2];

    get_my_mac(argv[1], ctx.my_mac);

    ctx.handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
    if (ctx.handle == nullptr)
        return 1;

    ctx.raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (ctx.raw_sock < 0)
        return 1;

    int on = 1;
    setsockopt(ctx.raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    bpf_program fp{};
    pcap_compile(ctx.handle, &fp, "tcp", 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(ctx.handle, &fp);
    pcap_freecode(&fp);

    printf("tls-block on %s\n", argv[1]);
    printf("server name: %s\n", argv[2]);

    pcap_loop(ctx.handle, 0, on_packet, reinterpret_cast<u_char*>(&ctx));

    close(ctx.raw_sock);
    pcap_close(ctx.handle);

    return 0;
}
