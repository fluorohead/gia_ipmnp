#ifndef GIA_IPMNP_H
#define GIA_IPMNP_H

#include <array>
#include <string>
#include <vector>
#include <cstdint>

using namespace std;

using u64i = uint64_t;
using u32i = uint32_t;
using u16i = uint16_t;
using u8i  = uint8_t;

class IPv4_Addr;
class IPv6_Addr;
class MAC_Addr;
using IPv4_Mask = IPv4_Addr;
using IPv6_Mask = IPv6_Addr;

class v4mnp {
public:
    static const u32i UNKNOWN_ADDR {0x00000000};
    static const u32i LOOPBACK_MASK {0xFFFFFFFF};
    static bool valid_addr(const string &ipstr, IPv4_Addr *ret = nullptr); // address validator
    static bool valid_mask(const string &maskstr, IPv4_Mask *ret = nullptr); // mask validator
    static u32i to_u32i(const string &ipstr); // ip string to integer
    static IPv4_Addr to_IPv4(const string &ipstr); // ip string to IPv4_Addr object
    static u32i mask_len(u32i bitmask); // integer mask to mask length
    static IPv4_Mask gen_mask(u32i mask_len); // generate mask object by mask length
    enum enOctets {oct1 = 3, oct2 = 2, oct3 = 1, oct4 = 0};
};

class v6mnp {
    static vector<string> xtts_split(const string &text, char spl); // hextets splitter
    static u32i word_cnt(const string &text, const string &patt); // word counter
    static inline u32i _fmt = 0; // IETF
public:
    static const u32i IETF = 0, Upper = 1, LeadZrs = 2, Expand = 4, Full = 7; // format flags
    static const char hexUpp[];  // "0123456789ABCDEF"
    static const char hexLow[];  // "0123456789abcdef"
    static const char hexPerm[]; // "0123456789abcdefABCDEF"
    static bool valid_addr(const string &ipstr, IPv6_Addr *ret = nullptr); // address validator
    static IPv6_Addr to_IPv6(const string &ipstr); // ip string to IPv6_Addr object
    static u32i mask_len(const IPv6_Mask &mask); // bitmask to mask len
    static IPv6_Mask gen_mask(u32i mask_len); // generate bitmask from mask length
    static IPv6_Addr gen_link_local(u64i iface_id); // generate link-local address
    static IPv6_Addr gen_link_local(const MAC_Addr &mac); // generate link-local address
    static void set_fmt(u32i fmt) { _fmt = fmt; }; // setting format using format flags
    static u32i what_fmt() { return _fmt; }; // return current format
    enum enHextets {xtt1 = 7, xtt2 = 6, xtt3 = 5, xtt4 = 4, xtt5 = 3, xtt6 = 2, xtt7 = 1, xtt8 = 0};
};

class macmnp {
    static inline char _def_sep {':'};
    static inline u32i _def_grp_len {1};
    static inline bool _def_caps {true};
public:
    static const char hexPerm[];
    static bool valid_addr(const string &macstr, char sep, u32i grp_len, MAC_Addr *ret = nullptr);
    static bool valid_addr(const string &macstr, MAC_Addr *ret = nullptr) { return valid_addr(macstr, _def_sep, _def_grp_len, ret); };
    static u64i to_48bits(const string &macstr, char sep, u32i grp_len);
    static u64i to_48bits(const string &macstr);
    static MAC_Addr to_MAC(const string &macstr, char sep, u32i grp_len);
    static MAC_Addr to_MAC(const string &macstr);
    static MAC_Addr gen_mcast(const IPv4_Addr &ip);
    static MAC_Addr gen_mcast(const IPv6_Addr &ip);
    static void set_fmt(char sep, u32i grp_len, bool caps) { _def_sep = sep; _def_grp_len = (grp_len <= 3) ? grp_len : 1; _def_caps = caps; };
    static char what_sep() { return _def_sep; };
    static u32i what_grp_len() { return _def_grp_len; };
    static bool what_caps() { return _def_caps; };
    enum enOctets {oct1 = 5, oct2 = 4, oct3 = 3, oct4 = 2, oct5 = 1, oct6 = 0};
};

class MAC_Addr {
public:
    union {
        u64i as_48bits;
        u8i  as_u8i[8]; // reversed order, not human readable
    };
    MAC_Addr() { as_48bits = 0; };
    MAC_Addr(u64i _48bits) { as_48bits = _48bits; fix(); };
    MAC_Addr(u32i oui, u32i nic) { as_48bits = oui; as_48bits = ((as_48bits << 24) & 0xFFFFFF000000) | (nic & 0xFFFFFF); fix(); };
    MAC_Addr(const string &macstr, char sep, u32i grp_len) { as_48bits = macmnp::to_48bits(macstr, sep, grp_len); };
    void fix() { as_48bits &= 0x0000FFFFFFFFFFFF; };
    string to_str(char sep, u32i grp_len, bool caps) const;
    string to_str() const { return to_str(macmnp::what_sep(), macmnp::what_grp_len(), macmnp::what_caps()); };
    array<u8i,6> to_media_tx() const ;
    void set_nic(u32i nic) { *((u16i*)&as_48bits) = *((u16i*)&nic); as_u8i[macmnp::oct4] = ((u8i*)&nic)[macmnp::oct4]; };
    void set_oui(u32i oui) { *((u32i*)&as_u8i[macmnp::oct3]) = oui; as_48bits &= 0xFFFFFFFFFFFF; };
    u32i get_nic() const { return as_48bits & 0xFFFFFF; };
    u32i get_oui() const { return (as_48bits >> 24) & 0x0000000000FFFFFF; };
    bool is_ucast() const { return (as_u8i[macmnp::oct1] & 0b00000001) ? false : true; };
    bool is_mcast() const { return !is_ucast(); };
    bool is_bcast() const { return as_48bits == 0xFFFFFFFFFFFF; };
    bool is_uaa() const { return (as_u8i[macmnp::oct1] & 0b00000010) ? false : true; };
    bool is_laa() const { return !is_uaa(); };
    MAC_Addr operator&(u64i bitmask) const { return MAC_Addr{as_48bits & bitmask}; };
    MAC_Addr operator&(const MAC_Addr &bitmask) const { return MAC_Addr{as_48bits & bitmask.as_48bits}; };
    void operator&=(u64i bitmask) { as_48bits &= bitmask; };
    void operator&=(MAC_Addr &bitmask) { as_48bits &= bitmask.as_48bits; };
    bool operator>(u64i _48bits) const { return as_48bits > _48bits; };
    bool operator>(MAC_Addr mac) const { return as_48bits > mac.as_48bits; };
    bool operator<(u64i _48bits) const { return as_48bits < _48bits; };
    bool operator<(MAC_Addr mac) const { return as_48bits < mac.as_48bits; };
    bool operator>=(u64i _48bits) const { return as_48bits >= _48bits; };
    bool operator>=(MAC_Addr mac) const { return as_48bits >= mac.as_48bits; };
    bool operator<=(u64i _48bits) const { return as_48bits <= _48bits; };
    bool operator<=(MAC_Addr mac) const { return as_48bits <= mac.as_48bits; };
    bool operator==(u64i _48bits) const { return as_48bits == _48bits; };
    bool operator==(MAC_Addr mac) const { return as_48bits == mac.as_48bits; };
    bool operator!=(u64i _48bits) const { return as_48bits != _48bits; };
    bool operator!=(MAC_Addr mac) const { return as_48bits != mac.as_48bits; };
    MAC_Addr operator~() { return MAC_Addr{~as_48bits}; };
};

class IPv4_Addr {
    static inline u8i garbage;
public:
    union {
        u32i as_u32i;
        u8i  as_u8i[4]; // index [3] is MSB, index [0] is LSB, reversed order, not human readable
    };
    IPv4_Addr() { as_u32i = 0; }; // all initializers have human readable order (from left to right), derived from symbolic notation of address, where most left is MSB and most right is LSB
    IPv4_Addr(u32i val) { as_u32i = val; };
    IPv4_Addr(u8i oct1, u8i oct2, u8i oct3, u8i oct4);
    IPv4_Addr(const u8i arr [4]);
    IPv4_Addr(const array<u8i,4> &arr);
    IPv4_Addr(const string &ipstr) { v4mnp::valid_addr(ipstr, this); };
    IPv4_Addr(const char *ipcstr) { v4mnp::valid_addr(ipcstr, this); };
    string to_str() const;
    array<u8i,4> to_media_tx() const;
    bool is_unknown() const { return as_u32i == 0; }; // 0.0.0.0/32
    bool is_this_host() const { return as_u32i == 0; }; // aka "This host on this network" - RFC 1112
    bool is_private() const; // 10/8, 192.168/16, 172.(16-31)/16 - RFC 1918
    bool is_loopback() const { return (as_u32i & 0xFF000000) == 0x7F000000; }; // 127/8 - RFC 1122
    bool is_link_local() const { return (as_u32i & 0xFFFF0000) == 0xA9FE0000;  }; // 169.254/16 - RFC 3927
    bool is_lim_bcast() const { return as_u32i == 0xFFFFFFFF; }; // 255.255.255.255/32 - RFC 6890
    bool is_mcast() const { return (as_u32i & 0xF0000000) == 0xE0000000; }; // 224/4 - RFC 5771
    bool is_ssm_blk() const { return (as_u32i & 0xFF000000) == 0xE8000000; }; // 232/8 - RFC 4607
    bool is_lan_cblock() const { return (as_u32i & 0xFFFFFF00) == 0xE0000000; }; // 224.0.0/24 - Local Network Control Block - RFC 5771
    bool is_inter_cblock() const { return (as_u32i & 0xFFFFFF00) == 0xE0000100; } // 224.0.1/24 - Internetwork Control Block - RFC 5771
    bool is_adhoc_blk1() const; // 224.0.2/24-224.0.255/24 - AD-HOC Block 1 - RFC 5771
    bool is_adhoc_blk2() const; // 224.3/16-224.4/16 - AD-HOC Block II - RFC 5771
    bool is_adhoc_blk3() const { return (as_u32i & 0xFFFC0000) == 0xE9FC0000; }; // 233.252/14-233.255/14 - AD-HOC Block III - RFC 5771
    bool is_sdp_sap() const { return (as_u32i & 0xFFFF0000) == 0xE0020000; }; // 224.2/16 - SDP/SAP Block - RFC 5771
    bool is_glop_blk() const; // 233.0/16-233.251/16 - RFC 5771
    bool is_adm_scp_blk() const { return (as_u32i & 0xFF000000) == 0xEF000000; }; // 239/8 - Administratively Scoped Block - RFC 5771
    bool is_ubm() const { return (as_u32i & 0xFF000000) == 0xEA000000; } // 234/8 - RFC 6034
    bool is_ucast() const { return (as_u32i & 0xF0000000) != 0xE0000000; };
    bool is_as112() const { return (as_u32i & 0xFFFFFF00) == 0xC01FC400; }; // 192.31.196/24 - RFC 7535
    bool is_global_ucast() const;
    bool is_shared() const { return (as_u32i & 0xFFC00000) == 0x64400000; }; // 100.64/10 - RFC 6598
    bool is_reserved() const { return (as_u32i & 0xF0000000) == 0xF0000000; }; // 240/4 - RFC 6890
    bool is_docum() const; // 192.0.2/24, 198.51.100/24, 203.0.113/24 - RFC 5737
    bool is_benchm() const { return (as_u32i & 0xFFFE0000) == 0xC6120000; }; // 198.18/15 - RFC 2544
    bool is_ietf() const { return (as_u32i & 0xFFFFFF00) == 0xC0000000; }; // 192/24 - RFC 6890
    bool is_dslite() const { return (as_u32i & 0xFFFFFFF8) == 0xC0000000; }; // 192/29 - RFC 6333, RFC 7335
    bool is_amt() const { return (as_u32i & 0xFFFFFF00) == 0xC034C100; }; // 92.52.193/24 - RFC 7450
    bool is_dirdeleg() const { return (as_u32i & 0xFFFFFF00) == 0xC0AF3000; }; // 192.175.48/24 - RFC 7534
    IPv4_Addr operator+(u32i sum) const { return IPv4_Addr{as_u32i + sum}; };
    IPv4_Addr operator-(u32i sub) const { return IPv4_Addr{as_u32i - sub}; };
    void operator++(int val) { as_u32i++; };
    void operator--(int val) { as_u32i--; };
    void operator+=(u32i sum) { as_u32i += sum; };
    void operator-=(u32i sub) { as_u32i -= sub; };
    void operator+=(const IPv4_Addr &sum) { as_u32i += sum.as_u32i; };
    void operator-=(const IPv4_Addr &sub) { as_u32i -= sub.as_u32i; };
    IPv4_Addr operator<<(u32i shift) const { return IPv4_Addr{as_u32i << shift}; };
    IPv4_Addr operator>>(u32i shift) const { return IPv4_Addr{as_u32i >> shift}; };
    void operator<<=(u32i shift) { as_u32i <<= shift; };
    void operator>>=(u32i shift) { as_u32i >>= shift; };
    IPv4_Addr operator&(u32i bitmask) const { return IPv4_Addr{as_u32i & bitmask}; };
    IPv4_Addr operator&(const IPv4_Mask &bitmask) const { return IPv4_Addr{as_u32i & bitmask.as_u32i}; };
    void operator&=(u32i bitmask) { as_u32i &= bitmask; };
    void operator&=(const IPv4_Mask &bitmask) { as_u32i &= bitmask.as_u32i; };
    IPv4_Addr operator|(u32i bitmask) const { return IPv4_Addr{as_u32i | bitmask}; };
    IPv4_Addr operator|(IPv4_Mask bitmask) const { return IPv4_Addr{as_u32i | bitmask.as_u32i}; };
    void operator|=(u32i bitmask) { as_u32i |= bitmask; };
    void operator|=(const IPv4_Mask &bitmask) { as_u32i |= bitmask.as_u32i; };
    bool operator>(u32i ip) const { return as_u32i > ip; };
    bool operator>(const IPv4_Addr &ip) const { return as_u32i > ip.as_u32i; };
    bool operator<(u32i ip) const { return as_u32i < ip; };
    bool operator<(const IPv4_Addr &ip) const { return as_u32i < ip.as_u32i; };
    bool operator>=(u32i ip) const { return as_u32i >= ip; };
    bool operator>=(const IPv4_Addr &ip) const { return as_u32i >= ip.as_u32i; };
    bool operator<=(u32i ip) const { return as_u32i <= ip; };
    bool operator<=(const IPv4_Addr &ip) const { return as_u32i <= ip.as_u32i; };
    bool operator==(u32i ip) const { return as_u32i == ip; };
    bool operator==(const IPv4_Addr &ip) const { return as_u32i == ip.as_u32i; };
    bool operator!=(u32i ip) const { return as_u32i != ip; };
    bool operator!=(const IPv4_Addr &ip) const { return as_u32i != ip.as_u32i; };
    u32i operator()() const { return as_u32i; };
    u8i& operator[](u32i octet) { if (octet > 3) return garbage; return as_u8i[octet]; };
    const u8i& operator[](u32i octet) const { if (octet > 3) return garbage; return as_u8i[octet]; };
    IPv4_Addr operator~() { return IPv4_Addr{~as_u32i}; };
};

class IPv6_Addr {
    bool getzg(u32i *beg, u32i *end) const; // finds longest group of zero-hextets
    bool show_ipv4 {true};
public:
    union {
        u64i as_u64i[2]; // index [1] is MSB (left part), index [0] is LSB (right part), reversed order, not human readable
        u32i as_u32i[4]; // same principe, not human readable
        u16i as_u16i[8]; // same principe, not human readable
        u8i  as_u8i[16]; // same principe, not human readable
    };
    IPv6_Addr() { as_u64i[1] = 0; as_u64i[0] = 0; }; // all initializers have human readable order (from left to right), derived from symbolic notation of address, where most left is MSB and most right is LSB
    IPv6_Addr(u64i left, u64i right, bool flag_show_ipv4 = true) { as_u64i[0] = right; as_u64i[1] = left; show_ipv4 = flag_show_ipv4; }
    IPv6_Addr(u16i xtt1, u16i xtt2, u16i xtt3, u16i xtt4, u16i xtt5, u16i xtt6, u16i xtt7, u16i xtt8);
    IPv6_Addr(const u16i *arr);
    IPv6_Addr(const string &ipstr) { *this = v6mnp::to_IPv6(ipstr); };
    string to_str(u32i fmt) const;
    string to_str() const { return to_str(v6mnp::what_fmt()); };
    array<u8i,16> to_media_tx() const;
    bool is_unspec() const { return !(as_u64i[0] | as_u64i[1]); }; // ::1/128 - RFC 4291
    bool is_loopback() const { return (as_u64i[0] | as_u64i[1]) == 1; }; // ::/128 - RFC 4291
    bool is_glob_ucast() const { return (as_u16i[v6mnp::xtt1] & 0xFFE0) == 0x2000; }; // 2000::/3 - RFC 3513
    bool is_mcast() const {return (as_u16i[v6mnp::xtt1] & 0xFF00) == 0xFF00; }; // ff00::/8 - RFC 3513
    bool is_uniq_local() const { return (as_u16i[v6mnp::xtt1] & 0xFE00) == 0xFC00; }; // fc00::/7 - RFC 4193
    bool is_link_local() const { return (as_u16i[v6mnp::xtt1] & 0xFFC0) == 0xFE80; }; // fe80::/10 - RFC 4862
    bool is_mapped_ipv4() const { return as_u16i[v6mnp::xtt6] == 0xFFFF; }; // ::ffff:0:0/96 - RFC 4291
    bool is_wknown_pfx() const { return (as_u64i[1] == 0x0064FF9B00000000) && (as_u32i[1] == 0x00000000); } // 64:ff9b::/96 - RFC 6052
    bool is_lu_trans() const { return (as_u32i[3] == 0x0064FF9B) && (as_u16i[v6mnp::xtt3] == 0x0001); }; // 64:ff9b:1::/48  - RFC 8215
    bool is_ietf() const { return (as_u32i[3] & 0xFFFFFE) == 0x20010000; }; // 2001:0::/23 - RFC2928
    bool is_teredo() const { return as_u32i[3] == 0x20010000; }; // 2001:0::/32 - RFC4380
    bool is_benchm() const { return (as_u32i[3] == 0x20010002) && (as_u16i[v6mnp::xtt3] == 0x0000); }; // 2001:2::/48  - RFC 5180
    bool is_amt() const { return as_u32i[3] == 0x20010003; }; // 2001:3::/32 - RFC 7450
    bool is_as112() const { return (as_u32i[3] == 0x20010004) && (as_u16i[v6mnp::xtt3] == 0x0112); }; // 2001:4:112::/48 - RFC 7535
    bool is_orchv2() const { return (as_u32i[3] & 0xFFFFFFF0) == 0x20010020; }; // 2001:20::/28 - RFC 7343
    bool is_docum() const { return as_u32i[3] == 0x20010DB8; } // 2001:db8::/32 - RFC 3849
    bool is_6to4() const { return as_u16i[v6mnp::xtt1] == 0x2002; }; // 2002::/16 - RFC 3056
    void map_ipv4(u32i ipv4) { as_u16i[v6mnp::xtt6] = 0xFFFF; as_u32i[0] = ipv4; };
    void map_ipv4(IPv4_Addr ipv4) { map_ipv4(ipv4()); };
    void setflag_show_ipv4() { show_ipv4 = true; };
    void unsetflag_show_ipv4() { show_ipv4 = false; };
    IPv6_Addr operator+(const IPv6_Addr &sum) const;
    IPv6_Addr operator+(u64i sum) const;
    IPv6_Addr operator-(const IPv6_Addr &sub) const;
    IPv6_Addr operator-(u64i sub) const;
    void operator++(int val) { if (as_u64i[0] == 0xFFFFFFFFFFFFFFFF) as_u64i[1]++; as_u64i[0]++; };
    void operator--(int val) { if (as_u64i[0] == 0) as_u64i[1]--; as_u64i[0]--; };
    void operator+=(const IPv6_Addr &sum);
    void operator+=(u64i sum);
    void operator-=(const IPv6_Addr &sub);
    void operator-=(u64i sub);
    IPv6_Addr operator&(const IPv6_Addr &bitmask) const { return IPv6_Addr{as_u64i[1] & bitmask.as_u64i[1], as_u64i[0] & bitmask.as_u64i[0]}; };
    void operator&=(const IPv6_Addr &bitmask) { as_u64i[1] &= bitmask.as_u64i[1]; as_u64i[0] &= bitmask.as_u64i[0]; };
    bool operator==(const IPv6_Addr &ip) const { return (as_u64i[1] == ip.as_u64i[1]) && (as_u64i[0] == ip.as_u64i[0]); };
    bool operator!=(const IPv6_Addr &ip) const { return (as_u64i[1] != ip.as_u64i[1]) || (as_u64i[0] != ip.as_u64i[0]); };
    bool operator>(const IPv6_Addr &ip) const ;
    bool operator<(const IPv6_Addr &ip) const ;
    bool operator>=(const IPv6_Addr &ip) const ;
    bool operator<=(const IPv6_Addr &ip) const ;
    IPv6_Addr operator<<(u32i shift) const ;
    void operator<<=(u32i shift);
    IPv6_Addr operator>>(u32i shift) const ;
    void operator>>=(u32i shift);
    IPv6_Addr operator~(){ return IPv6_Addr{~as_u64i[1], ~as_u64i[0]}; };
};


#endif // GIA_IPMNP_H
