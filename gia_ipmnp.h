#ifndef GIA_IPMNP_H
#define GIA_IPMNP_H

#include <array>
#include <string>
#include <vector>
#include <cstdint>
#include <iostream>

#define DEFSEP ':'

using namespace std;

using u8i  = uint8_t;
using u16i = uint16_t;
using u32i = uint32_t;
using u64i = uint64_t;

struct u128i {
    u64i ls; // least significant
    u64i ms; // most significant
    u128i(u64i _left, u64i _right) { ls = _right, ms = _left; };
};

class IPv4_Addr;
class IPv6_Addr;
class MAC_Addr;
using IPv4_Mask = IPv4_Addr;
using IPv6_Mask = IPv6_Addr;
using MAC_Mask  = MAC_Addr;

class v4mnp {
    static u32i inner_pow(u32i x, u8i y) { if (!y) return 1; u32i ret {1}; for (; y > 0; y--) ret *= x; return ret; }
    static u32i dstr_to_u32i(const string &str);
    static string sub_str(const string &str, u32i pos, u32i len);
    static inline u8i garbage;
    static const char EX_LOW_MEM[];
    static const char EX_EXCEPT[];
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
    enum enLastError : u8i {NoError = 0, BadSyntax = 1, BadIndex = 2, STL_Exception = 3};

    friend IPv4_Addr;
    friend class v6mnp;
};

class v6mnp {
    static u16i inner_pow(u8i x, u8i y) { if (!y) return 1; u32i ret {1}; for (; y > 0; y--) ret *= x; return ret; }
    static u16i hstr_to_u16i(const string &str);
    static vector<string> xtts_split(const string &text, char spl); // hextets splitter
    static u32i word_cnt(const string &text, const string &patt); // word counter
    static inline u32i _fmt = 0; // IETF_VIEW
    static inline u16i garbage;
    static const char HEX_UPP[];  // "0123456789ABCDEF"
    static const char HEX_LOW[];  // "0123456789abcdef"
    static const char HEX_PERM[]; // "0123456789abcdefABCDEF"
public:
    static const u32i IETF_VIEW = 0, UPPER_VIEW = 1, LEADZRS_VIEW = 2, EXPAND_VIEW = 4, FULL_VIEW = 7; // format flags
    static bool valid_addr(const string &ipstr, IPv6_Addr *ret = nullptr); // address validator
    static bool valid_mask(const string &maskstr, IPv6_Mask *ret = nullptr); // mask validator
    static u128i to_u128i(const string &ipstr);
    static IPv6_Addr to_IPv6(const string &ipstr); // ip string to IPv6_Addr object
    static u32i mask_len(const IPv6_Mask &mask); // bitmask to mask len
    static IPv6_Mask gen_mask(u32i mask_len); // generate bitmask from mask length
    static IPv6_Addr gen_link_local(u64i iface_id); // generate link-local address
    static IPv6_Addr gen_link_local(const MAC_Addr &mac); // generate link-local address
    static void set_fmt(u32i fmt) { _fmt = fmt; }; // setting format using format flags
    static u32i what_fmt() { return _fmt; }; // return current format
    enum enHextets {xtt1 = 7, xtt2 = 6, xtt3 = 5, xtt4 = 4, xtt5 = 3, xtt6 = 2, xtt7 = 1, xtt8 = 0};
    enum enLastError : u8i {NoError = 0, BadSyntax = 1, BadIndex = 2, STL_Exception = 3};

    friend class IPv6_Addr;
    friend class MAC_Addr;
};

class macmnp {
    static u64i inner_pow(u8i x, u8i y);
    static u64i hstr_to_u64i(const string &str);
    static inline char _def_sep {DEFSEP};
    static inline u32i _def_grp_len {1};
    static inline bool _def_caps {true};
    static inline u8i garbage;
public:
    static const char hexPerm[];
    static bool valid_addr(const string &macstr, u32i grp_len, char sep = DEFSEP, MAC_Addr *ret = nullptr);
    static bool valid_addr(const string &macstr, MAC_Addr *ret = nullptr) { return valid_addr(macstr, _def_grp_len, _def_sep, ret); };
    static u64i to_48bits(const string &macstr, u32i grp_len, char sep = DEFSEP);
    static u64i to_48bits(const string &macstr);
    static MAC_Addr to_MAC(const string &macstr, u32i grp_len, char sep = DEFSEP);
    static MAC_Addr to_MAC(const string &macstr);
    static MAC_Addr gen_mcast(const IPv4_Addr &ip);
    static MAC_Addr gen_mcast(const IPv6_Addr &ip);
    static void set_fmt(u32i grp_len, bool caps, char sep = DEFSEP);
    static char what_sep() { return _def_sep; };
    static u32i what_grp_len() { return _def_grp_len; };
    static bool what_caps() { return _def_caps; };
    enum enOctets {oct1 = 5, oct2 = 4, oct3 = 3, oct4 = 2, oct5 = 1, oct6 = 0};
    enum enLastError : u8i {NoError = 0, BadSyntax = 1, BadIndex = 2, STL_Exception = 3};

    friend class MAC_Addr;
};

class MAC_Addr {
    union {
        u64i as_48bits {0x0};
        u8i  as_u8i[8]; // reversed order, not human readable
    };
    mutable macmnp::enLastError lerr {macmnp::NoError};
    void fix() { as_48bits &= 0x0000FFFFFFFFFFFF; };
public:
    MAC_Addr() { as_48bits = 0; };
    MAC_Addr(u64i _48bits) { as_48bits = _48bits; fix(); };
    MAC_Addr(u32i oui, u32i nic) { as_48bits = oui; as_48bits = ((as_48bits << 24) & 0xFFFFFF000000) | (nic & 0xFFFFFF); fix(); };
    MAC_Addr(const string &macstr, u32i grp_len, char sep = DEFSEP) { lerr = (macmnp::valid_addr(macstr, grp_len, sep, this)) ? macmnp::NoError : macmnp::BadSyntax; };
    MAC_Addr(const string &macstr) { lerr = (macmnp::valid_addr(macstr, macmnp::what_grp_len(), macmnp::what_sep(), this)) ? macmnp::NoError : macmnp::BadSyntax; };
    string to_str(u32i grp_len, bool caps, char sep = DEFSEP) const;
    string to_str() const { return to_str(macmnp::what_grp_len(), macmnp::what_caps(), macmnp::what_sep()); };
    array<u8i,6> to_media_tx() const;
    macmnp::enLastError last_err() const { return lerr; };
    void set_nic(u32i nic) { *((u16i*)&as_48bits) = *((u16i*)&nic); as_u8i[macmnp::oct4] = ((u8i*)&nic)[macmnp::oct4]; };
    void set_oui(u32i oui) { *((u32i*)&as_u8i[macmnp::oct3]) = oui; as_48bits &= 0xFFFFFFFFFFFF; };
    u32i get_nic() const { return as_48bits & 0xFFFFFF; };
    u32i get_oui() const { return (as_48bits >> 24) & 0x0000000000FFFFFF; };
    bool is_ucast() const { return (as_u8i[macmnp::oct1] & 0b00000001) ? false : true; };
    bool is_mcast() const { return !is_ucast(); };
    bool is_bcast() const { return as_48bits == 0xFFFFFFFFFFFF; };
    bool is_uaa() const { return (as_u8i[macmnp::oct1] & 0b00000010) ? false : true; }; // universally administered addresses
    bool is_laa() const { return !is_uaa(); }; // locally administered addresses
    bool is_even() const { return (as_48bits & 1) != 1; };
    bool is_odd() const { return (as_48bits & 1) != 0; };
    void operator+=(u64i sum) { as_48bits += sum; fix(); };
    void operator-=(u64i sub) { as_48bits -= sub; fix(); };
    void operator+=(const MAC_Addr &sum) { as_48bits += sum.as_48bits; };
    void operator-=(const MAC_Addr &sub) { as_48bits -= sub.as_48bits; };
    void operator<<=(u32i shift) { as_48bits <<= shift; fix(); };
    void operator>>=(u32i shift) { as_48bits >>= shift; };
    void operator&=(u64i bitmask) { as_48bits &= bitmask; };
    void operator&=(MAC_Mask &bitmask) { as_48bits &= bitmask.as_48bits; };
    void operator|=(u64i val) { as_48bits |= val; };
    void operator|=(MAC_Addr &val) { as_48bits |= val.as_48bits; };
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
    u64i operator()() const { return as_48bits; };
    u8i& operator[](u32i octet) { if (octet > 5) { lerr = macmnp::BadIndex; return macmnp::garbage; } lerr = macmnp::NoError; return as_u8i[octet]; };
    const u8i operator[](u32i octet) const { if (octet > 5) { lerr = macmnp::BadIndex; return macmnp::garbage; } lerr = macmnp::NoError; return as_u8i[octet]; };
    void operator/=(u64i div) { as_48bits /= div; };

    friend IPv6_Addr v6mnp::gen_link_local(const MAC_Addr &mac);
    friend bool macmnp::valid_addr(const string &macstr, u32i grp_len, char sep, MAC_Addr *ret);
    friend u64i macmnp::to_48bits(const string &macstr, u32i grp_len, char sep);
    friend u64i macmnp::to_48bits(const string &macstr);
};

class IPv4_Addr {
    union {
        u32i as_u32i {0x0};
        u8i  as_u8i[4]; // index [3] is MSB, index [0] is LSB, reversed order, not human readable
    };
    mutable v4mnp::enLastError lerr {v4mnp::NoError};
public:
    IPv4_Addr() { as_u32i = 0; }; // all initializers have human readable order (from left to right), derived from symbolic notation of address, where most left is MSB and most right is LSB
    IPv4_Addr(u32i val) { as_u32i = val; };
    IPv4_Addr(u8i oct1, u8i oct2, u8i oct3, u8i oct4);
    IPv4_Addr(const u8i arr [4]);
    IPv4_Addr(const array<u8i,4> &arr);
    IPv4_Addr(const string &ipstr) { lerr = (v4mnp::valid_addr(ipstr, this)) ? v4mnp::NoError : v4mnp::BadSyntax; };
    string to_str() const;
    array<u8i,4> to_media_tx() const;
    v4mnp::enLastError last_err() const { return lerr; };
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
    bool is_ubm() const { return (as_u32i & 0xFF000000) == 0xEA000000; } // 234/8 - Unicast-Prefix-Based Multicast - RFC 6034
    bool is_ucast() const { return (as_u32i & 0xF0000000) != 0xE0000000; }; // Unicast
    bool is_as112() const { return (as_u32i & 0xFFFFFF00) == 0xC01FC400; }; // 192.31.196/24 - RFC 7535
    bool is_global_ucast() const; // Globally routed unicast
    bool is_shared() const { return (as_u32i & 0xFFC00000) == 0x64400000; }; // 100.64/10 - RFC 6598
    bool is_reserved() const { return (as_u32i & 0xF0000000) == 0xF0000000; }; // 240/4 - RFC 6890
    bool is_docum() const; // 192.0.2/24, 198.51.100/24, 203.0.113/24 - RFC 5737
    bool is_benchm() const { return (as_u32i & 0xFFFE0000) == 0xC6120000; }; // 198.18/15 - RFC 2544
    bool is_ietf() const { return (as_u32i & 0xFFFFFF00) == 0xC0000000; }; // 192/24 - RFC 6890
    bool is_dslite() const { return (as_u32i & 0xFFFFFFF8) == 0xC0000000; }; // 192/29 - RFC 6333, RFC 7335
    bool is_amt() const { return (as_u32i & 0xFFFFFF00) == 0xC034C100; }; // 92.52.193/24 - RFC 7450
    bool is_dirdeleg() const { return (as_u32i & 0xFFFFFF00) == 0xC0AF3000; }; // 192.175.48/24 - RFC 7534
    bool is_even() const { return !(as_u32i & 1); };
    bool is_odd() const { return as_u32i & 1; };
    bool can_be_mask() const;
    void operator++(int val) { as_u32i++; };
    void operator--(int val) { as_u32i--; };
    void operator+=(u32i sum) { as_u32i += sum; };
    void operator-=(u32i sub) { as_u32i -= sub; };
    void operator+=(const IPv4_Addr &sum) { as_u32i += sum.as_u32i; };
    void operator-=(const IPv4_Addr &sub) { as_u32i -= sub.as_u32i; };
    void operator<<=(u32i shift) { as_u32i <<= shift; };
    void operator>>=(u32i shift) { as_u32i >>= shift; };
    void operator&=(u32i bitmask) { as_u32i &= bitmask; };
    void operator&=(const IPv4_Mask &bitmask) { as_u32i &= bitmask.as_u32i; };
    void operator|=(u32i val) { as_u32i |= val; };
    void operator|=(const IPv4_Addr &val) { as_u32i |= val.as_u32i; };
    bool operator>(u64i val) const { return as_u32i > val; };
    bool operator>(const IPv4_Addr &ip) const { return as_u32i > ip.as_u32i; };
    bool operator<(u64i val) const { return as_u32i < val; };
    bool operator<(const IPv4_Addr &ip) const { return as_u32i < ip.as_u32i; };
    bool operator>=(u64i val) const { return as_u32i >= val; };
    bool operator>=(const IPv4_Addr &ip) const { return as_u32i >= ip.as_u32i; };
    bool operator<=(u64i val) const { return as_u32i <= val; };
    bool operator<=(const IPv4_Addr &ip) const { return as_u32i <= ip.as_u32i; };
    bool operator==(u64i val) const { return as_u32i == val; };
    bool operator==(const IPv4_Addr &ip) const { return as_u32i == ip.as_u32i; };
    bool operator!=(u64i val) const { return as_u32i != val; };
    bool operator!=(const IPv4_Addr &ip) const { return as_u32i != ip.as_u32i; };
    u32i operator()() const { return as_u32i; };
    u8i& operator[](u32i octet) { if (octet > 3) { lerr = v4mnp::BadIndex; return v4mnp::garbage; } lerr = v4mnp::NoError; return as_u8i[octet]; };
    const u8i& operator[](u32i octet) const { if (octet > 3) { lerr = v4mnp::BadIndex; return v4mnp::garbage; } lerr = v4mnp::NoError; return as_u8i[octet]; };
    IPv4_Addr operator~() { return IPv4_Addr{~as_u32i}; };
    void operator/=(u32i div) { as_u32i /= div; };

    friend bool v4mnp::valid_addr(const string &ipstr, IPv4_Addr *ret);
    friend bool v4mnp::valid_mask(const string &maskstr, IPv4_Mask *ret);
    friend MAC_Addr macmnp::gen_mcast(const IPv4_Addr &ip);
};

class IPv6_Addr {
    union {
        u128i as_u128i {0x0, 0x0};
        u64i  as_u64i[2]; // index [1] is MSB (left part), index [0] is LSB (right part), reversed order, not human readable
        u32i  as_u32i[4]; // same principe, not human readable
        u16i  as_u16i[8]; // same principe, not human readable
        u8i   as_u8i[16]; // same principe, not human readable
    };
    mutable v6mnp::enLastError lerr {v6mnp::NoError};
    bool getzg(u32i *beg, u32i *end) const; // finds longest group of zero-hextets
    bool show_ipv4 {true};
public:
    IPv6_Addr() { as_u128i.ms = 0; as_u128i.ls = 0; }; // all initializers have human readable order (from ms to ls), derived from symbolic notation of address, where most ms is MSB and most ls is LSB
    IPv6_Addr(u64i left, u64i right) { as_u128i.ls = right; as_u128i.ms = left; }
    IPv6_Addr(u64i left, u64i right, bool flag_show_ipv4) { as_u128i.ls = right; as_u128i.ms = left; show_ipv4 = flag_show_ipv4; }
    IPv6_Addr(u128i val) { as_u128i = val; };
    IPv6_Addr(u16i xtt1, u16i xtt2, u16i xtt3, u16i xtt4, u16i xtt5, u16i xtt6, u16i xtt7, u16i xtt8);
    IPv6_Addr(const u16i arr[8]);
    IPv6_Addr(const array<u16i,8> &arr);
    IPv6_Addr(const string &ipstr) { lerr = (v6mnp::valid_addr(ipstr, this)) ? v6mnp::NoError : v6mnp::BadSyntax; };
    string to_str(u32i fmt) const;
    string to_str() const { return to_str(v6mnp::what_fmt()); };
    array<u8i,16> to_media_tx() const;
    v6mnp::enLastError last_err() const { return lerr; };
    bool is_unspec() const { return !(as_u128i.ls | as_u128i.ms); }; // ::1/128 - RFC 4291
    bool is_loopback() const { return (as_u128i.ls | as_u128i.ms) == 1; }; // ::/128 - RFC 4291
    bool is_glob_ucast() const { return (as_u16i[v6mnp::xtt1] & 0xFFE0) == 0x2000; }; // 2000::/3 - RFC 3513
    bool is_mcast() const {return (as_u16i[v6mnp::xtt1] & 0xFF00) == 0xFF00; }; // ff00::/8 - RFC 3513
    bool is_uniq_local() const { return (as_u16i[v6mnp::xtt1] & 0xFE00) == 0xFC00; }; // fc00::/7 - RFC 4193
    bool is_link_local() const { return (as_u16i[v6mnp::xtt1] & 0xFFC0) == 0xFE80; }; // fe80::/10 - RFC 4862
    bool is_mapped_ipv4() const { return as_u16i[v6mnp::xtt6] == 0xFFFF; }; // ::ffff:0:0/96 - RFC 4291
    bool is_wknown_pfx() const { return (as_u128i.ms == 0x0064FF9B00000000) && (as_u32i[1] == 0x00000000); } // 64:ff9b::/96 - RFC 6052
    bool is_lu_trans() const { return (as_u32i[3] == 0x0064FF9B) && (as_u16i[v6mnp::xtt3] == 0x0001); }; // 64:ff9b:1::/48  - RFC 8215
    bool is_ietf() const { return (as_u32i[3] & 0xFFFFFE) == 0x20010000; }; // 2001:0::/23 - RFC2928
    bool is_teredo() const { return as_u32i[3] == 0x20010000; }; // 2001:0::/32 - RFC4380
    bool is_benchm() const { return (as_u32i[3] == 0x20010002) && (as_u16i[v6mnp::xtt3] == 0x0000); }; // 2001:2::/48  - RFC 5180
    bool is_amt() const { return as_u32i[3] == 0x20010003; }; // 2001:3::/32 - RFC 7450
    bool is_as112() const { return (as_u32i[3] == 0x20010004) && (as_u16i[v6mnp::xtt3] == 0x0112); }; // 2001:4:112::/48 - RFC 7535
    bool is_orchv2() const { return (as_u32i[3] & 0xFFFFFFF0) == 0x20010020; }; // 2001:20::/28 - RFC 7343
    bool is_docum() const { return as_u32i[3] == 0x20010DB8; } // 2001:db8::/32 - RFC 3849
    bool is_6to4() const { return as_u16i[v6mnp::xtt1] == 0x2002; }; // 2002::/16 - RFC 3056
    bool is_even() const { return !(as_u128i.ls & 1); };
    bool is_odd() const { return as_u128i.ls & 1; };
    bool can_be_mask() const;
    void map_ipv4(u32i ipv4) { as_u16i[v6mnp::xtt6] = 0xFFFF; as_u32i[0] = ipv4; };
    void map_ipv4(IPv4_Addr ipv4) { map_ipv4(ipv4()); };
    void setflag_show_ipv4() { show_ipv4 = true; };
    void unsetflag_show_ipv4() { show_ipv4 = false; };
    void operator++(int val) { if (as_u128i.ls == 0xFFFFFFFFFFFFFFFF) as_u128i.ms++; as_u128i.ls++; };
    void operator--(int val) { if (as_u128i.ls == 0) as_u128i.ms--; as_u128i.ls--; };
    void operator+=(const IPv6_Addr &sum);
    void operator+=(u64i sum);
    void operator-=(const IPv6_Addr &sub);
    void operator-=(u64i sub);
    void operator&=(const IPv6_Mask &bitmask) { as_u128i.ms &= bitmask.as_u128i.ms; as_u128i.ls &= bitmask.as_u128i.ls; };
    bool operator==(const IPv6_Addr &ip) const { return (as_u128i.ms == ip.as_u128i.ms) && (as_u128i.ls == ip.as_u128i.ls); };
    void operator|=(const IPv6_Addr &val) { as_u128i.ms |= val.as_u128i.ms; as_u128i.ls |= val.as_u128i.ls; };
    bool operator!=(const IPv6_Addr &ip) const { return (as_u128i.ms != ip.as_u128i.ms) || (as_u128i.ls != ip.as_u128i.ls); };
    bool operator>(const IPv6_Addr &ip) const;
    bool operator<(const IPv6_Addr &ip) const;
    bool operator>=(const IPv6_Addr &ip) const;
    bool operator<=(const IPv6_Addr &ip) const;
    IPv6_Addr operator<<(u32i shift) const;
    void operator<<=(u32i shift);
    IPv6_Addr operator>>(u32i shift) const;
    void operator>>=(u32i shift);
    u128i operator()() const { return as_u128i; };
    u16i& operator[](u32i xtet) { if (xtet > 7) { lerr = v6mnp::BadIndex; return v6mnp::garbage;} lerr = v6mnp::NoError; return as_u16i[xtet]; };
    const u16i& operator[](u32i xtet) const { if (xtet > 7) { lerr = v6mnp::BadIndex; return v6mnp::garbage;} lerr = v6mnp::NoError; return as_u16i[xtet]; };
    IPv6_Addr operator~(){ return IPv6_Addr{~as_u128i.ms, ~as_u128i.ls}; };

    friend bool v6mnp::valid_addr(const string &ip, IPv6_Addr *ret);
    friend bool v6mnp::valid_mask(const string &ipstr, IPv6_Mask *ret);
    friend u32i v6mnp::mask_len(const IPv6_Mask &mask);
    friend u128i v6mnp::to_u128i(const string &ipstr);
    friend MAC_Addr macmnp::gen_mcast(const IPv6_Addr &ip);
};


#endif // GIA_IPMNP_H
