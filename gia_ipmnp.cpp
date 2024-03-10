#include "gia_ipmnp.h"
#include <memory.h>
//#include <iostream>

using namespace std;

const char v6mnp::hexUpp[]  {"0123456789ABCDEF"};
const char v6mnp::hexLow[]  {"0123456789abcdef"};
const char v6mnp::hexPerm[] {"0123456789abcdefABCDEF:."};

const char macmnp::hexPerm[] {"0123456789abcdefABCDEF"};

u32i v4mnp::dstr_to_u32i(const string &str) { // string must be preliminarily checked for permitted symbols and max len = 3
    u8i strLen = str.length();
    u8i digNum = strLen;
    u32i ret {0x0};
    do {
        ret += (str[digNum - 1] - '0') * inner_pow(10, (strLen - digNum));
        digNum--;
    } while (digNum > 0);
    return ret;
}

string v4mnp::sub_str(const string &str, u32i pos, u32i len) {
    u32i strLen = str.length();
    if (pos < strLen) {
        u32i resLen = (pos + len > strLen) ? strLen - pos : len;
        string ret(resLen, '\0');
        memcpy(ret.data(), str.data() + pos, resLen);
        return ret;
    }
    return "";
}

bool v4mnp::valid_addr(const string &ipstr, IPv4_Addr *ret) {
    if (ret != nullptr) ret->as_u32i = 0x0;
    size_t len {ipstr.length()};
    if ((len > 15) || (len < 7)) return false;
    size_t dotpos[3];
    size_t index {0}; // [index] in dotsPos array
    u32i dots {0}; // dots counter
    for (auto && ch : ipstr) { // check for permitted symbols and dots counting
        if ((ch > '9') || ((ch < '0') && (ch != '.'))) return false;
        if (ch == '.') {
            if (dots <= 3) dotpos[dots] = index;
            dots++;
        }
        index++;
    }
    if (dots != 3) return false;
    string ss[4] {
        // ipstr.substr(dotpos[2] + 1, len - dotpos[2] - 1),
        // ipstr.substr(dotpos[1] + 1, dotpos[2] - dotpos[1] - 1),
        // ipstr.substr(dotpos[0] + 1, dotpos[1] - dotpos[0] - 1),
        // ipstr.substr(0, dotpos[0])
        sub_str(ipstr, dotpos[2] + 1, len - dotpos[2] - 1),
        sub_str(ipstr, dotpos[1] + 1, dotpos[2] - dotpos[1] - 1),
        sub_str(ipstr, dotpos[0] + 1, dotpos[1] - dotpos[0] - 1),
        sub_str(ipstr, 0, dotpos[0])
    };
    u32i octets[4];
    for (u32i oct = 0; oct < 4; oct++) {
        if ((!ss[oct].empty()) && (ss[oct].length() <= 3)) {
            //octets[oct] = stoi(ss[oct]);
            octets[oct] = dstr_to_u32i(ss[oct]);
        } else {
            return false;
        }
    }
    if ((octets[0] > 255) || (octets[1] > 255) || (octets[2] > 255) || (octets[3] > 255)) return false;
    if (ret != nullptr) {
        for (auto i = 0; i <= 3; i++) {
            ret->as_u32i |= (octets[i] << (8 * i));
        }
    }
    return true;
}

bool v4mnp::valid_mask(const string &maskstr, IPv4_Mask *ret) {
    if (ret != nullptr) *ret = u32i(0x0);
    IPv4_Mask interim;
    if (!valid_addr(maskstr, &interim)) return false;
    u32i shift {0};
    for ( ; shift < 32; shift++) { // looking for binary ones
        if ((interim.as_u32i >> shift) & 1) break;
    }
    if (shift != 32) { // looking for binary zeros
        for ( ; shift < 32; shift++)
            if (!((interim.as_u32i >> shift) & 1))
                return false;
    }
    if (ret != nullptr) *ret = interim;
    return true;
}

u32i v4mnp::to_u32i(const string &ipstr) {
    IPv4_Addr ret;
    valid_addr(ipstr, &ret);
    return ret();
}

IPv4_Addr v4mnp::to_IPv4(const string &ipstr) {
    IPv4_Addr ret;
    valid_addr(ipstr, &ret);
    return ret;
}

u32i v4mnp::mask_len(u32i bitmask) {
    u32i shift {0};
    for ( ; shift < 32; shift++ ) if ((bitmask >> shift) & 1) break;
    return 32 - shift;
}

IPv4_Mask v4mnp::gen_mask(u32i mlen) {
    if (mlen > 32) mlen = 32;
    return (mlen == 0) ? IPv4_Mask(u32i(0)): IPv4_Mask(UINT32_MAX << (32 - mlen));
}

u32i v6mnp::word_cnt(const string &text, const string &patt) {
    size_t tlen {text.length()};
    size_t plen {patt.length()};
    size_t nextPos {0};
    u32i wc {0}; // word counter
    do {
        nextPos = text.find(patt, nextPos);
        if (nextPos == SIZE_MAX) {
            break;
        } else {
            wc++;
        }
        nextPos++;
    } while (nextPos <= (tlen - plen));
    return wc;
}

u16i v6mnp::hstr_to_u16i(const string &str) { // string must be preliminarily checked for permitted symbols and max len = 4
    u8i strLen = str.length();
    u8i digNum = strLen;
    u16i ret {0x0};
    u8i  deduct;
    u8i  symb;
    do {
        symb = str[digNum - 1];
        switch (symb & 0xF0) {
        case 0b01100000: // a - f
            deduct = 87;
            break;
        case 0b01000000: // A - F
            deduct = 55;
            break;
        default: // 0 - 9
            deduct = 48;
        }
        ret += (symb - deduct) * inner_pow(16, (strLen - digNum));
        digNum--;
    } while (digNum > 0);
    return ret;
}

vector<string> v6mnp::xtts_split(const string &text, char spl) {
    vector<string> ret;
    size_t lastIdx = text.length() - 1;
    size_t start {0}; // start of new hextet
    for (size_t idx = 0; idx <= lastIdx; idx++) {
        if (text[idx] == spl) {
            if (idx == 0) {
                if (text[idx + 1] == ':') {
                    ret.push_back("0");
                } else {
                    ret.push_back("");
                }
            } else {
                if (idx == start) {
                    //ret.push_back(text.substr(start, 1));
                    ret.push_back(v4mnp::sub_str(text, start, 1));
                } else {
                    //ret.push_back(text.substr(start, idx - start));
                    ret.push_back(v4mnp::sub_str(text, start, idx - start));
                }
            }
            start = idx + 1;
            if (idx == lastIdx) {
                if (text[idx - 1] == ':') {
                    ret.push_back("0");
                } else {
                    ret.push_back("");
                }
            }
        }
        if ((idx == lastIdx) && (text[idx] != ':')) {
            //ret.push_back(text.substr(start, idx - start + 1));
            ret.push_back(v4mnp::sub_str(text, start, idx - start + 1));
        }
    }
    return ret;
}

bool v6mnp::valid_addr(const string &ipstr, IPv6_Addr *ret) {
    if (ret != nullptr) *ret = {0x0, 0x0};
    IPv6_Addr interim {0, 0}; // reverse order like in real memory
    u32i leftToFill {8}; // hextets left to fill
    size_t fullLen {ipstr.length()};
    bool v4embed {false}; // is embedded ipv4 address present?
    u32i v4dots {0}; // ipv4 dots counter
    size_t v4Len {0}; // len of embedden ipv4
    u32i dblColons {0}; // times of double colons repeating
    u32i colons {0}; // single colons count

    // length check;
    if ((fullLen < 2) || (fullLen > 45)) return false;
    // repeating of double colon check
    dblColons = word_cnt(ipstr, "::");
    if (dblColons > 1) return false;
    // colon count check
    colons = word_cnt(ipstr, ":");
    if ((colons > 7) || (colons < 2)) return false;
    // dots count check
    v4dots = word_cnt(ipstr, ".");
    if (((v4dots >= 1) && (v4dots <= 2)) || (v4dots > 3)) return false;
    if (v4dots == 3) v4embed = true;
    if (v4embed && (!dblColons) && (colons < 6)) return false; // in case "a:b:a:255.100.3.3"
    if ((!dblColons) && (colons < 7)) return false;
    if (ipstr == "::") return true;
    if (ipstr == "::1") {
        if (ret != nullptr) (*ret).as_u8i[0] = 1;
        return true;
    }

    // bad symbols check
    bool badsymb; // is bad symbols present?
    for (auto && ipchar : ipstr) {
        badsymb = true;
        for (auto && perm : hexPerm) {
            if (ipchar == perm) {
                badsymb = false;
                break;
            }
        }
        if (badsymb) return false;
    }

    // if ipv4 is mapped, checking for correctness of ipv4
    if (v4embed) {
        size_t idx = fullLen;
        do {
            idx--;
            if (ipstr[idx] == ':') break;
        } while (idx > 1);
        idx++;
        IPv4_Addr ipv4;
        v4Len = fullLen - idx;
        //if (v4mnp::valid_addr(ipstr.substr(idx, fullLen - idx), &ipv4)) {
        if (v4mnp::valid_addr(v4mnp::sub_str(ipstr, idx, fullLen - idx), &ipv4)) {
            interim.as_u32i[0] = ipv4();
            leftToFill -= 2;
        } else return false;
    }

    // check for ipv4 dots in wrong places
    //if ((v4embed) && (word_cnt(ipstr.substr(0, fullLen - v4Len), "."))) return false;
    if ((v4embed) && (word_cnt(v4mnp::sub_str(ipstr, 0, fullLen - v4Len), "."))) return false;

    // splitting hextets
    vector <string> xttVec;
    if (v4embed) {
//        if (ipstr.substr(fullLen - v4Len - 2, 2) != "::") {
//            xttVec = xtts_split(ipstr.substr(0, fullLen - v4Len - 1), ':');
        if (v4mnp::sub_str(ipstr, fullLen - v4Len - 2, 2) != "::") {
            xttVec = xtts_split(v4mnp::sub_str(ipstr, 0, fullLen - v4Len - 1), ':');
        } else {
            //xttVec = xtts_split(ipstr.substr(0, fullLen - v4Len), ':');
            xttVec = xtts_split(v4mnp::sub_str(ipstr, 0, fullLen - v4Len), ':');
        }
    } else {
//        xttVec = xtts_split(ipstr.substr(0, fullLen), ':');
        xttVec = xtts_split(v4mnp::sub_str(ipstr, 0, fullLen), ':');
    }
    size_t vecLen = xttVec.size(); // vector length
    if (vecLen > leftToFill) return false;
    if ((!dblColons) && (vecLen < leftToFill)) return false;

    // checking hextets, and multiplying double colon hextets
    u32i nextIdx {8 - leftToFill}; // next hextet to fill
    for (auto it = xttVec.rbegin(); it != xttVec.rend(); it++) {
        if ((*it).empty()) return false;
        if ((*it).length() > 4) return false; // check for each hextet length
        u32i decimal;
        if (*it != ":") { // colon symbol is used as marker of repeating zeroes group
            //decimal = stoi(*it, nullptr, 16);
            decimal = hstr_to_u16i(*it);
            interim.as_u16i[nextIdx] = decimal;
            nextIdx++;
        } else { // multiply zero-hextets by skipping such groups in interim (interim is also initialized by zeroes)
            nextIdx += (leftToFill - vecLen + 1);
        }
    }
    if (ret != nullptr) *ret = interim;
    return true;
}

bool v6mnp::valid_mask(const string &maskstr, IPv6_Mask *ret) {
    if (ret != nullptr) *ret = {0x0, 0x0};
    IPv6_Mask interim;
    if (!valid_addr(maskstr, &interim)) return false;
    u32i shift {0};
    for ( ; shift < 64; shift++) { // looking for binary ones in least signif. part
        if ((interim.as_u128i.ls >> shift) & 1) break;
    }
    if (shift != 64) { // found last binary one in previous loop; looking for binary zeros in least signif. part
        for ( ; shift < 64; shift++)
            if (!((interim.as_u128i.ls >> shift) & 1))
                return false;
    }
    // here, if no binary ones was found in least signif. part
    shift = 0;
    for ( ; shift < 64; shift++) { // looking for binary ones in most signif. part
        if ((interim.as_u128i.ms >> shift) & 1) break;
    }
    if (shift != 64) { // looking for binary zeros in most signif. part
        for ( ; shift < 64; shift++)
            if (!((interim.as_u128i.ms >> shift) & 1))
                return false;
    }
    if (ret != nullptr) *ret = interim;
    return true;
}

u128i v6mnp::to_u128i(const string &ipstr) {
    IPv6_Addr ret;
    valid_addr(ipstr, &ret);
    return ret();
}

IPv6_Addr v6mnp::to_IPv6(const string &ipstr) {
    IPv6_Addr ret;
    valid_addr(ipstr, &ret);
    return ret;
}

u32i v6mnp::mask_len(const IPv6_Mask &mask) {
    u32i zrcnt {0};
    for ( ; zrcnt < 64; zrcnt++) {
        if ((mask.as_u128i.ls >> zrcnt) & 1) return 128 - zrcnt;
    };
    zrcnt = 0;
    for (; zrcnt < 64; zrcnt++) {
        if ((mask.as_u128i.ms >> zrcnt) & 1) return 64 - zrcnt;
    }
    return 0;
}

IPv6_Mask v6mnp::gen_mask(u32i mask_len) {
    if (mask_len > 128) mask_len = 128;
    u64i left = 0xFFFF'FFFF'FFFF'FFFF, right = 0xFFFF'FFFF'FFFF'FFFF;
    u32i shift = 128 - mask_len;
    if ((shift > 64) && (shift < 128)) {
        left = 0;
        left |= (right << (64 - mask_len));
        right = 0;
    } else (shift == 128) ? (left = 0, right = 0) : ((shift == 64) ? right = 0 : right <<= shift);
    return IPv6_Mask {left, right, false};
}

IPv6_Addr v6mnp::gen_link_local(u64i iface_id) {
    return IPv6_Addr{0xFE80000000000000, iface_id, false};
}

IPv6_Addr v6mnp::gen_link_local(const MAC_Addr &mac) {
    u8i _as_u8i[8];
    _as_u8i[7] = mac.as_u8i[macmnp::oct1] | 0b00000010;
    *((u16i*)(&_as_u8i[5])) = *((u16i*)(&mac.as_u8i[macmnp::oct3]));
    *((u16i*)(&_as_u8i[3])) = 0xFFFE;
    _as_u8i[2] = mac.as_u8i[macmnp::oct4];
    *((u16i*)(&_as_u8i[0])) = *((u16i*)(&mac.as_u8i[macmnp::oct6]));
    return IPv6_Addr{0xFE80000000000000, *((u64i*)(&_as_u8i[0])), false};
}

IPv4_Addr::IPv4_Addr(u8i oct1, u8i oct2, u8i oct3, u8i oct4) {
    as_u8i[0] = oct4;
    as_u8i[1] = oct3;
    as_u8i[2] = oct2;
    as_u8i[3] = oct1;
}

IPv4_Addr::IPv4_Addr(const u8i *arr) {
    for (u32i idx = 0; idx <= 3; idx++){
        as_u8i[idx] = arr[3 - idx];
    }
}

IPv4_Addr::IPv4_Addr(const array<u8i,4> &arr) {
    for (u32i idx = 0; idx <= 3; idx++){
        as_u8i[idx] = arr[3 - idx];
    }
}

string IPv4_Addr::to_str() const {
    string ret;
    ret.reserve(17);
    u32i idx {4};
    do {
        idx--;
        ret += (to_string(u32i(as_u8i[idx])) + ".");
    } while (idx != 0);
    ret.pop_back(); // cut-off last dot
    return ret;
}

array<u8i,4> IPv4_Addr::to_media_tx() const {
    array <u8i,4> ret;
    for (u32i idx = 0; idx < 4; idx++) {
        ret[3 - idx] = as_u8i[idx];
    }
    return ret;
}

bool IPv4_Addr::is_global_ucast() const {
    return (!is_unknown()) && (!is_private()) && (!is_loopback()) && (!is_link_local()) && (!is_lim_bcast()) && (!is_mcast())
           && (!is_as112()) && (!is_shared()) && (!is_reserved()) && (!is_docum()) && (!is_benchm()) && (!is_ietf()) && (!is_amt()) && (!is_dirdeleg());
}

bool IPv4_Addr::is_glop_blk() const {
    if ((as_u8i[v4mnp::oct1] == 233) && ((as_u8i[v4mnp::oct2] >= 0) && (as_u8i[v4mnp::oct2] <= 251))) return true;
    return false;
};

bool IPv4_Addr::is_adhoc_blk1() const {
    if (((as_u32i & 0xFFFF0000) == 0xE0000000) && ((as_u8i[v4mnp::oct3] >= 2) && (as_u8i[v4mnp::oct3] <= 255))) return true;
    return false;
}

bool  IPv4_Addr::is_adhoc_blk2() const {
    if (((as_u32i & 0xFF000000) == 0xE0000000) && ((as_u8i[v4mnp::oct2] == 3) || (as_u8i[v4mnp::oct2] == 4))) return true;
    return false;
}

bool IPv4_Addr::is_private() const {
    if ((as_u32i & 0xFF000000) == 0x0A000000) return true; // 10/8
    if ((as_u32i & 0xFFF00000) == 0xAC100000) return true; // 172.(16-31)/16
    if ((as_u32i & 0xFFFF0000) == 0xC0A80000) return true; // 192.168/16
    return false;
}

bool IPv4_Addr::can_be_mask() const {
    u32i shift {0};
    for ( ; shift < 32; shift++ ) { // looking for binary ones
        if ((as_u32i >> shift) & 1) break;
    }
    if (shift != 32) { // looking for binary zeros
        for ( ; shift < 32; shift++)
            if (!((as_u32i >> shift) & 1))
                return false;
    }
    return true;
}

bool IPv4_Addr::is_docum() const {
    if ((as_u32i & 0xFFFFFF00) == 0xC0000200) return true; // 192.0.2/24 (TEST-NET-1)
    if ((as_u32i & 0xFFFFFF00) == 0xC6336400) return true; // 198.51.100/24 (TEST-NET-2)
    if ((as_u32i & 0xFFFFFF00) == 0xCB007100) return true; // 203.0.113/24 (TEST-NET-3)
    return false;
}

IPv6_Addr::IPv6_Addr(const u16i arr[8]) {
    for (u32i idx = 0; idx <= 7; idx++) {
        as_u16i[idx] = arr[7 - idx];
    }
}

IPv6_Addr::IPv6_Addr(const array<u16i,8> &arr) {
    for (u32i idx = 0; idx <= 7; idx++) {
        as_u16i[idx] = arr[7 - idx];
    }
}

IPv6_Addr::IPv6_Addr(u16i xtt1, u16i xtt2, u16i xtt3, u16i xtt4, u16i xtt5, u16i xtt6, u16i xtt7, u16i xtt8) {
    as_u16i[7] = xtt1;
    as_u16i[6] = xtt2;
    as_u16i[5] = xtt3;
    as_u16i[4] = xtt4;
    as_u16i[3] = xtt5;
    as_u16i[2] = xtt6;
    as_u16i[1] = xtt7;
    as_u16i[0] = xtt8;
}

bool IPv6_Addr::getzg(u32i *beg, u32i *end) const {
    struct { u32i beg, end, len; } zrGrp[3] {{0,0,0}, {0,0,0}, {0,0,0}}, zrBestGrp; // groups of zeroed hextets
    u32i cur {0}; // current group number
    bool start {true}; // start of zeroes sequence ?
    bool preZr {false}; // previous hextet was zero?
    u32i idx {8};
    do {
        idx--;
        if (as_u16i[idx] == 0) {
            zrGrp[cur].len++;
            if (start) {
                zrGrp[cur].beg = idx;
                start = false;
            }
            preZr = true;
        } else {
            if (preZr) {
                zrGrp[cur].end = idx + 1;
                cur++;
                preZr = false;
            }
            start = true;
        }
    } while (idx > 0);
    zrBestGrp = zrGrp[0];
    for (u32i i = 1; i < 3; i++) {
        if ((zrGrp[i].beg - zrGrp[i].end) > (zrBestGrp.beg - zrBestGrp.end)) {
            zrBestGrp = zrGrp[i];
        }
    }
    if (zrBestGrp.len > 1) {
        *beg = zrBestGrp.beg;
        *end = zrBestGrp.end;
        return true;
    } else {
        *beg = 0;
        *end = 0;
    }
    return false;
}

string IPv6_Addr::to_str(u32i fmt) const {
    const char *useSet = ((fmt & v6mnp::UPPER_VIEW) == v6mnp::UPPER_VIEW) ? v6mnp::hexUpp : v6mnp::hexLow;
    string ret;
    ret.reserve(46);
    char full[8][6] {"0000:", "0000:", "0000:", "0000:", "0000:", "0000:", "0000:", "0000\0"};
    u32i leadZr[8] {0, 0, 0, 0, 0, 0, 0, 0}; // counters of leading zeroes in each hextet
    for (u32i idx = 0; idx < 8; idx++) { // walking thru each hextet
        bool prevZr {true}; // previous symbol was zero?
        u32i mul {4};
        do { // walking thru each nibble
            mul--;
            full[idx][3 - mul] = useSet[(as_u16i[7 - idx] >> (4 * mul)) & 0x0F];
            if ((full[idx][3 - mul] == '0') && prevZr) {
                leadZr[idx]++;
                if (leadZr[idx] == 4) leadZr[idx] = 3;
            } else {
                prevZr = false;
            };
        } while (mul > 0);
    }
    if ((fmt & v6mnp::LEADZRS_VIEW) != v6mnp::LEADZRS_VIEW) { // deleting leading zeroes in each hextet
        for (u32i idx = 0; idx < 8; idx++) {
            memcpy(&(full[idx][0]), &(full[idx][leadZr[idx]]), (6 - leadZr[idx]));
        }
    }
    bool v4 = (show_ipv4 && (as_u16i[v6mnp::xtt6] == 0xFFFF)) ? true : false;
    u32i lastIdx = (v4) ? 2 : 0;
    u32i izg, ezg; // initial and ending repeating-zeroes group of hextets
    if (((fmt & v6mnp::EXPAND_VIEW) != v6mnp::EXPAND_VIEW) && getzg(&izg, &ezg)) { // collapsing repeating zeroes group
        u32i idx {8};
        do {
            idx--;
            if ((idx > izg) || (idx < ezg)) {
                ret = ret + full[7 - idx];
            } else { // jump right after end of zero-hextet group
                if (ret.empty()) {
                    ret.append("::");
                } else {
                    ret.push_back(':');
                }
                idx = ezg;
            }
        } while (idx > lastIdx);
    } else { // w/o collapsing (expanded form)
        for (u32i idx = 0; idx < 8 - lastIdx; idx++) {
            ret.append(full[idx]);
        }
    }
    if (v4) {
        ret.append(IPv4_Addr(as_u32i[0]).to_str());
    }
    return ret;
}

array<u8i,16> IPv6_Addr::to_media_tx() const {
    array <u8i,16> ret;
    for (u32i idx = 0; idx < 16; idx++) {
        ret[15 - idx] = as_u8i[idx];
    }
    return ret;
}

bool IPv6_Addr::can_be_mask() const {
    u32i shift {0};
    for ( ; shift < 64; shift++ ) { // looking for binary ones in least signif. part
        if ((as_u128i.ls >> shift) & 1) break;
    }
    if (shift != 64) { // looking for binary zeros in least signif. part
        for ( ; shift < 64; shift++)
            if (!((as_u128i.ls >> shift) & 1))
                return false;
    }
    // here, if no binary ones was found in least signif. part
    shift = 0;
    for ( ; shift < 64; shift++ ) { // looking for binary ones in most signif. part
        if ((as_u128i.ms >> shift) & 1) break;
    }
    if (shift != 64) { // looking for binary zeros in most signif. part
        for ( ; shift < 64; shift++)
            if (!((as_u128i.ms >> shift) & 1))
                return false;
    }
    return true;
}

// IPv6_Addr IPv6_Addr::operator+(const IPv6_Addr &sum) const {
//     IPv6_Addr ret {*this};
//     ret.as_u128i.ms += sum.as_u128i.ms;
//     if ((0xFFFF'FFFF'FFFF'FFFF - as_u128i.ls) < sum.as_u128i.ls) ret.as_u128i.ms++;
//     ret.as_u128i.ls += sum.as_u128i.ls;
//     return ret;
// }

// IPv6_Addr IPv6_Addr::operator+(u64i sum) const {
//     IPv6_Addr ret {*this};
//     if ((0xFFFF'FFFF'FFFF'FFFF - as_u128i.ls) < sum) ret.as_u128i.ms++;
//     ret.as_u128i.ls += sum;
//     return ret;
// }

// IPv6_Addr IPv6_Addr::operator-(const IPv6_Addr &sub) const {
//     IPv6_Addr ret {*this};
//     ret.as_u128i.ms -= sub.as_u128i.ms;
//     if (sub.as_u128i.ls > as_u128i.ls) ret.as_u128i.ms--;
//     ret.as_u128i.ls -= sub.as_u128i.ls;
//     return ret;
// }

// IPv6_Addr IPv6_Addr::operator-(u64i sub) const {
//     IPv6_Addr ret {*this};
//     if (sub > as_u128i.ls) ret.as_u128i.ms--;
//     ret.as_u128i.ls -= sub;
//     return ret;
// }

void IPv6_Addr::operator+=(const IPv6_Addr &sum) {
    as_u128i.ms += sum.as_u128i.ms;
    if ((0xFFFF'FFFF'FFFF'FFFF - as_u128i.ls) < sum.as_u128i.ls) as_u128i.ms++;
    as_u128i.ls += sum.as_u128i.ls;
}

void IPv6_Addr::operator+=(u64i sum) {
    if ((0xFFFF'FFFF'FFFF'FFFF - as_u128i.ls) < sum) as_u128i.ms++;
    as_u128i.ls += sum;
}

void IPv6_Addr::operator-=(const IPv6_Addr &sub) {
    as_u128i.ms -= sub.as_u128i.ms;
    if (sub.as_u128i.ls > as_u128i.ls) as_u128i.ms--;
    as_u128i.ls -= sub.as_u128i.ls;
}

void IPv6_Addr::operator-=(u64i sub) {
    if (sub > as_u128i.ls) as_u128i.ms--;
    as_u128i.ls -= sub;
}

bool IPv6_Addr::operator>(const IPv6_Addr &ip) const {
    if (as_u128i.ms > ip.as_u128i.ms) return true;
    if (as_u128i.ms == ip.as_u128i.ms) return as_u128i.ls > ip.as_u128i.ls;
    return false;
}

bool IPv6_Addr::operator<(const IPv6_Addr &ip) const {
    if (as_u128i.ms < ip.as_u128i.ms) return true;
    if (as_u128i.ms == ip.as_u128i.ms) return as_u128i.ls < ip.as_u128i.ls;
    return false;
}

bool IPv6_Addr::operator>=(const IPv6_Addr &ip) const {
    if (as_u128i.ms > ip.as_u128i.ms) return true;
    if (as_u128i.ms == ip.as_u128i.ms) return as_u128i.ls >= ip.as_u128i.ls;
    return false;
}

bool IPv6_Addr::operator<=(const IPv6_Addr &ip) const {
    if (as_u128i.ms < ip.as_u128i.ms) return true;
    if (as_u128i.ms == ip.as_u128i.ms) return as_u128i.ls <= ip.as_u128i.ls;
    return false;
}

IPv6_Addr IPv6_Addr::operator<<(u32i shift) const {
    IPv6_Addr ret {*this};
    if (shift > 128) shift = 128;
    if ((shift > 64) && (shift < 128)) {
        ret.as_u128i.ms = 0;
        ret.as_u128i.ms |= (ret.as_u128i.ls << (shift - 64));
        ret.as_u128i.ls = 0;
    } else {
        if (shift == 128) {
            ret.as_u128i.ms = 0;
            ret.as_u128i.ls = 0;
        } else {
            if (shift == 64) {
                ret.as_u128i.ms = ret.as_u128i.ls;
                ret.as_u128i.ls = 0;
            } else {
                if (shift != 0) {
                    ret.as_u128i.ms <<= shift;
                    ret.as_u128i.ms |= (ret.as_u128i.ls >> (64 - shift));
                    ret.as_u128i.ls <<= shift;
                }
            }
        }
    }
    return ret;
}

void IPv6_Addr::operator<<=(u32i shift) {
    if (shift > 128) shift = 128;
    if ((shift > 64) && (shift < 128)) {
        as_u128i.ms = 0;
        as_u128i.ms |= (as_u128i.ls << (shift - 64));
        as_u128i.ls = 0;
    } else {
        if (shift == 128) {
            as_u128i.ms = 0;
            as_u128i.ls = 0;
        } else {
            if (shift == 64) {
                as_u128i.ms = as_u128i.ls;
                as_u128i.ls = 0;
            } else {
                if (shift != 0) {
                    as_u128i.ms <<= shift;
                    as_u128i.ms |= (as_u128i.ls >> (64 - shift));
                    as_u128i.ls <<= shift;
                }
            }
        }
    }
}

IPv6_Addr IPv6_Addr::operator>>(u32i shift) const {
    IPv6_Addr ret {*this};
    if (shift > 128) shift = 128;
    if ((shift > 64) && (shift < 128)) {
        ret.as_u128i.ls = 0;
        ret.as_u128i.ls |= (ret.as_u128i.ms >> (shift - 64));
        ret.as_u128i.ms = 0;
    } else {
        if (shift == 128) {
            ret.as_u128i.ms = 0;
            ret.as_u128i.ls = 0;
        } else {
            if (shift == 64) {
                ret.as_u128i.ls = ret.as_u128i.ms;
                ret.as_u128i.ms = 0;
            } else {
                if (shift != 0) {
                    ret.as_u128i.ls >>= shift;
                    ret.as_u128i.ls |= (ret.as_u128i.ms << (64 - shift));
                    ret.as_u128i.ms >>= shift;
                }
            }
        }
    }
    return ret;
}

void IPv6_Addr::operator>>=(u32i shift) {
    if (shift > 128) shift = 128;
    if ((shift > 64) && (shift < 128)) {
        as_u128i.ls = 0;
        as_u128i.ls |= (as_u128i.ms >> (shift - 64));
        as_u128i.ms = 0;
    } else {
        if (shift == 128) {
            as_u128i.ms = 0;
            as_u128i.ls = 0;
        } else {
            if (shift == 64) {
                as_u128i.ls = as_u128i.ms;
                as_u128i.ms = 0;
            } else {
                if (shift != 0) {
                    as_u128i.ls >>= shift;
                    as_u128i.ls |= (as_u128i.ms << (64 - shift));
                    as_u128i.ms >>= shift;
                }
            }
        }
    }
}

string MAC_Addr::to_str(u32i grp_len, bool caps, char sep) const {
    string ret;
    ret.reserve(18);
    if (grp_len == 0) grp_len = 1;
    if (grp_len > 6) grp_len = 6;
    if ((grp_len > 3) && (grp_len < 6)) grp_len = 3;
    u32i idx {6};
    u32i gCnt{0}; // count elements in one group
    char octet[3] {"  "};
    const char *useSet = (caps) ? v6mnp::hexUpp : v6mnp::hexLow;
    do {
        idx--;
        gCnt++;
        octet[0] = useSet[as_u8i[idx] >> 4];
        octet[1] = useSet[as_u8i[idx] & 0xF];
        ret.append(octet);
        if (gCnt == grp_len) {
            ret.push_back(sep);
            gCnt = 0;
        }
    } while (idx > 0);
    ret.pop_back();
    return ret;
}

array<u8i,6> MAC_Addr::to_media_tx() const {
    array<u8i,6> ret;
    for (u32i idx = 0; idx < 6; idx++) {
        ret[5 - idx] = as_u8i[idx];
    }
    return ret;
}

u64i macmnp::inner_pow(u8i x, u8i y) {
    if (!y) return 1;
    u64i ret {1};
    for (; y > 0; y--) ret *= x;
    return ret;
}

u64i macmnp::hstr_to_u64i(const string &str) { // string must be preliminarily checked for permitted symbols and max len = 12
    u8i strLen = str.length();
    u8i digNum = strLen;
    u64i ret {0x0};
    u8i  deduct;
    u8i  symb;
    do {
        symb = str[digNum - 1];
        switch (symb & 0xF0) {
        case 0b01100000: // a - f
            deduct = 87;
            break;
        case 0b01000000: // A - F
            deduct = 55;
            break;
        default: // 0 - 9
            deduct = 48;
        }
        ret += (symb - deduct) * inner_pow(16, (strLen - digNum));
        digNum--;
    } while (digNum > 0);
    return ret;
}

bool macmnp::valid_addr(const string &macstr, u32i grp_len, char sep, MAC_Addr *ret) {
    if (ret != nullptr) *ret = u64i(0);
    size_t len {macstr.length()};
    if ((len > 17) || (len < 12)) return false; // len(06:05:04:03:02:01) == 17
    if (grp_len != 6) {
        if ((grp_len > 3) || (grp_len == 0) || (grp_len > 6)) return false;
    }
    u64i _48bits;
    string interim; // cleaned from separators
    interim.reserve(len);
    u32i hexCnt {0}; // counter of hex symbols total (must be <= 12)
    u32i gSymbs {0}; // counter of symbols in one group
    u32i gSymbsMax = grp_len * 2; // amount of hex symbols that must be present one group
    u32i seps {0}; // separators counter
    u32i sepsMax = (6 / grp_len) - 1;
    bool badSymb; // is bad symbols present?
    for (auto && ch : macstr) {
        badSymb = true;
        for (auto && perm : hexPerm) {
            if (ch == perm) {
                badSymb = false;
                break;
            }
        }
        if (ch != sep) {
            if (badSymb) return false;
            gSymbs++;
            if (gSymbs > gSymbsMax) return false;
            hexCnt++;
            if (hexCnt <= 12) {
                interim.push_back(ch);
            } else return false;
        } else {
            seps++;
            if (seps > sepsMax) return false;
            if ((gSymbs < gSymbsMax) || (gSymbs > gSymbsMax)) return false;
            gSymbs = 0;
        }
    }
    if (seps != sepsMax) return false;
    if (interim.length() != 12) return false;
    //_48bits = stoull(interim, nullptr, 16);
    _48bits = hstr_to_u64i(interim);
    if (ret != nullptr) ret->as_48bits = _48bits;
    return true;
}

u64i macmnp::to_48bits(const string &macstr, u32i grp_len, char sep) {
    MAC_Addr mac;
    valid_addr(macstr, grp_len, sep, &mac);
    return mac.as_48bits;
}

u64i macmnp::to_48bits(const string &macstr) {
    MAC_Addr mac;
    valid_addr(macstr, _def_grp_len, _def_sep, &mac);
    return mac.as_48bits;
}

MAC_Addr macmnp::to_MAC(const string &macstr, u32i grp_len, char sep) {
    MAC_Addr mac;
    valid_addr(macstr, grp_len, sep, &mac);
    return mac;
}

MAC_Addr macmnp::to_MAC(const string &macstr) {
    MAC_Addr mac;
    valid_addr(macstr, _def_grp_len, _def_sep, &mac);
    return mac;
}

MAC_Addr macmnp::gen_mcast(const IPv4_Addr &ip) {
    return MAC_Addr{0x01005E, ip.as_u32i & 0x007FFFFF};
}

MAC_Addr macmnp::gen_mcast(const IPv6_Addr &ip) {
    return MAC_Addr{u32i(ip.as_u8i[3]) | 0x333300, ip.as_u32i[0] & 0x00FFFFFF};
}

void macmnp::set_fmt(u32i grp_len, bool caps, char sep) {
    _def_sep = sep;
    if ((grp_len >= 1) && (grp_len <= 3) || (grp_len == 6)) {
        _def_grp_len = grp_len;
    } else {
        if (grp_len == 0) {
            _def_grp_len = 1;
        } else {
            if (grp_len > 6) {
                _def_grp_len = 6;
            }
        }
    }
    _def_caps = caps;
};
