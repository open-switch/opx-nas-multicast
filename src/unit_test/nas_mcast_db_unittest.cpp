/*
 * Copyright (c) 2019 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */

/*
 * filename: nas_mcast_db_unittest.cpp
 */

#include "nas_ndi_mcast.h"
#include "nas_ndi_l2mc.h"
#include "nas_ndi_ipmc.h"
#include "nas_ndi_vlan.h"
#include "nas_mc_util.h"
#include "std_ip_utils.h"
#include "hal_if_mapping.h"

#include <unordered_set>
#include <unordered_map>
#include <set>
#include <map>
#include <algorithm>
#include <sstream>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <gtest/gtest.h>

t_std_error ndi_mcast_entry_create(npu_id_t npu_id, const ndi_mcast_entry_t *mc_entry_p)
{
    return STD_ERR_OK;
}

t_std_error ndi_mcast_entry_delete(npu_id_t npu_id, const ndi_mcast_entry_t *mc_entry_p)
{
    return STD_ERR_OK;
}

t_std_error ndi_mcast_entry_update(npu_id_t npu_id, const ndi_mcast_entry_t *mc_entry_p,
                                   ndi_mcast_update_type_t upd_type)
{
    return STD_ERR_OK;
}

const ndi_obj_id_t MC_GROUP_ID_BASE = 1000;
const ndi_obj_id_t MC_PORT_MBR_ID_BASE = 2000;
const ndi_obj_id_t MC_LAG_MBR_ID_BASE = 3000;

std::unordered_map<ndi_obj_id_t, std::unordered_set<ndi_obj_id_t>> mc_ut_group_db{};
std::unordered_map<ndi_obj_id_t, ndi_obj_id_t> mc_ut_member_db{};

const uint32_t MIN_TEST_VLAN_ID = 1000;
const uint32_t MAX_TEST_VLAN_ID = 1200;
const hal_ifindex_t MIN_TEST_IFINDEX = 10;
const hal_ifindex_t MAX_TEST_IFINDEX = 100;
const char *TEST_IPV4_GRP_ADDR = "230.1.1.1";
const char *TEST_IPV4_SRC_ADDR = "10.11.1.1";
const char *TEST_IPV6_GRP_ADDR = "ff09::1";
const char *TEST_IPV6_SRC_ADDR = "1234:8888::1";
const uint32_t MAX_OFFSET = 1000;

namespace std
{
    template<>
    struct less<hal_ip_addr_t>
    {
        bool operator()(const hal_ip_addr_t& a1, const hal_ip_addr_t& a2) const
        {
            if (a1.af_index != a2.af_index) {
                return a1.af_index < a2.af_index;
            }
            if (a1.af_index == AF_INET) {
                return a1.u.v4_addr < a2.u.v4_addr;
            } else if (a1.af_index == AF_INET6) {
                return memcmp(a1.u.v6_addr, a2.u.v6_addr, sizeof(a1.u.v6_addr)) < 0;
            }
            return false;
        }
    };

    template<>
    struct less<mc_entry_key_t>
    {
        bool operator()(const mc_entry_key_t& k1, const mc_entry_key_t& k2) const
        {
            if (!_ip_addr_key_equal()(k1.dst_ip, k2.dst_ip)) {
                return less<hal_ip_addr_t>()(k1.dst_ip, k2.dst_ip);
            }
            if (k1.is_xg != k2.is_xg) {
                return !k1.is_xg;
            }
            if (!k1.is_xg) {
                return less<hal_ip_addr_t>()(k1.src_ip, k2.src_ip);
            }
            return false;
        }
    };
}

// af, vlan
using af_vlan_key_t = std::pair<uint32_t, uint32_t>;
using ut_entry_list_t = std::map<mc_entry_key_t, std::set<hal_ifindex_t>>;

// (af, vlan) => list of ifindex
std::map<af_vlan_key_t, std::set<hal_ifindex_t>> ut_mrouter_cache;
// (af, vlan) => (S, G, type, to_cpu) => list of ifindex
std::map<af_vlan_key_t, ut_entry_list_t> ut_entry_cache;
// group_key => entry list
std::map<std::set<hal_ifindex_t>, std::map<af_vlan_key_t, std::vector<mc_entry_key_t>>> ut_group_list;

static void compose_group_list()
{
    ut_group_list.clear();
    for (auto& af_vlan: ut_entry_cache) {
        std::set<hal_ifindex_t> mr_list{};
        if (ut_mrouter_cache.find(af_vlan.first) != ut_mrouter_cache.end()) {
            mr_list.insert(ut_mrouter_cache.at(af_vlan.first).begin(), ut_mrouter_cache.at(af_vlan.first).end());
        }
        for (auto& entry: af_vlan.second) {
            auto if_list = entry.second;
            if_list.insert(mr_list.begin(), mr_list.end());
            ut_group_list[if_list][af_vlan.first].push_back(entry.first);
        }
    }
}

static void get_offset_ip(const char *base_addr, uint32_t af, size_t offset,
                          hal_ip_addr_t& ret_ip)
{
    ret_ip.af_index = af;
    if (af == AF_INET) {
        struct in_addr addr;
        ASSERT_EQ(inet_pton(af, base_addr, &addr), 1);
        uint32_t addr_num = ntohl(addr.s_addr);
        ret_ip.u.v4_addr = htonl(addr_num + offset);
    } else if (af == AF_INET6) {
        ASSERT_EQ(inet_pton(af, base_addr, &ret_ip.u.ipv6), 1);
        int idx = 15;
        while(idx > 0 && offset > 0) {
            offset += ret_ip.u.v6_addr[idx];
            ret_ip.u.v6_addr[idx] = (offset & 0xff);
            offset >>= 8;
            idx --;
        }
    } else {
        std::cout << "Unknown IP address family: " << af << std::endl;
        ASSERT_TRUE(false);
    }
}

static mc_entry_key_t get_random_entry()
{
    uint32_t af = (std::rand() % 2 == 0 ? AF_INET : AF_INET6);
    mc_entry_key_t entry{};
    entry.is_xg = (std::rand() % 2 == 0);
    int offset = std::rand() % MAX_OFFSET;
    const char *grp_ip = (af == AF_INET ? TEST_IPV4_GRP_ADDR : TEST_IPV6_GRP_ADDR);
    get_offset_ip(grp_ip, af, offset, entry.dst_ip);
    if (!entry.is_xg) {
        const char *src_ip = (af == AF_INET ? TEST_IPV4_SRC_ADDR : TEST_IPV6_SRC_ADDR);
        offset = std::rand() % MAX_OFFSET;
        get_offset_ip(src_ip, af, offset, entry.src_ip);
    }
    return entry;
}

static std::string dump_entry_key(const mc_entry_key_t& entry_key)
{
    char ip_buf[HAL_INET6_TEXT_LEN + 1];
    std::ostringstream ss{};
    ss << "[";
    if (entry_key.is_xg) {
        ss << "*";
    } else {
        ss << std_ip_to_string(&entry_key.src_ip, ip_buf, sizeof(ip_buf));
    }
    ss << ",";
    ss << std_ip_to_string(&entry_key.dst_ip, ip_buf, sizeof(ip_buf));
    if (entry_key.copy_to_cpu) {
        ss << " TO_CPU";
    }
    ss << "]";
    return ss.str();
}

auto get_random_vid = []()->hal_vlan_id_t{return std::rand() % (MAX_TEST_VLAN_ID - MIN_TEST_VLAN_ID) + MIN_TEST_VLAN_ID;};
auto get_random_ifindex = []()->hal_ifindex_t{return std::rand() % (MAX_TEST_IFINDEX - MIN_TEST_IFINDEX) + MIN_TEST_IFINDEX;};

static void add_random_mrouters(size_t count)
{
    for (size_t idx = 0; idx < count; idx ++) {
        mc_event_type_t req_type = (std::rand() % 2 == 0 ? mc_event_type_t::IGMP : mc_event_type_t::MLD);
        uint32_t af = (req_type == mc_event_type_t::IGMP ? AF_INET : AF_INET6);
        auto vid = get_random_vid();
        auto ifindex = get_random_ifindex();
        nas_mc_add_mrouter(req_type, vid, ifindex);
        ut_mrouter_cache[{af, vid}].insert(ifindex);
    }
}

static void add_random_routes(size_t count)
{
    for (size_t idx = 0; idx < count; idx ++) {
        auto vid = get_random_vid();
        auto ifindex = get_random_ifindex();
        auto entry_key = get_random_entry();
        auto af = entry_key.dst_ip.af_index;
        mc_event_type_t req_type = (af == AF_INET ? mc_event_type_t::IGMP : mc_event_type_t::MLD);
        nas_mc_add_route(req_type, vid, entry_key.dst_ip, entry_key.is_xg, entry_key.src_ip, true, ifindex);
        ut_entry_cache[{af, vid}][entry_key].insert(ifindex);
    }
}

static void delete_all_routes()
{
    for (auto& entry: ut_entry_cache) {
        for (auto& vlan_entry: entry.second) {
            for (auto ifindex: vlan_entry.second) {
                nas_mc_del_route(entry.first.first == AF_INET ? mc_event_type_t::IGMP : mc_event_type_t::MLD,
                                 entry.first.second, vlan_entry.first.dst_ip, vlan_entry.first.is_xg, vlan_entry.first.src_ip,
                                 true, ifindex);
            }
        }
    }
    ut_entry_cache.clear();
}

static bool check_db_mrouters_with_cache_int(std::ostringstream& err_msg)
{
    mc_get_mrouter_list_t mrouter_list{};
    nas_mc_get_mrouter(mc_event_type_t::IGMP_MLD, 0, mrouter_list);
    if (ut_mrouter_cache.empty()) {
        if (!mrouter_list.empty()) {
            err_msg << "MRouter cached is cleared, but some items left in DB" << std::endl;
        }
        return mrouter_list.empty();
    }
    for (auto& mrouter: mrouter_list) {
        auto vid = mrouter.first;
        auto& ipv4_mrouter_list = ut_mrouter_cache[{AF_INET, vid}];
        auto ipv4_size = ipv4_mrouter_list.size();
        if (ipv4_size != mrouter.second.igmp_if_list.size()) {
            err_msg << "VLAN " << vid << " IPv4 cache mis-match with DB: " << ipv4_size << " <> "
                    << mrouter.second.igmp_if_list.size() << std::endl;
            return false;
        }
        for (auto ifindex: mrouter.second.igmp_if_list) {
            if (ipv4_mrouter_list.find(ifindex) == ipv4_mrouter_list.end()) {
                err_msg << "Ifindex " << ifindex << " is not in IPv4 mrouter cache of VLAN " << vid << std::endl;
                return false;
            }
        }
        auto& ipv6_mrouter_list = ut_mrouter_cache[{AF_INET6, vid}];
        auto ipv6_size = ipv6_mrouter_list.size();
        if (ipv6_size != mrouter.second.mld_if_list.size()) {
            err_msg << "VLAN " << vid << " IPv6 cache mis-match with DB: " << ipv6_size << " <> "
                    << mrouter.second.mld_if_list.size() << std::endl;
            return false;
        }
        for (auto ifindex: mrouter.second.mld_if_list) {
            if (ipv6_mrouter_list.find(ifindex) == ipv6_mrouter_list.end()) {
                err_msg << "Ifindex " << ifindex << " is not in IPv6 mrouter cache of VLAN " << vid << std::endl;
                return false;
            }
        }
    }

    return true;
}

static bool check_db_mrouters_with_cache()
{
    std::ostringstream ss{};
    for (int idx = 0; idx < 10; idx ++) {
        ss.str("");
        if (check_db_mrouters_with_cache_int(ss)) {
            return true;
        }
        sleep(2);
    }
    std::cout << "Failure validating mrouter info in cache with DB" << std::endl;
    std::cout << ss.str() << std::endl;
    return false;
}

static bool check_route_list_with_cache(const mc_get_route_list_t& route_list, std::ostringstream& err_msg)
{
    for (auto& route: route_list) {
        auto vlan_id = route.first;
        for (auto& route_item: route.second) {
            auto af = route_item.entry.dst_ip.af_index;
            auto cache_key = std::make_pair(af, vlan_id);
            auto ent_itor = ut_entry_cache.find(cache_key);
            if (ent_itor == ut_entry_cache.end()) {
                err_msg << "AF " << af << " and VLAN " << vlan_id << " not found in cache" << std::endl;
                return false;
            }
            auto mbr_itor = ent_itor->second.find(route_item.entry);
            if (mbr_itor == ent_itor->second.end()) {
                err_msg << "Route entry AF " << af << " VLAN " << vlan_id << " "
                        << std::string(route_item.entry) << " not found in cache" << std::endl;
                return false;
            }
            if (route_item.host_if_list.size() != mbr_itor->second.size()) {
                err_msg << "Route entry AF " << af << " VLAN " << vlan_id << " "
                        << std::string(route_item.entry) << " port list size mis-match from cache" << std::endl;
                err_msg << "DB port list size: " << route_item.host_if_list.size() << " Cache port list size: "
                        << mbr_itor->second.size() << std::endl;
                return false;
            }
            for (auto ifindex: route_item.host_if_list) {
                if (mbr_itor->second.find(ifindex) == mbr_itor->second.end()) {
                    err_msg << "Route entry AF " << af << " VLAN " << vlan_id << " "
                            << std::string(route_item.entry) << " ifindex " << ifindex << " not found in cache" << std::endl;
                    return false;
                }
            }
            if (!route_item.mrouter_if_list.empty()) {
                auto mrt_itor = ut_mrouter_cache.find(cache_key);
                if (mrt_itor == ut_mrouter_cache.end()) {
                    err_msg << "AF " << af << " and VLAN " << vlan_id << " not found in mrouter cache" << std::endl;
                    return false;
                }
                if (route_item.mrouter_if_list.size() != mrt_itor->second.size()) {
                    err_msg << "Route entry AF " << af << " VLAN " << vlan_id << " "
                            << std::string(route_item.entry) << " mrouter list size mis-match from cache" << std::endl;
                    err_msg << "DB list size: " << route_item.mrouter_if_list.size() << " Cache list size: "
                            << mrt_itor->second.size() << std::endl;
                    return false;
                }
                for (auto ifindex: route_item.mrouter_if_list) {
                    if (mrt_itor->second.find(ifindex) == mrt_itor->second.end()) {
                        err_msg << "Route entry AF " << af << " VLAN " << vlan_id << " "
                                << std::string(route_item.entry) << " ifindex " << ifindex
                                << " not found in mrouter cache" << std::endl;
                        return false;
                    }
                }
            }
        }
    }

    return true;
}

static bool check_cache_routes_count(size_t db_count, uint32_t af, bool is_xg, std::ostringstream& err_msg)
{
    size_t rt_count = 0;
    for (auto& cached_entry: ut_entry_cache) {
        if (cached_entry.first.first != af) {
            continue;
        }
        for (auto& entry_info: cached_entry.second) {
            if (entry_info.first.is_xg == is_xg) {
                rt_count ++;
            }
        }
    }
    if (rt_count != db_count) {
        err_msg << "Entry count mismatch for AF " << af << " " << (is_xg ? "XG" : "SG") << ": ";
        err_msg << "in_DB " << db_count << " in_cache " << rt_count << std::endl;
        return false;
    }
    return true;
}

template<typename T>
size_t get_member_count(const T& group)
{
    using list_item_t = typename T::value_type;
    size_t mbr_cnt = 0;
    std::for_each(group.begin(), group.end(),
            [&mbr_cnt](const list_item_t& item){mbr_cnt += item.second.size();});
    return mbr_cnt;
}

static bool check_db_routes_with_cache_int(std::ostringstream& err_msg)
{
    mc_get_route_list_t route_list{};
    bool ret_val = false;
    do {
        nas_mc_get_route(mc_event_type_t::IGMP, 0, hal_ip_addr_t{AF_INET}, true, hal_ip_addr_t{AF_INET}, route_list);
        if (!check_cache_routes_count(get_member_count(route_list), AF_INET, true, err_msg)) {
            err_msg << "Validation failed for routes count of AF_INET and XG" << std::endl;
            break;
        }
        if (!check_route_list_with_cache(route_list, err_msg)) {
            err_msg << "Validation failed for IPv4 (*, G) entries" << std::endl;
            break;
        }
        route_list.clear();
        nas_mc_get_route(mc_event_type_t::IGMP, 0, hal_ip_addr_t{AF_INET}, false, hal_ip_addr_t{AF_INET}, route_list);
        if (!check_cache_routes_count(get_member_count(route_list), AF_INET, false, err_msg)) {
            err_msg << "Validation failed for routes count of AF_INET and SG" << std::endl;
            break;
        }
        if (!check_route_list_with_cache(route_list, err_msg)) {
            err_msg << "Validation failed for IPv4 (S, G) entries" << std::endl;
            break;
        }
        route_list.clear();
        nas_mc_get_route(mc_event_type_t::MLD, 0, hal_ip_addr_t{AF_INET6}, true, hal_ip_addr_t{AF_INET6}, route_list);
        if (!check_cache_routes_count(get_member_count(route_list), AF_INET6, true, err_msg)) {
            err_msg << "Validation failed for routes count of AF_INET6 and XG" << std::endl;
            break;
        }
        if (!check_route_list_with_cache(route_list, err_msg)) {
            err_msg << "Validation failed for IPv6 (*, G) entries" << std::endl;
            break;
        }
        route_list.clear();
        nas_mc_get_route(mc_event_type_t::MLD, 0, hal_ip_addr_t{AF_INET6}, false, hal_ip_addr_t{AF_INET6}, route_list);
        if (!check_cache_routes_count(get_member_count(route_list), AF_INET6, false, err_msg)) {
            err_msg << "Validation failed for routes count of AF_INET6 and SG" << std::endl;
            break;
        }
        if (!check_route_list_with_cache(route_list, err_msg)) {
            err_msg << "Validation failed for IPv6 (S, G) entries" << std::endl;
            break;
        }
        ret_val = true;
    } while(0);
    if (!ret_val) {
        err_msg << "---------------------------" << std::endl;
        err_msg << " Routes read from DB" << std::endl;
        err_msg << "---------------------------" << std::endl;
        for (auto& vlan_route: route_list) {
            err_msg << "VLAN " << vlan_route.first << ":" << std::endl;
            for (auto& route_info: vlan_route.second) {
                err_msg << "  " << std::string(route_info.entry) << " => ";
                err_msg << "MRT ";
                for (auto ifindex: route_info.mrouter_if_list) {
                    err_msg << ifindex << ",";
                }
                err_msg << " HST ";
                for (auto ifindex: route_info.host_if_list) {
                    err_msg << ifindex << ",";
                }
                err_msg << std::endl;
            }
        }
    }
    return ret_val;
}

static bool check_db_routes_with_cache()
{
    std::ostringstream ss{};
    for (int idx = 0; idx < 10; idx ++) {
        ss.str("");
        if (check_db_routes_with_cache_int(ss)) {
            return true;
        }
        sleep(2);
    }
    std::cout << "Failure validating route info in cache with DB" << std::endl;
    std::cout << ss.str() << std::endl;
    return false;
}

static bool check_db_groups_with_cache_int(std::ostringstream& err_msg)
{
    std::vector<hal_ifindex_t> db_oif_list{};
    for (auto& group: ut_group_list) {
        auto& cache_oif_list = group.first;
        err_msg << "Cached OIF: ";
        for (auto ifindex: cache_oif_list) {
            err_msg << ifindex << ",";
        }
        err_msg << std::endl;
        auto entry_cnt = get_member_count(group.second);
        for (auto& af_vlan: group.second) {
            auto vlan_id = af_vlan.first.second;
            for (auto& entry: af_vlan.second) {
                ndi_obj_id_t grp_id;
                err_msg << "Checking VLAN " << vlan_id << " entry " << std::string(entry) << std::endl;
                if (!nas_mc_get_entry_group_id(vlan_id, entry, grp_id)) {
                    err_msg << "Failed to get group ID for entry " << std::string(entry) << std::endl;
                    return false;
                }
                db_oif_list.clear();
                hal_vlan_id_t db_vlan_id;
                size_t ref_count;
                err_msg << "Get group info with ID " << std::hex << std::showbase << grp_id << std::endl;
                if (!nas_mc_get_group_info_by_id(grp_id, db_vlan_id, db_oif_list, ref_count)) {
                    err_msg << "Failed to get group info with ID " << grp_id << std::endl;
                    return false;
                }
                err_msg << std::dec << std::noshowbase;
                err_msg << "Group info: VLAN " << db_vlan_id << " ref_count " << ref_count << " OIF ";
                for (auto ifindex: db_oif_list) {
                    err_msg << ifindex << ",";
                }
                err_msg << std::endl;
                // Uncomment below if VLAN ID is part of key for group re-use
                /**
                if (db_vlan_id != vlan_id) {
                    err_msg << "VLAN ID " << db_vlan_id << " read from DB is not equal to VLAN ID " << vlan_id
                            << " in cache" << std::endl;
                    return false;
                }
                **/
                if (ref_count != entry_cnt) {
                    err_msg << "Ref_count " << ref_count << " is not equal to entry number " << entry_cnt
                            << " that referenced to the group" << std::endl;
                    return false;
                }
                if (db_oif_list.size() != cache_oif_list.size()) {
                    err_msg << "OIF count " << db_oif_list.size() << " is not equal to OIF number "
                            << cache_oif_list.size() << " from cache" << std::endl;
                    return false;
                }
                for (auto oif: db_oif_list) {
                    if (cache_oif_list.find(oif) == cache_oif_list.end()) {
                        err_msg << "OIF " << oif << " not found in cached list" << std::endl;
                        return false;
                    }
                }
            }
        }
    }

    return true;
}

static bool check_db_groups_with_cache()
{
    std::ostringstream ss{};
    for (int idx = 0; idx < 10; idx ++) {
        ss.str("");
        if (check_db_groups_with_cache_int(ss)) {
            return true;
        }
        sleep(2);
    }
    std::cout << "Failure validating group info in cache with DB" << std::endl;
    std::cout << ss.str() << std::endl;
    return false;
}

t_std_error ndi_l2mc_group_create(npu_id_t npu_id, ndi_obj_id_t *mc_grp_id_p)
{
    static ndi_obj_id_t grp_id_offset = 0;

    *mc_grp_id_p = MC_GROUP_ID_BASE + grp_id_offset;
    if (mc_ut_group_db.find(*mc_grp_id_p) != mc_ut_group_db.end()) {
        std::cout << "Group " << *mc_grp_id_p << " already exists" << std::endl;
        return STD_ERR(MCAST, PARAM, 0);
    }
    mc_ut_group_db.insert(std::make_pair(*mc_grp_id_p, std::unordered_set<ndi_obj_id_t>{}));
    grp_id_offset ++;
    return STD_ERR_OK;
}

t_std_error ndi_l2mc_group_delete(npu_id_t npu_id, ndi_obj_id_t mc_grp_id)
{
    if (mc_ut_group_db.find(mc_grp_id) == mc_ut_group_db.end()) {
        std::cout << "Group " << mc_grp_id << " not found" << std::endl;
        return STD_ERR(MCAST, PARAM, 0);
    }
    if (!mc_ut_group_db[mc_grp_id].empty()) {
        std::cout << "Group " << mc_grp_id << " not empty" << std::endl;
        return STD_ERR(MCAST, PARAM, 0);
    }
    mc_ut_group_db.erase(mc_grp_id);
    return STD_ERR_OK;
}

static t_std_error add_member_to_group(ndi_obj_id_t group_id, ndi_obj_id_t member_id)
{
    if (mc_ut_group_db.find(group_id) == mc_ut_group_db.end()) {
        std::cout << "Group " << group_id << " not found" << std::endl;
        return STD_ERR(MCAST, PARAM, 0);
    }
    if (mc_ut_group_db[group_id].find(member_id) != mc_ut_group_db[group_id].end()) {
        std::cout << "Member " << member_id << " already exists in group DB" << std::endl;
    }
    if (mc_ut_member_db.find(member_id) != mc_ut_member_db.end()) {
        std::cout << "Member " << member_id << " already exists in member DB" << std::endl;
        return STD_ERR(MCAST, PARAM, 0);
    }
    mc_ut_member_db.insert(std::make_pair(member_id, group_id));
    mc_ut_group_db[group_id].insert(member_id);

    return STD_ERR_OK;
}

t_std_error ndi_l2mc_group_add_port_member(npu_id_t npu_id,
                                           ndi_obj_id_t group_id, port_t port_id,
                                           ndi_obj_id_t *member_id_p)
{
    static ndi_obj_id_t mbr_id_offset = 0;

    *member_id_p = MC_PORT_MBR_ID_BASE + mbr_id_offset;
    mbr_id_offset ++;

    return add_member_to_group(group_id, *member_id_p);
}

t_std_error ndi_l2mc_group_add_lag_member(npu_id_t npu_id,
                                           ndi_obj_id_t group_id, ndi_obj_id_t lag_id,
                                           ndi_obj_id_t *member_id_p)
{
    static ndi_obj_id_t mbr_id_offset = 0;

    *member_id_p = MC_LAG_MBR_ID_BASE + mbr_id_offset;
    mbr_id_offset ++;

    return add_member_to_group(group_id, *member_id_p);
}

t_std_error ndi_l2mc_group_delete_member(npu_id_t npu_id, ndi_obj_id_t member_id)
{
    if (mc_ut_member_db.find(member_id) == mc_ut_member_db.end()) {
        std::cout << "Member " << member_id << " already exists in member DB" << std::endl;
        return STD_ERR(MCAST, PARAM, 0);
    }
    auto group_id = mc_ut_member_db[member_id];
    if (mc_ut_group_db.find(group_id) == mc_ut_group_db.end()) {
        std::cout << "Group " << group_id << " not found" << std::endl;
        return STD_ERR(MCAST, PARAM, 0);
    }
    if (mc_ut_group_db[group_id].find(member_id) == mc_ut_group_db[group_id].end()) {
        std::cout << "Member " << member_id << " not found in group DB" << std::endl;
    }
    mc_ut_member_db.erase(member_id);
    mc_ut_group_db[group_id].erase(member_id);

    return STD_ERR_OK;
}


t_std_error ndi_l2mc_set_flood_restrict(npu_id_t npu_id, hal_vlan_id_t vid,
                                        ndi_flood_restrict_type_t restr_type,
                                        ndi_obj_id_t group_id)
{
    return STD_ERR_OK;
}

t_std_error ndi_create_repl_group(npu_id_t npu_id, ndi_repl_grp_owner_type_t owner,
                                  ndi_mc_grp_mbr_t *rpf_grp_mbr,
                                  size_t ipmc_grp_mbr_cnt, ndi_mc_grp_mbr_t *ipmc_grp_mbr,
                                  ndi_obj_id_t *repl_group_id_p)
{
    return STD_ERR_OK;
}


t_std_error ndi_delete_repl_group(npu_id_t npu_id, ndi_obj_id_t repl_group_id)
{
    return STD_ERR_OK;
}

t_std_error ndi_ipmc_entry_create(npu_id_t npu_id, const ndi_ipmc_entry_t *ipmc_entry_p)
{
    return STD_ERR_OK;
}

t_std_error ndi_ipmc_entry_delete(npu_id_t npu_id, const ndi_ipmc_entry_t *ipmc_entry_p)
{
    return STD_ERR_OK;
}

t_std_error ndi_ipmc_entry_update(npu_id_t npu_id, const ndi_ipmc_entry_t *ipmc_entry_p,
                                  ndi_ipmc_update_type_t upd_type)
{
    return STD_ERR_OK;
}

t_std_error ndi_ipmc_entry_get(npu_id_t npu_id, ndi_ipmc_entry_t *ipmc_entry_p)
{
    return STD_ERR_OK;
}

t_std_error ndi_rif_create (ndi_rif_entry_t *rif_entry, ndi_rif_id_t *rif_id)
{
    return STD_ERR_OK;
}

t_std_error ndi_rif_delete(npu_id_t npu_id, ndi_rif_id_t rif_id)
{
    return STD_ERR_OK;
}

t_std_error ndi_rif_get_attribute (ndi_rif_entry_t *rif_entry)
{
    return STD_ERR_OK;
}

t_std_error ndi_rif_set_attribute (ndi_rif_entry_t *rif_entry)
{
    return STD_ERR_OK;
}

t_std_error ndi_route_vr_set_attribute (ndi_vr_entry_t *vr_entry)
{
    return STD_ERR_OK;
}

bool ndi_l2mc_vlan_port_lookup_enabled_get(void)
{
    return false;
}

t_std_error ndi_vlan_set_mcast_lookup_key(npu_id_t npu_id, hal_vlan_id_t vlan_id,
                                          uint32_t af,
                                          ndi_vlan_mcast_lookup_key_type_t key)
{
    return STD_ERR_OK;
}

TEST(nas_mc_db_init, reg_vlan_and_intf)
{
    char name_buf[32];
    interface_ctrl_t if_info;
    for (uint32_t vlan_id = MIN_TEST_VLAN_ID; vlan_id <= MAX_TEST_VLAN_ID; vlan_id ++) {
        snprintf(name_buf, sizeof(name_buf), "br%d", vlan_id);
        memset(&if_info, 0, sizeof(if_info));
        if_info.int_type = nas_int_type_VLAN;
        if_info.vlan_id = vlan_id;
        if_info.if_index = vlan_id + 1000;
        strcpy(if_info.vrf_name, "default");
        strncpy(if_info.if_name, name_buf, sizeof(if_info.if_name) - 1);
        ASSERT_EQ(dn_hal_if_register(HAL_INTF_OP_REG, &if_info), STD_ERR_OK);
    }
    int port_num = 1;
    for (hal_ifindex_t ifindex = MIN_TEST_IFINDEX; ifindex <= MAX_TEST_IFINDEX;
         ifindex ++, port_num ++) {
        snprintf(name_buf, sizeof(name_buf), "e101-%03d-0", port_num);
        memset(&if_info, 0, sizeof(if_info));
        if_info.int_type = nas_int_type_PORT;
        if_info.port_mapped = true;
        if_info.npu_id = 0;
        if_info.port_id = port_num;
        if_info.tap_id = port_num;
        if_info.if_index = ifindex;
        strcpy(if_info.vrf_name, "default");
        strncpy(if_info.if_name, name_buf, sizeof(if_info.if_name) - 1);
        ASSERT_EQ(dn_hal_if_register(HAL_INTF_OP_REG, &if_info), STD_ERR_OK);
    }
}

TEST(nas_mc_db_init, start_msg_handling)
{
    ASSERT_EQ(nas_mc_proc_init(), STD_ERR_OK);
}

TEST(nas_mc_db_init, enable_vlan_snooping)
{
    for (uint32_t vlan_id = MIN_TEST_VLAN_ID; vlan_id <= MAX_TEST_VLAN_ID; vlan_id ++) {
        nas_mc_change_snooping_status(mc_event_type_t::IGMP_MLD, vlan_id, true);
    }
    sleep(1);
}

TEST(nas_mc_db_route, add_route)
{
    add_random_mrouters(200);
    add_random_routes(1000);
    add_random_mrouters(200);
    std::cout << "---------------------------" << std::endl;
    std::cout << " Added mrouter ports" << std::endl;
    std::cout << "---------------------------" << std::endl;
    for (auto& af_vlan: ut_mrouter_cache) {
        std::cout << (af_vlan.first.first == AF_INET ? "IPv4" : "IPv6") << " V" << af_vlan.first.second << " => ";
        for (auto ifindex: af_vlan.second) {
            std::cout << ifindex << ",";
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;
    std::cout << "---------------------------" << std::endl;
    std::cout << " Added route entries" << std::endl;
    std::cout << "---------------------------" << std::endl;
    for (auto& af_vlan: ut_entry_cache) {
        std::cout << (af_vlan.first.first == AF_INET ? "IPv4" : "IPv6") << " VLAN " << af_vlan.first.second << ":" << std::endl;
        for (auto& entry: af_vlan.second) {
            std::cout << "  " << dump_entry_key(entry.first) << " => ";
            for (auto ifindex: entry.second) {
                std::cout << ifindex << ",";
            }
            std::cout << std::endl;
        }
    }
    std::cout << std::endl;
    compose_group_list();
    std::cout << "---------------------------" << std::endl;
    std::cout << " Groups shared by entry" << std::endl;
    std::cout << "---------------------------" << std::endl;
    for (auto& group: ut_group_list) {
        std::cout << "(";
        for (auto ifindex: group.first) {
            std::cout << ifindex <<",";
        }
        std::cout << ") => " << std::endl;
        for (auto& af_vlan: group.second) {
            std::cout  << "  " << (af_vlan.first.first == AF_INET ? "IPv4" : "IPv6") << " V" << af_vlan.first.second << ": ";
            for (auto& entry: af_vlan.second) {
                std::cout << dump_entry_key(entry) << ",";
            }
            std::cout << std::endl;
        }
    }
    std::cout << std::endl;
    sleep(1);
    ASSERT_TRUE(check_db_mrouters_with_cache());
    ASSERT_TRUE(check_db_routes_with_cache());
    ASSERT_TRUE(check_db_groups_with_cache());
    delete_all_routes();
    sleep(1);
    ASSERT_TRUE(check_db_routes_with_cache());
    ut_mrouter_cache.clear();
}

TEST(nas_mc_db_cleanup, disable_vlan_snooping)
{
    for (uint32_t vlan_id = MIN_TEST_VLAN_ID; vlan_id <= MAX_TEST_VLAN_ID; vlan_id ++) {
        nas_mc_change_snooping_status(mc_event_type_t::IGMP_MLD, vlan_id, false);
    }
    sleep(1);
}

TEST(nas_mc_db_cleanup, stop_msg_handling)
{
    ASSERT_EQ(nas_mc_proc_deinit(), STD_ERR_OK);
}

int main(int argc, char *argv[])

{
    std::srand(std::time(nullptr));
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
