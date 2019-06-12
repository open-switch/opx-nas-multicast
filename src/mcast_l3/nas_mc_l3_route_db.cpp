/*
* Copyright (c) 2019 Dell Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may
* not use this file except in compliance with the License. You may obtain
* a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
*
* THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR
* CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */

/*
 * filename: nas_mc_l3_route_db.cpp
 */

#include "nas_types.h"
#include "nas_mc_l3_msg.h"
#include "nas_mc_l3_util.h"

#include <unordered_map>
#include <vector>
#include <cstring>
#include <mutex>
#include <memory>
#include <sstream>
#include <arpa/inet.h>

template<int AF>
struct ip_type_traits{};

template<>
struct ip_type_traits<AF_INET>
{
    using type = dn_ipv4_addr_t;
    static void from_common_ip(type& dst_ip, const hal_ip_addr_t& src_ip)
    {
        dst_ip.s_addr = src_ip.u.v4_addr;
    }
    static void to_common_ip(hal_ip_addr_t& dst_ip, const type& src_ip)
    {
        dst_ip.af_index = HAL_INET4_FAMILY;
        dst_ip.u.v4_addr = src_ip.s_addr;
    }
    static size_t hash_value(const type& ip_addr)
    {
        return std::hash<int>()(static_cast<int>(ip_addr.s_addr));
    }
    static bool is_equal(const type& ip1, const type& ip2)
    {
        return ip1.s_addr == ip2.s_addr;
    }
    static bool is_equal(const hal_ip_addr_t& ip1, const type& ip2)
    {
        return ip1.u.v4_addr == ip2.s_addr;
    }
    static std::string to_string(const type& ip)
    {
        char ip_buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &ip, ip_buf, sizeof(ip_buf)) != nullptr) {
            return std::string{ip_buf};
        }

        return std::string{};
    }
};

template<>
struct ip_type_traits<AF_INET6>
{
    using type = dn_ipv6_addr_t;
    static void from_common_ip(type& dst_ip, const hal_ip_addr_t& src_ip)
    {
        memcpy(dst_ip.s6_addr, src_ip.u.v6_addr, sizeof(dst_ip.s6_addr));
    }
    static void to_common_ip(hal_ip_addr_t& dst_ip, const type& src_ip)
    {
        dst_ip.af_index = HAL_INET6_FAMILY;
        memcpy(dst_ip.u.v6_addr, src_ip.s6_addr, sizeof(src_ip.s6_addr));
    }
    static size_t hash_value(const type& ip_addr)
    {
        return std::hash<std::string>()(
                    std::string{std::begin(ip_addr.s6_addr), std::end(ip_addr.s6_addr) - 1});
    }
    static bool is_equal(const type& ip1, const type& ip2)
    {
        return memcmp(ip1.s6_addr, ip2.s6_addr, sizeof(ip1.s6_addr)) == 0;
    }
    static bool is_equal(const hal_ip_addr_t& ip1, const type& ip2)
    {
        return memcmp(ip1.u.v6_addr, ip2.s6_addr, sizeof(ip2.s6_addr)) == 0;
    }
    static std::string to_string(const type& ip)
    {
        char ip_buf[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &ip, ip_buf, sizeof(ip_buf)) != nullptr) {
            return std::string{ip_buf};
        }

        return std::string{};
    }
};

template<int AF>
using ipmc_route_addr_t = typename ip_type_traits<AF>::type;

enum {
    RT_VRF_ID_POS = 0,
    RT_TYPE_POS,
    RT_GRP_IP_POS,
    RT_SRC_IP_POS,
    RT_MBR_RIF_POS,
    RT_MAX_POS
};

template<int AF>
struct ipmc_route_key_t
{
    uint32_t vrf_id;
    L3_MCAST_ROUTE_TYPE_t type;
    ipmc_route_addr_t<AF> grp_ip = ipmc_route_addr_t<AF>{};
    ipmc_route_addr_t<AF> src_ip = ipmc_route_addr_t<AF>{};

    ipmc_route_key_t(const mc_route_t& mc_route)
    {
        type = mc_route.rtype;
        vrf_id = mc_route.vrf_id;
        ip_type_traits<AF>::from_common_ip(grp_ip, mc_route.grp_ip);
        if ((type == L3_MCAST_ROUTE_TYPE_SG) || (type == L3_MCAST_ROUTE_TYPE_SGRPT)) {
            ip_type_traits<AF>::from_common_ip(src_ip, mc_route.src_ip);
        }
    }

    ipmc_route_key_t() = default;

    void set_mc_route(mc_route_t& mc_route) const
    {
        mc_route.af = static_cast<uint32_t>(AF);
        mc_route.rtype = type;
        mc_route.vrf_id = vrf_id;
        ip_type_traits<AF>::to_common_ip(mc_route.grp_ip, grp_ip);
        if ((type == L3_MCAST_ROUTE_TYPE_SG) || (type == L3_MCAST_ROUTE_TYPE_SGRPT)) {
            ip_type_traits<AF>::to_common_ip(mc_route.src_ip, src_ip);
        }
    }

    size_t get_hash_value() const
    {
        size_t h_val = std::hash<int>()(static_cast<int>(vrf_id));
        h_val <<= 1;
        h_val ^= std::hash<int>()(static_cast<int>(type));
        h_val <<= 1;
        h_val ^= ip_type_traits<AF>::hash_value(grp_ip);
        if ((type == L3_MCAST_ROUTE_TYPE_SG) || (type == L3_MCAST_ROUTE_TYPE_SGRPT)) {
            h_val <<= 1;
            h_val ^= ip_type_traits<AF>::hash_value(src_ip);
        }

        return h_val;
    }

    bool operator==(const ipmc_route_key_t<AF>& route) const
    {
        if (!(vrf_id == route.vrf_id && type == route.type &&
              ip_type_traits<AF>::is_equal(grp_ip, route.grp_ip))) {
            return false;
        }
        if ((type == L3_MCAST_ROUTE_TYPE_SG) || (type == L3_MCAST_ROUTE_TYPE_SGRPT)) {
            return ip_type_traits<AF>::is_equal(src_ip, route.src_ip);
        }

        return true;
    }

    operator std::string() const
    {
        std::ostringstream ss{};
        ss << "[VRF " << vrf_id << " GRP " << ip_type_traits<AF>::to_string(grp_ip);
        if ((type == L3_MCAST_ROUTE_TYPE_SG) || (type == L3_MCAST_ROUTE_TYPE_SGRPT)) {
            ss << " SRC " << ip_type_traits<AF>::to_string(src_ip);
        } else {
            ss << " SRC *";
        }
        ss << "]";
        return ss.str();
    }
};

namespace std
{
    template<int AF>
    struct hash<ipmc_route_key_t<AF>>
    {
        size_t operator()(const ipmc_route_key_t<AF>& route) const
        {
            return route.get_hash_value();
        }
    };
}

template<int AF>
using ipmc_route_filter_t = std::tuple<ipmc_route_key_t<AF>, hal_vrf_id_t, hal_ifindex_t>;

template<int AF>
class ipmc_route_db
{
public:
    t_std_error add_route(const mc_route_t& rt_info);
    t_std_error delete_route(const mc_route_t& rt_info);
    t_std_error update_route(const mc_route_t& rt_info,
                             const std::vector<rt_upd_type_t>& upd_type_list);
    void get_route(std::vector<mc_route_t*>& route_list,
                   const ipmc_route_filter_t<AF>& filter, const std::bitset<RT_MAX_POS>& filter_mask);
    void get_route(std::vector<mc_route_t>& route_list,
                   const ipmc_route_filter_t<AF>& filter, const std::bitset<RT_MAX_POS>& filter_mask) const;
private:
    static bool match_filter(const mc_route_t& route, const ipmc_route_filter_t<AF>& filter,
                             const std::bitset<RT_MAX_POS>& mask)
    {
        auto& route_key = std::get<0>(filter);
        if (mask.test(RT_VRF_ID_POS) && route.vrf_id != route_key.vrf_id) {
            return false;
        }
        if (mask.test(RT_TYPE_POS) && route.rtype != route_key.type) {
            return false;
        }
        if (mask.test(RT_GRP_IP_POS) && !ip_type_traits<AF>::is_equal(route.grp_ip, route_key.grp_ip)) {
            return false;
        }
        if (mask.test(RT_SRC_IP_POS) &&
            (route.rtype == L3_MCAST_ROUTE_TYPE_XG || !ip_type_traits<AF>::is_equal(route.src_ip, route_key.src_ip))) {
            return false;
        }

        if (mask.test(RT_MBR_RIF_POS)) {
            auto vrf_id = std::get<1>(filter);
            auto rif_id = std::get<2>(filter);
            if (route.vrf_id != vrf_id) {
                return false;
            }
            if (route.iif_id == rif_id) {
                return true;
            }
            for (auto& oif: route.oif_list) {
                if (oif.first == rif_id) {
                    return true;
                }
            }
            return false;
        }

        return true;
    }
    std::unordered_map<ipmc_route_key_t<AF>, std::unique_ptr<mc_route_t>> _route_list;
    mutable std::mutex _mutex;
};

template<int AF>
t_std_error ipmc_route_db<AF>::add_route(const mc_route_t& rt_info)
{
    std::lock_guard<std::mutex> lock(_mutex);
    ipmc_route_key_t<AF> route_key{rt_info};
    if (_route_list.find(route_key) != _route_list.end()) {
        NAS_MC_L3_LOG_ERR("ROUTE-DB", "Route %s already exists in DB",
                          std::string(route_key).c_str());
        return STD_ERR(MCAST, PARAM, 0);
    }

    _route_list.insert(std::make_pair(route_key, std::unique_ptr<mc_route_t>{new mc_route_t{rt_info}}));

    return STD_ERR_OK;
}

template<int AF>
t_std_error ipmc_route_db<AF>::delete_route(const mc_route_t& rt_info)
{
    std::lock_guard<std::mutex> lock(_mutex);
    ipmc_route_key_t<AF> route_key{rt_info};
    if (_route_list.find(route_key) == _route_list.end()) {
        NAS_MC_L3_LOG_ERR("ROUTE-DB", "Route %s not exists in DB",
                          std::string(route_key).c_str());
        return STD_ERR(MCAST, PARAM, 0);
    }

    _route_list.erase(route_key);

    return STD_ERR_OK;
}

template<int AF>
t_std_error ipmc_route_db<AF>::update_route(const mc_route_t& rt_info,
                                const std::vector<rt_upd_type_t>& upd_type_list)
{
    std::lock_guard<std::mutex> lock(_mutex);
    ipmc_route_key_t<AF> route_key{rt_info};
    if (_route_list.find(route_key) == _route_list.end()) {
        NAS_MC_L3_LOG_ERR("ROUTE-DB", "Route %s not exists in DB for update",
                          std::string(route_key).c_str());
        return STD_ERR(MCAST, PARAM, 0);
    }
    auto route_data = _route_list[route_key].get();
    for (auto upd_type: upd_type_list) {
        switch(upd_type) {
        case rt_upd_type_t::COPY_TO_CPU:
            route_data->copy_to_cpu = rt_info.copy_to_cpu;
            break;
        case rt_upd_type_t::OIF:
            route_data->oif_list.clear();
            for (auto& oif: rt_info.oif_list) {
                route_data->oif_list[oif.first] = oif.second;
            }
            break;
        case rt_upd_type_t::REPL_GRP_ID:
            route_data->repl_grp_id = rt_info.repl_grp_id;
            break;
        case rt_upd_type_t::STATUS:
            route_data->status = rt_info.status;
            break;
        default:
            NAS_MC_L3_LOG_ERR("ROUTE-DB", "Invalid route update type");
            return STD_ERR(MCAST, PARAM, 0);
        }
    }

    return STD_ERR_OK;
}

template<int AF>
void ipmc_route_db<AF>::get_route(std::vector<mc_route_t*>& route_list,
                                  const ipmc_route_filter_t<AF>& filter,
                                  const std::bitset<RT_MAX_POS>& filter_mask)
{
    std::lock_guard<std::mutex> lock(_mutex);
    for (auto& route: _route_list) {
        if (match_filter(*route.second, filter, filter_mask)) {
            route_list.push_back(route.second.get());
        }
    }
}

template<int AF>
void ipmc_route_db<AF>::get_route(std::vector<mc_route_t>& route_list,
                                  const ipmc_route_filter_t<AF>& filter,
                                  const std::bitset<RT_MAX_POS>& filter_mask) const
{
    std::lock_guard<std::mutex> lock(_mutex);
    for (auto& route: _route_list) {
        if (match_filter(*route.second, filter, filter_mask)) {
            mc_route_t mc_route{};
            route.first.set_mc_route(mc_route);
            mc_route.iif_id = route.second->iif_id;
            for (auto& oif: route.second->oif_list) {
                mc_route.oif_list.insert(std::make_pair(oif.first, oif.second));
            }
            mc_route.copy_to_cpu = route.second->copy_to_cpu;
            mc_route.npu_prg_status = route.second->npu_prg_status;
            mc_route.walker_pending_evt_list_tracker_index = route.second->walker_pending_evt_list_tracker_index;
            mc_route.repl_grp_id = route.second->repl_grp_id;
            mc_route.status = route.second->status;
            route_list.push_back(mc_route);
        }
    }
}

static ipmc_route_db<AF_INET>& ipv4_route_db = *new ipmc_route_db<AF_INET>{};
static ipmc_route_db<AF_INET6>& ipv6_route_db = *new ipmc_route_db<AF_INET6>{};

// Add route or route OIF member to DB
t_std_error nas_mc_l3_route_db_add(const mc_route_t& rt_info)
{
    NAS_MC_L3_LOG_DEBUG("ROUTE-DB", "Add route to DB: %s", std::string(rt_info).c_str());
    t_std_error ret_val;
    if (rt_info.af == AF_INET) {
        ret_val = ipv4_route_db.add_route(rt_info);
    } else if (rt_info.af == AF_INET6) {
        ret_val = ipv6_route_db.add_route(rt_info);
    } else {
        NAS_MC_L3_LOG_ERR("ROUTE-DB", "Invalid address family");
        return STD_ERR(MCAST, PARAM, 0);
    }

    return ret_val;
}

// Delete route OIF member or route from DB
t_std_error nas_mc_l3_route_db_delete(const mc_route_t& rt_info)
{
    NAS_MC_L3_LOG_DEBUG("ROUTE-DB", "Delete route from DB: %s", std::string(rt_info).c_str());
    t_std_error ret_val;
    if (rt_info.af == AF_INET) {
        ret_val = ipv4_route_db.delete_route(rt_info);
    } else if (rt_info.af == AF_INET6) {
        ret_val = ipv6_route_db.delete_route(rt_info);
    } else {
        NAS_MC_L3_LOG_ERR("ROUTE-DB", "Invalid address family");
        return STD_ERR(MCAST, PARAM, 0);
    }

    return ret_val;
}

t_std_error nas_mc_l3_route_db_update(const mc_route_t& rt_info,
                                      const std::vector<rt_upd_type_t>& utype_list)
{
    NAS_MC_L3_LOG_DEBUG("ROUTE-DB", "Update route in DB: %s", std::string(rt_info).c_str());
    t_std_error ret_val;
    if (rt_info.af == AF_INET) {
        ret_val = ipv4_route_db.update_route(rt_info, utype_list);
    } else if (rt_info.af == AF_INET6) {
        ret_val = ipv6_route_db.update_route(rt_info, utype_list);
    } else {
        NAS_MC_L3_LOG_ERR("ROUTE-DB", "Invalid address family");
        return STD_ERR(MCAST, PARAM, 0);
    }

    return ret_val;
}

template<typename T>
std::vector<T> nas_mc_l3_route_db_get(const uint32_t* vrf_id, const uint32_t* af,
                                                const L3_MCAST_ROUTE_TYPE_t* rtype,
                                                const hal_ip_addr_t* grp_ip,
                                                const hal_ip_addr_t* src_ip,
                                                const std::pair<hal_vrf_id_t, hal_ifindex_t>* mbr_rif)
{
    mc_route_t mc_route{};
    std::bitset<RT_MAX_POS> mask{};
    if (vrf_id != nullptr) {
        mc_route.vrf_id = *vrf_id;
        mask.set(RT_VRF_ID_POS);
    }
    if (rtype != nullptr) {
        mc_route.rtype = *rtype;
        mask.set(RT_TYPE_POS);
    }
    if (grp_ip != nullptr) {
        mc_route.grp_ip = *grp_ip;
        mask.set(RT_GRP_IP_POS);
    }
    if (src_ip != nullptr) {
        mc_route.src_ip = *src_ip;
        mask.set(RT_SRC_IP_POS);
    }

    hal_vrf_id_t rif_vrf = 0;
    hal_ifindex_t rif_id = 0;
    if (mbr_rif != nullptr) {
        mask.set(RT_MBR_RIF_POS);
        rif_vrf = mbr_rif->first;
        rif_id = mbr_rif->second;
    }

    std::vector<T> route_list{};
    if (af == nullptr || *af == AF_INET) {
        ipv4_route_db.get_route(route_list,
                                std::make_tuple(ipmc_route_key_t<AF_INET>{mc_route}, rif_vrf, rif_id), mask);
    }
    if (af == nullptr || *af == AF_INET6) {
        ipv6_route_db.get_route(route_list,
                                std::make_tuple(ipmc_route_key_t<AF_INET6>{mc_route}, rif_vrf, rif_id), mask);
    }

    return route_list;
}

std::vector<mc_route_t*> nas_mc_l3_route_db_get(const uint32_t* vrf_id, const uint32_t* af,
                                                const L3_MCAST_ROUTE_TYPE_t* route_type,
                                                const hal_ip_addr_t* grp_ip,
                                                const hal_ip_addr_t* src_ip,
                                                const std::pair<hal_vrf_id_t, hal_ifindex_t>* mbr_rif)
{
    return nas_mc_l3_route_db_get<mc_route_t*>(vrf_id, af, route_type, grp_ip, src_ip, mbr_rif);
}

std::vector<mc_route_t> nas_mc_l3_route_db_get_copy(const uint32_t* vrf_id, const uint32_t* af,
                                                    const L3_MCAST_ROUTE_TYPE_t* route_type,
                                                    const hal_ip_addr_t* grp_ip,
                                                    const hal_ip_addr_t* src_ip)
{
    return nas_mc_l3_route_db_get<mc_route_t>(vrf_id, af, route_type, grp_ip, src_ip, nullptr);
}

mc_route_t* nas_mc_l3_route_db_get_exact(const mc_route_t& mc_route)
{
    std::bitset<RT_MAX_POS> mask{};
    mask.set(RT_VRF_ID_POS);
    mask.set(RT_TYPE_POS);
    mask.set(RT_GRP_IP_POS);
    if (mc_route.rtype != L3_MCAST_ROUTE_TYPE_XG) {
        mask.set(RT_SRC_IP_POS);
    }

    std::vector<mc_route_t*> route_list{};
    if (mc_route.af == AF_INET) {
        ipv4_route_db.get_route(route_list, std::make_tuple(ipmc_route_key_t<AF_INET>{mc_route}, 0, 0), mask);
    } else {
        ipv6_route_db.get_route(route_list, std::make_tuple(ipmc_route_key_t<AF_INET6>{mc_route}, 0, 0), mask);
    }

    if (route_list.empty() || route_list.size() > 1) {
        return nullptr;
    }

    return route_list[0];
}
