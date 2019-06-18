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
 * filename: nas_mc_util.h
 */

#ifndef __NAS_MC_UTIL_H__
#define __NAS_MC_UTIL_H__

#include "std_error_codes.h"
#include "ds_common_types.h"
#include "cps_api_object.h"
#include "event_log.h"
#include "nas_types.h"
#include <vector>
#include <unordered_map>

#define NAS_MC_LOG_EMERG(ID, ...)   EV_LOGGING(BASE_MCAST_SNOOP, EMERG, ID, __VA_ARGS__)
#define NAS_MC_LOG_ALERT(ID, ...)   EV_LOGGING(BASE_MCAST_SNOOP, ALERT, ID, __VA_ARGS__)
#define NAS_MC_LOG_CRIT(ID, ...)    EV_LOGGING(BASE_MCAST_SNOOP, CRIT, ID, __VA_ARGS__)
#define NAS_MC_LOG_ERR(ID, ...)     EV_LOGGING(BASE_MCAST_SNOOP, ERR, ID, __VA_ARGS__)
#define NAS_MC_LOG_WARN(ID, ...)    EV_LOGGING(BASE_MCAST_SNOOP, WARN, ID, __VA_ARGS__)
#define NAS_MC_LOG_NOTICE(ID, ...)  EV_LOGGING(BASE_MCAST_SNOOP, NOTICE, ID, __VA_ARGS__)
#define NAS_MC_LOG_INFO(ID, ...)    EV_LOGGING(BASE_MCAST_SNOOP, INFO, ID, __VA_ARGS__)
#define NAS_MC_LOG_DEBUG(ID, ...)   EV_LOGGING(BASE_MCAST_SNOOP, DEBUG, ID, __VA_ARGS__)

const hal_ifindex_t ALL_INTERFACES = static_cast<hal_ifindex_t>(-1);
// Mark if entry is non-OIF entry
const hal_ifindex_t NULL_INTERFACE = static_cast<hal_ifindex_t>(-2);
// CPU port as route member
const hal_ifindex_t CPU_INTERFACE = static_cast<hal_ifindex_t>(-3);

struct _ip_addr_key_hash
{
    size_t operator()(const hal_ip_addr_t& key) const {
        size_t hash = std::hash<unsigned int>()(key.af_index);
        if (key.af_index == HAL_INET4_FAMILY) {
            hash ^= (std::hash<unsigned int>()(key.u.ipv4.s_addr) << 1);
        } else {
            for (int idx = 0; idx < HAL_INET6_LEN; idx ++) {
                hash ^= (std::hash<unsigned char>()(key.u.ipv6.s6_addr[idx]) << (idx + 1));
            }
        }
        return hash;
    }
};

struct _ip_addr_key_equal
{
    bool operator()(const hal_ip_addr_t& k1, const hal_ip_addr_t& k2) const
    {
        if (k1.af_index != k2.af_index) {
            return false;
        }
        if (k1.af_index == HAL_INET4_FAMILY) {
            return k1.u.ipv4.s_addr == k2.u.ipv4.s_addr;
        } else {
            return memcmp(k1.u.ipv6.s6_addr, k2.u.ipv6.s6_addr, HAL_INET6_LEN) == 0;
        }
    }
};

enum class mc_event_type_t
{
    IGMP,
    MLD,
    IGMP_MLD
};

struct mc_entry_key_t
{
    hal_ip_addr_t dst_ip;
    bool is_xg;
    hal_ip_addr_t src_ip;
    mutable bool copy_to_cpu;

    operator std::string() const;
};

struct _mc_entry_key_hash
{
    size_t operator()(const mc_entry_key_t& key) const {
        size_t hash = _ip_addr_key_hash()(key.dst_ip);
        hash ^= (std::hash<bool>()(key.is_xg) << 1);
        if (!key.is_xg) {
            hash ^= (_ip_addr_key_hash()(key.src_ip) << 1);
        }
        return hash;
    }
};

struct _mc_entry_key_equal
{
    bool operator()(const mc_entry_key_t& k1, const mc_entry_key_t& k2) const
    {
        if (!_ip_addr_key_equal()(k1.dst_ip, k2.dst_ip)) {
            return false;
        }
        if (k1.is_xg != k2.is_xg) {
            return false;
        }
        if (!k1.is_xg) {
            return _ip_addr_key_equal()(k1.src_ip, k2.src_ip);
        }

        return true;
    }
};

struct mc_vlan_route_info_t
{
    mc_entry_key_t entry;
    std::vector<hal_ifindex_t> mrouter_if_list;
    std::vector<hal_ifindex_t> host_if_list;
};

using mc_get_route_list_t = std::unordered_map<hal_vlan_id_t, std::vector<mc_vlan_route_info_t>>;

struct mc_vlan_mrouter_info_t
{
    std::vector<hal_ifindex_t> igmp_if_list;
    std::vector<hal_ifindex_t> mld_if_list;
};

using mc_get_mrouter_list_t = std::unordered_map<hal_vlan_id_t, mc_vlan_mrouter_info_t>;

using mc_flood_restr_status_t = std::unordered_map<hal_vlan_id_t, bool>;

t_std_error nas_mc_proc_init(void);
t_std_error nas_mc_proc_deinit(void);

t_std_error nas_mc_cps_init(void);

void nas_mc_change_snooping_status(mc_event_type_t req_type, hal_vlan_id_t vlan_id, bool enable);
void nas_mc_add_mrouter(mc_event_type_t req_type, hal_vlan_id_t vlan_id, hal_ifindex_t ifindex);
void nas_mc_del_mrouter(mc_event_type_t req_type, hal_vlan_id_t vlan_id, hal_ifindex_t ifindex);
void nas_mc_add_route(mc_event_type_t req_type, hal_vlan_id_t vlan_id,
                      hal_ip_addr_t group_addr, bool is_xg, hal_ip_addr_t src_addr, bool have_ifindex,
                      hal_ifindex_t ifindex);
void nas_mc_del_route(mc_event_type_t req_type, hal_vlan_id_t vlan_id,
                      hal_ip_addr_t group_addr, bool is_xg, hal_ip_addr_t src_addr, bool have_ifindex,
                      hal_ifindex_t ifindex);
void nas_mc_cleanup_vlan_member(hal_vlan_id_t vlan_id, hal_ifindex_t ifindex);
void nas_mc_cleanup_interface(hal_ifindex_t ifindex);
void nas_mc_cleanup_vlan(hal_vlan_id_t vlan_id);

void nas_mc_get_route(mc_event_type_t entry_type, hal_vlan_id_t vlan_id,
                      hal_ip_addr_t group_addr, bool is_xg, hal_ip_addr_t src_addr,
                      mc_get_route_list_t& route_list);
void nas_mc_get_mrouter(mc_event_type_t entry_type, hal_vlan_id_t vlan_id,
                        mc_get_mrouter_list_t& mrouter_list);
void nas_mc_set_flood_restrict(hal_vlan_id_t vlan_id, bool enable);
void nas_mc_get_flood_restrict_status(bool all_vlan, hal_vlan_id_t vlan_id,
                                      mc_flood_restr_status_t& vlan_status);
bool nas_mc_get_entry_group_id(hal_vlan_id_t vlan_id, const mc_entry_key_t& entry_key,
                               ndi_obj_id_t& grp_id);
bool nas_mc_get_group_info_by_id(ndi_obj_id_t ndi_grp_id, hal_vlan_id_t& vlan_id,
                                 std::vector<hal_ifindex_t>& oif_list, size_t& ref_count);

#ifdef __cplusplus
extern "C" {
#endif

t_std_error nas_mc_init(void);

#ifdef __cplusplus
}
#endif

#endif
