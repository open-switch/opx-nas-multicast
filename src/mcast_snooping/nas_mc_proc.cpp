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
 * filename: nas_mc_proc.cpp
 */


#include "cps_api_object.h"
#include "nas_mc_util.h"
#include "nas_types.h"
#include "std_thread_tools.h"
#include "std_ip_utils.h"
#include "nas_ndi_common.h"
#include "hal_if_mapping.h"
#include "nas_ndi_mcast.h"
#include "nas_ndi_l2mc.h"
#include "nas_ndi_vlan.h"
#include "event_log.h"
#include "nas_switch.h"
#include "nas_mc_l3_cps.h"

#include <set>
#include <queue>
#include <unordered_set>
#include <mutex>
#include <condition_variable>
#include <inttypes.h>
#include <sstream>
#include <memory>
#include <algorithm>

#define TAG_PRINT_BUF_LEN   256

/**
 * Data structure related to message decoded from
 * event and used by main thread for configuring
 * multicast router port and route entry
 **/

/* Multicast snooping message type */
enum class mc_msg_type_t
{
    // Multicast router update
    MROUTER,
    // Multicast route entry update
    ROUTE,
    // Interface update
    INTERFACE,
    // Enable/disable copy route hit packet to cpu
    COPY_TO_CPU
};

/* Multicast snooping operation type */
enum class mc_oper_type_t
{
    // Add mrouter or route entry
    ADD,
    // Delete mrouter or route entry
    DELETE,
    // Change enable/disable status of multicast snooping
    STATUS,
    // Update route entry
    UPDATE,
    // Get route from cache
    GET,
    // Enable/disable unknown multicast flooding restrict
    FLOOD_RESTRICT
};

static const char* get_oper_type_name(mc_oper_type_t oper_type)
{
    switch(oper_type) {
    case mc_oper_type_t::ADD:
        return "ADD";
    case mc_oper_type_t::DELETE:
        return "DELETE";
    case mc_oper_type_t::STATUS:
        return "STATUS";
    case mc_oper_type_t::UPDATE:
        return "UPDATE";
    case mc_oper_type_t::GET:
        return "GET";
    case mc_oper_type_t::FLOOD_RESTRICT:
        return "FLOOD_RESTRICT";
    }
    return "";
}

static const char* get_msg_type_name(mc_msg_type_t msg_type)
{
    switch(msg_type) {
    case mc_msg_type_t::MROUTER:
        return "Multicast Router Interface";
    case mc_msg_type_t::ROUTE:
        return "Group Attached Interface";
    case mc_msg_type_t::INTERFACE:
        return "Physical Interface";
    case mc_msg_type_t::COPY_TO_CPU:
        return "Copy Route Hit Packets to CPU";
    }
    return "";
}

static inline bool _is_af_match_ip_type(uint32_t af_index, mc_event_type_t ip_type)
{
    return ((af_index == HAL_INET4_FAMILY && ip_type == mc_event_type_t::IGMP) ||
            (af_index == HAL_INET6_FAMILY && ip_type == mc_event_type_t::MLD) ||
            (ip_type == mc_event_type_t::IGMP_MLD));
}

static char mc_ip_buf[HAL_INET6_TEXT_LEN + 1];

static const char *nas_mc_ip_to_string(const hal_ip_addr_t& ip_addr)
{
    const char* ip_str = std_ip_to_string(&ip_addr, mc_ip_buf, sizeof(mc_ip_buf));
    if (ip_str == nullptr) {
        ip_str = "";
    }
    return ip_str;
}

mc_entry_key_t::operator std::string() const
{
    std::ostringstream ss;
    ss << "[";
    if (is_xg) {
        ss << "*";
    } else {
        ss << nas_mc_ip_to_string(src_ip);
    }
    ss << ", " << nas_mc_ip_to_string(dst_ip);
    if (copy_to_cpu) {
        ss << " TO_CPU";
    }
    ss << "]";
    return ss.str();
}

const uint32_t REPLACE_WITH_EXISTING_GROUP = 1;
const uint32_t CREATE_NEW_GROUP = 2;
const uint32_t UPDATE_CURRENT_GROUP = 3;
const uint32_t DELETE_OLD_GROUP = 0x80;

const ndi_obj_id_t INVALID_GROUP_ID = static_cast<ndi_obj_id_t>(-1);

const int ENTRY_MROUTER_MEMBER = 0;
const int ENTRY_HOST_MEMBER = 1;
const int ENTRY_MROUTER_AND_HOST_MEMBER = 2;

/* Information about multicast entry update along with mrouter port add/delete */
struct mc_group_update_info_t
{
    // Original l2mc group ID associated with each entry
    ndi_obj_id_t orig_group_id;
    // Update type flag
    mutable uint32_t upd_type;
    // New l2mc group ID of group newly created or to replace the original one
    ndi_obj_id_t new_group_id;
    // List of l2mc group members
    std::unordered_map<hal_ifindex_t, ndi_obj_id_t> grp_member_list;
    // Copy to cpu flag
    bool copy_to_cpu;

    std::string dump_update_info() const;
};

std::string mc_group_update_info_t::dump_update_info() const
{
    std::ostringstream ss;
    ss << std::endl;
    ss << "Old Group OID    : ";
    ss << std::hex << std::showbase;
    if (orig_group_id == INVALID_GROUP_ID) {
        ss << "-" << std::endl;
    } else {
        ss << orig_group_id << std::endl;
    }
    ss << "Update Type      : ";
    switch (upd_type & 0xf) {
    case REPLACE_WITH_EXISTING_GROUP:
        ss << "Use existing group";
        break;
    case CREATE_NEW_GROUP:
        ss << "Create new group";
        break;
    case UPDATE_CURRENT_GROUP:
        ss << "Update old group";
        break;
    default:
        break;
    }
    if (upd_type & DELETE_OLD_GROUP) {
        if (upd_type & 0xf) {
            ss << " + ";
        }
        ss << "Delete old group";
    }
    ss << std::endl;
    ss << "New Group OID    : ";
    if (new_group_id == INVALID_GROUP_ID) {
        ss << "-" << std::endl;
    } else {
        ss << new_group_id << std::endl;
    }
    ss << "Group Member     : ";
    for (auto& grp_mbr: grp_member_list) {
        ss << "(" << "IFIDX-" << grp_mbr.first << ",OID-" << grp_mbr.second << "), ";
    }
    ss << std::endl;
    ss << "Copy to CPU      : " << (copy_to_cpu ? "enable" : "disable") << std::endl;
    ss << std::endl;
    return ss.str();
}

struct mc_group_key_t
{
    hal_vlan_id_t vlan_id;
    std::set<hal_ifindex_t> oif_list;
    bool copy_to_cpu;
};

static const bool group_key_check_vlan(void);

struct _mc_group_key_hash
{
    size_t operator()(const mc_group_key_t& grp_key) const
    {
        size_t h_val = 0;
        if (group_key_check_vlan()) {
            h_val = std::hash<int>()(grp_key.vlan_id);
        }
        for (auto if_index: grp_key.oif_list) {
            h_val <<= 1;
            h_val ^= std::hash<int>()(if_index);
        }
        h_val <<= 1;
        h_val ^= std::hash<bool>()(grp_key.copy_to_cpu);
        return h_val;
    }
};

struct _mc_group_key_equal
{
    bool operator()(const mc_group_key_t& k1, const mc_group_key_t& k2) const
    {
        if (group_key_check_vlan() && k1.vlan_id != k2.vlan_id) {
            return false;
        }

        return k1.oif_list == k2.oif_list && k1.copy_to_cpu == k2.copy_to_cpu;
    }
};


static bool nas_mc_ipaddr_match(const hal_ip_addr_t& filter_ip,
                                const hal_ip_addr_t& target_ip)
{
    static const hal_ip_addr_t zero_ip{0};
    if (filter_ip.af_index != target_ip.af_index) {
        return false;
    }
    // wildcard ip check
    if (filter_ip.af_index == AF_INET && filter_ip.u.v4_addr == 0) {
        return true;
    } else if (filter_ip.af_index == AF_INET6) {
        if (memcmp(filter_ip.u.v6_addr, zero_ip.u.v6_addr, sizeof(filter_ip.u.v6_addr)) == 0) {
            return true;
        }
    }
    return _ip_addr_key_equal()(filter_ip, target_ip);
}

struct mc_entry_op_t
{
    hal_vlan_id_t vlan_id;
    mc_entry_key_t entry_key;
    mc_oper_type_t op_type;
};

using mc_entry_op_list = std::vector<mc_entry_op_t>;
using mc_entry_update_map_t = std::unordered_map<mc_entry_key_t, std::shared_ptr<mc_group_update_info_t>,
                                                 _mc_entry_key_hash, _mc_entry_key_equal>;
using mc_group_update_map_t = std::unordered_map<mc_group_key_t, std::pair<std::shared_ptr<mc_group_update_info_t>,
                                                                           mc_entry_op_list>,
                                                 _mc_group_key_hash, _mc_group_key_equal>;
using mc_flood_restr_update_map_t = std::unordered_map<npu_id_t, std::shared_ptr<mc_group_update_info_t>>;

/* Multicast snooping message */
struct mc_snooping_msg_t
{
    // Request event type
    mc_event_type_t req_type;
    // VLAN ID
    hal_vlan_id_t vlan_id;
    // Operation type
    mc_oper_type_t oper_type;
    // For operation type STATUS, indicate if multicast snooping is enabled
    bool enable;
    // Message type
    mc_msg_type_t msg_type;
    // Specify valid ifindex is given or not
    bool have_ifindex;
    // Specify interface mapped to mrouter port or multicast host port
    hal_ifindex_t ifindex;
    // For interface cleanup, apply for all VLANs
    bool all_vlan;
    // For message type ROUTE, specify multicast group address
    hal_ip_addr_t group_addr;
    // For message type ROUTE, specify if it is (*,G) or (S, G)
    bool xg_entry;
    // For message type ROUTE, if it is (S, G) entry, specify group source address
    hal_ip_addr_t source_addr;

    bool match_route_type;

    // List of multicast groups that need to be updated
    std::unordered_map<hal_vlan_id_t, mc_entry_update_map_t> route_update_list;
    mc_group_update_map_t group_update_list;
    std::unordered_map<hal_vlan_id_t, mc_flood_restr_update_map_t> flood_restr_update_list;

    std::string dump_msg_info(bool is_sync);

    const mc_group_update_info_t* group_update_info() const;

    bool is_route_match(const mc_entry_key_t& route_key) const
    {
        if (match_route_type && xg_entry != route_key.is_xg) {
            return false;
        }
        if (!nas_mc_ipaddr_match(group_addr, route_key.dst_ip)) {
            return false;
        }
        if (!route_key.is_xg && !nas_mc_ipaddr_match(source_addr, route_key.src_ip)) {
            return false;
        }

        return true;
    }
};

const mc_group_update_info_t* mc_snooping_msg_t::group_update_info() const
{
    if (route_update_list.empty() || route_update_list.begin()->second.empty()) {
        return nullptr;
    }
    return route_update_list.begin()->second.begin()->second.get();
}

std::string mc_snooping_msg_t::dump_msg_info(bool is_sync)
{
    std::ostringstream ss;
    ss << "-------------------------------" << std::endl;
    ss << "Received Multicast Message" << std::endl;
    ss << "-------------------------------" << std::endl;
    ss << "  Task Type      : " << (is_sync ? "SYNC" : "NON-SYNC") << std::endl;
    ss << "  Event Type     : " <<
                     (req_type == mc_event_type_t::IGMP_MLD ? "IGMP_MLD" :
                      (req_type == mc_event_type_t::IGMP ? "IGMP" : "MLD"))
                     << std::endl;
    if (all_vlan) {
        ss << "  VLAN ID        : All" << std::endl;
    } else {
        ss << "  VLAN ID        : " << vlan_id << std::endl;
    }
    ss << "  Operation Type : " <<
                     get_oper_type_name(oper_type) << std::endl;
    if (oper_type == mc_oper_type_t::STATUS || oper_type == mc_oper_type_t::FLOOD_RESTRICT) {
        ss << "  Enable         : " <<
                         (enable ? "TRUE" : "FALSE") << std::endl;
    } else {
        ss << "  Message Type   : " <<

                         get_msg_type_name(msg_type) << std::endl;
        if (msg_type == mc_msg_type_t::ROUTE || msg_type == mc_msg_type_t::COPY_TO_CPU) {
            ss << "  Group Address  : " <<
                             nas_mc_ip_to_string(group_addr) << std::endl;
            if (xg_entry) {
                ss << "  Source Address : *" << std::endl;
            } else {
                ss << "  Source Address : " <<
                             nas_mc_ip_to_string(source_addr) << std::endl;
            }
        }
        if (msg_type == mc_msg_type_t::COPY_TO_CPU) {
            ss << "  Copy to CPU    : " << (enable ? "Enable" : "Disable") << std::endl;
        }
        if (have_ifindex) {
            ss << "  Ifindex        : " << ifindex << std::endl;
        } else {
            ss << "  Ifindex        : -" << std::endl;
        }
    }
    ss << std::endl;
    return ss.str();
}

class nas_mc_msg_queue
{
public:
    // Make class as singleton
    static nas_mc_msg_queue& get_instance()
    {
        static nas_mc_msg_queue inst;
        return inst;
    }
    nas_mc_msg_queue(const nas_mc_msg_queue&) = delete;
    nas_mc_msg_queue& operator=(const nas_mc_msg_queue&) = delete;
    nas_mc_msg_queue(nas_mc_msg_queue&&) = delete;
    nas_mc_msg_queue& operator=(nas_mc_msg_queue&&) = delete;

    void push(mc_snooping_msg_t* msg, bool sync = false)
    {
        std::unique_lock<std::mutex> lock{_mutex};
        _pending_msg.push(std::make_pair(std::unique_ptr<mc_snooping_msg_t>{msg}, sync));
        _req_cond.notify_one();
        if (sync) {
            // wait for processing finish
            _ack_cond.wait(lock);
        }
    }

    void wait_for_msg(void)
    {
        std::unique_lock<std::mutex> lock{_mutex};
        if (_pending_msg.empty()) {
            // check if there is pending msg
            _req_cond.wait(lock, [this](){return !_pending_msg.empty();});
        }
    }

    bool pop(std::unique_ptr<mc_snooping_msg_t>& msg, bool& is_sync)
    {
        std::unique_lock<std::mutex> lock{_mutex};
        if (_pending_msg.empty()) {
            return false;
        }
        auto& q_item = _pending_msg.front();
        msg = std::move(q_item.first);
        is_sync = q_item.second;
        _pending_msg.pop();
        return true;
    }

    void proc_finish()
    {
        _ack_cond.notify_one();
    }

private:
    nas_mc_msg_queue(){}
    ~nas_mc_msg_queue(){}

    // Queue to store messages pending for main thread to process
    std::queue<std::pair<std::unique_ptr<mc_snooping_msg_t>, bool>> _pending_msg;
    std::mutex _mutex;
    std::condition_variable _req_cond;
    std::condition_variable _ack_cond;
};

static std::string grp_key_to_string(const mc_group_key_t& grp_key)
{
    std::ostringstream ss;
    ss << "[";
    ss << "V" << grp_key.vlan_id << " ";
    std::for_each(grp_key.oif_list.begin(), grp_key.oif_list.end(),
                  [&ss](hal_ifindex_t ifidx){ss << ifidx << ",";});
    if (grp_key.copy_to_cpu) {
        ss << " C";
    }
    ss << "]";
    return ss.str();
}

struct mc_group_info_t
{
    // NDI multicast group ID
    ndi_obj_id_t ndi_group_id;
    // VLAN ID
    hal_vlan_id_t vlan_id;
    // List of member port and NDI member ID for each group member
    std::unordered_map<hal_ifindex_t, ndi_obj_id_t> group_member_list;
    // Reference count
    size_t ref_count;

    mc_group_key_t get_group_key(bool copy_to_cpu) const
    {
        std::set<hal_ifindex_t> iflist{};
        for (auto& grp_mbr: group_member_list) {
            iflist.insert(grp_mbr.first);
        }
        return mc_group_key_t{vlan_id, iflist, copy_to_cpu};
    }

    std::string dump_group_info(bool copy_to_cpu = false) const
    {
        std::ostringstream ss;
        ss << std::endl;
        ss << "Group OID : ";
        ss << std::hex << std::showbase;
        ss << ndi_group_id << std::endl;
        ss << "Group Key : ";
        ss << grp_key_to_string(get_group_key(copy_to_cpu)) << std::endl;
        ss << "Ref Count : ";
        ss << std::dec << std::noshowbase;
        ss << ref_count << std::endl;
        ss << std::endl;
        return ss.str();
    }
};

/**
  * Data struction used to cache multicast status, multicast router ports
  * and multicast route entry
  **/

struct mc_route_info_t
{
    // List of member port for multicast host
    std::unordered_set<hal_ifindex_t> router_member_list;
    // List of member port for multicast router
    std::unordered_set<hal_ifindex_t> host_member_list;
    // Associated multicast group pointer
    std::shared_ptr<mc_group_info_t> group_info;

    ndi_obj_id_t get_member_obj_id(hal_ifindex_t if_index) const
    {
        if (group_info->group_member_list.find(if_index) == group_info->group_member_list.end()) {
            return INVALID_GROUP_ID;
        }
        return group_info->group_member_list.at(if_index);
    }

    bool is_non_oif_entry() const
    {
        return host_member_list.find(NULL_INTERFACE) != host_member_list.end();
    }
};

using mc_route_map_t =
        std::unordered_map<mc_entry_key_t, mc_route_info_t, _mc_entry_key_hash, _mc_entry_key_equal>;

struct mc_snooping_info_t
{
    // List of multicast router ports of ipv4 family
    std::set<hal_ifindex_t> ipv4_mrouter_list;
    bool ipv4_to_cpu_enabled;
    // List of multicast router ports of ipv6 family
    std::set<hal_ifindex_t> ipv6_mrouter_list;
    bool ipv6_to_cpu_enabled;
    // List of multicast route entry
    mc_route_map_t route_list;
};

const bool DEFAULT_MC_SNOOPING_ENABLED = true;

// Cache of multicast snooping units indexed with NPU_ID and VLAN ID
using mc_snooping_npu_info_t = std::unordered_map<hal_vlan_id_t, mc_snooping_info_t>;

struct mc_snooping_cfg_t
{
    bool igmp_snoop_enabled;
    bool mld_snoop_enabled;
    std::unordered_map<npu_id_t, ndi_obj_id_t> flood_restr_grp_id;
    bool flood_restr_enabled(npu_id_t npu_id) const
    {
        return flood_restr_grp_id.find(npu_id) != flood_restr_grp_id.end();
    }
    mc_snooping_cfg_t() :
        igmp_snoop_enabled(DEFAULT_MC_SNOOPING_ENABLED),
        mld_snoop_enabled(DEFAULT_MC_SNOOPING_ENABLED) {}
};

template<bool P>
struct if_insert_impl
{
    template<typename T>
    static void insert_to_list(hal_ifindex_t ifindex, T& if_list)
    {
        if_list.insert(ifindex);
    }
};

template<>
struct if_insert_impl<true>
{
    template<typename T>
    static void insert_to_list(hal_ifindex_t ifindex, T& if_list)
    {
        if_list.insert(std::make_pair(ifindex, 0));
    }
};

class nas_mc_snooping
{
public:
    // Make class as singleton
    static nas_mc_snooping& get_instance()
    {
        static nas_mc_snooping inst;
        return inst;
    }
    nas_mc_snooping(const nas_mc_snooping&) = delete;
    nas_mc_snooping& operator=(const nas_mc_snooping&) = delete;
    nas_mc_snooping(nas_mc_snooping&&) = delete;
    nas_mc_snooping& operator=(nas_mc_snooping&&) = delete;


    // Check if cache could/need to be updated by attributes in multicast snooping
    // message
    bool update_needed(const mc_snooping_msg_t& msg_info) const;
    // Update the cache based on multicast snooping message
    void update(const mc_snooping_msg_t& msg_info);
    // Get cached information for multicast router,
    // and store them in multicast message data
    bool get_mrouter_ndi_info(mc_snooping_msg_t& msg_info) const;
    // Get cached information for route interface delete
    bool get_route_interface_ndi_info(mc_snooping_msg_t& msg_info) const;
    bool get_copy_to_cpu_ndi_info(mc_snooping_msg_t& msg_info) const;
    // Get cached NDI IDs for multicast entry, group and member,
    // and store them in multicast message data
    bool get_route_ndi_info(mc_snooping_msg_t& msg_info) const;

    bool get_flood_restr_ndi_info(mc_snooping_msg_t& msg_info) const;

    // Clear all multicast snooping entries of specified VLAN and IP family from cache
    void flush(hal_vlan_id_t vlan_id, mc_event_type_t ip_type);

    // Delete all multicast snooping entries of specified VLAN and IP family on NPU
    t_std_error delete_vlan_entries(hal_vlan_id_t vlan_id, mc_event_type_t ip_type);
    // Dump all vlan cache entries to log
    std::string dump_vlan_entries(npu_id_t npu_id, hal_vlan_id_t vlan_id) const;

    // Get matched route entries from cache
    void get_route_entries(mc_snooping_msg_t& msg_info) const;
    // Get matched mrouter interfaces from cache
    void get_mrouter_intfs(mc_snooping_msg_t& msg_info) const;

    t_std_error nas_mc_l2_snooped_port_list_get (npu_id_t npu_id, hal_vlan_id_t vlan_id, BASE_CMN_AF_TYPE_t af,
                                                 bool is_xg, hal_ip_addr_t grp_ip, hal_ip_addr_t src_ip,
                                                 std::set<hal_ifindex_t> &if_list);

    // Return or set default copy to cpu status of specific VLAN and address family
    bool copy_to_cpu_enabled(mc_event_type_t req_type, npu_id_t npu_id, hal_vlan_id_t vlan_id) const;
    void copy_to_cpu_enabled(mc_event_type_t req_type, npu_id_t npu_id, hal_vlan_id_t vlan_id,
                             bool enable);
    bool& vlan_in_group_key()
    {
        return _group_key_with_vlan;
    }

    const bool vlan_in_group_key() const
    {
        return _group_key_with_vlan;
    }

    void get_flood_restr_status(npu_id_t npu_id, bool all_vlan, hal_vlan_id_t vlan_id,
                                mc_flood_restr_status_t& vlan_status) const;

    bool get_entry_group_id(npu_id_t npu_id, hal_vlan_id_t vlan_id, const mc_entry_key_t& entry_key,
                            ndi_obj_id_t& grp_id) const;
private:
    nas_mc_snooping(){}
    ~nas_mc_snooping(){}

    // Check if multicast is enable for specific VLAN and IP type
    bool enabled(mc_event_type_t req_type, hal_vlan_id_t vlan_id) const;
    // Check if multicast is enable for specific VLAN and all IP type
    bool all_ip_enabled(hal_vlan_id_t vlan_id) const;

    // Indicate if multicast snooping is enabled for each vlan
    std::unordered_map<hal_vlan_id_t, mc_snooping_cfg_t> _vlan_config;
    // Snooping info for each NPU
    std::unordered_map<npu_id_t, mc_snooping_npu_info_t> _npu_info;

    // Flag indicate if VLAN ID used as key for L2MC group re-use
    bool _group_key_with_vlan;

    mutable std::recursive_mutex _mutex;

    template<bool P, typename T>
    void mrouter_port_list_get(npu_id_t npu_id, hal_vlan_id_t vlan_id, mc_event_type_t proto_type,
                               T& if_list) const
    {
        if (_npu_info.find(npu_id) == _npu_info.end()) {
            return;
        }
        auto rt_itor = _npu_info.at(npu_id).find(vlan_id);
        if (rt_itor == _npu_info.at(npu_id).end()) {
            return;
        }
        if (proto_type == mc_event_type_t::IGMP || proto_type == mc_event_type_t::IGMP_MLD) {
            for (auto ifindex: rt_itor->second.ipv4_mrouter_list) {
                if_insert_impl<P>::insert_to_list(ifindex, if_list);
            }
        }
        if (proto_type == mc_event_type_t::MLD || proto_type == mc_event_type_t::IGMP_MLD) {
            for (auto ifindex: rt_itor->second.ipv6_mrouter_list) {
                if_insert_impl<P>::insert_to_list(ifindex, if_list);
            }
        }
    }

    bool get_flood_restr_group_update(mc_snooping_msg_t& msg_info, hal_vlan_id_t vlan_id, npu_id_t npu_id) const;
    bool flood_restr_group_update_needed(bool is_add, npu_id_t npu_id, hal_vlan_id_t vlan_id, hal_ifindex_t ifindex) const;
    bool update_flood_restr_group(const mc_snooping_msg_t& msg_info, hal_vlan_id_t vlan_id, npu_id_t npu_id);
};

class mc_snooping_group_db
{
public:
    mc_snooping_group_db() = default;
    bool get_group_upd_info(hal_vlan_id_t vlan_id, hal_ifindex_t if_index, bool is_add,
                            size_t old_entry_num, size_t new_entry_num,
                            mc_group_update_info_t& grp_upd_info) const;
    bool update_group(hal_vlan_id_t vlan_id, const mc_group_update_info_t& grp_upd_info);
    bool delete_group(ndi_obj_id_t ndi_grp_id);
    std::shared_ptr<mc_group_info_t> get_group_ptr(ndi_obj_id_t group_id) const
    {
        if (_id_to_group_map.find(group_id) == _id_to_group_map.end()) {
            return nullptr;
        }
        return _id_to_group_map.at(group_id).first;
    }
    mc_group_info_t* get_group_info(ndi_obj_id_t ndi_grp_id) const
    {
        if (_id_to_group_map.find(ndi_grp_id) == _id_to_group_map.end()) {
            return nullptr;
        }
        return _id_to_group_map.at(ndi_grp_id).first.get();
    }
    mc_group_info_t* get_group_info(hal_vlan_id_t vlan_id,
                                    const std::vector<hal_ifindex_t>& ifindex_list,
                                    bool copy_to_cpu) const
    {
        mc_group_key_t grp_key{vlan_id, {}, copy_to_cpu};
        for (auto ifindex: ifindex_list) {
            grp_key.oif_list.insert(ifindex);
        }
        if (_plist_to_group_map.find(grp_key) == _plist_to_group_map.end()) {
            return nullptr;
        }
        return _plist_to_group_map.at(grp_key).get();
    }
private:
    std::unordered_map<mc_group_key_t, std::shared_ptr<mc_group_info_t>,
                       _mc_group_key_hash, _mc_group_key_equal>
            _plist_to_group_map;
    std::unordered_map<ndi_obj_id_t, std::pair<std::shared_ptr<mc_group_info_t>, bool>>
            _id_to_group_map;
};

bool mc_snooping_group_db::get_group_upd_info(hal_vlan_id_t vlan_id, hal_ifindex_t if_index, bool is_add,
                                              size_t old_entry_num, size_t new_entry_num,
                                              mc_group_update_info_t& grp_upd_info) const
{
    NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "Processing group member %s for %d-%d entries:",
                     is_add ? "add" : "delete", old_entry_num, new_entry_num);
    if (if_index == NULL_INTERFACE) {
        NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", " Interface - None");
    } else {
        NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", " Interface - %d", (int)if_index);
    }
    NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", " Input Update Info");
    NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "%s", grp_upd_info.dump_update_info().c_str());
    auto old_group_id = grp_upd_info.orig_group_id;
    mc_group_info_t* orig_grp = nullptr;
    if (old_group_id != INVALID_GROUP_ID) {
        if (_id_to_group_map.find(old_group_id) == _id_to_group_map.end()) {
            NAS_MC_LOG_ERR("NAS-MC-PROC-DB", "Old group 0x%lx not found in DB", old_group_id);
            return false;
        }
        orig_grp = _id_to_group_map.at(old_group_id).first.get();
    }

    bool reuse_group_found = false;
    mc_group_key_t group_key{vlan_id, {}, grp_upd_info.copy_to_cpu};
    if (new_entry_num > 0) {
        if (orig_grp != nullptr) {
            for (auto& mbr_info: orig_grp->group_member_list) {
                if (!is_add && mbr_info.first == if_index) {
                    continue;
                }
                group_key.oif_list.insert(mbr_info.first);
            }
        }
        for (auto& if_itor: grp_upd_info.grp_member_list) {
            group_key.oif_list.insert(if_itor.first);
        }
        if (is_add && if_index != NULL_INTERFACE) {
            group_key.oif_list.insert(if_index);
        }

        NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "Search group with key: %s",
                         grp_key_to_string(group_key).c_str());
        auto itor = _plist_to_group_map.find(group_key);
        if (itor != _plist_to_group_map.end()) {
            grp_upd_info.new_group_id = itor->second->ndi_group_id;
            reuse_group_found = true;
        }
    } else {
        grp_upd_info.new_group_id = INVALID_GROUP_ID;
        reuse_group_found = true;
    }

    if (!reuse_group_found) {
        // Reusable group not found
        NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "Re-usable group not found");
        if (orig_grp != nullptr && orig_grp->ref_count == old_entry_num) {
            // No other entry linked to current group, just need to
            // add/delete member to/from group
            NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "Old group was only used by updated entries, just update it");
            grp_upd_info.upd_type = UPDATE_CURRENT_GROUP;
            if (if_index != NULL_INTERFACE) {
                if (is_add) {
                    grp_upd_info.grp_member_list.insert(std::make_pair(if_index, 0));
                } else {
                    if (orig_grp->group_member_list.find(if_index) ==
                        orig_grp->group_member_list.end()) {
                        return false;
                    }
                    auto del_mbr_id = orig_grp->group_member_list.at(if_index);
                    grp_upd_info.grp_member_list.insert(std::make_pair(if_index, del_mbr_id));
                }
            }
        } else {
            // Need to create new group
            if (orig_grp != nullptr) {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "Old group was used by %d entries, create new group",
                                 orig_grp->ref_count);
            }
            grp_upd_info.upd_type = CREATE_NEW_GROUP;
            for (auto ifidx: group_key.oif_list) {
                grp_upd_info.grp_member_list.insert(std::make_pair(ifidx, 0));
            }
        }
    } else {
        // Reusable group exist
        NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "Found re-usable group with ID 0x%lx",
                         grp_upd_info.new_group_id);
        grp_upd_info.upd_type =  REPLACE_WITH_EXISTING_GROUP;
        if (orig_grp != nullptr && orig_grp->ref_count == old_entry_num &&
            old_group_id != grp_upd_info.new_group_id) {
            // Flag to delete old group
            grp_upd_info.upd_type |= DELETE_OLD_GROUP;
            grp_upd_info.grp_member_list = orig_grp->group_member_list;
        }
    }
    NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "New Update Info:");
    NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "%s", grp_upd_info.dump_update_info().c_str());
    return true;
}

bool mc_snooping_group_db::update_group(hal_vlan_id_t vlan_id, const mc_group_update_info_t& grp_upd_info)
{
    NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "Update DB with Info for VLAN %d:", vlan_id);
    NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "%s", grp_upd_info.dump_update_info().c_str());
    auto orig_group_id = grp_upd_info.orig_group_id;
    if (grp_upd_info.upd_type & DELETE_OLD_GROUP) {
        // Delete original group from cache
        if (!delete_group(orig_group_id)) {
            NAS_MC_LOG_ERR("NAS-MC-PROC-DB", "Failed to delete original group from cache");
            return false;
        }
        NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "Group 0x%lx was deleted from cache", orig_group_id);
        orig_group_id = INVALID_GROUP_ID;
        grp_upd_info.upd_type &= ~DELETE_OLD_GROUP;
    }

    if (grp_upd_info.upd_type == REPLACE_WITH_EXISTING_GROUP && orig_group_id == grp_upd_info.new_group_id) {
        // Nothing to do if there is no group change
        return true;
    }

    if (grp_upd_info.upd_type == CREATE_NEW_GROUP || grp_upd_info.upd_type == REPLACE_WITH_EXISTING_GROUP) {
        // Decrement ref count of old group
        if (orig_group_id != INVALID_GROUP_ID) {
            if (_id_to_group_map.find(orig_group_id) != _id_to_group_map.end()) {
                // Already deleted
                auto& grp_info = _id_to_group_map[orig_group_id];
                grp_info.first->ref_count --;
                NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "Original group updated: %s",
                                 grp_info.first->dump_group_info(grp_info.second).c_str());
            }
        }
    }

    if (grp_upd_info.upd_type == CREATE_NEW_GROUP) {
        // Add new group to cache
        if (_id_to_group_map.find(grp_upd_info.new_group_id) != _id_to_group_map.end()) {
            auto& grp_info = _id_to_group_map[grp_upd_info.new_group_id];
            grp_info.first->ref_count ++;
            NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "New group updated: %s",
                             grp_info.first->dump_group_info(grp_info.second).c_str());
            return true;
        }
        mc_group_key_t group_key{vlan_id, {}, grp_upd_info.copy_to_cpu};
        auto* grp_p = new mc_group_info_t{grp_upd_info.new_group_id, vlan_id, {}, 1};
        for (auto& grp_mbr: grp_upd_info.grp_member_list) {
            group_key.oif_list.insert(grp_mbr.first);
            grp_p->group_member_list.insert(grp_mbr);
        }
        std::shared_ptr<mc_group_info_t> grp_ptr{grp_p};
        _id_to_group_map.insert(std::make_pair(grp_upd_info.new_group_id,
                                               std::make_pair(grp_ptr, grp_upd_info.copy_to_cpu)));
        _plist_to_group_map.insert(std::make_pair(group_key, grp_ptr));
        NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "New group added: %s",
                         grp_p->dump_group_info(grp_upd_info.copy_to_cpu).c_str());
    } else if (grp_upd_info.upd_type == UPDATE_CURRENT_GROUP) {
        // Update member port list
        if (_id_to_group_map.find(grp_upd_info.new_group_id) == _id_to_group_map.end()) {
            NAS_MC_LOG_ERR("NAS-MC-PROC-DB", "Failed to find group ID %lx for port member update",
                           grp_upd_info.new_group_id);
            return false;
        }
        auto& grp_info = _id_to_group_map.at(grp_upd_info.new_group_id);

        mc_group_key_t group_key{vlan_id, {}, grp_info.second};
        for (auto& grp_mbr: grp_info.first->group_member_list) {
            group_key.oif_list.insert(grp_mbr.first);
        }
        if (_plist_to_group_map.find(group_key) == _plist_to_group_map.end()) {
            // Group was already updated
            NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "Group key %s not found in DB, it was updated",
                             grp_key_to_string(group_key).c_str());
            return true;
        }
        _plist_to_group_map.erase(group_key);

        for (auto& grp_mbr: grp_upd_info.grp_member_list) {
            if (grp_info.first->group_member_list.find(grp_mbr.first) == grp_info.first->group_member_list.end()) {
                grp_info.first->group_member_list.insert(grp_mbr);
                group_key.oif_list.insert(grp_mbr.first);
            } else {
                grp_info.first->group_member_list.erase(grp_mbr.first);
                group_key.oif_list.erase(grp_mbr.first);
            }
        }
        if (grp_upd_info.grp_member_list.empty()) {
            grp_info.second = group_key.copy_to_cpu = grp_upd_info.copy_to_cpu;
        }
        // Add new port list to group map
        _plist_to_group_map.insert(std::make_pair(group_key, grp_info.first));

        NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "Group updated: %s", grp_info.first->dump_group_info(grp_info.second).c_str());
        NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "With key: %s", grp_key_to_string(group_key).c_str());

        // Reset update type to prevent duplicate update
        grp_upd_info.upd_type = 0;
    } else if (grp_upd_info.upd_type == REPLACE_WITH_EXISTING_GROUP) {
        if (grp_upd_info.new_group_id != INVALID_GROUP_ID) {
            // Increment ref count of new group
            if (_id_to_group_map.find(grp_upd_info.new_group_id) == _id_to_group_map.end()) {
                NAS_MC_LOG_ERR("NAS-MC-PROC-DB", "Failed to find new group ID %ld for ref_cnt update",
                               grp_upd_info.new_group_id);
                return false;
            }
            auto& grp_info = _id_to_group_map[grp_upd_info.new_group_id];
            grp_info.first->ref_count ++;
            NAS_MC_LOG_DEBUG("NAS-MC-PROC-DB", "New group updated: %s",
                             grp_info.first->dump_group_info(grp_info.second).c_str());
        }
    }

    return true;
}

bool mc_snooping_group_db::delete_group(ndi_obj_id_t ndi_grp_id)
{
    if (_id_to_group_map.find(ndi_grp_id) == _id_to_group_map.end()) {
        // Already deleted
        return true;
    }
    auto& grp_info = _id_to_group_map.at(ndi_grp_id);
    mc_group_key_t group_key{grp_info.first->vlan_id, {}, grp_info.second};
    for (auto& grp_mbr: grp_info.first->group_member_list) {
        group_key.oif_list.insert(grp_mbr.first);
    }
    if (_plist_to_group_map.find(group_key) == _plist_to_group_map.end()) {
        NAS_MC_LOG_ERR("NAS-MC-PROC-DB", "Failed to find group with port list key");
        return false;
    }
    _plist_to_group_map.erase(group_key);
    _id_to_group_map.erase(ndi_grp_id);

    return true;
}

static mc_snooping_group_db& mc_group_db = *new mc_snooping_group_db{};

t_std_error nas_mc_l2_snooped_port_list_cache_get (npu_id_t npu_id, hal_vlan_id_t vlan_id,
                                                   BASE_CMN_AF_TYPE_t af, bool is_xg,
                                                   hal_ip_addr_t grp_ip, hal_ip_addr_t src_ip,
                                                   std::set<hal_ifindex_t> &if_list)
{
    nas_mc_snooping & mc_snoop = nas_mc_snooping::get_instance();

    return mc_snoop.nas_mc_l2_snooped_port_list_get(npu_id, vlan_id, af, is_xg, grp_ip, src_ip, if_list);
}

static const char *nas_mc_entry_tag(hal_ip_addr_t src_ip, hal_ip_addr_t dst_ip,
                                    bool is_xg)
{
    static char str_buf[TAG_PRINT_BUF_LEN + 1];
    size_t buf_size = TAG_PRINT_BUF_LEN;
    char *buf_p = str_buf;
    snprintf(buf_p, buf_size, "(%s, ", is_xg ? "*" : nas_mc_ip_to_string(src_ip));
    buf_p += strlen(buf_p);
    buf_size -= strlen(buf_p);
    if (buf_size == 0) {
        return str_buf;
    }
    snprintf(buf_p, buf_size, "%s)", nas_mc_ip_to_string(dst_ip));
    return str_buf;
}

static const char *nas_mc_entry_key_tag(const mc_entry_key_t& entry_key)
{
    return nas_mc_entry_tag(entry_key.src_ip, entry_key.dst_ip, entry_key.is_xg);
}

static inline nas_mc_msg_queue& pending_msg()
{
    return nas_mc_msg_queue::get_instance();
}
// API to enable/disable multicast snooping
void nas_mc_change_snooping_status(mc_event_type_t req_type, hal_vlan_id_t vlan_id, bool enable)
{
    pending_msg().push(new mc_snooping_msg_t{req_type, vlan_id, mc_oper_type_t::STATUS, enable});
}

// API to add multicast router port
void nas_mc_add_mrouter(mc_event_type_t req_type, hal_vlan_id_t vlan_id, hal_ifindex_t ifindex)
{
    pending_msg().push(new mc_snooping_msg_t{req_type, vlan_id, mc_oper_type_t::ADD, true,
                        mc_msg_type_t::MROUTER, true, ifindex});
}

// API to delete mrouter port
void nas_mc_del_mrouter(mc_event_type_t req_type, hal_vlan_id_t vlan_id, hal_ifindex_t ifindex)
{
    pending_msg().push(new mc_snooping_msg_t{req_type, vlan_id, mc_oper_type_t::DELETE, true,
                        mc_msg_type_t::MROUTER, true, ifindex});
}

static size_t nas_mc_get_max_npus(void)
{
    auto max_npus = nas_switch_get_max_npus();
    if (max_npus == 0) {
        // There is no way to configure max NPU number by UT code, so we assume for non-UT case,
        // max NPU number should not be 0 and return 1 as default number for UT only case.
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "There is no NPU configured.");
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "If it is called from UT, 1 will be returned for testing.\
                          Otherwise there might be configuration issue.");
        return 1;
    }

    return max_npus;
}

// API to add multicast route entry
void nas_mc_add_route(mc_event_type_t req_type, hal_vlan_id_t vlan_id,
                      hal_ip_addr_t group_addr, bool is_xg, hal_ip_addr_t src_addr, bool have_ifindex,
                      hal_ifindex_t ifindex)
{
    size_t max_npu = nas_mc_get_max_npus();
    if (have_ifindex) {
        if (ifindex == CPU_INTERFACE) {
            NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Add cpu port to route group");
            for (size_t npu_id = 0; npu_id < max_npu; npu_id ++) {
                pending_msg().push(new mc_snooping_msg_t{req_type, vlan_id, mc_oper_type_t::UPDATE, true,
                                                         mc_msg_type_t::COPY_TO_CPU,
                                                         false, static_cast<hal_ifindex_t>(npu_id),
                                                         false, group_addr, is_xg, src_addr, true});
            }
        } else {
            pending_msg().push(new mc_snooping_msg_t{req_type, vlan_id, mc_oper_type_t::ADD, true,
                            mc_msg_type_t::ROUTE, true, ifindex, false, group_addr, is_xg, src_addr});
        }
    } else {
        for (size_t npu_id = 0; npu_id < max_npu; npu_id ++) {
            pending_msg().push(new mc_snooping_msg_t{req_type, vlan_id, mc_oper_type_t::ADD, true,
                                mc_msg_type_t::ROUTE, false, static_cast<hal_ifindex_t>(npu_id), false,
                                group_addr, is_xg, src_addr});
        }
    }
}

// API to delete multicast route entry
void nas_mc_del_route(mc_event_type_t req_type, hal_vlan_id_t vlan_id,
                      hal_ip_addr_t group_addr, bool is_xg, hal_ip_addr_t src_addr, bool have_ifindex,
                      hal_ifindex_t ifindex)
{
    size_t max_npu = nas_mc_get_max_npus();
    if (have_ifindex) {
        if (ifindex == CPU_INTERFACE) {
            NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Remove cpu port from route group");
            for (size_t npu_id = 0; npu_id < max_npu; npu_id ++) {
                pending_msg().push(new mc_snooping_msg_t{req_type, vlan_id, mc_oper_type_t::UPDATE, false,
                                                         mc_msg_type_t::COPY_TO_CPU,
                                                         false, static_cast<hal_ifindex_t>(npu_id),
                                                         false, group_addr, is_xg, src_addr, true});
            }
        } else {
            pending_msg().push(new mc_snooping_msg_t{req_type, vlan_id, mc_oper_type_t::DELETE, true,
                            mc_msg_type_t::ROUTE, true, ifindex, false, group_addr, is_xg, src_addr});
        }
    } else {
        for (size_t npu_id = 0; npu_id < max_npu; npu_id ++) {
            pending_msg().push(new mc_snooping_msg_t{req_type, vlan_id, mc_oper_type_t::DELETE, true,
                                mc_msg_type_t::ROUTE, false, static_cast<hal_ifindex_t>(npu_id), false,
                                group_addr, is_xg, src_addr});
        }
    }
}

// API to delete all route entries for VLAN member interface
void nas_mc_cleanup_vlan_member(hal_vlan_id_t vlan_id, hal_ifindex_t ifindex)
{
    pending_msg().push(new mc_snooping_msg_t{mc_event_type_t::IGMP_MLD, vlan_id, mc_oper_type_t::DELETE, true,
                        mc_msg_type_t::INTERFACE, true, ifindex}, true);
}

// API to delete all route entries for interface
void nas_mc_cleanup_interface(hal_ifindex_t ifindex)
{
    pending_msg().push(new mc_snooping_msg_t{mc_event_type_t::IGMP_MLD, 0, mc_oper_type_t::DELETE, true,
                        mc_msg_type_t::INTERFACE, true, ifindex, true}, true);
}

// API to delete all route entries for VLAN
void nas_mc_cleanup_vlan(hal_vlan_id_t vlan_id)
{
    pending_msg().push(new mc_snooping_msg_t{mc_event_type_t::IGMP_MLD, vlan_id, mc_oper_type_t::DELETE, true,
                        mc_msg_type_t::INTERFACE, true, ALL_INTERFACES}, true);
}

void nas_mc_set_flood_restrict(hal_vlan_id_t vlan_id, bool enable)
{
    size_t max_npu = nas_mc_get_max_npus();
    for (size_t npu_id = 0; npu_id < max_npu; npu_id ++) {
        pending_msg().push(new mc_snooping_msg_t{mc_event_type_t::IGMP_MLD, vlan_id, mc_oper_type_t::FLOOD_RESTRICT, enable,
                                                 mc_msg_type_t::ROUTE, false, static_cast<hal_ifindex_t>(npu_id), false});
    }
}

static void nas_mc_get_route_npu(npu_id_t npu_id, mc_event_type_t entry_type, hal_vlan_id_t vlan_id,
                                 hal_ip_addr_t group_addr, bool is_xg, hal_ip_addr_t src_addr,
                                 mc_get_route_list_t& route_list)
{
    auto* msg_ptr = new mc_snooping_msg_t{entry_type, vlan_id, mc_oper_type_t::GET, true,
                        mc_msg_type_t::ROUTE, false, static_cast<hal_ifindex_t>(npu_id), vlan_id == 0,
                        group_addr, is_xg, src_addr, true};
    pending_msg().push(msg_ptr, true);

    std::vector<hal_ifindex_t> mrouter_mbr_list;
    std::vector<hal_ifindex_t> host_mbr_list;
    for (auto& vlan_info: msg_ptr->route_update_list) {
        for (auto& entry_info: vlan_info.second) {
            mrouter_mbr_list.clear();
            host_mbr_list.clear();
            for (auto& mbr_info: entry_info.second->grp_member_list) {
                if (mbr_info.second == ENTRY_MROUTER_MEMBER || mbr_info.second == ENTRY_MROUTER_AND_HOST_MEMBER) {
                    mrouter_mbr_list.push_back(mbr_info.first);
                }
                if (mbr_info.second == ENTRY_HOST_MEMBER || mbr_info.second == ENTRY_MROUTER_AND_HOST_MEMBER) {
                    host_mbr_list.push_back(mbr_info.first);
                }
            }
            route_list[vlan_info.first].push_back({entry_info.first, mrouter_mbr_list, host_mbr_list});
        }
    }
    delete msg_ptr;
}

void nas_mc_get_route(mc_event_type_t entry_type, hal_vlan_id_t vlan_id,
                      hal_ip_addr_t group_addr, bool is_xg, hal_ip_addr_t src_addr,
                      mc_get_route_list_t& route_list)
{
    size_t max_npu = nas_mc_get_max_npus();
    for (size_t npu_id = 0; npu_id < max_npu; npu_id ++) {
        nas_mc_get_route_npu(npu_id, entry_type, vlan_id, group_addr, is_xg, src_addr, route_list);
    }
}

static void nas_mc_get_mrouter_npu(npu_id_t npu_id, mc_event_type_t entry_type, hal_vlan_id_t vlan_id,
                                   mc_get_mrouter_list_t& mrouter_list)
{
    auto* msg_ptr = new mc_snooping_msg_t{entry_type, vlan_id, mc_oper_type_t::GET, true,
                        mc_msg_type_t::MROUTER, false, static_cast<hal_ifindex_t>(npu_id), vlan_id == 0};
    pending_msg().push(msg_ptr, true);

    for (auto& vlan_info: msg_ptr->route_update_list) {
        uint32_t af_index;
        for (auto& entry_info: vlan_info.second) {
            af_index = entry_info.first.dst_ip.af_index;
            for (auto& mbr_info: entry_info.second->grp_member_list) {
                if (af_index == AF_INET) {
                    mrouter_list[vlan_info.first].igmp_if_list.push_back(mbr_info.first);
                } else if (af_index == AF_INET6) {
                    mrouter_list[vlan_info.first].mld_if_list.push_back(mbr_info.first);
                }
            }
        }
    }
    delete msg_ptr;
}

void nas_mc_get_mrouter(mc_event_type_t entry_type, hal_vlan_id_t vlan_id,
                        mc_get_mrouter_list_t& mrouter_list)
{
    size_t max_npu = nas_mc_get_max_npus();
    for (size_t npu_id = 0; npu_id < max_npu; npu_id ++) {
        nas_mc_get_mrouter_npu(npu_id, entry_type, vlan_id, mrouter_list);
    }
}

struct mc_npu_port_t
{
    npu_id_t npu_id;
    nas_int_type_t port_type;
    union {
        npu_port_t port_id;
        hal_vlan_id_t vlan_id;
        lag_id_t lag_id;
    };
};

static t_std_error ifindex_to_npu_port(hal_ifindex_t ifindex, mc_npu_port_t& npu_port)
{
    interface_ctrl_t intf_ctrl;
    t_std_error rc = STD_ERR_OK;

    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.if_index = ifindex;

    if((rc= dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        return STD_ERR(MCAST,FAIL, rc);
    }

    npu_port.npu_id = intf_ctrl.npu_id;
    npu_port.port_type = intf_ctrl.int_type;
    if (intf_ctrl.int_type == nas_int_type_LAG) {
        npu_port.lag_id = intf_ctrl.lag_id;
    } else if (intf_ctrl.int_type == nas_int_type_VLAN) {
        npu_port.vlan_id = intf_ctrl.vlan_id;
    } else {
        npu_port.port_id = intf_ctrl.port_id;
    }

    return STD_ERR_OK;
}

t_std_error nas_mc_snooping::nas_mc_l2_snooped_port_list_get (npu_id_t npu_id, hal_vlan_id_t vlan_id,
                                             BASE_CMN_AF_TYPE_t af, bool is_xg,
                                             hal_ip_addr_t grp_ip, hal_ip_addr_t src_ip,
                                             std::set<hal_ifindex_t> &if_list)
{
    std::unique_lock<std::recursive_mutex> lock{_mutex};

    std::string grp_ip_str{nas_mc_ip_to_string(grp_ip)};
    std::string src_ip_str{nas_mc_ip_to_string(src_ip)};
    NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Expand snooping ports for VLAN %d Group %s Source %s",
                     vlan_id, grp_ip_str.c_str(), is_xg ? "*" : src_ip_str.c_str());

    mc_event_type_t proto_type = (af == BASE_CMN_AF_TYPE_INET ? mc_event_type_t::IGMP : mc_event_type_t::MLD);
    if (enabled(proto_type, vlan_id) == false) {
        NAS_MC_LOG_INFO("NAS-MC-PROC", " %s snooping disabled on vlan id(%u)", proto_type == mc_event_type_t::IGMP? "IGMP" : "MLD", vlan_id);
        return STD_ERR(MCAST, FAIL, 0);
    }

    bool route_found = false;
    auto npu_it = _npu_info.find(npu_id);
    if (npu_it != _npu_info.end()) {
        typename std::remove_reference<decltype(npu_it->second)>::type::iterator vlan_it;
        vlan_it = npu_it->second.find(vlan_id);
        if (vlan_it != npu_it->second.end()) {
            auto& route_list = vlan_it->second.route_list;
            mc_entry_key_t key;
            key.is_xg = is_xg;
            memcpy(&key.dst_ip, &grp_ip, sizeof(grp_ip));
            memcpy(&key.src_ip, &src_ip, sizeof(src_ip));
            key.dst_ip.af_index = af;
            key.src_ip.af_index = af;

            auto mc_rt_it = route_list.find(key);
            if (mc_rt_it != route_list.end()) {
                auto hm_it = mc_rt_it->second.host_member_list.begin();
                while (hm_it != mc_rt_it->second.host_member_list.end()) {
                    if_list.insert(*hm_it);
                    ++hm_it;
                }
                auto rm_it = mc_rt_it->second.router_member_list.begin();
                while (rm_it != mc_rt_it->second.router_member_list.end()) {
                    if_list.insert(*rm_it);
                    ++rm_it;
                }
                route_found = true;
            } else if (!is_xg) {
                /*if port expansion is requested for SG entry, and snoop does not have
                  SG entry route, thne look up (*,G) entry and return (*,G) routes ports. */
                key.is_xg = true;
                mc_rt_it = route_list.find(key);
                if (mc_rt_it != route_list.end()) {
                    auto hm_it = mc_rt_it->second.host_member_list.begin();
                    while (hm_it != mc_rt_it->second.host_member_list.end()) {
                        if_list.insert(*hm_it);
                        ++hm_it;
                    }
                    auto rm_it = mc_rt_it->second.router_member_list.begin();
                    while (rm_it != mc_rt_it->second.router_member_list.end()) {
                        if_list.insert(*rm_it);
                        ++rm_it;
                    }
                    route_found = true;
                }
            }
        }
    }

    /* Flow comes here if snooping is enabled only.
       if route is not found, if snooping enabled for AF and flood resrict enabled, return
       mrouter ports for that AF if any else flood restrict is disabled return error,
       so that calling place all VLAN members are added.*/
    if (!route_found) {
        if (_vlan_config[vlan_id].flood_restr_enabled(npu_id)) {
            // Get mrouter port list if multicast snooping enabled and flood restrict enabled
            NAS_MC_LOG_INFO("NAS-MC-PROC", "Snoop flood restrict enabled on vlan id(%u), return mrouter ports", vlan_id);
            mrouter_port_list_get<false>(npu_id, vlan_id, proto_type, if_list);
        } else {
            NAS_MC_LOG_INFO("NAS-MC-PROC", "Snoop flood restrict disabled on vlan id(%u), VLAN ports to be added", vlan_id);
            return STD_ERR(MCAST, FAIL, 0);
        }
    }else {
        NAS_MC_LOG_INFO("NAS-MC-PROC", "Snooping route found on vlan id(%u), return snooped ports ", vlan_id);
    }

    return STD_ERR_OK;
}

bool nas_mc_snooping::enabled(mc_event_type_t req_type, hal_vlan_id_t vlan_id) const
{
    if (_vlan_config.find(vlan_id) == _vlan_config.end()) {
        return DEFAULT_MC_SNOOPING_ENABLED;
    }

    switch(req_type) {
    case mc_event_type_t::IGMP:
        return _vlan_config.at(vlan_id).igmp_snoop_enabled;
    case mc_event_type_t::MLD:
        return _vlan_config.at(vlan_id).mld_snoop_enabled;
    case mc_event_type_t::IGMP_MLD:
        return _vlan_config.at(vlan_id).igmp_snoop_enabled ||
               _vlan_config.at(vlan_id).mld_snoop_enabled;
    }

    return false;
}

bool nas_mc_snooping::all_ip_enabled(hal_vlan_id_t vlan_id) const
{
    return enabled(mc_event_type_t::IGMP, vlan_id) &&
           enabled(mc_event_type_t::MLD, vlan_id);
}

bool nas_mc_snooping::copy_to_cpu_enabled(mc_event_type_t req_type, npu_id_t npu_id,
                                          hal_vlan_id_t vlan_id) const
{
    std::unique_lock<std::recursive_mutex> lock{_mutex};
    auto npu_itor = _npu_info.find(npu_id);
    if (npu_itor == _npu_info.end()) {
        return false;
    }
    auto vlan_itor = npu_itor->second.find(vlan_id);
    if (vlan_itor == npu_itor->second.end()) {
        return false;
    }

    switch(req_type) {
    case mc_event_type_t::IGMP:
        return vlan_itor->second.ipv4_to_cpu_enabled;
    case mc_event_type_t::MLD:
        return vlan_itor->second.ipv6_to_cpu_enabled;
    case mc_event_type_t::IGMP_MLD:
        return vlan_itor->second.ipv4_to_cpu_enabled && vlan_itor->second.ipv6_to_cpu_enabled;
    }

    return false;
}

void nas_mc_snooping::copy_to_cpu_enabled(mc_event_type_t req_type, npu_id_t npu_id, hal_vlan_id_t vlan_id,
                                          bool enable)
{
    std::unique_lock<std::recursive_mutex> lock{_mutex};
    auto& vlan_cfg = _npu_info[npu_id][vlan_id];
    switch(req_type) {
    case mc_event_type_t::IGMP:
        vlan_cfg.ipv4_to_cpu_enabled = enable;
        break;
    case mc_event_type_t::MLD:
        vlan_cfg.ipv6_to_cpu_enabled = enable;
        break;
    case mc_event_type_t::IGMP_MLD:
        vlan_cfg.ipv4_to_cpu_enabled = vlan_cfg.ipv6_to_cpu_enabled = enable;
        break;
    }
}

t_std_error nas_mc_snooping::delete_vlan_entries(hal_vlan_id_t vlan_id, mc_event_type_t ip_type)
{
    t_std_error rc, ret_val = STD_ERR_OK;

    NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Delete all %s entries of VLAN %d from NPU",
                     ip_type == mc_event_type_t::IGMP_MLD ? "IPv4 and IPv6" :
                                (ip_type == mc_event_type_t::IGMP ? "IPv4" : "IPv6"),
                     vlan_id);
    std::unique_lock<std::recursive_mutex> lock{_mutex};
    std::vector<std::pair<mc_group_info_t*, bool>> del_grp_list{};
    for (auto& npu_info: _npu_info) {
        auto npu_id = npu_info.first;
        auto vlan_it = npu_info.second.find(vlan_id);
        if (vlan_it == npu_info.second.end()) {
            continue;
        }
        del_grp_list.clear();
        auto& route_list = vlan_it->second.route_list;
        for (auto& route_info: route_list) {
            if (!_is_af_match_ip_type(route_info.first.dst_ip.af_index, ip_type)) {
                continue;
            }
            ndi_mcast_entry_t mc_entry{vlan_id,
                                       route_info.first.is_xg ? NAS_NDI_MCAST_ENTRY_TYPE_XG : NAS_NDI_MCAST_ENTRY_TYPE_SG,
                                       route_info.first.dst_ip,
                                       route_info.first.src_ip};
            rc = ndi_mcast_entry_delete(npu_id, &mc_entry);
            if (rc != STD_ERR_OK) {
                NAS_MC_LOG_ERR("NAS-MC-PROC",
                               "Failed to delete multicast entry of %s and VLAN %d",
                               nas_mc_entry_key_tag(route_info.first),
                               vlan_id);
                ret_val = rc;
            }
            del_grp_list.push_back(std::make_pair(route_info.second.group_info.get(),
                                                  route_info.first.copy_to_cpu));
        }

        // For flood-restrict cleanup
        if (_vlan_config.find(vlan_id) != _vlan_config.end() &&
            _vlan_config[vlan_id].flood_restr_enabled(npu_id)) {
            rc = ndi_l2mc_set_flood_restrict(npu_id, vlan_id, NDI_FLOOD_TO_ALL_PORTS, 0);
            if (rc != STD_ERR_OK) {
                NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to disable flood restrict for VLAN %d, rc=%d",
                               vlan_id, rc);
            } else {
                auto grp_id = _vlan_config[vlan_id].flood_restr_grp_id[npu_id];
                auto grp_ptr = mc_group_db.get_group_info(grp_id);
                if (grp_ptr != nullptr) {
                    NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Add flood restrict group 0x%lx to list for delete", grp_id);
                    del_grp_list.push_back(std::make_pair(grp_ptr, false));
                } else {
                    NAS_MC_LOG_ERR("NAS-MC-PROC", "Could not find flood restrict group 0x%lx from cache",
                                   grp_id);
                }
            }
        }

        for (auto& grp_info: del_grp_list) {
            auto grp_ptr = grp_info.first;
            NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Decrement ref count for group %s",
                             grp_ptr->dump_group_info(grp_info.second).c_str());
            grp_ptr->ref_count --;
            if (grp_ptr->ref_count == 0) {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Group ref count becomes 0, delete group");
                for (auto& grp_mbr: grp_ptr->group_member_list) {
                    rc = ndi_l2mc_group_delete_member(npu_id, grp_mbr.second);
                    if (rc != STD_ERR_OK) {
                        NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to delete group member 0x%lx",
                                       grp_mbr.second);
                        ret_val = rc;
                    }
                }

                rc = ndi_l2mc_group_delete(npu_id, grp_ptr->ndi_group_id);
                if (rc != STD_ERR_OK) {
                    NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to delete multicast group");
                    ret_val = rc;
                }

                if (!mc_group_db.delete_group(grp_ptr->ndi_group_id)) {
                    NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to delete group from cache");
                    ret_val = STD_ERR(MCAST, FAIL, 0);
                }
            }
        }
    }

    return ret_val;
}

bool nas_mc_snooping::get_flood_restr_group_update(mc_snooping_msg_t& msg_info,
                                                   hal_vlan_id_t vlan_id, npu_id_t npu_id) const
{
    if (_vlan_config.find(vlan_id) == _vlan_config.end() ||
        !_vlan_config.at(vlan_id).flood_restr_enabled(npu_id)) {
        return true;
    }
    auto restr_grp_id = _vlan_config.at(vlan_id).flood_restr_grp_id.at(npu_id);
    auto grp_ptr = mc_group_db.get_group_info(restr_grp_id);
    if (grp_ptr == nullptr) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "Flood restrict group 0x%lx of VLAN %d not found in DB",
                       restr_grp_id, vlan_id);
        return false;
    }
    auto grp_key = grp_ptr->get_group_key(false);
    std::shared_ptr<mc_group_update_info_t> grp_upd_ptr;
    if (msg_info.group_update_list.find(grp_key) == msg_info.group_update_list.end()) {
        grp_upd_ptr.reset(new mc_group_update_info_t{});
        grp_upd_ptr->orig_group_id = restr_grp_id;
        grp_upd_ptr->copy_to_cpu = false;
        msg_info.group_update_list.insert(
                std::make_pair(grp_key, std::make_pair(grp_upd_ptr, mc_entry_op_list{})));
    } else {
        grp_upd_ptr = msg_info.group_update_list.at(grp_key).first;
    }

    msg_info.flood_restr_update_list[vlan_id][npu_id] = grp_upd_ptr;
    return true;
}

bool nas_mc_snooping::get_route_interface_ndi_info(mc_snooping_msg_t& msg_info) const
{
    if (msg_info.msg_type != mc_msg_type_t::INTERFACE) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "Message type %d is not matched for collect route interface info",
                       static_cast<int>(msg_info.msg_type));
        return false;
    }
    if (msg_info.oper_type != mc_oper_type_t::DELETE) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "Only delete operation is supported for route interface config");
        return false;
    }
    if (msg_info.ifindex == ALL_INTERFACES) {
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "VLAN cleanup for VLAN %d, no need for further processing",
                         msg_info.vlan_id);
        return true;
    }

    if (msg_info.all_vlan) {
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Delete group members of ifindex %d for all VLANs",
                         msg_info.ifindex);
    } else {
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Delete group members of ifindex %d for VLAN %d",
                         msg_info.ifindex, msg_info.vlan_id);
    }
    mc_npu_port_t npu_port;
    t_std_error rc = ifindex_to_npu_port(msg_info.ifindex, npu_port);
    if (rc != STD_ERR_OK) {
         NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to get NPU port for ifindex %d",
                        msg_info.ifindex);
         return false;
    }
    auto npu_it = _npu_info.find(npu_port.npu_id);
    if (npu_it == _npu_info.end()) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "NPU ID %d not found in cache", npu_port.npu_id);
        return false;
    }
    typename std::remove_reference<decltype(npu_it->second)>::type::const_iterator vlan_it;
    if (msg_info.all_vlan) {
        vlan_it = npu_it->second.begin();
    } else {
        vlan_it = npu_it->second.find(msg_info.vlan_id);
    }
    if (vlan_it == npu_it->second.end()) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "VLAN not found in cache");
        return false;
    }

    while (vlan_it != npu_it->second.end()) {
        auto& route_list = vlan_it->second.route_list;
        auto vlan_id = vlan_it->first;
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Handling interface entry cleanup for VLAN %d", vlan_id);
        for (auto& route_info: route_list) {
            auto mbr_it = route_info.second.host_member_list.find(msg_info.ifindex);
            auto rtr_mbr_it = route_info.second.router_member_list.find(msg_info.ifindex);
            if (mbr_it == route_info.second.host_member_list.end() &&
                rtr_mbr_it == route_info.second.router_member_list.end()) {
                // Does not contain specified interface as member
                continue;
            }
            mc_oper_type_t op;
            if (mbr_it != route_info.second.host_member_list.end() &&
                route_info.second.host_member_list.size() == 1) {
                op = mc_oper_type_t::DELETE;
            } else {
                op = mc_oper_type_t::UPDATE;
            }
            mc_entry_op_t entry_op{vlan_id, route_info.first, op};
            auto group_key = route_info.second.group_info->get_group_key(route_info.first.copy_to_cpu);
            std::shared_ptr<mc_group_update_info_t> grp_upd_ptr;
            if (msg_info.group_update_list.find(group_key) == msg_info.group_update_list.end()) {
                grp_upd_ptr.reset(new mc_group_update_info_t{});
                auto& grp_ptr = route_info.second.group_info;
                if (!grp_ptr) {
                    return false;
                }
                grp_upd_ptr->orig_group_id = grp_ptr->ndi_group_id;
                grp_upd_ptr->copy_to_cpu = route_info.first.copy_to_cpu;
                msg_info.group_update_list.insert(std::make_pair(group_key, std::make_pair(grp_upd_ptr,
                                                            mc_entry_op_list{entry_op})));
            } else {
                grp_upd_ptr = msg_info.group_update_list.at(group_key).first;
                msg_info.group_update_list.at(group_key).second.push_back(entry_op);
            }
            msg_info.route_update_list[vlan_id].insert(std::make_pair(route_info.first, grp_upd_ptr));
        }
        if (vlan_it->second.ipv4_mrouter_list.find(msg_info.ifindex) != vlan_it->second.ipv4_mrouter_list.end() ||
            vlan_it->second.ipv6_mrouter_list.find(msg_info.ifindex) != vlan_it->second.ipv6_mrouter_list.end()) {
            // Handle for flood restrict group update
            get_flood_restr_group_update(msg_info, vlan_id, npu_port.npu_id);
        }
        if (msg_info.all_vlan) {
            ++ vlan_it;
        } else {
            break;
        }
    }

    for (auto& grp_upd: msg_info.group_update_list) {
        auto& grp_upd_ptr = grp_upd.second.first;
        size_t old_entry_num = grp_upd.second.second.size();
        size_t new_entry_num = 0;
        for (auto& entry_op: grp_upd.second.second) {
            if (entry_op.op_type != mc_oper_type_t::DELETE) {
                new_entry_num ++;
            }
        }
        if (old_entry_num == 0) {
            // Flood restrict group update
            old_entry_num = new_entry_num = 1;
        }
        if (!mc_group_db.get_group_upd_info(grp_upd.first.vlan_id, msg_info.ifindex, false,
                                            old_entry_num, new_entry_num,
                                            *grp_upd_ptr)) {
            NAS_MC_LOG_ERR("NAS-MC-PROC", "failed to get group update info");
            return false;
        }
    }
    return true;
}

bool nas_mc_snooping::get_copy_to_cpu_ndi_info(mc_snooping_msg_t& msg_info) const
{
    if (msg_info.msg_type != mc_msg_type_t::COPY_TO_CPU) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "Message type %d is not matched for collect route copy to cpu info",
                       static_cast<int>(msg_info.msg_type));
        return false;
    }
    if (msg_info.oper_type != mc_oper_type_t::UPDATE) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "Only update operation is supported for route copy to cpu config");
        return false;
    }

    if (msg_info.all_vlan) {
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Config copy to cpu status for all VLANs",
                         msg_info.ifindex);
    } else {
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Config copy to cpu status for VLAN %d",
                         msg_info.ifindex, msg_info.vlan_id);
    }

    auto npu_id = static_cast<npu_id_t>(msg_info.ifindex);
    auto npu_it = _npu_info.find(npu_id);
    if (npu_it == _npu_info.end()) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "NPU ID %d not found in cache", npu_id);
        return false;
    }
    typename std::remove_reference<decltype(npu_it->second)>::type::const_iterator vlan_it;
    if (msg_info.all_vlan) {
        vlan_it = npu_it->second.begin();
    } else {
        vlan_it = npu_it->second.find(msg_info.vlan_id);
    }
    if (vlan_it == npu_it->second.end()) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "VLAN not found in cache");
        return false;
    }

    while (vlan_it != npu_it->second.end()) {
        auto& route_list = vlan_it->second.route_list;
        auto vlan_id = vlan_it->first;
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Handling copy to cpu config for VLAN %d", vlan_id);
        for (auto& route_info: route_list) {
            if (!msg_info.is_route_match(route_info.first)) {
                continue;
            }
            if (route_info.first.copy_to_cpu == msg_info.enable) {
                continue;
            }
            mc_entry_op_t entry_op{vlan_id, route_info.first, mc_oper_type_t::UPDATE};
            entry_op.entry_key.copy_to_cpu = msg_info.enable;
            auto group_key = route_info.second.group_info->get_group_key(msg_info.enable);
            std::shared_ptr<mc_group_update_info_t> grp_upd_ptr;
            if (msg_info.group_update_list.find(group_key) == msg_info.group_update_list.end()) {
                grp_upd_ptr.reset(new mc_group_update_info_t{});
                auto& grp_ptr = route_info.second.group_info;
                if (!grp_ptr) {
                    return false;
                }
                grp_upd_ptr->orig_group_id = grp_ptr->ndi_group_id;
                grp_upd_ptr->copy_to_cpu = msg_info.enable;
                msg_info.group_update_list.insert(std::make_pair(group_key, std::make_pair(grp_upd_ptr,
                                                            mc_entry_op_list{entry_op})));
            } else {
                grp_upd_ptr = msg_info.group_update_list.at(group_key).first;
                msg_info.group_update_list.at(group_key).second.push_back(entry_op);
            }
            msg_info.route_update_list[vlan_id].insert(std::make_pair(entry_op.entry_key, grp_upd_ptr));
        }
        if (msg_info.all_vlan) {
            ++ vlan_it;
        } else {
            break;
        }
    }

    for (auto& grp_upd: msg_info.group_update_list) {
        auto& grp_upd_ptr = grp_upd.second.first;
        size_t entry_num = grp_upd.second.second.size();
        if (!mc_group_db.get_group_upd_info(grp_upd.first.vlan_id, NULL_INTERFACE, true,
                                            entry_num, entry_num, *grp_upd_ptr)) {
            NAS_MC_LOG_ERR("NAS-MC-PROC", "failed to get group update info");
            return false;
        }
    }

    return true;
}

void nas_mc_snooping::flush(hal_vlan_id_t vlan_id, mc_event_type_t ip_type)
{
    NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Flush all %s entries for VLAN %d",
                     ip_type == mc_event_type_t::IGMP_MLD ? "IGMP and MLD" :
                                (ip_type == mc_event_type_t::IGMP ? "IGMP" : "MLD"),
                     vlan_id);
    std::unique_lock<std::recursive_mutex> lock{_mutex};
    for (auto& npu_info: _npu_info) {
        auto vlan_it = npu_info.second.find(vlan_id);
        if (vlan_it == npu_info.second.end()) {
            continue;
        }
        auto& route_list = vlan_it->second.route_list;
        for (auto ent_it = route_list.begin(); ent_it != route_list.end();) {
            if (_is_af_match_ip_type(ent_it->first.dst_ip.af_index, ip_type)) {
                ent_it = route_list.erase(ent_it);
            } else {
                ent_it ++;
            }
        }
        if (route_list.empty() && !vlan_it->second.ipv4_to_cpu_enabled && ! vlan_it->second.ipv6_to_cpu_enabled) {
            npu_info.second.erase(vlan_it);
        }

        // For VLAN flood restrict cleanup
        _vlan_config[vlan_id].flood_restr_grp_id.erase(npu_info.first);
    }
}

bool nas_mc_snooping::update_needed(const mc_snooping_msg_t& msg_info) const
{
    if (msg_info.oper_type == mc_oper_type_t::STATUS) {
        if (msg_info.all_vlan) {
            NAS_MC_LOG_ERR("NAS-MC-PROC", "ALL-VLANs mode is not supported for status update");
            return false;
        }
        auto itor = _vlan_config.find(msg_info.vlan_id);
        if (itor == _vlan_config.end()) {
            return true;
        }
        if (msg_info.req_type == mc_event_type_t::IGMP_MLD) {
            if (msg_info.enable != itor->second.igmp_snoop_enabled ||
                msg_info.enable != itor->second.mld_snoop_enabled) {
                return true;
            }
        } else {
            bool enabled =
                (msg_info.req_type == mc_event_type_t::IGMP ?
                                        itor->second.igmp_snoop_enabled : itor->second.mld_snoop_enabled);
            if (enabled != msg_info.enable) {
                return true;
            } else {
                // Use duplicate enable/disable as trigger point to dump cache
                NAS_MC_LOG_DEBUG("NAS-MC-PROC", "\n%s\n",
                                 dump_vlan_entries(0, msg_info.vlan_id).c_str());
            }
        }
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "No need to update status in cache , current setting of VLAN %d: IGMP %s MLD %s",
                         itor->first, itor->second.igmp_snoop_enabled ? "Enabled" : "Disabled",
                         itor->second.mld_snoop_enabled ? "Enabled" : "Disabled");
        // Default snoop status is enabled in BASE, so first time when snooping gets enabled.
        // status will be same and no trigger to update HW. So true is returned to trigger
        // update NPU with lookup key.
        return true;
    } else if (msg_info.oper_type == mc_oper_type_t::FLOOD_RESTRICT) {
        if (msg_info.all_vlan) {
            NAS_MC_LOG_ERR("NAS-MC-PROC", "ALL-VLANs mode is not supported for flood restrict update");
            return false;
        }
        if (!all_ip_enabled(msg_info.vlan_id)) {
            NAS_MC_LOG_ERR("NAS-MC-PROC", "IGMP and MLD snooping are not both enabled for VLAN %d", msg_info.vlan_id);
            if (!enabled(mc_event_type_t::IGMP, msg_info.vlan_id)) {
                NAS_MC_LOG_ERR("NAS-MC-PROC", "IGMP snooping is not enabled");
            }
            if (!enabled(mc_event_type_t::MLD, msg_info.vlan_id)) {
                NAS_MC_LOG_ERR("NAS-MC-PROC", "MLD snooping is not enabled");
            }
            return false;
        }
        auto npu_id = static_cast<npu_id_t>(msg_info.ifindex);
        bool enabled;
        if (_vlan_config.find(msg_info.vlan_id) == _vlan_config.end()) {
            enabled = false;
        } else {
            enabled = _vlan_config.at(msg_info.vlan_id).flood_restr_enabled(npu_id);
        }
        if (enabled == msg_info.enable) {
            NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Flood restrict of VLAN %d is already %s, no need to update",
                             msg_info.vlan_id, enabled ? "enabled" : "disabled");
        }
        return enabled != msg_info.enable;
    }

    if (!msg_info.all_vlan && !enabled(msg_info.req_type, msg_info.vlan_id)) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "Mulitcast snooping for VLAN %d was not enabled",
                       msg_info.vlan_id);
        return false;
    }

    if (!msg_info.have_ifindex &&
         msg_info.msg_type != mc_msg_type_t::ROUTE &&
         msg_info.msg_type != mc_msg_type_t::COPY_TO_CPU) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "NULL port is only supported by route or copy-to-cpu config");
        return false;
    }

    if (msg_info.msg_type == mc_msg_type_t::INTERFACE && msg_info.ifindex == ALL_INTERFACES) {
        if (msg_info.oper_type != mc_oper_type_t::DELETE) {
            NAS_MC_LOG_ERR("NAS-MC-PROC",
                           "Only delete is supported for VLAN update handling");
            return false;
        }
        if (msg_info.all_vlan) {
            NAS_MC_LOG_ERR("NAS-MC-PROC",
                           "Specific VLAN ID should be given for VLAN cleanup");
            return false;
        }
        return true;
    }

    if (msg_info.msg_type == mc_msg_type_t::COPY_TO_CPU && msg_info.all_vlan) {
        NAS_MC_LOG_ERR("NAS-MC-PROC",
                       "Enable/disable copy to cpu to all VLANs is not supported");
        return false;
    }

    mc_npu_port_t npu_port;
    if (msg_info.have_ifindex) {
        t_std_error rc = ifindex_to_npu_port(msg_info.ifindex, npu_port);
        if (rc != STD_ERR_OK) {
            NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to get NPU port from ifindex %d",
                           msg_info.ifindex);
            return false;
        }
    } else {
        npu_port = {static_cast<npu_id_t>(msg_info.ifindex), nas_int_type_PORT};
    }
    if (_npu_info.find(npu_port.npu_id) == _npu_info.end()) {
        if (msg_info.oper_type == mc_oper_type_t::ADD) {
            return true;
        } else if (msg_info.oper_type == mc_oper_type_t::DELETE ||
                   msg_info.oper_type == mc_oper_type_t::UPDATE) {
            NAS_MC_LOG_ERR("NAS-MC-PROC", "NPU ID %d not found in cache for delete or update",
                           npu_port.npu_id);
            return false;
        }
    }

    typename std::remove_reference<decltype(_npu_info.at(npu_port.npu_id))>::type::const_iterator itor;
    if (msg_info.all_vlan) {
        itor = _npu_info.at(npu_port.npu_id).begin();
    } else {
        itor = _npu_info.at(npu_port.npu_id).find(msg_info.vlan_id);
    }
    if (itor == _npu_info.at(npu_port.npu_id).end()) {
        if (msg_info.oper_type == mc_oper_type_t::DELETE ||
            msg_info.oper_type == mc_oper_type_t::UPDATE) {
            if (msg_info.all_vlan) {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC", "NPU %d has no VLAN entry for delete or update",
                                 npu_port.npu_id);
            } else {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Entry for VLAN %d not exist for delete or update",
                                 msg_info.vlan_id);
            }
            return false;
        } else {
            return true;
        }
    }

    auto& snp_info = itor->second;
    if (msg_info.msg_type == mc_msg_type_t::MROUTER) {
        auto ipv4_mr_itor = snp_info.ipv4_mrouter_list.find(msg_info.ifindex);
        auto ipv6_mr_itor = snp_info.ipv6_mrouter_list.find(msg_info.ifindex);
        if (msg_info.req_type == mc_event_type_t::IGMP) {
            if ((ipv4_mr_itor == snp_info.ipv4_mrouter_list.end() && msg_info.oper_type == mc_oper_type_t::ADD) ||
                (ipv4_mr_itor != snp_info.ipv4_mrouter_list.end() && msg_info.oper_type == mc_oper_type_t::DELETE)) {
                return true;
            }
        } else if (msg_info.req_type == mc_event_type_t::MLD) {
            if ((ipv6_mr_itor == snp_info.ipv6_mrouter_list.end() && msg_info.oper_type == mc_oper_type_t::ADD) ||
                (ipv6_mr_itor != snp_info.ipv6_mrouter_list.end() && msg_info.oper_type == mc_oper_type_t::DELETE)) {
                return true;
            }
        } else if (msg_info.req_type == mc_event_type_t::IGMP_MLD) {
            if ((ipv4_mr_itor == snp_info.ipv4_mrouter_list.end() && ipv6_mr_itor == snp_info.ipv6_mrouter_list.end() &&
                 msg_info.oper_type == mc_oper_type_t::ADD) ||
                (ipv4_mr_itor != snp_info.ipv4_mrouter_list.end() && ipv6_mr_itor != snp_info.ipv6_mrouter_list.end() &&
                 msg_info.oper_type == mc_oper_type_t::DELETE)) {
                return true;
            }
        }

        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Ifindex %d %s in mrouter list of VLAN %d", msg_info.ifindex,
                         msg_info.oper_type == mc_oper_type_t::ADD ? "already exists" : "not found",
                         itor->first);
    } else if (msg_info.msg_type == mc_msg_type_t::ROUTE){
        if (!_is_af_match_ip_type(msg_info.group_addr.af_index, msg_info.req_type)) {
            NAS_MC_LOG_ERR("NAS-MC-PROC", "Input group address  family %d is not matched with event type %d",
                           msg_info.group_addr.af_index, static_cast<int>(msg_info.req_type));
            return false;
        }
        if (!msg_info.xg_entry && !_is_af_match_ip_type(msg_info.source_addr.af_index, msg_info.req_type)) {
            NAS_MC_LOG_ERR("NAS-MC-PROC", "Input source address  family %d is not matched with event type %d",
                           msg_info.source_addr.af_index, static_cast<int>(msg_info.req_type));
            return false;
        }
        auto rt_itor = snp_info.route_list.find({msg_info.group_addr, msg_info.xg_entry, msg_info.source_addr});
        if (rt_itor == snp_info.route_list.end()) {
            if (msg_info.oper_type == mc_oper_type_t::DELETE) {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Multicast group %s not found for delete",
                                 nas_mc_entry_tag(msg_info.source_addr, msg_info.group_addr, msg_info.xg_entry));
                return false;
            } else {
                return true;
            }
        }
        if (msg_info.have_ifindex) {
            auto& mbr_list = rt_itor->second.host_member_list;
            auto mbr_itor = mbr_list.find(msg_info.ifindex);
            if ((mbr_itor == mbr_list.end() && msg_info.oper_type == mc_oper_type_t::ADD) ||
                (mbr_itor != mbr_list.end() && msg_info.oper_type == mc_oper_type_t::DELETE)) {
                return true;
            } else {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Ifindex %d %s in host member list of VLAN %d group %s",
                                 msg_info.ifindex,
                                 msg_info.oper_type == mc_oper_type_t::ADD ? "already exists" : "not found",
                                 itor->first, nas_mc_ip_to_string(msg_info.group_addr));
            }
        } else {
            // Non-OIF entry
            if ((!rt_itor->second.is_non_oif_entry() && msg_info.oper_type == mc_oper_type_t::ADD) ||
                (rt_itor->second.is_non_oif_entry() && msg_info.oper_type == mc_oper_type_t::DELETE)) {
                return true;
            } else {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC", "No need for non-OIF entry %s for VLAN %d group %s",
                                 msg_info.oper_type == mc_oper_type_t::ADD ? "add" : "delete",
                                 itor->first, nas_mc_ip_to_string(msg_info.group_addr));
            }
        }
    } else if (msg_info.msg_type == mc_msg_type_t::INTERFACE){
        if (msg_info.oper_type != mc_oper_type_t::DELETE) {
            NAS_MC_LOG_ERR("NAS-MC-PROC",
                           "Only delete is supported for interface update handling");
            return false;
        }
        if (!msg_info.have_ifindex || msg_info.ifindex == ALL_INTERFACES) {
            NAS_MC_LOG_ERR("NAS-MC-PROC",
                           "Invalid ifindex given for interface cleanup");
            return false;
        }
        return true;
    } else if (msg_info.msg_type == mc_msg_type_t::COPY_TO_CPU){
        for (auto& route_info: snp_info.route_list) {
            if (!msg_info.is_route_match(route_info.first)) {
                continue;
            }
            if (route_info.first.copy_to_cpu != msg_info.enable) {
                return true;
            }
        }
    } else {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "Unknown message type %d", static_cast<int>(msg_info.msg_type));
        return false;
    }

    NAS_MC_LOG_DEBUG("NAS-MC-PROC", "No need to update mrouter or entry of VLAN %d", itor->first);
    return false;
}

static std::string get_vlan_if_name(hal_vlan_id_t vlan_id)
{
    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl,0,sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_VLAN;
    intf_ctrl.vlan_id = vlan_id;
    intf_ctrl.int_type = nas_int_type_VLAN;

    if(dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK){
        NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to get VLAN interface name from VID %d", vlan_id);
        return std::string{};
    }

    return std::string{intf_ctrl.if_name};
}

static bool trigger_ipmc_vlan_update(hal_vlan_id_t vlan_id, mc_event_type_t req_type)
{
    auto vlan_if_name = get_vlan_if_name(vlan_id);
    if (vlan_if_name.empty()) {
        NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Failed to get interface name for VLAN %d", vlan_id);
        return false;
    }
    NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Calling IPMC VLAN snooping update handler for %s and %s",
                     vlan_if_name.c_str(),
                     req_type == mc_event_type_t::IGMP_MLD ? "IGMP_MLD" :
                                    (req_type == mc_event_type_t::IGMP ? "IGMP" : "MLD"));
    uint32_t af = 0;
    switch(req_type) {
    case mc_event_type_t::IGMP:
        af = AF_INET;
        break;
    case mc_event_type_t::MLD:
        af = AF_INET6;
        break;
    case mc_event_type_t::IGMP_MLD:
        af = AF_MAX;
        break;
    }
    if (mcast_snoop_vlan_update_event_handler(vlan_if_name.c_str(), af) != cps_api_ret_code_OK) {
        NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Failed to call vlan update handler for %s", vlan_if_name.c_str());
        return false;
    }

    return true;
}

static bool trigger_ipmc_route_update(hal_vlan_id_t vlan_id,
                                      const hal_ip_addr_t& grp_ip, bool is_xg, const hal_ip_addr_t& src_ip)
{
    auto vlan_name = get_vlan_if_name(vlan_id);
    if (vlan_name.empty()) {
        return false;
    }
    std::string grp_ip_str{nas_mc_ip_to_string(grp_ip)};
    std::string src_ip_str{nas_mc_ip_to_string(src_ip)};
    NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Calling IPMC route update handler for VLAN %s Group %s Source %s",
                     vlan_name.c_str(), grp_ip_str.c_str(), is_xg ? "*" : src_ip_str.c_str());
    const hal_ip_addr_t* src_ip_p = is_xg ?  nullptr : &src_ip;
    if (mcast_snoop_route_update_event_handler(vlan_name.c_str(), grp_ip.af_index, &grp_ip, src_ip_p) !=
            cps_api_ret_code_OK) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to call route update handler for VLAN %s Group %s Source %s",
                        vlan_name.c_str(), grp_ip_str.c_str(), is_xg ? "*" : src_ip_str.c_str());
        return false;
    }
    return true;
}

bool nas_mc_snooping::update_flood_restr_group(const mc_snooping_msg_t& msg_info,
                                               hal_vlan_id_t vlan_id, npu_id_t npu_id)
{
    if (msg_info.flood_restr_update_list.find(vlan_id) == msg_info.flood_restr_update_list.end()) {
        return true;
    }
    auto& vlan_upd = msg_info.flood_restr_update_list.at(vlan_id);
    if (vlan_upd.find(npu_id) != vlan_upd.end()) {
        auto& upd_ptr = vlan_upd.at(npu_id);
        if (!mc_group_db.update_group(vlan_id, *upd_ptr)) {
            NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Failed to update flood restrict group in DB for mrouter add");
            return false;
        }
        if (upd_ptr->upd_type == CREATE_NEW_GROUP ||
            upd_ptr->upd_type == REPLACE_WITH_EXISTING_GROUP) {
            _vlan_config[vlan_id].flood_restr_grp_id[npu_id] = upd_ptr->new_group_id;
        }
    }
    return true;
}

void nas_mc_snooping::update(const mc_snooping_msg_t& msg_info)
{
    std::unique_lock<std::recursive_mutex> lock{_mutex};
    if (msg_info.oper_type == mc_oper_type_t::STATUS) {
        if (msg_info.req_type == mc_event_type_t::IGMP ||
            msg_info.req_type == mc_event_type_t::IGMP_MLD) {
            _vlan_config[msg_info.vlan_id].igmp_snoop_enabled = msg_info.enable;
        }
        if (msg_info.req_type == mc_event_type_t::MLD ||
            msg_info.req_type == mc_event_type_t::IGMP_MLD) {
            _vlan_config[msg_info.vlan_id].mld_snoop_enabled = msg_info.enable;
        }
    }

    if ((msg_info.oper_type == mc_oper_type_t::STATUS && !msg_info.enable) ||
        (msg_info.msg_type == mc_msg_type_t::INTERFACE && msg_info.ifindex == ALL_INTERFACES)) {
        NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Flush cached %s snooping entries for VLAN %d",
                         msg_info.req_type == mc_event_type_t::IGMP_MLD ? "IGMP and MLD" :
                         (msg_info.req_type == mc_event_type_t::IGMP ? "IGMP" : "MLD"),
                         msg_info.vlan_id);
        flush(msg_info.vlan_id, msg_info.req_type);
    }

    if (msg_info.oper_type == mc_oper_type_t::FLOOD_RESTRICT) {
        npu_id_t npu_id = static_cast<npu_id_t>(msg_info.ifindex);
        auto grp_upd_ptr = msg_info.flood_restr_update_list.at(msg_info.vlan_id).at(npu_id);
        if (grp_upd_ptr != nullptr) {
            if (!mc_group_db.update_group(msg_info.vlan_id, *grp_upd_ptr)) {
                NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Failed to update group DB for route add");
                return;
            }
            if (msg_info.enable) {
                _vlan_config[msg_info.vlan_id].flood_restr_grp_id[npu_id] = grp_upd_ptr->new_group_id;
            } else {
                _vlan_config[msg_info.vlan_id].flood_restr_grp_id.erase(npu_id);
            }
        } else {
            NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "No group update info found for VLAN %d", msg_info.vlan_id);
        }
    }

    if (msg_info.oper_type == mc_oper_type_t::STATUS ||
        msg_info.oper_type == mc_oper_type_t::FLOOD_RESTRICT) {
        trigger_ipmc_vlan_update(msg_info.vlan_id, msg_info.req_type);
        return;
    } else if (msg_info.msg_type == mc_msg_type_t::INTERFACE && msg_info.ifindex == ALL_INTERFACES) {
        return;
    }

    mc_npu_port_t npu_port;
    if (msg_info.have_ifindex) {
        t_std_error rc = ifindex_to_npu_port(msg_info.ifindex, npu_port);
        if (rc != STD_ERR_OK) {
            NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Failed to get NPU port for ifindex %d",
                           msg_info.ifindex);
            return;
        }
    } else {
        npu_port = {static_cast<npu_id_t>(msg_info.ifindex), nas_int_type_PORT};
    }

    if (_npu_info.find(npu_port.npu_id) == _npu_info.end()) {
        // Added slot for new NPU ID
        _npu_info.insert({npu_port.npu_id, mc_snooping_npu_info_t{}});
    }

    typename std::remove_reference<decltype(_npu_info[npu_port.npu_id])>::type::iterator itor;
    if (msg_info.all_vlan) {
        itor = _npu_info[npu_port.npu_id].begin();
    } else {
        itor = _npu_info[npu_port.npu_id].find(msg_info.vlan_id);
    }

    if (msg_info.oper_type != mc_oper_type_t::ADD &&
        itor == _npu_info[npu_port.npu_id].end()) {
        if (msg_info.all_vlan) {
            NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "No VLAN found in cache");
        } else {
            NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Entry for VLAN %d not exist in cache",
                           msg_info.vlan_id);
        }
        return;
    }

    if (msg_info.oper_type == mc_oper_type_t::ADD) {
        if (itor == _npu_info[npu_port.npu_id].end()) {
            _npu_info[npu_port.npu_id][msg_info.vlan_id] = mc_snooping_info_t{};
        }
        auto& snp_info = _npu_info[npu_port.npu_id].at(msg_info.vlan_id);
        if (msg_info.msg_type == mc_msg_type_t::MROUTER) {
            NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Add mrouter ifindex %d to VLAN %d mrouter list",
                             msg_info.ifindex, msg_info.vlan_id);
            if (msg_info.req_type == mc_event_type_t::IGMP || msg_info.req_type == mc_event_type_t::IGMP_MLD) {
                snp_info.ipv4_mrouter_list.insert(msg_info.ifindex);
            }
            if (msg_info.req_type == mc_event_type_t::MLD || msg_info.req_type == mc_event_type_t::IGMP_MLD) {
                snp_info.ipv6_mrouter_list.insert(msg_info.ifindex);
            }

            if (msg_info.route_update_list.find(msg_info.vlan_id) != msg_info.route_update_list.end()) {
                // Add to mrouter interface to multicast entries
                for (auto& rt_info: snp_info.route_list) {
                    auto mrt_itor = msg_info.route_update_list.at(msg_info.vlan_id).find(rt_info.first);
                    if (mrt_itor != msg_info.route_update_list.at(msg_info.vlan_id).end()) {
                        NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Add mrouter interface to multicast entry %s",
                                         nas_mc_entry_key_tag(rt_info.first));
                        if (mrt_itor->second) {
                            // Update group
                            if (!mc_group_db.update_group(msg_info.vlan_id, *mrt_itor->second)) {
                                NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Failed to update group DB for mrouter add");
                                return;
                            }
                            if (mrt_itor->second->upd_type == CREATE_NEW_GROUP ||
                                mrt_itor->second->upd_type == REPLACE_WITH_EXISTING_GROUP) {
                                // Route entry point to new group
                                auto new_grp_ptr = mc_group_db.get_group_ptr(mrt_itor->second->new_group_id);
                                if (!new_grp_ptr) {
                                    NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Group ID %ld is not found in DB",
                                                   mrt_itor->second->new_group_id);
                                    return;
                                }
                                rt_info.second.group_info = new_grp_ptr;
                            }
                            if (!_vlan_config[msg_info.vlan_id].flood_restr_enabled(npu_port.npu_id)) {
                                // If flood-restrict is not enabled for VLAN, just need to update specific L3 route
                                // Other route will use all VLAN members, that will not get impacted by mrouter port
                                // update
                                trigger_ipmc_route_update(msg_info.vlan_id, mrt_itor->first.dst_ip,
                                                          mrt_itor->first.is_xg, mrt_itor->first.src_ip);
                            }
                        }
                        rt_info.second.router_member_list.insert(msg_info.ifindex);
                    }
                }
            } else {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "MRouter add: VLAN %d not found in route update list",
                                 msg_info.vlan_id);
            }

            // Update flood restrict group in cache and notify IPMC
            update_flood_restr_group(msg_info, msg_info.vlan_id, npu_port.npu_id);

            if (_vlan_config[msg_info.vlan_id].flood_restr_enabled(npu_port.npu_id)) {
                // If flood-restrict is enabled for VLAN, need to update all L3 routes that have the VLAN as member
                trigger_ipmc_vlan_update(msg_info.vlan_id, msg_info.req_type);
            }
        } else if (msg_info.msg_type == mc_msg_type_t::ROUTE) {
            mc_entry_key_t entry_key{msg_info.group_addr, msg_info.xg_entry, msg_info.source_addr};
            auto* grp_upd_ptr = msg_info.group_update_info();
            if (grp_upd_ptr != nullptr) {
                entry_key.copy_to_cpu = grp_upd_ptr->copy_to_cpu;
                if (!mc_group_db.update_group(msg_info.vlan_id, *grp_upd_ptr)) {
                    NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Failed to update group DB for route add");
                    return;
                }
                auto rt_itor = snp_info.route_list.find(entry_key);
                if (rt_itor == snp_info.route_list.end()) {
                    NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Add route entry: VLAN %d %s Group ID 0x%" PRIx64,
                                     msg_info.vlan_id,
                                     nas_mc_entry_tag(msg_info.source_addr, msg_info.group_addr, msg_info.xg_entry),
                                     grp_upd_ptr->new_group_id);

                    snp_info.route_list.insert(std::make_pair(entry_key, mc_route_info_t{}));
                    // Add all members for mrouter interface to new multicast entry
                    decltype(snp_info.ipv4_mrouter_list)* mrouter_list_p = nullptr;
                    if (msg_info.req_type == mc_event_type_t::IGMP) {
                        mrouter_list_p = &snp_info.ipv4_mrouter_list;
                    } else {
                        mrouter_list_p = &snp_info.ipv6_mrouter_list;
                    }
                    for (auto mrt_ifindex: *mrouter_list_p) {
                        if (grp_upd_ptr->grp_member_list.find(mrt_ifindex) != grp_upd_ptr->grp_member_list.end()) {
                            NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Add mrouter ifindex %d to route member list",
                                             mrt_ifindex);
                            snp_info.route_list.at(entry_key).router_member_list.insert(mrt_ifindex);
                        }
                    }
                }
            }
            auto& route_info = snp_info.route_list.at(entry_key);
            if (grp_upd_ptr != nullptr) {
                if (grp_upd_ptr->upd_type == CREATE_NEW_GROUP || grp_upd_ptr->upd_type == REPLACE_WITH_EXISTING_GROUP) {
                    // Route entry point to new group
                    auto new_grp_ptr = mc_group_db.get_group_ptr(grp_upd_ptr->new_group_id);
                    if (!new_grp_ptr) {
                        NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Group ID %ld is not found in DB",
                                       grp_upd_ptr->new_group_id);
                        return;
                    }
                    route_info.group_info = new_grp_ptr;
                }
            }
            if (msg_info.have_ifindex) {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Add route member: VLAN %d group %s ifindex %d",
                                 msg_info.vlan_id, nas_mc_entry_tag(msg_info.source_addr,
                                                                   msg_info.group_addr,msg_info.xg_entry),
                                msg_info.ifindex);
                route_info.host_member_list.insert(msg_info.ifindex);
            } else {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Add non-OIF route member: VLAN %d group %s",
                                 msg_info.vlan_id, nas_mc_entry_tag(msg_info.source_addr,
                                                                   msg_info.group_addr,msg_info.xg_entry));
                route_info.host_member_list.insert(NULL_INTERFACE);
            }
            trigger_ipmc_route_update(msg_info.vlan_id, msg_info.group_addr,
                                      msg_info.xg_entry, msg_info.source_addr);
        }
    } else if (msg_info.oper_type == mc_oper_type_t::DELETE) {
        if (msg_info.all_vlan && msg_info.msg_type != mc_msg_type_t::INTERFACE) {
            NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "ALL-VLANs mode is only supported for interface delete");
            return;
        }
        while(itor != _npu_info[npu_port.npu_id].end()) {
            auto vlan_id = itor->first;
            auto& snp_info = itor->second;
            if (msg_info.msg_type == mc_msg_type_t::MROUTER) {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Delete mrouter ifindex %d from VLAN %d mrouter list",
                                 msg_info.ifindex, vlan_id);

                if (msg_info.req_type == mc_event_type_t::IGMP || msg_info.req_type == mc_event_type_t::IGMP_MLD) {
                    snp_info.ipv4_mrouter_list.erase(msg_info.ifindex);
                }
                if (msg_info.req_type == mc_event_type_t::MLD || msg_info.req_type == mc_event_type_t::IGMP_MLD) {
                    snp_info.ipv6_mrouter_list.erase(msg_info.ifindex);
                }

                if (msg_info.route_update_list.find(vlan_id) != msg_info.route_update_list.end()) {
                    // Delete from router member list
                    for (auto& rt_info: snp_info.route_list) {
                        auto mrt_itor = msg_info.route_update_list.at(vlan_id).find(rt_info.first);
                        if (mrt_itor != msg_info.route_update_list.at(vlan_id).end()) {
                            NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Delete mrouter interface from multicast entry %s",
                                             nas_mc_entry_key_tag(rt_info.first));
                            if (mrt_itor->second) {
                                if (!mc_group_db.update_group(vlan_id, *mrt_itor->second)) {
                                    NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Failed to update group DB for mrouter delete");
                                    return;
                                }
                                if (mrt_itor->second->upd_type == CREATE_NEW_GROUP ||
                                    mrt_itor->second->upd_type == REPLACE_WITH_EXISTING_GROUP) {
                                    // Route entry point to new group
                                    auto new_grp_ptr = mc_group_db.get_group_ptr(mrt_itor->second->new_group_id);
                                    if (!new_grp_ptr) {
                                        NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Group ID %ld is not found in DB",
                                                       mrt_itor->second->new_group_id);
                                        return;
                                    }
                                    rt_info.second.group_info = new_grp_ptr;
                                }
                                if (!_vlan_config[vlan_id].flood_restr_enabled(npu_port.npu_id)) {
                                    // If flood-restrict is not enabled for VLAN, just need to update specific L3 route
                                    // Other route will use all VLAN members, that will not get impacted by mrouter port
                                    // update
                                    trigger_ipmc_route_update(vlan_id, mrt_itor->first.dst_ip,
                                                              mrt_itor->first.is_xg, mrt_itor->first.src_ip);
                                }
                            }
                            rt_info.second.router_member_list.erase(msg_info.ifindex);
                        }
                    }
                } else {
                    NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "MRouter delete: VLAN %d not found in route update list",
                                   vlan_id);
                }

                // Update flood restrict group in cache and notify IPMC
                update_flood_restr_group(msg_info, vlan_id, npu_port.npu_id);

                if (_vlan_config[vlan_id].flood_restr_enabled(npu_port.npu_id)) {
                    // If flood-restrict is enabled for VLAN, need to update all L3 routes that have the VLAN as member
                    trigger_ipmc_vlan_update(vlan_id, msg_info.req_type);
                }
            } else if (msg_info.msg_type == mc_msg_type_t::ROUTE) {
                mc_entry_key_t entry_key{msg_info.group_addr, msg_info.xg_entry, msg_info.source_addr};
                auto rt_itor = snp_info.route_list.find(entry_key);
                auto grp_upd_ptr = msg_info.group_update_info();
                if (grp_upd_ptr != nullptr) {
                    if (!mc_group_db.update_group(vlan_id, *grp_upd_ptr)) {
                        NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Failed to update group DB for route delete");
                        return;
                    }
                    if (rt_itor != snp_info.route_list.end()) {
                        if (grp_upd_ptr->upd_type == CREATE_NEW_GROUP ||
                            grp_upd_ptr->upd_type == REPLACE_WITH_EXISTING_GROUP) {
                            // Route entry point to new group
                            auto new_group_id = grp_upd_ptr->new_group_id;
                            if (new_group_id != INVALID_GROUP_ID) {
                                auto new_grp_ptr = mc_group_db.get_group_ptr(new_group_id);
                                if (!new_grp_ptr) {
                                    NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Group ID %ld is not found in DB",
                                                   new_group_id);
                                    return;
                                }
                                rt_itor->second.group_info = new_grp_ptr;
                            } else {
                                rt_itor->second.group_info.reset();
                            }
                        }
                    }
                }
                if (rt_itor != snp_info.route_list.end()) {
                    hal_ifindex_t if_index = msg_info.have_ifindex ? msg_info.ifindex : NULL_INTERFACE;
                    auto& mbr_list = rt_itor->second.host_member_list;
                    NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Delete route member: VLAN %d group %s port %d",
                                     vlan_id, nas_mc_ip_to_string(msg_info.group_addr),
                                     if_index);
                    mbr_list.erase(if_index);
                    if (mbr_list.empty()) {
                        // If all members deleted, route entry will also be deleted
                        NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Delete empty route entry: VLAN %d group %s",
                                         vlan_id, nas_mc_ip_to_string(msg_info.group_addr));
                        snp_info.route_list.erase(rt_itor);
                        rt_itor = snp_info.route_list.end();
                    }
                    trigger_ipmc_route_update(vlan_id, msg_info.group_addr,
                                              msg_info.xg_entry, msg_info.source_addr);
                }
            } else if (msg_info.msg_type == mc_msg_type_t::INTERFACE) {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Delete ifindex %d from VLAN %d mrouter and route list",
                                 msg_info.ifindex, vlan_id);
                if (snp_info.ipv4_mrouter_list.find(msg_info.ifindex) != snp_info.ipv4_mrouter_list.end()) {
                    snp_info.ipv4_mrouter_list.erase(msg_info.ifindex);
                }
                if (snp_info.ipv6_mrouter_list.find(msg_info.ifindex) != snp_info.ipv6_mrouter_list.end()) {
                    snp_info.ipv6_mrouter_list.erase(msg_info.ifindex);
                }

                if (msg_info.route_update_list.find(vlan_id) != msg_info.route_update_list.end()) {

                    // Delete from router member list
                    for (auto it = snp_info.route_list.begin(); it != snp_info.route_list.end();) {
                        auto mrt_itor = msg_info.route_update_list.at(vlan_id).find(it->first);
                        if (mrt_itor != msg_info.route_update_list.at(vlan_id).end()) {
                            NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Delete interface from multicast entry %s",
                                             nas_mc_entry_key_tag(it->first));
                            if (mrt_itor->second) {
                                if (!mc_group_db.update_group(vlan_id, *mrt_itor->second)) {
                                    NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Failed to update group DB for route interface delete");
                                    return;
                                }
                                if ((mrt_itor->second->upd_type == CREATE_NEW_GROUP ||
                                    mrt_itor->second->upd_type == REPLACE_WITH_EXISTING_GROUP) &&
                                        mrt_itor->second->new_group_id != INVALID_GROUP_ID) {
                                    // Route entry point to new group
                                    auto new_grp_ptr = mc_group_db.get_group_ptr(mrt_itor->second->new_group_id);
                                    if (!new_grp_ptr) {
                                        NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Group ID %ld is not found in DB",
                                                       mrt_itor->second->new_group_id);
                                        return;
                                    }
                                    it->second.group_info = new_grp_ptr;
                                }
                            }
                        }

                        auto mr_it = it->second.router_member_list.find(msg_info.ifindex);
                        if (mr_it != it->second.router_member_list.end()) {
                            NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Remove mrouter interface from multicast entry %s",
                                             nas_mc_entry_key_tag(it->first));
                            it->second.router_member_list.erase(mr_it);
                        }
                        if (!it->second.host_member_list.empty()) {
                            auto hst_it = it->second.host_member_list.find(msg_info.ifindex);
                            if (hst_it != it->second.host_member_list.end()) {
                                NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Remove host interface from multicast entry %s",
                                                 nas_mc_entry_key_tag(it->first));
                                it->second.host_member_list.erase(hst_it);
                            }
                            if (it->second.host_member_list.empty()) {
                                // If all members deleted, route entry will also be deleted
                                it = snp_info.route_list.erase(it);
                            } else {
                                ++it;
                            }
                        } else {
                            /* non-OIF entry */
                            ++it;
                        }
                    }
                }
                update_flood_restr_group(msg_info, vlan_id, npu_port.npu_id);
            }
            if (snp_info.ipv4_mrouter_list.empty() && snp_info.ipv6_mrouter_list.empty() && snp_info.route_list.empty()
                && !snp_info.ipv4_to_cpu_enabled && !snp_info.ipv6_to_cpu_enabled) {
                // If there is no mrouter, no copy_to_cpu  and route entry left for VLAN, VLAN unit
                // will be deleted
                NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Delete empty multicast unit for VLAN %d",
                                 vlan_id);
                itor = _npu_info[npu_port.npu_id].erase(itor);
            } else {
                ++ itor;
            }
            if (!msg_info.all_vlan) {
                break;
            }
        }
    } else if (msg_info.oper_type == mc_oper_type_t::UPDATE) {
        if (msg_info.msg_type != mc_msg_type_t::COPY_TO_CPU) {
            NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Only copy to cpu status config is allowed for UPDATE type");
            return;
        }
        for (auto& vlan_upd: msg_info.route_update_list) {
            auto vlan_id = vlan_upd.first;
            for (auto& entry_upd: vlan_upd.second) {
                auto route_itor = _npu_info[npu_port.npu_id][vlan_id].route_list.find(entry_upd.first);
                if (route_itor != _npu_info[npu_port.npu_id][vlan_id].route_list.end()) {
                    route_itor->first.copy_to_cpu = entry_upd.first.copy_to_cpu;
                    mc_group_db.update_group(vlan_id, *entry_upd.second);
                    if (entry_upd.second->upd_type == CREATE_NEW_GROUP ||
                        entry_upd.second->upd_type == REPLACE_WITH_EXISTING_GROUP) {
                        // Route entry point to new group
                        auto new_grp_ptr = mc_group_db.get_group_ptr(entry_upd.second->new_group_id);
                        if (!new_grp_ptr) {
                            NAS_MC_LOG_ERR("NAS-MC-PROC-CACHE", "Group ID %ld is not found in DB",
                                           entry_upd.second->new_group_id);
                            return;
                        }
                        route_itor->second.group_info = new_grp_ptr;
                    }
                }
            }
            /* On DELETE event vlan info erase was skipped if copy_to_cpu was enabled. Now check and delete */
            auto _snoop_itr = _npu_info[npu_port.npu_id].find(vlan_id);
            if (_snoop_itr != _npu_info[npu_port.npu_id].end()) {
                auto _vlan_info = _snoop_itr->second;
                if (_vlan_info.ipv4_mrouter_list.empty() && _vlan_info.ipv6_mrouter_list.empty() &&
                    _vlan_info.route_list.empty() && !_vlan_info.ipv4_to_cpu_enabled && !_vlan_info.ipv6_to_cpu_enabled) {
                    // If there is no mrouter, no copy_to_cpu  and route entry left for VLAN, VLAN unit
                    // will be deleted
                    NAS_MC_LOG_DEBUG("NAS-MC-PROC-CACHE", "Delete empty multicast unit for VLAN %d, copy_to_cpu update",
                                     vlan_id);
                    _npu_info[npu_port.npu_id].erase(_snoop_itr);
                }
            }
        }
    }
}

bool nas_mc_snooping::flood_restr_group_update_needed(bool is_add, npu_id_t npu_id, hal_vlan_id_t vlan_id,
                                                      hal_ifindex_t ifindex) const
{
    bool is_igmp_mrt = false, is_mld_mrt = false;
    auto npu_it = _npu_info.find(npu_id);
    if (npu_it != _npu_info.end()) {
        auto vlan_it = npu_it->second.find(vlan_id);
        if (vlan_it != npu_it->second.end()) {
            is_igmp_mrt = (vlan_it->second.ipv4_mrouter_list.find(ifindex) != vlan_it->second.ipv4_mrouter_list.end());
            is_mld_mrt = (vlan_it->second.ipv6_mrouter_list.find(ifindex) != vlan_it->second.ipv6_mrouter_list.end());
        }
    }
    if ((is_add && (is_igmp_mrt || is_mld_mrt)) ||
        (!is_add && (is_igmp_mrt && is_mld_mrt))) {
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Flood restrict group update is not needed: %s intf %d is %s mrouter for VLAN %d",
                         is_add ? "add" : "delete", ifindex,
                         (is_igmp_mrt && is_mld_mrt) ?
                            "IGMP and MLD" : (is_igmp_mrt ? "IGMP" : (is_mld_mrt ? "MLD" : "not")), vlan_id);
        return false;
    }
    return true;
}

bool nas_mc_snooping::get_mrouter_ndi_info(mc_snooping_msg_t& msg_info) const
{
    if (msg_info.msg_type != mc_msg_type_t::MROUTER) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "Message type %d is not matched for collect mrouter info",
                       static_cast<int>(msg_info.msg_type));
        return false;
    }
    mc_npu_port_t npu_port;
    t_std_error rc = ifindex_to_npu_port(msg_info.ifindex, npu_port);
    if (rc != STD_ERR_OK) {
         NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to get NPU port for ifindex %d",
                        msg_info.ifindex);
         return false;
    }
    if (_npu_info.find(npu_port.npu_id) != _npu_info.end()) {
        auto itor = _npu_info.at(npu_port.npu_id).find(msg_info.vlan_id);
        if (itor != _npu_info.at(npu_port.npu_id).end()) {
            for (auto& route_info: _npu_info.at(npu_port.npu_id).at(msg_info.vlan_id).route_list) {
                if (!_is_af_match_ip_type(route_info.first.dst_ip.af_index, msg_info.req_type)) {
                    continue;
                }
                auto hst_itor = route_info.second.host_member_list.find(msg_info.ifindex);
                if (hst_itor != route_info.second.host_member_list.end()) {
                    // mrouter interface is also host member, no need to update NPU
                    msg_info.route_update_list[msg_info.vlan_id].insert(std::make_pair(route_info.first,
                                                    std::shared_ptr<mc_group_update_info_t>{}));
                    continue;
                }
                auto group_key = route_info.second.group_info->get_group_key(route_info.first.copy_to_cpu);
                mc_entry_op_t entry_op{msg_info.vlan_id, route_info.first, mc_oper_type_t::UPDATE};
                std::shared_ptr<mc_group_update_info_t> grp_upd_ptr;
                if (msg_info.group_update_list.find(group_key) == msg_info.group_update_list.end()) {
                    grp_upd_ptr.reset(new mc_group_update_info_t{});
                    grp_upd_ptr->orig_group_id = route_info.second.group_info->ndi_group_id;
                    grp_upd_ptr->copy_to_cpu = route_info.first.copy_to_cpu;
                    msg_info.group_update_list.insert(std::make_pair(group_key, std::make_pair(grp_upd_ptr,
                                                                mc_entry_op_list{entry_op})));
                } else {
                    grp_upd_ptr = msg_info.group_update_list.at(group_key).first;
                    msg_info.group_update_list.at(group_key).second.push_back(entry_op);
                }
                msg_info.route_update_list[msg_info.vlan_id].insert(std::make_pair(route_info.first, grp_upd_ptr));
            }
        }
    }

    bool is_add = (msg_info.oper_type == mc_oper_type_t::ADD);
    if (flood_restr_group_update_needed(is_add, npu_port.npu_id, msg_info.vlan_id, msg_info.ifindex)) {
        // For flood restrict group update
        get_flood_restr_group_update(msg_info, msg_info.vlan_id, npu_port.npu_id);
    }

    for (auto& grp_upd: msg_info.group_update_list) {
        auto& grp_upd_ptr = grp_upd.second.first;
        size_t entry_num = grp_upd.second.second.size();
        if (entry_num == 0) {
            // Flood restrict group update
            entry_num = 1;
        }
        if (!mc_group_db.get_group_upd_info(msg_info.vlan_id, msg_info.ifindex, is_add, entry_num, entry_num,
                                            *grp_upd_ptr)) {
            NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to get group update info");
            return false;
        }
    }

    return true;
}

static inline nas_mc_snooping& cache()
{
    return nas_mc_snooping::get_instance();
}

static const bool group_key_check_vlan()
{
    return cache().vlan_in_group_key();
}

bool nas_mc_snooping::get_route_ndi_info(mc_snooping_msg_t& msg_info) const
{
    bool last_host_member = false, entry_exist = false;
    if (msg_info.msg_type != mc_msg_type_t::ROUTE) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "Message type %d is not matched for collect route info",
                       static_cast<int>(msg_info.msg_type));
        return false;
    }

    mc_npu_port_t npu_port;
    if (msg_info.have_ifindex) {
        t_std_error rc = ifindex_to_npu_port(msg_info.ifindex, npu_port);
        if (rc != STD_ERR_OK) {
            NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to get NPU port for ifindex %d",
                           msg_info.ifindex);
            return false;
        }
    } else {
        npu_port = {static_cast<npu_id_t>(msg_info.ifindex), nas_int_type_PORT};
    }

    auto copy_to_cpu = cache().copy_to_cpu_enabled(msg_info.req_type, npu_port.npu_id, msg_info.vlan_id);
    mc_entry_key_t entry_key{msg_info.group_addr, msg_info.xg_entry, msg_info.source_addr, copy_to_cpu};
    std::shared_ptr<mc_group_update_info_t> grp_upd_ptr{new mc_group_update_info_t{}};
    grp_upd_ptr->orig_group_id = INVALID_GROUP_ID;
    grp_upd_ptr->copy_to_cpu = copy_to_cpu;

    if (_npu_info.find(npu_port.npu_id) != _npu_info.end()) {
        auto itor = _npu_info.at(npu_port.npu_id).find(msg_info.vlan_id);
        if (itor != _npu_info.at(npu_port.npu_id).end()) {
            auto grp_itor = itor->second.route_list.find(entry_key);
            if (grp_itor == itor->second.route_list.end()) {
                // Entry not found in cache
                entry_exist = false;
                if (msg_info.oper_type == mc_oper_type_t::ADD) {
                    // Add all mrouter interfaces to list for new multicast entry
                    const decltype(itor->second.ipv4_mrouter_list)* mrouter_list_p = nullptr;
                    if (msg_info.req_type == mc_event_type_t::IGMP) {
                        mrouter_list_p = &itor->second.ipv4_mrouter_list;
                    } else {
                        mrouter_list_p = &itor->second.ipv6_mrouter_list;
                    }
                    for (auto rt_ifindex: *mrouter_list_p) {
                        grp_upd_ptr->grp_member_list.insert(std::make_pair(rt_ifindex, 0));
                    }
                }
            } else {
                // Entry found in cache
                entry_exist = true;
                bool bypass_grp_upd = false;
                if (msg_info.have_ifindex) {
                    auto mrt_itor = grp_itor->second.router_member_list.find(msg_info.ifindex);
                    if (mrt_itor != grp_itor->second.router_member_list.end()) {
                        // Group member already in mrouter list
                        bypass_grp_upd = true;
                    }
                } else {
                    if (msg_info.oper_type == mc_oper_type_t::ADD) {
                        // Add non-OIF member to existing route entry
                        bypass_grp_upd = true;
                    }
                }
                auto& grp_ptr = grp_itor->second.group_info;
                if (!grp_ptr) {
                    return false;
                }
                grp_upd_ptr->orig_group_id = grp_ptr->ndi_group_id;
                if (grp_itor->second.host_member_list.size() > 1) {
                    last_host_member = false;
                } else {
                    last_host_member = true;
                }
                if (bypass_grp_upd && !(msg_info.oper_type == mc_oper_type_t::DELETE && last_host_member)) {
                    NAS_MC_LOG_DEBUG("NAS-MC-PROC", "No need to update group cache");
                    msg_info.route_update_list[msg_info.vlan_id].insert(
                            std::make_pair(entry_key, std::shared_ptr<mc_group_update_info_t>{}));
                    return true;
                }
            }
        }
    }
    mc_oper_type_t entry_op;
    size_t new_entry_num;
    if (msg_info.oper_type == mc_oper_type_t::DELETE && last_host_member) {
        entry_op = mc_oper_type_t::DELETE;
        new_entry_num = 0;
    } else {
        new_entry_num = 1;
        if (msg_info.oper_type == mc_oper_type_t::ADD && !entry_exist) {
            entry_op = mc_oper_type_t::ADD;
        } else {
            entry_op = mc_oper_type_t::UPDATE;
        }
    }
    if (!mc_group_db.get_group_upd_info(msg_info.vlan_id,
                                        msg_info.have_ifindex ? msg_info.ifindex : NULL_INTERFACE,
                                        msg_info.oper_type == mc_oper_type_t::ADD,
                                        1, new_entry_num, *grp_upd_ptr)) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "failed to get group update info");
        return false;
    }
    msg_info.route_update_list[msg_info.vlan_id].insert(std::make_pair(entry_key, grp_upd_ptr));
    mc_entry_op_list entry_list{mc_entry_op_t{msg_info.vlan_id, entry_key, entry_op}};
    msg_info.group_update_list.insert(std::make_pair(mc_group_key_t{msg_info.vlan_id, std::set<hal_ifindex_t>{}, entry_key.copy_to_cpu},
                                    std::make_pair(grp_upd_ptr, entry_list)));
    return true;
}

bool nas_mc_snooping::get_flood_restr_ndi_info(mc_snooping_msg_t& msg_info) const
{
    if (msg_info.oper_type != mc_oper_type_t::FLOOD_RESTRICT) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "Operation type %d is not matched for collect flood-restrict info",
                       static_cast<int>(msg_info.oper_type));
        return false;
    }
    std::shared_ptr<mc_group_update_info_t> grp_upd_ptr{new mc_group_update_info_t{}};
    grp_upd_ptr->copy_to_cpu = false;
    npu_id_t npu_id = static_cast<npu_id_t>(msg_info.ifindex);
    size_t new_entry_num;
    if (msg_info.enable) {
        grp_upd_ptr->orig_group_id = INVALID_GROUP_ID;
        new_entry_num = 1;
        // Get all mrouter ports
        mrouter_port_list_get<true>(npu_id, msg_info.vlan_id, mc_event_type_t::IGMP_MLD, grp_upd_ptr->grp_member_list);
    } else {
        auto cfg_itor = _vlan_config.find(msg_info.vlan_id);
        if (cfg_itor == _vlan_config.end()) {
            NAS_MC_LOG_ERR("NAS-MC-PROC", "Could not find config info for VLAN %d", msg_info.vlan_id);
            return false;
        }
        grp_upd_ptr->orig_group_id = cfg_itor->second.flood_restr_grp_id.at(npu_id);
        new_entry_num = 0;
    }
    if (!mc_group_db.get_group_upd_info(msg_info.vlan_id, NULL_INTERFACE, msg_info.enable, 1, new_entry_num,
                                        *grp_upd_ptr)) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "failed to get group update info for flood restrict config");
        return false;
    }
    msg_info.group_update_list.insert(std::make_pair(mc_group_key_t{msg_info.vlan_id, std::set<hal_ifindex_t>{}, false},
                                    std::make_pair(grp_upd_ptr, mc_entry_op_list{})));
    msg_info.flood_restr_update_list[msg_info.vlan_id][npu_id] = grp_upd_ptr;
    return true;
}

std::string nas_mc_snooping::dump_vlan_entries(npu_id_t npu_id, hal_vlan_id_t vlan_id) const
{
    auto itor = _npu_info.find(npu_id);
    if (itor == _npu_info.end()) {
        itor = _npu_info.begin();
        if (itor == _npu_info.end()) {
            return "";
        } else {
            NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Use NPU %d instead of default NPU", itor->first);
        }
    }
    auto vlan_itor = itor->second.find(vlan_id);
    if (vlan_itor == itor->second.end()) {
        return "";
    }
    auto& snp_info = vlan_itor->second;
    std::ostringstream ss;
    ss << "---------------------------------------" << std::endl;
    ss << "     Cache of VLAN " << vlan_itor->first << std::endl;
    ss << "---------------------------------------" << std::endl;
    ss << " ipv4 mrouters: ";
    for (auto ifindex: snp_info.ipv4_mrouter_list) {
        ss << ifindex << " ";
    }
    ss << std::endl;
    ss << " ipv6 mrouters: ";
    for (auto ifindex: snp_info.ipv6_mrouter_list) {
        ss << ifindex << " ";
    }
    ss << std::endl;
    ss << " entries:" << std::endl;
    for (auto& route_info: snp_info.route_list) {
        ss << "  " << nas_mc_entry_key_tag(route_info.first) << " ==> R:{";
        for (auto mbr_ifindex: route_info.second.router_member_list) {
            ss << mbr_ifindex << " ";
        }
        ss << "} H:{";
        for (auto& mbr_ifindex: route_info.second.host_member_list) {
            ss << mbr_ifindex << " ";
        }
        ss << "}";
        ss << std::endl;
    }
    return ss.str();
}

void nas_mc_snooping::get_route_entries(mc_snooping_msg_t& msg_info) const
{
    npu_id_t npu_id = static_cast<npu_id_t>(msg_info.ifindex);
    auto npu_it = _npu_info.find(npu_id);
    if (npu_it == _npu_info.end()) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "NPU ID %d not found in cache", npu_id);
        return;
    }
    typename std::remove_reference<decltype(npu_it->second)>::type::const_iterator vlan_it;
    if (msg_info.all_vlan) {
        vlan_it = npu_it->second.begin();
    } else {
        vlan_it = npu_it->second.find(msg_info.vlan_id);
    }
    if (vlan_it == npu_it->second.end()) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "VLAN not found in cache");
        return;
    }

    while (vlan_it != npu_it->second.end()) {
        auto& route_list = vlan_it->second.route_list;
        auto vlan_id = vlan_it->first;
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Get route entries for VLAN %d", vlan_id);
        for (auto& route_info: route_list) {
            if (!msg_info.is_route_match(route_info.first)) {
                continue;
            }
            std::shared_ptr<mc_group_update_info_t> grp_ptr{new mc_group_update_info_t{}};
            for (auto ifindex: route_info.second.router_member_list) {
                grp_ptr->grp_member_list.insert(std::make_pair(ifindex, ENTRY_MROUTER_MEMBER));
            }
            for (auto ifindex: route_info.second.host_member_list) {
                if (grp_ptr->grp_member_list.find(ifindex) == grp_ptr->grp_member_list.end()) {
                    grp_ptr->grp_member_list.insert(std::make_pair(ifindex, ENTRY_HOST_MEMBER));
                } else {
                    grp_ptr->grp_member_list[ifindex] = ENTRY_MROUTER_AND_HOST_MEMBER;
                }
            }
            msg_info.route_update_list[vlan_id].insert(std::make_pair(route_info.first, grp_ptr));
        }
        if (msg_info.all_vlan) {
            ++ vlan_it;
        } else {
            break;
        }
    }
}

void nas_mc_snooping::get_mrouter_intfs(mc_snooping_msg_t& msg_info) const
{
    npu_id_t npu_id = static_cast<npu_id_t>(msg_info.ifindex);
    auto npu_it = _npu_info.find(npu_id);
    if (npu_it == _npu_info.end()) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "NPU ID %d not found in cache", npu_id);
        return;
    }
    typename std::remove_reference<decltype(npu_it->second)>::type::const_iterator vlan_it;
    if (msg_info.all_vlan) {
        vlan_it = npu_it->second.begin();
    } else {
        vlan_it = npu_it->second.find(msg_info.vlan_id);
    }
    if (vlan_it == npu_it->second.end()) {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "VLAN not found in cache");
        return;
    }

    while (vlan_it != npu_it->second.end()) {
        mc_entry_key_t entry_key;
        auto vlan_id = vlan_it->first;
        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Get mrouter ports for VLAN %d", vlan_id);
        std::vector<uint32_t> af_list;
        if (msg_info.req_type == mc_event_type_t::IGMP || msg_info.req_type == mc_event_type_t::IGMP_MLD) {
            af_list.push_back(AF_INET);
        }
        if (msg_info.req_type == mc_event_type_t::MLD || msg_info.req_type == mc_event_type_t::IGMP_MLD) {
            af_list.push_back(AF_INET6);
        }
        for (auto af: af_list) {
            std::shared_ptr<mc_group_update_info_t> grp_ptr{new mc_group_update_info_t{}};
            entry_key.dst_ip.af_index = af;
            if (af == AF_INET) {
                std::for_each(vlan_it->second.ipv4_mrouter_list.begin(), vlan_it->second.ipv4_mrouter_list.end(),
                              [&grp_ptr](hal_ifindex_t ifidx){grp_ptr->grp_member_list.insert(std::make_pair(ifidx, 0));});
            } else {
                std::for_each(vlan_it->second.ipv6_mrouter_list.begin(), vlan_it->second.ipv6_mrouter_list.end(),
                              [&grp_ptr](hal_ifindex_t ifidx){grp_ptr->grp_member_list.insert(std::make_pair(ifidx, 0));});
            }
            msg_info.route_update_list[vlan_id].insert(std::make_pair(entry_key, grp_ptr));
        }
        if (msg_info.all_vlan) {
            ++ vlan_it;
        } else {
            break;
        }
    }
}

void nas_mc_snooping::get_flood_restr_status(npu_id_t npu_id, bool all_vlan, hal_vlan_id_t vlan_id,
                                             mc_flood_restr_status_t& vlan_status) const
{
    std::unique_lock<std::recursive_mutex> lock{_mutex};

    typename std::remove_reference<decltype(_vlan_config)>::type::const_iterator itor;
    if (all_vlan) {
        itor = _vlan_config.begin();
    } else {
        itor = _vlan_config.find(vlan_id);
    }
    while(itor != _vlan_config.end()) {
        vlan_status[itor->first] = itor->second.flood_restr_enabled(npu_id);
        if (all_vlan) {
            itor ++;
        } else {
            break;
        }
    }
}

bool nas_mc_snooping::get_entry_group_id(npu_id_t npu_id, hal_vlan_id_t vlan_id,
                                         const mc_entry_key_t& entry_key,
                                         ndi_obj_id_t& grp_id) const
{
    if (_npu_info.find(npu_id) == _npu_info.end()) {
        NAS_MC_LOG_ERR("NAS-MC-ENTRY-GET", "NPU ID %d not found in cache", npu_id);
        return false;
    }
    auto& vlan_route = _npu_info.at(npu_id);
    if (vlan_route.find(vlan_id) == vlan_route.end()) {
        NAS_MC_LOG_ERR("NAS-MC-ENTRY-GET", "VLAN ID %d not found in cache", vlan_id);
        return false;
    }
    auto& entry_list = vlan_route.at(vlan_id).route_list;
    if (entry_list.find(entry_key) == entry_list.end()) {
        NAS_MC_LOG_ERR("NAS-MC-ENTRY-GET", "Entry %s of VLAN %d not found in cache",
                       std::string(entry_key).c_str(), vlan_id);
        return false;
    }
    grp_id = entry_list.at(entry_key).group_info->ndi_group_id;
    return true;
}

static t_std_error nas_mc_npu_add_group_member(ndi_obj_id_t group_id, const mc_npu_port_t& npu_port,
                                               ndi_obj_id_t& member_id)
{
    if (npu_port.port_type == nas_int_type_LAG) {
        return ndi_l2mc_group_add_lag_member(npu_port.npu_id, group_id, npu_port.lag_id,
                                             &member_id);
    } else if (npu_port.port_type == nas_int_type_VLAN) {
        // TODO: currently not supported
        return STD_ERR_OK;
    } else {
        return ndi_l2mc_group_add_port_member(npu_port.npu_id, group_id, npu_port.port_id,
                                              &member_id);
    }
}

static t_std_error update_entry_group_hw(npu_id_t npu_id,
                                         const mc_entry_op_list& entry_op_list,
                                         mc_group_update_info_t& grp_upd_info, bool is_add)
{
    uint32_t update_type = grp_upd_info.upd_type & ~DELETE_OLD_GROUP;
    NAS_MC_LOG_DEBUG("NAS-MC-PROC-HW", "Update group for NPU %d:", npu_id);
    NAS_MC_LOG_DEBUG("NAS-MC-PROC-HW", "%s", grp_upd_info.dump_update_info().c_str());
    t_std_error rc = STD_ERR_OK;
    if (update_type == UPDATE_CURRENT_GROUP) {
        grp_upd_info.new_group_id = grp_upd_info.orig_group_id;
    }
    if (update_type == CREATE_NEW_GROUP) {
        rc = ndi_l2mc_group_create(npu_id, &grp_upd_info.new_group_id);
        if (rc != STD_ERR_OK) {
            NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to create new multicast group, rc=%d", rc);
            return rc;
        }
        NAS_MC_LOG_DEBUG("NAS-MC-PROC-HW", "Created new group with ID 0x%lx", grp_upd_info.new_group_id);
        // for new group create, always add memeber
        is_add = true;
    }
    mc_npu_port_t npu_port;
    if (update_type == CREATE_NEW_GROUP || update_type == UPDATE_CURRENT_GROUP) {
        for (auto& grp_mbr: grp_upd_info.grp_member_list) {
            rc = ifindex_to_npu_port(grp_mbr.first, npu_port);
            if (rc != STD_ERR_OK) {
                NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to convert ifindex %d to NPU port", grp_mbr.first);
                return rc;
            }
            if (is_add) {
                rc = nas_mc_npu_add_group_member(grp_upd_info.new_group_id, npu_port, grp_mbr.second);
            } else {
                rc = ndi_l2mc_group_delete_member(npu_id, grp_mbr.second);
            }
            if (rc != STD_ERR_OK) {
                NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to %s multicast group member for ifindex %d, rc=%d",
                               is_add ? "add" : "delete", grp_mbr.first, rc);
                return rc;
            }
        }
    }

    for (auto& entry_op: entry_op_list) {
        NAS_MC_LOG_DEBUG("NAS-MC-PROC-HW", "Update entry VLAN %d %s, op=%d",
                         entry_op.vlan_id, nas_mc_entry_key_tag(entry_op.entry_key),
                         static_cast<int>(entry_op.op_type));
        ndi_mcast_entry_t mc_entry{entry_op.vlan_id,
                                   entry_op.entry_key.is_xg ? NAS_NDI_MCAST_ENTRY_TYPE_XG : NAS_NDI_MCAST_ENTRY_TYPE_SG,
                                   entry_op.entry_key.dst_ip, entry_op.entry_key.src_ip};
        if (grp_upd_info.new_group_id != INVALID_GROUP_ID) {
            NAS_MC_LOG_DEBUG("NAS-MC-PROC-HW", "Use new group ID 0x%lx", grp_upd_info.new_group_id);
            mc_entry.group_id = grp_upd_info.new_group_id;
        }
        mc_entry.copy_to_cpu = grp_upd_info.copy_to_cpu;
        switch (entry_op.op_type) {
        case mc_oper_type_t::ADD:
            rc = ndi_mcast_entry_create(npu_id, &mc_entry);
            break;
        case mc_oper_type_t::UPDATE:
            if (update_type != UPDATE_CURRENT_GROUP) {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC-HW", "Update mc entry group ID to 0x%lx",
                                 mc_entry.group_id);
                rc = ndi_mcast_entry_update(npu_id, &mc_entry, NAS_NDI_MCAST_UPD_GRP);
                if (rc != STD_ERR_OK) {
                    NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to update entry group ID");
                    return rc;
                }
            }
            if (grp_upd_info.grp_member_list.empty()) {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC-HW", "Update mc entry copy to cpu status to %d",
                                 mc_entry.copy_to_cpu);
                rc = ndi_mcast_entry_update(npu_id, &mc_entry, NAS_NDI_MCAST_UPD_COPY_TO_CPU);
                if (rc != STD_ERR_OK) {
                    NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to update entry copy-to-cpu status");
                    return rc;
                }
            }
            break;
        case mc_oper_type_t::DELETE:
            rc = ndi_mcast_entry_delete(npu_id, &mc_entry);
            break;
        default:
            NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Un-supported entry update op");
            return STD_ERR(MCAST, PARAM, 0);
        }
        if (rc != STD_ERR_OK) {
            NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to %s multicast entry VLAN %d %s, rc=%d",
                            entry_op.op_type == mc_oper_type_t::ADD ? "create" :
                                            (entry_op.op_type == mc_oper_type_t::UPDATE ?
                                                        "update" : "delete"),
                            entry_op.vlan_id,
                            nas_mc_entry_key_tag(entry_op.entry_key),
                            rc);
            return rc;
        }
    }

    if (grp_upd_info.upd_type & DELETE_OLD_GROUP) {
        NAS_MC_LOG_DEBUG("NAS-MC-PROC-HW", "Delete old group with ID 0x%lx and its members",
                         grp_upd_info.orig_group_id);
        for (auto& grp_mbr: grp_upd_info.grp_member_list) {
            rc = ifindex_to_npu_port(grp_mbr.first, npu_port);
            if (rc != STD_ERR_OK) {
                NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to convert ifindex %d to NPU port", grp_mbr.first);
                return rc;
            }
            rc = ndi_l2mc_group_delete_member(npu_id, grp_mbr.second);
            if (rc != STD_ERR_OK) {
                NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to delete multicast group member for ifindex %d, rc=%d",
                               grp_mbr.first, rc);
                return rc;
            }
        }
        rc = ndi_l2mc_group_delete(npu_id, grp_upd_info.orig_group_id);
        if (rc != STD_ERR_OK) {
            NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to delete multicast group with ID 0x%lx, rc=%d",
                           grp_upd_info.orig_group_id, rc);
            return rc;
        }
    }
    return STD_ERR_OK;
}

static t_std_error update_flood_restrict_hw(const mc_snooping_msg_t& msg_info, bool before_grp_upd)
{
    t_std_error rc = STD_ERR_OK;
    for (auto& restr_upd: msg_info.flood_restr_update_list) {
        auto vlan_id = restr_upd.first;
        for (auto& npu_grp: restr_upd.second) {
            auto npu_id = npu_grp.first;
            auto& grp_ptr = npu_grp.second;
            auto upd_type = grp_ptr->upd_type & 0xf;
            bool del_old_grp = ((grp_ptr->upd_type & DELETE_OLD_GROUP) != 0);
            if (upd_type == UPDATE_CURRENT_GROUP) {
                // Only group member change, SAI will handle this case
                continue;
            } else if (del_old_grp && upd_type == CREATE_NEW_GROUP) {
                NAS_MC_LOG_ERR("NAS-MC-PROC-HW",
                               "Invalid Group Update Type: DELETE_OLD_GROUP and CREATE_NEW_GROUP should not co-exist");
                continue;
            }
            bool disable = (grp_ptr->new_group_id == INVALID_GROUP_ID);
            if ((del_old_grp && before_grp_upd) || (!del_old_grp && !before_grp_upd)) {
                if (disable) {
                    NAS_MC_LOG_DEBUG("NAS-MC-PROC-HW", "Disable flood restrict for VLAN %d", vlan_id);
                    rc = ndi_l2mc_set_flood_restrict(npu_id, vlan_id, NDI_FLOOD_TO_ALL_PORTS, 0);
                } else {
                    NAS_MC_LOG_DEBUG("NAS-MC-PROC-HW", "Enable or update flood restrict for VLAN %d with group 0x%lx",
                                     vlan_id, grp_ptr->new_group_id);
                    rc = ndi_l2mc_set_flood_restrict(npu_id, vlan_id, NDI_FLOOD_TO_GROUP, grp_ptr->new_group_id);
                }
                if (rc != STD_ERR_OK) {
                    NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to %s flood restrict for VLAN %d, rc=%d",
                                   disable ? "disable" : "enable", vlan_id, rc);
                    return rc;
                }
            }
        }
    }

    return STD_ERR_OK;
}

static t_std_error nas_mc_config_hw(mc_snooping_msg_t& msg_info)
{
    if (msg_info.oper_type == mc_oper_type_t::STATUS) {

        ndi_vlan_mcast_lookup_key_type_t key = NAS_NDI_VLAN_MCAST_LOOKUP_KEY_MACDA;

        if(msg_info.enable) {
           key = NAS_NDI_VLAN_MCAST_LOOKUP_KEY_XG_AND_SG;
        }
        if ((msg_info.req_type == mc_event_type_t::IGMP) || (msg_info.req_type == mc_event_type_t::MLD)) {
            uint32_t af = msg_info.req_type == mc_event_type_t::IGMP?NDI_IPV4_VERSION:NDI_IPV6_VERSION;
            if (STD_ERR_OK != (ndi_vlan_set_mcast_lookup_key(0,msg_info.vlan_id,af,key))) {
                NAS_MC_LOG_ERR("NAS-MC-PROC-HW",
                                "Failed to set %s VLAN MCAST lookup key to %d on VLAN %d",
                                msg_info.req_type == mc_event_type_t::IGMP ? "IGMP" : "MLD",
                                key, msg_info.vlan_id);
            }else
                NAS_MC_LOG_DEBUG("NAS-MC-PROC-HW",
                                 "Set %s VLAN MCAST lookup key to %d on VLAN %d success",
                                 msg_info.req_type == mc_event_type_t::IGMP ? "IGMP" : "MLD",
                                 key, msg_info.vlan_id);
        }
    }

    if (msg_info.oper_type == mc_oper_type_t::STATUS ||
        (msg_info.msg_type == mc_msg_type_t::INTERFACE && msg_info.ifindex == ALL_INTERFACES)) {
        if (msg_info.oper_type == mc_oper_type_t::STATUS && msg_info.enable) {
            NAS_MC_LOG_DEBUG("NAS-MC-PROC-HW",
                             "Nothing to be done by NPU to enable multicast snooping");
        } else {
            if (msg_info.oper_type == mc_oper_type_t::STATUS) {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC-HW",
                                 "%s snooping for VLAN %d is disabled, all related multicast entries will be deleted from NPU",
                                  msg_info.req_type == mc_event_type_t::IGMP_MLD ? "IGMP and MLD" :
                                  (msg_info.req_type == mc_event_type_t::IGMP ? "IGMP" : "MLD"),
                                  msg_info.vlan_id);
            } else {
                NAS_MC_LOG_DEBUG("NAS-MC-PROC-HW", "Delete all %s snooping entries from NPU for VLAN %d",
                                  msg_info.req_type == mc_event_type_t::IGMP_MLD ? "IGMP and MLD" :
                                  (msg_info.req_type == mc_event_type_t::IGMP ? "IGMP" : "MLD"),
                                  msg_info.vlan_id);
            }
            t_std_error rc = cache().delete_vlan_entries(msg_info.vlan_id, msg_info.req_type);
            if (rc != STD_ERR_OK) {
                // Log the error info and return success to continue to cache flushing
                NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to delete all entries for VLAN %d: rc=%d", msg_info.vlan_id, rc);
            }
        }
        return STD_ERR_OK;
    }

    t_std_error rc;
    if ((rc = update_flood_restrict_hw(msg_info, true)) != STD_ERR_OK) {
        NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to update flood restrict to HW before group update, rc=%d", rc);
        return rc;
    }

    mc_npu_port_t npu_port;
    if (msg_info.have_ifindex) {
        rc = ifindex_to_npu_port(msg_info.ifindex, npu_port);
        if (rc != STD_ERR_OK) {
            NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to get NPU port for ifindex %d", msg_info.ifindex);
            return rc;
        }
    } else {
        npu_port = {static_cast<npu_id_t>(msg_info.ifindex), nas_int_type_PORT};
    }
    switch(msg_info.msg_type) {
    case mc_msg_type_t::MROUTER:
    case mc_msg_type_t::ROUTE:
    case mc_msg_type_t::INTERFACE:
    case mc_msg_type_t::COPY_TO_CPU:
        for (auto& mrt_member: msg_info.group_update_list) {
            if (!mrt_member.second.first) {
                continue;
            }
            rc = update_entry_group_hw(npu_port.npu_id, mrt_member.second.second,
                                       *mrt_member.second.first,
                                       msg_info.oper_type == mc_oper_type_t::ADD);
            if (rc != STD_ERR_OK) {
                NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to update group for ifindex %d, rc=%d",
                               msg_info.ifindex, rc);
                return rc;
            }
        }
        break;
    default:
        NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Unsupported message type %d", static_cast<int>(msg_info.msg_type));
        return STD_ERR(MCAST, PARAM, 0);
    }

    if ((rc = update_flood_restrict_hw(msg_info, false)) != STD_ERR_OK) {
        NAS_MC_LOG_ERR("NAS-MC-PROC-HW", "Failed to update flood restrict to HW after group update, rc=%d", rc);
        return rc;
    }

    return STD_ERR_OK;
}

void nas_mc_update_pim_status(hal_vlan_id_t vlan_id, uint32_t af, bool status)
{
    mc_event_type_t req_type;
    if (af == AF_INET) {
        req_type = mc_event_type_t::IGMP;
    } else if (af == AF_INET6) {
        req_type = mc_event_type_t::MLD;
    } else {
        NAS_MC_LOG_ERR("NAS-MC-PROC", "Un-supported AF type: %d", af);
        return;
    }
    size_t max_npu = nas_mc_get_max_npus();
    for (size_t npu_id = 0; npu_id < max_npu; npu_id ++) {
        cache().copy_to_cpu_enabled(req_type, npu_id, vlan_id, status);
        // Push message
        pending_msg().push(new mc_snooping_msg_t{req_type, vlan_id, mc_oper_type_t::UPDATE, status,
                                                 mc_msg_type_t::COPY_TO_CPU,
                                                 false, static_cast<hal_ifindex_t>(npu_id),
                                                 false, hal_ip_addr_t{af}, false, hal_ip_addr_t{af}, false}, true);
    }
}

void nas_mc_get_flood_restrict_status(bool all_vlan, hal_vlan_id_t vlan_id, mc_flood_restr_status_t& vlan_status)
{
    size_t max_npu = nas_mc_get_max_npus();
    for (size_t npu_id = 0; npu_id < max_npu; npu_id ++) {
        cache().get_flood_restr_status(npu_id, all_vlan, vlan_id, vlan_status);
    }
}

bool nas_mc_get_entry_group_id(hal_vlan_id_t vlan_id, const mc_entry_key_t& entry_key, ndi_obj_id_t& grp_id)
{
    size_t max_npu = nas_mc_get_max_npus();
    for (size_t npu_id = 0; npu_id < max_npu; npu_id ++) {
        if (cache().get_entry_group_id(npu_id, vlan_id, entry_key, grp_id)) {
            return true;
        }
    }
    return false;
}

bool nas_mc_get_group_info_by_id(ndi_obj_id_t ndi_grp_id, hal_vlan_id_t& vlan_id,
                                 std::vector<hal_ifindex_t>& oif_list, size_t& ref_count)
{
    auto grp_ptr = mc_group_db.get_group_info(ndi_grp_id);
    if (grp_ptr == nullptr) {
        return false;
    }
    vlan_id = grp_ptr->vlan_id;
    for (auto& grp_mbr: grp_ptr->group_member_list) {
        oif_list.push_back(grp_mbr.first);
    }
    ref_count = grp_ptr->ref_count;
    return true;
}

static bool msg_proc_running = true;

// Thread main function
static int nas_mc_proc_snooping_msg(void)
{
    std::unique_ptr<mc_snooping_msg_t> msg_ptr{};
    while(msg_proc_running) {
        bool is_sync = false;
        pending_msg().wait_for_msg();
        if (!msg_proc_running) {
            NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Break out from message handling main loop");
            break;
        }
        while (pending_msg().pop(msg_ptr, is_sync)) {
            auto& msg_info = *msg_ptr;
            NAS_MC_LOG_DEBUG("NAS-MC-PROC", "\n%s\n", msg_info.dump_msg_info(is_sync).c_str());
            try {
                if (msg_info.oper_type == mc_oper_type_t::GET) {
                    if (msg_info.msg_type == mc_msg_type_t::ROUTE) {
                        cache().get_route_entries(msg_info);
                    } else if (msg_info.msg_type == mc_msg_type_t::MROUTER) {
                        cache().get_mrouter_intfs(msg_info);
                    }
                    // will be manually freed later
                    msg_ptr.release();
                } else if (cache().update_needed(msg_info)) {
                    t_std_error rc = STD_ERR_OK;
                    // call ndi api to program multicast settings to npu
                    if (msg_info.oper_type == mc_oper_type_t::FLOOD_RESTRICT) {
                        if (!cache().get_flood_restr_ndi_info(msg_info)) {
                            NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to get NDI info for flood restrict config");
                            rc = STD_ERR(MCAST, FAIL, 0);
                        }
                    } else if (msg_info.oper_type != mc_oper_type_t::STATUS) {
                        if (msg_info.msg_type == mc_msg_type_t::ROUTE) {
                            if (!cache().get_route_ndi_info(msg_info)) {
                                NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to get NDI info for route config");
                                rc = STD_ERR(MCAST, FAIL, 0);
                            }
                        } else if (msg_info.msg_type == mc_msg_type_t::MROUTER) {
                            if (!cache().get_mrouter_ndi_info(msg_info)) {
                                NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to get NDI info for mrouter config");
                                rc = STD_ERR(MCAST, FAIL, 0);
                            }
                        } else if (msg_info.msg_type == mc_msg_type_t::INTERFACE) {
                            if (!cache().get_route_interface_ndi_info(msg_info)) {
                                NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to get NDI info for route interface config");
                                rc = STD_ERR(MCAST, FAIL, 0);
                            }
                        } else if (msg_info.msg_type == mc_msg_type_t::COPY_TO_CPU) {
                            if (!cache().get_copy_to_cpu_ndi_info(msg_info)) {
                                NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to get NDI info for route copy to cpu config");
                                rc = STD_ERR(MCAST, FAIL, 0);
                            }
                        }
                    }
                    if (rc == STD_ERR_OK) {
                        NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Call NDI APIs to configure Multicast Entry to NPU");
                        if ((rc = nas_mc_config_hw(msg_info)) != STD_ERR_OK) {
                            NAS_MC_LOG_ERR("NAS-MC-PROC", "Failed to configure multicast on NPU, rc = %d", rc);
                        }
                    }

                    if (rc == STD_ERR_OK) {
                        cache().update(msg_info);
                    }
                } else {
                    NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Cache is not needed or could not be updated");
                }
            } catch(std::exception& ex) {
                NAS_MC_LOG_ERR("NAS-MC-PROC", "Exception: %s", ex.what());
            }
            if (is_sync) {
                pending_msg().proc_finish();
            }
            NAS_MC_LOG_DEBUG("NAS-MC-PROC", "Multicast message processing done");
        }
    }

    return true;
}

static std_thread_create_param_t mc_msg_thr;

// Initiation
t_std_error nas_mc_proc_init(void)
{
    cache().vlan_in_group_key() = ndi_l2mc_vlan_port_lookup_enabled_get();
    NAS_MC_LOG_INFO("NAS-MC-PROC-INIT", "VLAN and port lookup is %s",
                    group_key_check_vlan() ? "enabled" : "disabled");

    // Start main thread
    std_thread_init_struct(&mc_msg_thr);
    mc_msg_thr.name = "mcast-snooping-msg";
    mc_msg_thr.thread_function = (std_thread_function_t)nas_mc_proc_snooping_msg;
    if (std_thread_create(&mc_msg_thr) !=  STD_ERR_OK) {
        NAS_MC_LOG_ERR("NAS-MC-PROC-INIT", "Error creating msg thread");
        return STD_ERR(MCAST, FAIL, 0);
    }
    NAS_MC_LOG_INFO("NAS-MC-PROC-INIT", "Multicast message porcessing thread started");

    return STD_ERR_OK;
}

t_std_error nas_mc_proc_deinit(void)
{
    msg_proc_running = false;
    pending_msg().push(new mc_snooping_msg_t{});
    std_thread_join(&mc_msg_thr);
    std_thread_destroy_struct(&mc_msg_thr);
    NAS_MC_LOG_INFO("NAS-MC-PROC-INIT", "Multicast message porcessing thread exited");

    return STD_ERR_OK;
}
