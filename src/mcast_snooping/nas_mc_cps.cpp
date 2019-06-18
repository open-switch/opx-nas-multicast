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
 * filename: nas_mc_cps.cpp
 */

#include "nas_l2_mc_api.h"
#include "nas_mc_util.h"
#include "cps_api_events.h"
#include "hal_if_mapping.h"
#include "ietf-igmp-mld-snooping.h"
#include "l2-multicast.h"
#include "std_utils.h"
#include "std_ip_utils.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"

#include <inttypes.h>
#include <vector>
#include <unordered_set>

static cps_api_key_t mc_igmp_obj_key;
static cps_api_key_t mc_mld_obj_key;

#define KEY_PRINT_BUF_LEN 100

static hal_ip_addr_t ipv4_null_ip;
static hal_ip_addr_t ipv6_null_ip;

// Convert interface name to ifindex
static t_std_error nas_mc_name_to_ifindex(const char *if_name, hal_ifindex_t& ifindex)
{
    interface_ctrl_t intf_ctrl;

    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
    safestrncpy(intf_ctrl.if_name, if_name, sizeof(intf_ctrl.if_name));

    if(dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
        return STD_ERR(MCAST, FAIL, 0);
    }

    if (intf_ctrl.int_type == nas_int_type_CPU) {
        ifindex = CPU_INTERFACE;
    } else {
        ifindex = intf_ctrl.if_index;
    }
    return STD_ERR_OK;
}

static std::string nas_mc_get_intf_name(hal_ifindex_t ifindex)
{
    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(intf_ctrl));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.vrf_id = NAS_DEFAULT_VRF_ID;
    intf_ctrl.if_index = ifindex;
    if (dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
        throw std::invalid_argument{"Invalid ifindex"};
    }
    return std::string{intf_ctrl.if_name};
}

static bool nas_mc_mrouter_handler(mc_event_type_t evt_type, hal_vlan_id_t vid, bool add,
                                   const cps_api_object_it_t& itor)
{
    const char *if_name = (char *)cps_api_object_attr_data_bin(itor.attr);
    NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Mrouter interface %s", if_name);
    hal_ifindex_t ifindex = 0;
    if (nas_mc_name_to_ifindex(if_name, ifindex) != STD_ERR_OK) {
        NAS_MC_LOG_ERR("NAS-MC-CPS", "Failed to get ifindex from if name");
        return false;
    }
    NAS_MC_LOG_INFO("NAS-MC-CPS", "%s multicast router interface %d, VID=%d",
                     add ? "Add" : "Delete", ifindex, vid);
    if (add) {
        nas_mc_add_mrouter(evt_type, vid, ifindex);
    } else {
        nas_mc_del_mrouter(evt_type, vid, ifindex);
    }
    return true;
}

static bool nas_mc_route_handler(mc_event_type_t evt_type, hal_vlan_id_t vid, bool add,
                                 const cps_api_object_it_t& itor)
{
    hal_ip_addr_t group_ip;
    hal_ip_addr_t source_ip;
    hal_ifindex_t ifindex = 0;
    cps_api_attr_id_t group_addr_id, group_src_id, group_src_addr_id;
    cps_api_attr_id_t group_if_id;

    if (evt_type == mc_event_type_t::IGMP) {
        group_addr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_ADDRESS;
        group_if_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_INTERFACE;
        group_src_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_SOURCE;
        group_src_addr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_SOURCE_ADDRESS;
    } else if (evt_type == mc_event_type_t::MLD) {
        group_addr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_ADDRESS;
        group_if_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_INTERFACE;
        group_src_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_SOURCE;
        group_src_addr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_SOURCE_ADDRESS;
    } else {
        return false;
    }

    std::vector<hal_ip_addr_t> src_ip_list = {};
    cps_api_object_it_t in_it = itor;
    cps_api_object_it_inside(&in_it);
    for (; cps_api_object_it_valid(&in_it); cps_api_object_it_next(&in_it)) {
        cps_api_attr_id_t list_index = cps_api_object_attr_id(in_it.attr);
        NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Multicast group item index: %lu", list_index);
        cps_api_object_it_t grp_it = in_it;
        cps_api_object_it_inside(&grp_it);
        bool addr_found = false, if_found = false;

        /* Clear source list from previous group */
        src_ip_list.clear();

        for(; cps_api_object_it_valid(&grp_it); cps_api_object_it_next(&grp_it)) {
            cps_api_attr_id_t grp_attr_id = cps_api_object_attr_id(grp_it.attr);
            NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Handling mc group attribute id %" PRIx64, grp_attr_id);
            if (grp_attr_id == group_if_id) {
                const char *if_name = (char *)cps_api_object_attr_data_bin(grp_it.attr);
                NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Multicast route interface %s", if_name);
                if (nas_mc_name_to_ifindex(if_name, ifindex) != STD_ERR_OK) {
                    NAS_MC_LOG_ERR("NAS-MC-CPS", "Failed to get ifindex from if name");
                    return false;
                }
                if_found = true;
            } else if (grp_attr_id == group_addr_id) {
                const char *ip_addr_str = (const char *)cps_api_object_attr_data_bin(grp_it.attr);
                NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Multicast route group address %s", ip_addr_str);
                memset(&group_ip, 0, sizeof(hal_ip_addr_t));
                if (!std_str_to_ip(ip_addr_str, &group_ip)) {
                    NAS_MC_LOG_ERR("NAS-MC-CPS", "Failed to convert IP string to data");
                    return false;
                }
                if (!((evt_type == mc_event_type_t::IGMP && group_ip.af_index == HAL_INET4_FAMILY) ||
                      (evt_type == mc_event_type_t::MLD && group_ip.af_index == HAL_INET6_FAMILY))) {
                    NAS_MC_LOG_ERR("NAS-MC-CPS", "Protocol family of group IP not match");
                    return false;
                }
                addr_found = true;
            } else if (grp_attr_id == group_src_id) {
                cps_api_object_it_t in_grp_it = grp_it;
                cps_api_object_it_inside(&in_grp_it);
                for(; cps_api_object_it_valid(&in_grp_it); cps_api_object_it_next(&in_grp_it)) {
                    cps_api_attr_id_t src_index = cps_api_object_attr_id(in_grp_it.attr);
                    NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Multicast source item index: %lu", src_index);
                    cps_api_object_it_t src_it = in_grp_it;
                    cps_api_object_it_inside(&src_it);
                    for(; cps_api_object_it_valid(&src_it); cps_api_object_it_next(&src_it)) {
                        cps_api_attr_id_t src_attr_id = cps_api_object_attr_id(src_it.attr);
                        if (src_attr_id == group_src_addr_id) {
                            const char *src_ip_str = (const char *)cps_api_object_attr_data_bin(src_it.attr);
                            NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Multicast route group source address %s", src_ip_str);
                            memset(&source_ip, 0, sizeof(hal_ip_addr_t));
                            if (!std_str_to_ip(src_ip_str, &source_ip)) {
                                NAS_MC_LOG_ERR("NAS-MC-CPS", "Failed to convert source IP string to data");
                                return false;
                            }
                            if (!((evt_type == mc_event_type_t::IGMP && source_ip.af_index == HAL_INET4_FAMILY) ||
                                  (evt_type == mc_event_type_t::MLD && source_ip.af_index == HAL_INET6_FAMILY))) {
                                NAS_MC_LOG_ERR("NAS-MC-CPS", "Protocol family of group source IP not match");
                                return false;
                            }
                            src_ip_list.push_back(source_ip);
                        }
                    }
                }
            }
        }
        if (!addr_found) {
            if (ifindex == CPU_INTERFACE) {
                NAS_MC_LOG_INFO("NAS-MC-CPS", "%s copy-to-cpu to VLAN %d", add ? "Enable" : "Disable", vid);
                if (evt_type == mc_event_type_t::IGMP) {
                    nas_mc_update_pim_status(vid, AF_INET, add);
                } else {
                    nas_mc_update_pim_status(vid, AF_INET6, add);
                }
                return true;
            } else {
                NAS_MC_LOG_ERR("NAS-MC-CPS", "Could not find mandatory attribute GROUP_IP");
                return false;
            }
        }
        bool is_xg = src_ip_list.empty();
        if (is_xg) {
            if (evt_type == mc_event_type_t::IGMP) {
                src_ip_list.push_back(ipv4_null_ip);
            } else {
                src_ip_list.push_back(ipv6_null_ip);
            }
        }
        for (auto& src_ip: src_ip_list) {
            char ip_buf[HAL_INET6_TEXT_LEN + 1];
            const char *ip_str = std_ip_to_string(&group_ip, ip_buf, sizeof(ip_buf));
            char src_ip_buf[HAL_INET6_TEXT_LEN + 1];
            const char *src_ip_str = std_ip_to_string(&src_ip, src_ip_buf, sizeof(src_ip_buf));
            NAS_MC_LOG_INFO("NAS-MC-CPS", "%s multicast route entry: VID %d IP %s SRC %s IF %d",
                             add ? "Add" : "Delete", vid, ip_str, src_ip_str, ifindex);
            if (add) {
                nas_mc_add_route(evt_type, vid, group_ip, is_xg, src_ip, if_found, ifindex);
            } else {
                nas_mc_del_route(evt_type, vid, group_ip, is_xg, src_ip, if_found, ifindex);
            }
        }
    }

    return true;
}

static bool nas_mc_event_handler(cps_api_object_t evt_obj, void *param)
{
    cps_api_object_attr_t vlan_id_attr;
    cps_api_object_attr_t status_attr;

    cps_api_attr_id_t mrouter_id;
    cps_api_attr_id_t group_id;

    mc_event_type_t evt_type;
    if (cps_api_key_matches(&mc_igmp_obj_key,
                    cps_api_object_key(evt_obj), true) == 0) {
        evt_type = mc_event_type_t::IGMP;

        vlan_id_attr = cps_api_get_key_data(evt_obj,
                IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_VLAN_ID);

        mrouter_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE;
        group_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP;

        status_attr = cps_api_object_attr_get(evt_obj,
                IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_ENABLE);
    } else if (cps_api_key_matches(&mc_mld_obj_key,
                    cps_api_object_key(evt_obj), true) == 0) {
        evt_type = mc_event_type_t::MLD;

        vlan_id_attr = cps_api_get_key_data(evt_obj,
                IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_VLAN_ID);

        mrouter_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE;
        group_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP;

        status_attr = cps_api_object_attr_get(evt_obj,
                IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_ENABLE);
    } else {
        char key_buf[KEY_PRINT_BUF_LEN];
        NAS_MC_LOG_ERR("NAS-MC-CPS", "Unsupported object key: %s",
                       cps_api_key_print(cps_api_object_key(evt_obj), key_buf, sizeof(key_buf)));
        return false;
    }

    if (vlan_id_attr == nullptr) {
        NAS_MC_LOG_ERR("NAS-MC-CPS", "VLAN ID attribute not found");
        return false;
    }

    hal_vlan_id_t vid = cps_api_object_attr_data_u16(vlan_id_attr);

    if (status_attr != nullptr) {
        uint_t snp_status = cps_api_object_attr_data_u32(status_attr);
        NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Setting Multicast snooping status %d",
                         snp_status);
        nas_mc_change_snooping_status(evt_type, vid, (bool)snp_status);
    }

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(evt_obj));
    NAS_MC_LOG_DEBUG("NAS-MC-CPS", "CPS Event received: VLAN_ID %d OPER_TYPE %d",
                     vid, op);

    bool is_add;
    if (op == cps_api_oper_CREATE) {
        is_add = true;
    } else if (op == cps_api_oper_DELETE) {
        is_add = false;
    } else {
        // Other operation type only for snooping status setting
        NAS_MC_LOG_DEBUG("NAS-MC-CPS", "No handling for operation set");
        return true;
    }

    cps_api_object_it_t it;
    for (cps_api_object_it_begin(evt_obj, &it); cps_api_object_it_valid(&it);
         cps_api_object_it_next(&it)) {
        cps_api_attr_id_t attr_id = cps_api_object_attr_id(it.attr);
        NAS_MC_LOG_DEBUG("NAS-MC-CPS", "Handling event object attribute id %" PRIx64, attr_id);
        if (attr_id == mrouter_id) {
            if (!nas_mc_mrouter_handler(evt_type, vid, is_add, it)) {
                NAS_MC_LOG_ERR("NAS-MC-CPS", "Failure on handling mrouter message");
                return false;
            }
        } else if (attr_id == group_id) {
            if (!nas_mc_route_handler(evt_type, vid, is_add, it)) {
                NAS_MC_LOG_ERR("NAS-MC-CPS", "Failure on handling mcast entry message");
                return false;
            }
        }
    }

    return true;
}

// Register event handler as thread
static t_std_error nas_mc_event_handle_reg(void)
{
    cps_api_event_reg_t reg;

    memset(&reg, 0, sizeof(reg));
    const uint_t NUM_KEYS = 2;
    cps_api_key_t key[NUM_KEYS];

    cps_api_key_from_attr_with_qual(&key[0],
                    IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN,
                    cps_api_qualifier_OBSERVED);
    memcpy(&mc_igmp_obj_key, &key[0], sizeof(cps_api_key_t));

    cps_api_key_from_attr_with_qual(&key[1],
                    IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN,
                    cps_api_qualifier_OBSERVED);
    memcpy(&mc_mld_obj_key, &key[1], sizeof(cps_api_key_t));

    reg.number_of_objects = NUM_KEYS;
    reg.objects = key;
    if (cps_api_event_thread_reg(&reg, nas_mc_event_handler, NULL)
            != cps_api_ret_code_OK) {
        NAS_MC_LOG_ERR("NAS-MC-CPS", "Failed to register on event handling thread");
        return STD_ERR(MCAST,FAIL,0);
    }
    return STD_ERR_OK;
}

#define NUM_MC_CPS_API_THREAD   1

static cps_api_operation_handle_t nas_mc_cps_handle;

static cps_api_return_code_t nas_mc_cleanup_handler(void *context,
                                            cps_api_transaction_params_t *param,
                                            size_t ix)
{
    NAS_MC_LOG_DEBUG("NAS-MC-CPS-CLEANUP",
                     "Entering multicast snooping entries cleanup handler");
    if (param == nullptr) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-CLEANUP", "Invalid argument");
        return cps_api_ret_code_ERR;
    }
    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    if (obj == NULL) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-CLEANUP", "Cleanup object is not present at index %lu", ix);
        return cps_api_ret_code_ERR;
    }

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if (op != cps_api_oper_ACTION) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-CLEANUP", "Invalid operation type %d", op);
        return cps_api_ret_code_ERR;
    }

    hal_ifindex_t ifindex = 0;
    cps_api_object_attr_t attr = cps_api_object_attr_get(obj,
                                        BASE_L2_MCAST_CLEANUP_L2MC_MEMBER_INPUT_IFINDEX);
    if (attr == nullptr) {
        attr = cps_api_object_attr_get(obj,
                                BASE_L2_MCAST_CLEANUP_L2MC_MEMBER_INPUT_IFNAME);
        if (attr == nullptr) {
            attr = cps_api_object_attr_get(obj, BASE_L2_MCAST_CLEANUP_L2MC_MEMBER_INPUT_VLAN_ID);
            if (attr == nullptr) {
                NAS_MC_LOG_ERR("NAS-MC-CPS-CLEANUP", "Either ifindex, ifname or vlan_id should be given");
                return cps_api_ret_code_ERR;
            }
            hal_vlan_id_t vlan_id = cps_api_object_attr_data_u32(attr);
            NAS_MC_LOG_DEBUG("NAS-MC-CPS-CLEANUP", "Multicast entry cleanup for VLAN %d", vlan_id);
            nas_mc_cleanup_vlan(vlan_id);
            return cps_api_ret_code_OK;
        }
        const char *ifname = static_cast<const char*>(cps_api_object_attr_data_bin(attr));
        t_std_error rc = nas_mc_name_to_ifindex(ifname, ifindex);
        if (rc != STD_ERR_OK) {
            NAS_MC_LOG_ERR("NAS-MC-CPS-CLEANUP", "Failed to get ifindex of interface %s, rc=%d",
                           ifname, rc);
            return rc;
        }
    } else {
        ifindex = cps_api_object_attr_data_u32(attr);
    }
    NAS_MC_LOG_DEBUG("NAS-MC-CPS-CLEANUP", "Multicast entry cleanup for interface with ifindex %d",
                     ifindex);

    attr = cps_api_object_attr_get(obj, BASE_L2_MCAST_CLEANUP_L2MC_MEMBER_INPUT_VLAN_ID);
    if (attr == nullptr) {
        NAS_MC_LOG_DEBUG("NAS-MC-CPS-CLEANUP", "Multicast entry cleanup for all VLANs");
        nas_mc_cleanup_interface(ifindex);
    } else {
        hal_vlan_id_t vlan_id = cps_api_object_attr_data_u32(attr);
        NAS_MC_LOG_DEBUG("NAS-MC-CPS-CLEANUP", "Multicast entry cleanup for VLAN %d", vlan_id);
        nas_mc_cleanup_vlan_member(vlan_id, ifindex);
    }

    return cps_api_ret_code_OK;
}

static t_std_error nas_mc_cleanup_handle_reg(void)
{
    cps_api_registration_functions_t f{};
    if (!cps_api_key_from_attr_with_qual(&f.key, BASE_L2_MCAST_CLEANUP_L2MC_MEMBER_OBJ,
                                         cps_api_qualifier_TARGET)) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-CLEANUP", "Failed to get object key");
        return STD_ERR(MCAST, FAIL, 0);
    }
    f.handle = nas_mc_cps_handle;
    f._write_function = nas_mc_cleanup_handler;
    if (cps_api_register(&f) != cps_api_ret_code_OK) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-CLEANUP", "Failed to register cps callback");
        return STD_ERR(MCAST, FAIL, 0);
    }

    return STD_ERR_OK;
}

struct mc_snooping_key_t
{
    hal_vlan_id_t vlan_id;
    hal_ip_addr_t grp_ip;
    hal_ifindex_t out_if;
    bool is_xg;
};

namespace std
{
    template<>
    struct hash<mc_snooping_key_t>
    {
        size_t operator()(const mc_snooping_key_t& key) const
        {
            size_t h_val = hash<int>()(key.vlan_id);
            h_val <<= 1;
            h_val ^= _ip_addr_key_hash()(key.grp_ip);
            h_val <<= 1;
            h_val ^= hash<int>()(key.out_if);
            h_val <<= 1;
            h_val ^= hash<bool>()(key.is_xg);
            return h_val;
        }
    };

    template<>
    struct equal_to<mc_snooping_key_t>
    {
        bool operator()(const mc_snooping_key_t& k1, const mc_snooping_key_t& k2) const
        {
            return k1.vlan_id == k2.vlan_id &&
                   _ip_addr_key_equal()(k1.grp_ip, k2.grp_ip) &&
                   k1.out_if == k2.out_if &&
                   k1.is_xg == k2.is_xg;
        }
    };
}

using mc_ip_addr_set_t = std::unordered_set<hal_ip_addr_t, _ip_addr_key_hash, _ip_addr_key_equal>;
using mc_snooping_map_t = std::unordered_map<mc_snooping_key_t, mc_ip_addr_set_t>;

static bool nas_mc_append_entry_obj(cps_api_get_params_t* param, cps_api_attr_id_t obj_attr_id,
                                    cps_api_attr_id_t vlan_attr_id, hal_vlan_id_t vlan_id,
                                    cps_api_attr_id_t grp_ip_attr_id, const hal_ip_addr_t& grp_ip,
                                    bool is_xg,
                                    cps_api_attr_id_t oif_attr_id, hal_ifindex_t out_if,
                                    cps_api_attr_id_t src_attr_id,
                                    cps_api_attr_id_t src_ip_attr_id, const mc_ip_addr_set_t& src_ip_list)
{
    char ip_buf[HAL_INET6_TEXT_LEN + 1];
    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(param->list);
    if (obj == nullptr) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-GET", "Failed to create and append new object to list");
        return false;
    }
    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj), obj_attr_id, cps_api_qualifier_OBSERVED)) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-GET", "Failed to get object key from attribute ID");
        return false;
    }
    cps_api_object_attr_add_u16(obj, vlan_attr_id, vlan_id);
    const char *ip_str = std_ip_to_string(&grp_ip, ip_buf, sizeof(ip_buf));
    if (ip_str == nullptr) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-GET", "Failed to convert group IP to string");
        return false;
    }
    if (out_if != NULL_INTERFACE) {
        try {
            auto if_name = nas_mc_get_intf_name(out_if);
            cps_api_object_attr_add(obj, oif_attr_id, if_name.c_str(), if_name.length() + 1);
        } catch (std::exception& ex) {
            NAS_MC_LOG_ERR("NAS-MC-CPS-GET", "Failed to get interface name from ifindex %d", out_if);
            return false;
        }
    }
    cps_api_object_attr_add(obj, grp_ip_attr_id, ip_str, strlen(ip_str) + 1);
    if (!is_xg) {
        cps_api_attr_id_t ids[3] = {src_attr_id, 0, src_ip_attr_id};
        size_t ip_index = 0;
        for (auto& src_ip: src_ip_list) {
            ip_str = std_ip_to_string(&src_ip, ip_buf, sizeof(ip_buf));
            if (ip_str == nullptr) {
                NAS_MC_LOG_ERR("NAS-MC-CPS-GET", "Failed to convert source IP to string");
                return false;
            }
            ids[1] = ip_index;
            cps_api_object_e_add(obj, ids, 3, cps_api_object_ATTR_T_BIN, ip_str, strlen(ip_str) + 1);
            ip_index ++;
        }
    }

    return true;
}

static cps_api_return_code_t nas_mc_route_get_handler(void *context, cps_api_get_params_t *param,
                                                      size_t ix)
{
    cps_api_object_list_t filters = param->filters;
    cps_api_object_t obj = cps_api_object_list_get(filters, ix);
    auto route_type_id = cps_api_key_element_at(cps_api_object_key(obj), CPS_OBJ_KEY_APP_INST_POS + 2);
    mc_event_type_t route_type;
    cps_api_attr_id_t obj_attr_id, vlan_attr_id, grp_ip_attr_id, src_attr_id, src_ip_attr_id, oif_attr_id;
    uint32_t af;
    if (route_type_id == IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING) {
        route_type = mc_event_type_t::IGMP;
        obj_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP;
        vlan_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_VLAN_ID;
        grp_ip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_ADDRESS;
        src_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_SOURCE;
        src_ip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_SOURCE_ADDRESS;
        oif_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_INTERFACE;
        af = AF_INET;
    } else if (route_type_id == IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING) {
        route_type = mc_event_type_t::MLD;
        obj_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP;
        vlan_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_VLAN_ID;
        grp_ip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_ADDRESS;
        src_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_SOURCE;
        src_ip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_SOURCE_ADDRESS;
        oif_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_INTERFACE;
        af = AF_INET6;
    } else {
        NAS_MC_LOG_ERR("NAS-MC-CPS-GET", "Invalid route type attribute ID %d", route_type_id);
        return STD_ERR(MCAST, PARAM, 0);
    }
    hal_vlan_id_t vlan_id = 0;
    auto vlan_id_attr = cps_api_get_key_data(obj, vlan_attr_id);
    if (vlan_id_attr != nullptr) {
        vlan_id = cps_api_object_attr_data_u16(vlan_id_attr);
    }
    hal_ip_addr_t grp_ip{af};
    auto grp_ip_attr = cps_api_get_key_data(obj, grp_ip_attr_id);
    if (grp_ip_attr != nullptr) {
        const char *ip_addr_str = (const char *)cps_api_object_attr_data_bin(grp_ip_attr);
        NAS_MC_LOG_DEBUG("NAS-MC-CPS-GET", "Get route entries with group address %s", ip_addr_str);
        memset(&grp_ip, 0, sizeof(hal_ip_addr_t));
        if (!std_str_to_ip(ip_addr_str, &grp_ip)) {
            NAS_MC_LOG_ERR("NAS-MC-CPS-GET", "Failed to convert IP string to data");
            return STD_ERR(MCAST, FAIL, 0);
        }
    }
    bool is_xg = true;
    hal_ip_addr_t src_ip{af};
    auto src_ip_attr = cps_api_get_key_data(obj, src_ip_attr_id);
    if (src_ip_attr != nullptr) {
        is_xg = false;
        const char *ip_addr_str = (const char *)cps_api_object_attr_data_bin(src_ip_attr);
        NAS_MC_LOG_DEBUG("NAS-MC-CPS-GET", "Get route entries with source address %s", ip_addr_str);
        memset(&src_ip, 0, sizeof(hal_ip_addr_t));
        if (!std_str_to_ip(ip_addr_str, &src_ip)) {
            NAS_MC_LOG_ERR("NAS-MC-CPS-GET", "Failed to convert IP string to data");
            return STD_ERR(MCAST, FAIL, 0);
        }
    }
    mc_get_route_list_t route_list{};
    nas_mc_get_route(route_type, vlan_id, grp_ip, is_xg, src_ip, route_list);
    mc_snooping_map_t snoop_grp_list{};
    for (auto& vlan_info: route_list) {
        for (auto& route_info: vlan_info.second) {
            size_t mrouter_list_size = route_info.mrouter_if_list.size();
            size_t total_size = mrouter_list_size + route_info.host_if_list.size();
            hal_ifindex_t ifidx;
            for (size_t idx = 0; idx < total_size; idx ++) {
                if (idx < mrouter_list_size) {
                    ifidx = route_info.mrouter_if_list[idx];
                } else {
                    ifidx = route_info.host_if_list[idx - mrouter_list_size];
                }
                mc_snooping_key_t snoop_key{vlan_info.first, route_info.entry.dst_ip, ifidx, route_info.entry.is_xg};
                snoop_grp_list[snoop_key].insert(route_info.entry.src_ip);
            }
        }
    }
    for (auto& snoop_info: snoop_grp_list) {
        nas_mc_append_entry_obj(param, obj_attr_id, vlan_attr_id, snoop_info.first.vlan_id,
                                grp_ip_attr_id, snoop_info.first.grp_ip, snoop_info.first.is_xg,
                                oif_attr_id, snoop_info.first.out_if,
                                src_attr_id, src_ip_attr_id, snoop_info.second);
    }
    return cps_api_ret_code_OK;
}

static bool nas_mc_append_mrouter_obj(cps_api_get_params_t* param, cps_api_attr_id_t obj_attr_id,
                                      cps_api_attr_id_t vlan_attr_id, hal_vlan_id_t vlan_id,
                                      hal_ifindex_t ifindex)
{
    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(param->list);
    if (obj == nullptr) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-GET", "Failed to create and append new object to list");
        return false;
    }
    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj), obj_attr_id, cps_api_qualifier_OBSERVED)) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-GET", "Failed to get object key from attribute ID");
        return false;
    }
    cps_api_object_attr_add_u16(obj, vlan_attr_id, vlan_id);
    try {
        auto if_name = nas_mc_get_intf_name(ifindex);
        cps_api_object_attr_add(obj, obj_attr_id, if_name.c_str(), if_name.length() + 1);
    } catch (std::exception& ex) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-GET", "Failed to get interface name from ifindex %d", ifindex);
        return false;
    }

    return true;
}

static cps_api_return_code_t nas_mc_mrouter_get_handler(void *context, cps_api_get_params_t *param,
                                                        size_t ix)
{
    cps_api_object_list_t filters = param->filters;
    cps_api_object_t obj = cps_api_object_list_get(filters, ix);
    auto mrouter_type_id = cps_api_key_element_at(cps_api_object_key(obj), CPS_OBJ_KEY_APP_INST_POS + 2);
    mc_event_type_t mrouter_type;
    cps_api_attr_id_t obj_attr_id, vlan_attr_id;
    if (mrouter_type_id == IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING) {
        mrouter_type = mc_event_type_t::IGMP;
        obj_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE;
        vlan_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_VLAN_ID;
    } else if (mrouter_type_id == IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING) {
        mrouter_type = mc_event_type_t::MLD;
        obj_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE;
        vlan_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_VLAN_ID;
    } else {
        NAS_MC_LOG_ERR("NAS-MC-CPS-GET", "Invalid mrouter type attribute ID %d", mrouter_type_id);
        return STD_ERR(MCAST, PARAM, 0);
    }

    hal_vlan_id_t vlan_id = 0;
    auto vlan_id_attr = cps_api_get_key_data(obj, vlan_attr_id);
    if (vlan_id_attr != nullptr) {
        vlan_id = cps_api_object_attr_data_u16(vlan_id_attr);
    }

    mc_get_mrouter_list_t mrouter_list{};
    nas_mc_get_mrouter(mrouter_type, vlan_id, mrouter_list);
    for(auto& vlan_info: mrouter_list) {
        if (mrouter_type == mc_event_type_t::IGMP) {
            for (auto ifindex: vlan_info.second.igmp_if_list) {
                nas_mc_append_mrouter_obj(param, obj_attr_id, vlan_attr_id, vlan_info.first, ifindex);
            }
        } else {
            for (auto ifindex: vlan_info.second.mld_if_list) {
                nas_mc_append_mrouter_obj(param, obj_attr_id, vlan_attr_id, vlan_info.first, ifindex);
            }
        }
    }

    return cps_api_ret_code_OK;
}

static t_std_error nas_mc_get_handle_reg(void)
{
    std::unordered_map<cps_api_attr_id_t, cps_api_return_code_t(*)(void*, cps_api_get_params_t*, size_t)>
    reg_func_map = {
        {IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP, nas_mc_route_get_handler},
        {IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP, nas_mc_route_get_handler},
        {IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE, nas_mc_mrouter_get_handler},
        {IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE, nas_mc_mrouter_get_handler}
    };
    cps_api_registration_functions_t f{};
    f.handle = nas_mc_cps_handle;
    for (auto& reg_info: reg_func_map) {
        if (!cps_api_key_from_attr_with_qual(&f.key, reg_info.first,
                                             cps_api_qualifier_OBSERVED)) {
            NAS_MC_LOG_ERR("NAS-MC-CPS-GET", "Failed to get object key");
            return STD_ERR(MCAST, FAIL, 0);
        }
        f._read_function = reg_info.second;
        if (cps_api_register(&f) != cps_api_ret_code_OK) {
            NAS_MC_LOG_ERR("NAS-MC-CPS-GET", "Failed to register cps callback");
            return STD_ERR(MCAST, FAIL, 0);
        }
    }

    return STD_ERR_OK;
}

static cps_api_return_code_t nas_mc_flood_restrict_handler(void *context,
                                            cps_api_transaction_params_t *param,
                                            size_t ix)
{
    NAS_MC_LOG_DEBUG("NAS-MC-CPS-FLOOD-RESTRICT",
                     "Entering multicast snooping entries flood restrict handler");
    if (param == nullptr) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-FLOOD-RESTRICT", "Invalid argument");
        return cps_api_ret_code_ERR;
    }
    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    if (obj == NULL) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-FLOOD-RESTRICT", "CPS bject is not present at index %lu", ix);
        return cps_api_ret_code_ERR;
    }

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if (op != cps_api_oper_SET) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-FLOOD-RESTRICT", "Invalid operation type %d", op);
        return cps_api_ret_code_ERR;
    }

    cps_api_key_t vlan_status_key;
    memset(&vlan_status_key, 0, sizeof(vlan_status_key));
    cps_api_key_from_attr_with_qual(&vlan_status_key, BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS,
                                    cps_api_qualifier_TARGET);
    bool bulk_mode = true;
    if (cps_api_key_matches(cps_api_object_key(obj), &vlan_status_key, true) == 0) {
        bulk_mode = false;
    }

    NAS_MC_LOG_DEBUG("NAS-MC-CPS-FLOOD-RESTRICT", "Set flood restrict for %s",
                     bulk_mode ? "VLAN list" : "specific VLAN");
    cps_api_object_attr_t attr;
    if (bulk_mode) {
        attr = cps_api_object_attr_get(obj, BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS);
        if (attr == nullptr) {
            NAS_MC_LOG_ERR("NAS-MC-CPS-FLOOD-RESTRICT", "VLAN status attribute not found");
        }
        cps_api_object_it_t itor;
        cps_api_object_it_from_attr(attr, &itor);
        for (cps_api_object_it_inside(&itor); cps_api_object_it_valid(&itor); cps_api_object_it_next(&itor)) {
            cps_api_object_it_t vlan_it = itor;
            hal_vlan_id_t vlan_id = 0;
            bool enable = false;
            bool vlan_id_found = false, status_found = false;
            for (cps_api_object_it_inside(&vlan_it); cps_api_object_it_valid(&vlan_it); cps_api_object_it_next(&vlan_it)) {
                auto attr_id = cps_api_object_attr_id(vlan_it.attr);
                if (attr_id == BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS_VLAN_ID) {
                    vlan_id = cps_api_object_attr_data_u32(vlan_it.attr);
                    vlan_id_found = true;
                } else if (attr_id == BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS_ENABLE) {
                    enable = static_cast<bool>(cps_api_object_attr_data_u32(vlan_it.attr));
                    status_found = true;
                }
            }
            if (vlan_id_found && status_found) {
                NAS_MC_LOG_DEBUG("NAS-MC-CPS-FLOOD-RESTRICT", "Set flood restrict of VLAN %d to %s",
                                 vlan_id, enable ? "enable" : "disable");
                nas_mc_set_flood_restrict(vlan_id, enable);
            }
        }
    } else {
        attr = cps_api_object_attr_get(obj, BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS_VLAN_ID);
        if (attr == nullptr) {
            NAS_MC_LOG_ERR("NAS-MC-CPS-FLOOD-RESTRICT", "VLAN ID attribute not found");
            return cps_api_ret_code_ERR;
        }
        hal_vlan_id_t vlan_id = cps_api_object_attr_data_u32(attr);
        attr = cps_api_object_attr_get(obj, BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS_ENABLE);
        if (attr == nullptr) {
            NAS_MC_LOG_ERR("NAS-MC-CPS-FLOOD-RESTRICT", "Enable attribute not found");
            return cps_api_ret_code_ERR;
        }
        bool enable = static_cast<bool>(cps_api_object_attr_data_u32(attr));
        NAS_MC_LOG_DEBUG("NAS-MC-CPS-FLOOD-RESTRICT", "Set flood restrict of VLAN %d to %s",
                         vlan_id, enable ? "enable" : "disable");
        nas_mc_set_flood_restrict(vlan_id, enable);
    }

    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_mc_flood_restrict_get(void* context, cps_api_get_params_t* param,
                                                       size_t ix)
{
    cps_api_object_list_t filters = param->filters;
    cps_api_object_t obj = cps_api_object_list_get(filters, ix);
    bool all_vlan;

    hal_vlan_id_t vlan_id = 0;
    auto attr = cps_api_object_attr_get(obj, BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS_VLAN_ID);
    if (attr == nullptr) {
        all_vlan = true;
        NAS_MC_LOG_DEBUG("NAS-MC-CPS-FLOOD-RESTRICT", "Get flood restrict status for all VLANs");
    } else {
        vlan_id = cps_api_object_attr_data_u32(attr);
        NAS_MC_LOG_DEBUG("NAS-MC-CPS-FLOOD-RESTRICT", "Get flood restrict status for VLAN %d",
                         vlan_id);
        all_vlan = false;
    }

    mc_flood_restr_status_t flood_restr_status{};
    nas_mc_get_flood_restrict_status(all_vlan, vlan_id, flood_restr_status);
    if (!all_vlan && flood_restr_status.find(vlan_id) == flood_restr_status.end()) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-FLOOD-RESTRICT", "Flood restrict was not configured for VLAN %d", vlan_id);
        return cps_api_ret_code_ERR;
    }

    for (auto& vlan_status: flood_restr_status) {
        cps_api_object_t obj = cps_api_object_list_create_obj_and_append(param->list);
        if (obj == nullptr) {
            NAS_MC_LOG_ERR("NAS-MC-CPS-FLOOD-RESTRICT", "Failed to create and append new object to list");
            continue;
        }
        if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj), BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS,
                                             cps_api_qualifier_TARGET)) {
            NAS_MC_LOG_ERR("NAS-MC-CPS-FLOOD-RESTRICT", "Failed to get object key from attribute ID");
            continue;
        }
        cps_api_object_attr_add_u16(obj, BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS_VLAN_ID, vlan_status.first);
        cps_api_object_attr_add_u32(obj, BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS_ENABLE, vlan_status.second);
    }

    return cps_api_ret_code_OK;
}

static t_std_error nas_mc_flood_restrict_handle_reg(void)
{
    cps_api_registration_functions_t f{};
    if (!cps_api_key_from_attr_with_qual(&f.key, BASE_L2_MCAST_FLOOD_RESTRICT_OBJ,
                                         cps_api_qualifier_TARGET)) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-CLEANUP", "Failed to get key for multicast flood restrict object");
        return STD_ERR(MCAST, FAIL, 0);
    }
    f.handle = nas_mc_cps_handle;
    f._read_function = nas_mc_flood_restrict_get;
    f._write_function = nas_mc_flood_restrict_handler;
    if (cps_api_register(&f) != cps_api_ret_code_OK) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-CLEANUP", "Failed to register cps callback for multicast flood restrict object accessing");
        return STD_ERR(MCAST, FAIL, 0);
    }

    return STD_ERR_OK;
}

t_std_error nas_mc_cps_init(void)
{
    NAS_MC_LOG_DEBUG("NAS-MC-CPS-INIT", "Initiating NAS multicast CPS serivce");

    // register event
    if (nas_mc_event_handle_reg() != STD_ERR_OK) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-INIT", "Failed to register event handler");
        return STD_ERR(MCAST, FAIL, 0);
    }
    NAS_MC_LOG_DEBUG("NAS-MC-CPS-INIT", "NAS multicast event handling registered");

    // cps handle init
    if (cps_api_operation_subsystem_init(&nas_mc_cps_handle, NUM_MC_CPS_API_THREAD) !=
        cps_api_ret_code_OK) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-INIT", "Failed to initiate cps subsystem");
        return STD_ERR(MCAST, FAIL, 0);
    }

    // register rpc handler
    if (nas_mc_cleanup_handle_reg() != STD_ERR_OK) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-INIT", "Failed to register cleanup handler");
        return STD_ERR(MCAST, FAIL, 0);
    }
    NAS_MC_LOG_DEBUG("NAS-MC-CPS-INIT", "NAS multicast cleanup handler registered");

    // register get handler
    if (nas_mc_get_handle_reg() != STD_ERR_OK) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-INIT", "Failed to register get handler");
        return STD_ERR(MCAST, FAIL, 0);
    }
    NAS_MC_LOG_DEBUG("NAS-MC-CPS-INIT", "NAS multicast get handler registered");

    // register flood restrict handler
    if (nas_mc_flood_restrict_handle_reg() != STD_ERR_OK) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-INIT", "Failed to register multicast flood restrict handler");
        return STD_ERR(MCAST, FAIL, 0);
    }
    NAS_MC_LOG_DEBUG("NAS-MC-CPS-INIT", "NAS multicast flood restrict handler registered");


    if (!std_str_to_ip("0.0.0.0", &ipv4_null_ip)) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-INIT", "Failed to convert NULL IPv4 string to data");
        memset(&ipv4_null_ip, 0, sizeof(ipv4_null_ip));
    }
    if (!std_str_to_ip("::", &ipv6_null_ip)) {
        NAS_MC_LOG_ERR("NAS-MC-CPS-INIT", "Failed to convert NULL IPv6 string to data");
        memset(&ipv6_null_ip, 0, sizeof(ipv6_null_ip));
    }

    return STD_ERR_OK;
}
