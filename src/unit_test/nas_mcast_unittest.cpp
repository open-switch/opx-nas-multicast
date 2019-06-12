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
 * filename: nas_mcast_unittest.cpp
 */

#include "gtest/gtest.h"

#include "cps_api_operation.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "cps_api_events.h"
#include "nas_types.h"
#include "dell-base-acl.h"
#include "dell-base-if.h"
#include "dell-base-if-vlan.h"
#include "dell-interface.h"
#include "ietf-igmp-mld-snooping.h"
#include "l2-multicast.h"
#include "l3-multicast.h"
#include "std_ip_utils.h"
#include "nas_mc_util.h"
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <stdio.h>
#include <arpa/inet.h>
#include <regex>
#include <algorithm>
#include <cctype>

using namespace std;

static const uint_t TEST_VID = 100;
static const string ROUTE_IF_NAME_1{"e101-001-0"};
static const string ROUTE_IF_NAME_2{"e101-005-0"};
static const string ROUTE_IF_NAME_3{"e101-006-0"};
static const string ROUTE_LAG_IF_NAME{"bond9"};
static const string LAG_IF_NAME_1{"e101-003-0"};
static const string LAG_IF_NAME_2{"e101-004-0"};
static unordered_set<string> TEST_NULL_LIST = {};
static unordered_set<string> TEST_GRP_IPV4 = {"228.0.0.8"};
static unordered_set<string> TEST_SRC_IPV4 = {"8.8.8.8"};
static unordered_set<string> TEST_GRP_IPV6 = {"ff0e::8888"};
static unordered_set<string> TEST_SRC_IPV6 = {"8888::8888"};
static unordered_set<string> TEST_GRP_IPV4_LIST = {"225.0.0.5", "225.0.0.6", "225.0.0.7"};
static unordered_set<string> TEST_SRC_IPV4_LIST = {"5.5.5.5", "6.6.6.6", "7.7.7.7"};
static unordered_set<string> TEST_GRP_IPV6_LIST = {"ff0e::5", "ff0e::6", "ff0e::7"};
static unordered_set<string> TEST_SRC_IPV6_LIST = {"5555::5555", "6666::6666", "7777::7777"};
static const string IGMP_MROUTER_IF_NAME{"e101-010-0"};
static const string MLD_MROUTER_IF_NAME{"e101-011-0"};
static const string IGMP_MROUTER_IF_NAME_1{"e101-012-0"};
static const string MLD_MROUTER_IF_NAME_1{"e101-013-0"};
static const uint_t IGMP_PROTO_ID = 2;
static const string L2VLAN_TYPE{"ianaift:l2vlan"};
static const string LAG_TYPE{"ianaift:ieee8023adLag"};

static const string KERNEL_CPU_IF_NAME{"npu-0"};
static const string SDK_CPU_IF_NAME{"cpu0"};

// Get all ACL tables that contain IP_PROTOCOL and OUTER_VLAN_ID types
// in its allowered filters list
static bool get_acl_tables(vector<nas_obj_id_t>& tbl_id_list, bool chk_vlan)
{
    cps_api_get_params_t gp;
    if (cps_api_get_request_init(&gp) != cps_api_ret_code_OK) {
        cout << "Failed to initiate cps reqeust" << endl;
        return false;
    }

    cps_api_object_t flt_obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if (flt_obj == nullptr) {
        cout << "Failed to append object to filter list" << endl;
        return false;
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(flt_obj),
                                         BASE_ACL_TABLE_OBJ,
                                         cps_api_qualifier_TARGET)) {
        cout << "Failed to generate object key" << endl;
        return false;
    }

    cps_api_object_t obj;
    if (cps_api_get(&gp) == cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);
        for (size_t ix = 0; ix < mx; ix ++) {
            obj = cps_api_object_list_get(gp.list, ix);
            cps_api_object_attr_t id_attr = cps_api_get_key_data(obj,
                                                    BASE_ACL_TABLE_ID);
            cps_api_object_attr_t stage_attr = cps_api_object_attr_get(obj,
                                                    BASE_ACL_TABLE_STAGE);
            if (id_attr == nullptr || stage_attr == nullptr) {
                cout << "ACL table object doesn't contian ID or stage attribute" << endl;
                continue;
            }
            BASE_ACL_STAGE_t stage =
                    static_cast<BASE_ACL_STAGE_t>(cps_api_object_attr_data_u32(stage_attr));
            if (stage != BASE_ACL_STAGE_INGRESS) {
                continue;
            }
            cps_api_object_it_t it;
            cps_api_object_it_begin(obj, &it);
            bool proto_flt_found = false, vlan_flt_found = false;
            while(cps_api_object_it_attr_walk(&it,
                                BASE_ACL_TABLE_ALLOWED_MATCH_FIELDS)) {
                BASE_ACL_MATCH_TYPE_t match_type =
                    static_cast<BASE_ACL_MATCH_TYPE_t>(cps_api_object_attr_data_u32(it.attr));
                if (match_type == BASE_ACL_MATCH_TYPE_IP_PROTOCOL) {
                    proto_flt_found = true;
                } else if (match_type == BASE_ACL_MATCH_TYPE_OUTER_VLAN_ID) {
                    vlan_flt_found = true;
                }
                if ((chk_vlan && proto_flt_found && vlan_flt_found) |
                    (!chk_vlan && proto_flt_found)) {
                    tbl_id_list.push_back(cps_api_object_attr_data_u64(id_attr));
                    break;
                }
                cps_api_object_it_next(&it);
            }
        }
    }

    cps_api_get_request_close(&gp);
    return true;
}

template<typename T>
static T get_attr_data_value(cps_api_object_attr_t attr)
{
    T data;

    if (is_same<T, uint8_t>::value) {
        data = ((uint8_t*)cps_api_object_attr_data_bin(attr))[0];
    } else if (is_same<T, uint16_t>::value) {
        data = cps_api_object_attr_data_u16(attr);
    } else if (is_same<T, uint32_t>::value) {
        data = cps_api_object_attr_data_u32(attr);
    } else if (is_same<T, uint64_t>::value) {
        data = cps_api_object_attr_data_u64(attr);
    } else {
        return static_cast<T>(0);
    }

    return data;
}

template<typename T>
static bool check_embedded_value(cps_api_object_attr_t attr,
                                 cps_api_attr_id_t data_id,
                                 cps_api_attr_id_t mask_id, T chk_val)
{
    cps_api_object_it_t sub_it;
    cps_api_object_it_from_attr(attr, &sub_it);
    cps_api_object_it_inside(&sub_it);
    auto data_attr = cps_api_object_it_find(&sub_it, data_id);
    if (data_attr == nullptr) {
        return false;
    }
    auto mask_attr = cps_api_object_it_find(&sub_it, mask_id);
    T data, mask = static_cast<T>(-1);
    data = get_attr_data_value<T>(data_attr);
    if (mask_attr != nullptr) {
        mask = get_attr_data_value<T>(mask_attr);
    }

    return (data & mask) == (chk_val & mask);
}

// An ACl entry was considered as IGMP Lifting rule if:
// 1. Contains one filter type IP_PROTOCOL with value 2 (IGMP)
// 2. Optionally contains filter type OUTER_VLAN_ID with value of specified VID
// 3. Contains no filter other than above
// 4. Contains ACL action type TRAP_TO_CPU
static bool check_acl_entry(cps_api_object_t entry_obj, bool chk_vlan, uint_t vid)
{
    cps_api_object_attr_t attr;
    cps_api_object_it_t attr_it;
    attr = cps_api_object_attr_get(entry_obj, BASE_ACL_ENTRY_MATCH);
    if (attr == nullptr) {
        cout << "Entry match attribute not exist" << endl;
        return false;
    }
    cps_api_object_it_from_attr(attr, &attr_it);
    bool proto_flt = false;
    bool vlan_flt = false;
    for (cps_api_object_it_inside(&attr_it);
         cps_api_object_it_valid(&attr_it);
         cps_api_object_it_next(&attr_it)) {
        cps_api_object_it_t match_it = attr_it;
        cps_api_object_it_inside(&match_it);
        attr = cps_api_object_it_find(&match_it, BASE_ACL_ENTRY_MATCH_TYPE);
        if (attr == nullptr) {
            cout << "Entry match type attribute not exist" << endl;
            return false;
        }
        BASE_ACL_MATCH_TYPE_t match_type =
            static_cast<BASE_ACL_MATCH_TYPE_t>(cps_api_object_attr_data_u32(attr));
        if (match_type == BASE_ACL_MATCH_TYPE_IP_PROTOCOL) {
            attr = cps_api_object_it_find(&match_it, BASE_ACL_ENTRY_MATCH_IP_PROTOCOL_VALUE);
            if (attr == nullptr) {
                cout << "IP protocol value attribute not exist" << endl;
                return false;
            }
            if (!check_embedded_value(attr,
                                      BASE_ACL_ENTRY_MATCH_IP_PROTOCOL_VALUE_DATA,
                                      BASE_ACL_ENTRY_MATCH_IP_PROTOCOL_VALUE_MASK,
                                      static_cast<uint8_t>(IGMP_PROTO_ID))) {
                return false;
            }
            proto_flt = true;
        } else if (match_type == BASE_ACL_MATCH_TYPE_OUTER_VLAN_ID && chk_vlan) {
            attr = cps_api_object_it_find(&match_it, BASE_ACL_ENTRY_MATCH_OUTER_VLAN_ID_VALUE);
            if (attr == nullptr) {
                cout << "Outer VLAN ID value attribute not exist" << endl;
                return false;
            }
            if (!check_embedded_value(attr,
                                      BASE_ACL_ENTRY_MATCH_OUTER_VLAN_ID_VALUE_DATA,
                                      BASE_ACL_ENTRY_MATCH_OUTER_VLAN_ID_VALUE_MASK,
                                      static_cast<uint16_t>(vid))) {
                return false;
            }
            vlan_flt = true;
        } else {
            return false;
        }
    }

    if (!proto_flt || (chk_vlan && !vlan_flt)) {
        return false;
    }

    attr = cps_api_object_attr_get(entry_obj, BASE_ACL_ENTRY_ACTION);
    if (attr == nullptr) {
        return false;
    }
    cps_api_object_it_from_attr(attr, &attr_it);

    for (cps_api_object_it_inside(&attr_it);
         cps_api_object_it_valid(&attr_it);
         cps_api_object_it_next(&attr_it)) {
        cps_api_object_it_t action_it = attr_it;
        cps_api_object_it_inside(&action_it);
        attr = cps_api_object_it_find(&action_it, BASE_ACL_ENTRY_ACTION_TYPE);
        if (attr == nullptr) {
            cout << "Action type attribute not exist" << endl;
            return false;
        }
        BASE_ACL_ACTION_TYPE_t action_type =
            static_cast<BASE_ACL_ACTION_TYPE_t>(cps_api_object_attr_data_u32(attr));
        if (action_type == BASE_ACL_ACTION_TYPE_PACKET_ACTION) {
            attr = cps_api_object_it_find(&action_it, BASE_ACL_ENTRY_ACTION_PACKET_ACTION_VALUE);
            if (attr == nullptr) {
                cout << "Packet action value not exist" << endl;
                return false;
            }
            BASE_ACL_PACKET_ACTION_TYPE_t act_type =
                static_cast<BASE_ACL_PACKET_ACTION_TYPE_t>(cps_api_object_attr_data_u32(attr));
            if (act_type == BASE_ACL_PACKET_ACTION_TYPE_TRAP_TO_CPU) {
                return true;
            }
        }

    }

    return false;
}

static bool check_igmp_lift_rule(nas_obj_id_t table_id, bool chk_vlan, hal_vlan_id_t vid,
                                 bool& rule_found)
{
    cps_api_get_params_t gp;
    if (cps_api_get_request_init(&gp) != cps_api_ret_code_OK) {
        return false;
    }

    cps_api_object_t flt_obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if (flt_obj == nullptr) {
        return false;
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(flt_obj),
                                         BASE_ACL_ENTRY_OBJ,
                                         cps_api_qualifier_TARGET)) {
        return false;
    }
    cps_api_set_key_data(flt_obj, BASE_ACL_ENTRY_TABLE_ID,
                         cps_api_object_ATTR_T_U64,
                         &table_id, sizeof(uint64_t));

    rule_found = false;
    if (cps_api_get(&gp) == cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);
        for (size_t ix = 0; ix < mx; ix ++) {
            auto obj = cps_api_object_list_get(gp.list, ix);
            if (check_acl_entry(obj, chk_vlan, vid)) {
                rule_found = true;
                break;
            }
        }
    }

    cps_api_get_request_close(&gp);
    return true;
}

static bool check_vlan_exists(hal_vlan_id_t vlan_id, string& br_name)
{
    cps_api_get_params_t gp;
    if (cps_api_get_request_init(&gp) != cps_api_ret_code_OK) {
        cout << "Failed to initiate cps reqeust" << endl;
        return false;
    }
    cps_api_get_request_guard grg(&gp);

    cps_api_object_t flt_obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if (flt_obj == nullptr) {
        cout << "Failed to append object to filter list" << endl;
        return false;
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(flt_obj),
                                         DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_OBJ,
                                         cps_api_qualifier_TARGET)) {
        cout << "Failed to generate object key" << endl;
        return false;
    }
    cps_api_object_attr_add(flt_obj, IF_INTERFACES_INTERFACE_TYPE,
                            L2VLAN_TYPE.c_str(), L2VLAN_TYPE.size() + 1);

    cps_api_object_t obj;
    if (cps_api_get(&gp) == cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);
        for (size_t ix = 0; ix < mx; ix ++) {
            obj = cps_api_object_list_get(gp.list, ix);
            auto vid_attr = cps_api_get_key_data(obj, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID);
            if (vid_attr == nullptr) {
                cout << "VID attribute not exist in VLAN object" << endl;
                continue;
            }
            hal_vlan_id_t vid = cps_api_object_attr_data_u16(vid_attr);
            if (vid == vlan_id) {
                auto name_attr = cps_api_get_key_data(obj, IF_INTERFACES_INTERFACE_NAME);
                if (name_attr == nullptr) {
                    cout << "Name attribute not exist in VLAN object, vid=" << vid << endl;
                    continue;
                }
                br_name = (char *)cps_api_object_attr_data_bin(name_attr);
                return true;
            }
        }
    }

    return false;
}

enum class intf_type
{
    LAG,
    VLAN
};

enum class oper_type
{
    CREATE,
    SET_MEMBER,
    DELETE
};

static bool set_vlan_or_lag_with_member(intf_type type, const string& name,
                                        const vector<string>& mbr_list,
                                        oper_type op, hal_vlan_id_t vlan_id = 0,
                                        bool tagged = false)
{
    cps_api_transaction_params_t trans;
    if (cps_api_transaction_init(&trans) != cps_api_ret_code_OK) {
        cout << "Failed to initiate cps transaction object" << endl;
        return false;
    }
    cps_api_object_t obj = cps_api_object_create();
    if (obj == nullptr) {
        cout << "Failed to create cps object" << endl;
        return false;
    }
    cps_api_object_guard obj_g(obj);
    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                         DELL_BASE_IF_CMN_SET_INTERFACE_OBJ,
                                         cps_api_qualifier_TARGET)) {
        cout << "Failed to generate object key" << endl;
        return false;
    }
    if (op == oper_type::CREATE) {
        cps_api_object_attr_add_u32(obj, DELL_BASE_IF_CMN_SET_INTERFACE_INPUT_OPERATION,
                                    DELL_BASE_IF_CMN_OPERATION_TYPE_CREATE);
        if (type == intf_type::VLAN) {
            cps_api_object_attr_add_u16(obj, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID, vlan_id);
            cps_api_object_attr_add_u32(obj, DELL_IF_IF_INTERFACES_INTERFACE_VLAN_TYPE,
                                        BASE_IF_VLAN_TYPE_DATA);
            cps_api_object_attr_add(obj, IF_INTERFACES_INTERFACE_TYPE, L2VLAN_TYPE.c_str(),
                                    L2VLAN_TYPE.size() + 1);
        } else {
            cps_api_object_attr_add(obj, IF_INTERFACES_INTERFACE_NAME,
                                    name.c_str(), name.size() + 1);
            cps_api_object_attr_add(obj, IF_INTERFACES_INTERFACE_TYPE, LAG_TYPE.c_str(),
                                    LAG_TYPE.size() + 1);
        }

    } else if (op == oper_type::SET_MEMBER) {
        cps_api_object_attr_add_u32(obj, DELL_BASE_IF_CMN_SET_INTERFACE_INPUT_OPERATION,
                                    DELL_BASE_IF_CMN_OPERATION_TYPE_UPDATE);
    } else if (op == oper_type::DELETE) {
        cps_api_object_attr_add_u32(obj, DELL_BASE_IF_CMN_SET_INTERFACE_INPUT_OPERATION,
                                    DELL_BASE_IF_CMN_OPERATION_TYPE_DELETE);
    } else {
        return false;
    }

    if (op == oper_type::SET_MEMBER || op == oper_type::DELETE) {
        cps_api_object_attr_add(obj, IF_INTERFACES_INTERFACE_NAME,
                                name.c_str(), name.size() + 1);
    }

    if (!mbr_list.empty()) {
        cps_api_attr_id_t list_index = 0;
        cps_api_attr_id_t lag_ids[3] = {DELL_IF_IF_INTERFACES_INTERFACE_MEMBER_PORTS};
        for (auto& if_name: mbr_list) {
            if (type == intf_type::VLAN) {
                if (tagged) {
                    cps_api_object_attr_add(obj, DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS,
                                            if_name.c_str(), if_name.size() + 1);
                } else {
                    cps_api_object_attr_add(obj, DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS,
                                            if_name.c_str(), if_name.size() + 1);
                }
            } else {
                lag_ids[1] = list_index;
                lag_ids[2] = DELL_IF_IF_INTERFACES_INTERFACE_MEMBER_PORTS_NAME;
                cps_api_object_e_add(obj, lag_ids, 3, cps_api_object_ATTR_T_BIN,
                                     if_name.c_str(), if_name.size() + 1);
                list_index ++;
            }
        }
    }

    obj_g.release();
    cps_api_transaction_guard tgd(&trans);
    cps_api_action(&trans, obj);
    if (cps_api_commit(&trans) != cps_api_ret_code_OK) {
        cout << "Failed to commit" << endl;
        return false;
    }

    return true;
}

bool check_vlan_member_exists(const string br_name, const string& if_name)
{
    cps_api_get_params_t gp;
    if (cps_api_get_request_init(&gp) != cps_api_ret_code_OK) {
        cout << "Failed to initiate cps reqeust" << endl;
        return false;
    }
    cps_api_get_request_guard grg(&gp);

    cps_api_object_t flt_obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if (flt_obj == nullptr) {
        cout << "Failed to append object to filter list" << endl;
        return false;
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(flt_obj),
                                         DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_OBJ,
                                         cps_api_qualifier_TARGET)) {
        cout << "Failed to generate object key" << endl;
        return false;
    }
    cps_api_object_attr_add(flt_obj, IF_INTERFACES_INTERFACE_NAME,
                            if_name.c_str(), if_name.size() + 1);

    if (cps_api_get(&gp) != cps_api_ret_code_OK) {
        cout << "Failed to read VLAN object" << endl;
        return false;
    }

    size_t mx = cps_api_object_list_size(gp.list);
    if (mx == 0) {
        cout << "No VLAN object returned for bridge " << if_name << endl;
        return false;
    }
    auto obj = cps_api_object_list_get(gp.list, 0);
    cps_api_object_it_t it;
    for (cps_api_object_it_begin(obj, &it); cps_api_object_it_valid(&it);
         cps_api_object_it_next(&it)) {
        auto attr_id = cps_api_object_attr_id(it.attr);
        if (attr_id == DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS ||
            attr_id == DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS) {
            string mbr_if_name = (char *)cps_api_object_attr_data_bin(it.attr);
            if (mbr_if_name == if_name) {
                return true;
            }
        }
    }

    return false;
}

static cps_api_event_service_handle_t evt_handle;
static bool evt_service_inited = false;

static bool event_service_init()
{
    if (cps_api_event_service_init() != cps_api_ret_code_OK) {
        return false;
    }
    if (cps_api_event_client_connect(&evt_handle) != cps_api_ret_code_OK) {
        return false;
    }
    evt_service_inited = true;
    return true;
}

static bool event_service_deinit()
{
    if (!evt_service_inited) {
        return true;
    }
    evt_service_inited = false;
    return (cps_api_event_client_disconnect(evt_handle) == cps_api_ret_code_OK);
}

static bool send_mc_update_event(hal_vlan_id_t vlan_id, const string& if_name,
                                 const unordered_set<string>& group_ip,
                                 const unordered_set<string>& src_ip,
                                 bool ipv4, bool mrouter, bool add)
{
    bool event_start_internal;
    if (!evt_service_inited) {
        if (!event_service_init()) {
            cout << "Failed to start event service" << endl;
            return false;
        }
        event_start_internal = true;
    } else {
        event_start_internal = false;
    }
    bool ret_val = false;
    do {
        cps_api_object_t obj = cps_api_object_create();
        if (obj == nullptr) {
            cout << "Failed to create cps object" << endl;
            break;
        }
        cps_api_attr_id_t key_id, vlan_attr_id, mr_if_attr_id, rt_if_attr_id, grp_id, gip_attr_id, src_id, srcip_attr_id;
        if (ipv4) {
            key_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN;
            vlan_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_VLAN_ID;
            mr_if_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE;
            rt_if_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_INTERFACE;
            grp_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP;
            gip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_ADDRESS;
            src_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_SOURCE;
            srcip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_SOURCE_ADDRESS;
        } else {
            key_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN;
            vlan_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_VLAN_ID;
            mr_if_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_MROUTER_INTERFACE;
            rt_if_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_INTERFACE;
            grp_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP;
            gip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_ADDRESS;
            src_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_SOURCE;
            srcip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_SOURCE_ADDRESS;
        }
        cps_api_object_guard og(obj);
        if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj), key_id,
                        cps_api_qualifier_OBSERVED)) {
            cout << "Failed to initiate object key" << endl;
            break;
        }
        cps_api_object_set_type_operation(cps_api_object_key(obj),
                                          add ? cps_api_oper_CREATE : cps_api_oper_DELETE);
        cps_api_object_attr_add_u16(obj, vlan_attr_id, vlan_id);
        if (mrouter) {
            if (!cps_api_object_attr_add(obj, mr_if_attr_id, if_name.c_str(), if_name.size() + 1)) {
                cout << "Failed to set mrouter interface name" << endl;
                break;
            }
        } else {
            if (group_ip.empty()) {
                cps_api_attr_id_t ids[3] = {grp_id, 0, rt_if_attr_id};
                if (!cps_api_object_e_add(obj, ids, 3, cps_api_object_ATTR_T_BIN, if_name.c_str(), if_name.size() + 1)) {
                    cout << "Failed to set mc entry interface name" << endl;
                    break;
                }
            } else {
                size_t grp_attr_idx = 0;
                for (auto& grp_ip_addr: group_ip) {
                    cps_api_attr_id_t ids[3] = {grp_id, grp_attr_idx, rt_if_attr_id};
                    if (if_name.length() > 0) {
                        if (!cps_api_object_e_add(obj, ids, 3, cps_api_object_ATTR_T_BIN, if_name.c_str(), if_name.size() + 1)) {
                            cout << "Failed to set mc entry interface name" << endl;
                            break;
                        }
                    }
                    ids[2] = gip_attr_id;
                    if (!cps_api_object_e_add(obj, ids, 3, cps_api_object_ATTR_T_BIN, grp_ip_addr.c_str(), grp_ip_addr.size() + 1)) {
                        cout << "Failed to set mc entry group IP address" << endl;
                        break;
                    }
                    size_t src_attr_idx = 0;
                    for (auto& src_ip_addr: src_ip) {
                        cps_api_attr_id_t srcip_ids[5] = {grp_id, grp_attr_idx, src_id, src_attr_idx, srcip_attr_id};
                        if (!cps_api_object_e_add(obj, srcip_ids, 5, cps_api_object_ATTR_T_BIN, src_ip_addr.c_str(), src_ip_addr.size() + 1)) {
                            cout << "Failed to set mc entry src IP address" << endl;
                            break;
                        }
                        src_attr_idx ++;
                    }
                    grp_attr_idx ++;
                }
            }
        }
        if (cps_api_event_publish(evt_handle, obj) != cps_api_ret_code_OK) {
            cout << "Failed to publish event" << endl;
            break;
        }
        ret_val = true;
    } while(0);

    if (event_start_internal) {
        event_service_deinit();
    }

    return ret_val;
}

static bool send_mc_update_pim_status(hal_vlan_id_t vlan_id, bool ipv4, bool status)
{
    return send_mc_update_event(vlan_id, KERNEL_CPU_IF_NAME, unordered_set<string>{}, unordered_set<string>{},
                                ipv4, false, status);
}

static bool is_ipv4_addr(const string& ip_addr)
{
    struct in_addr addr;
    return inet_pton(AF_INET, ip_addr.c_str(), &addr);
}

static bool is_ipv6_addr(const string& ip_addr)
{
    struct in6_addr addr;
    return inet_pton(AF_INET6, ip_addr.c_str(), &addr);
}

static const string dump_ip_to_string(const hal_ip_addr_t& ip_addr)
{
    char ip_buf[512];
    auto* ip_str = std_ip_to_string(&ip_addr, ip_buf, sizeof(ip_buf));
    if (ip_str == nullptr) {
        return "-";
    }
    return ip_str;
}

struct mc_entry_common
{
    hal_vlan_id_t vlan_id;
    hal_ip_addr_t src_ip;
    hal_ip_addr_t mc_ip;
    uint32_t group_id;

    mc_entry_common(hal_vlan_id_t vid, hal_ip_addr_t sip, hal_ip_addr_t dip, uint32_t gid) :
        vlan_id(vid), src_ip(sip), mc_ip(dip), group_id(gid) {}

    mc_entry_common() = default;

    void dump(ostream& os) const
    {
        os << "--------- multicast entry ---------" << endl;
        os << "  VLAN ID      : " << vlan_id << endl;
        os << "  Source IP    : " << dump_ip_to_string(src_ip) << endl;
        os << "  MC IP        : " << dump_ip_to_string(mc_ip) << endl;
        os << "  Group ID     : " << hex << showbase << group_id << dec << noshowbase << endl;
        os << "  Member Ports : ";
    }
};

struct igmp_mld_entry : public mc_entry_common
{
    set<string> port_list;

    igmp_mld_entry(hal_vlan_id_t vid, hal_ip_addr_t sip, hal_ip_addr_t dip, uint32_t gid,
                   const set<string>& plist = {}) : mc_entry_common(vid, sip, dip, gid), port_list(plist)
    {}

    igmp_mld_entry() = default;

    void dump(ostream& os) const
    {
        mc_entry_common::dump(os);
        for (auto& port: port_list) {
            os << port << ",";
        }
        os << endl;
        os << "-----------------------------------" << endl;
    }
};

using ipmc_port_list_t = unordered_map<int, set<string>>;

struct ipmc_entry_t : public mc_entry_common
{
    ipmc_port_list_t port_list;

    ipmc_entry_t(hal_vlan_id_t vid, hal_ip_addr_t sip, hal_ip_addr_t dip, uint32_t gid,
                   const ipmc_port_list_t& plist = {}) : mc_entry_common(vid, sip, dip, gid), port_list(plist)
    {}

    ipmc_entry_t() = default;

    void dump(ostream& os) const
    {
        mc_entry_common::dump(os);
        for (auto& port: port_list) {
            os << "encap " << port.first << ": ";
            for (auto& port_name: port.second) {
                os << port_name << ",";
            }
            os << " ";
        }
        os << endl;
        os << "-----------------------------------" << endl;
    }
};

enum class line_mark_t
{
    NONE,
    START,
    END,
};

using line_check_func_t = function<line_mark_t(string)>;
template<typename T>
using handler_func_t = bool(*)(const vector<string>&, vector<T>&);
static line_mark_t igmp_entry_check(const string& line)
{
    istringstream iss(line);
    vector<string> tokens{istream_iterator<string>(iss), {}};
    if (tokens.size() < 9) {
        return line_mark_t::NONE;
    }
    if (!is_ipv4_addr(tokens[0]) || !is_ipv4_addr(tokens[1])) {
        return line_mark_t::NONE;
    }

    return line_mark_t::START;
}

template<typename T>
static bool igmp_entry_proc(const vector<string>& line_list, vector<T>& entry_list)
{
    if (line_list.empty()) {
        return false;
    }
    istringstream iss(line_list[0]);
    vector<string> tokens{istream_iterator<string>(iss), {}};
    T igmp_entry;
    if (!std_str_to_ip(tokens[0].c_str(), &igmp_entry.src_ip)) {
        cout << "Invalid source IP: " << tokens[0] << endl;
        return false;
    }
    if (!std_str_to_ip(tokens[1].c_str(), &igmp_entry.mc_ip)) {
        cout << "Invalid multicast IP: " << tokens[1] << endl;
        return false;
    }

    igmp_entry.vlan_id = stoi(tokens[2]);
    igmp_entry.group_id = stoul(tokens[8], 0, 16);
    entry_list.push_back(igmp_entry);

    return true;
}

static line_mark_t mld_entry_check(const string& line)
{
    const string start_tag = "SRC IP ADDRESS: ";
    if (line.compare(0, start_tag.size(), start_tag) == 0) {
        return line_mark_t::START;
    }
    return line_mark_t::NONE;
}

static void right_trim(string& in_str)
{
    string t{" \t\n\r"};
    in_str.erase(in_str.find_last_not_of(t) + 1);
}

template<typename T>
static bool mld_entry_proc(const vector<string>& line_list, vector<T>& entry_list)
{
    const string src_ip_tag = "SRC IP ADDRESS: ";
    const string mc_ip_tag = "MC  IP ADDRESS: ";
    if (line_list.size() < 4) {
        cout << "Invalid line count for MLD entry" << endl;
        return false;
    }

    T igmp_entry;
    if (line_list[0].compare(0, src_ip_tag.size(), src_ip_tag) != 0) {
        cout << "Invalid line format: " << line_list[0] << endl;
        return false;
    }
    auto src_ip_str = line_list[0].substr(src_ip_tag.size());
    right_trim(src_ip_str);
    if (!is_ipv6_addr(src_ip_str)) {
        cout << "Invalid ipv6 address: " << src_ip_str << endl;
        return false;
    }
    if (!std_str_to_ip(src_ip_str.c_str(), &igmp_entry.src_ip)) {
        return false;
    }
    auto mc_ip_str = line_list[1].substr(mc_ip_tag.size());
    right_trim(mc_ip_str);
    if (!is_ipv6_addr(mc_ip_str)) {
        cout << "Invalid ipv6 address: " << mc_ip_str << endl;
        return false;
    }
    if (!std_str_to_ip(mc_ip_str.c_str(), &igmp_entry.mc_ip)) {
        return false;
    }
    istringstream iss(line_list[3]);
    vector<string> tokens{istream_iterator<string>(iss), {}};
    if (tokens.size() < 7) {
        return false;
    }
    igmp_entry.vlan_id = stoi(tokens[0]);
    igmp_entry.group_id = stoul(tokens[6], 0, 16);
    entry_list.push_back(igmp_entry);

    return true;
}
static line_mark_t mc_group_check(const string& line)
{
    const string start_tag = "Group ";
    if (line.compare(0, start_tag.size(), start_tag) == 0) {
        return line_mark_t::START;
    }
    return line_mark_t::NONE;
}

static bool parse_group_lines(const vector<string>& line_list, uint32_t& group_id,
                              vector<string>& port_list)
{
    if (line_list.empty()) {
        return false;
    }
    istringstream iss{line_list[0]};
    vector<string> tokens{istream_iterator<string>(iss), {}};
    if (tokens.size() < 3) {
        return false;
    }
    group_id = stoul(tokens[1], 0, 16);

    for (size_t idx = 1; idx < line_list.size(); idx ++) {
        istringstream iss{line_list[idx]};
        vector<string> tokens{istream_iterator<string>{iss}, {}};
        if (tokens.size() < 2) {
            continue;
        }
        auto port_name = tokens[1];
        if (port_name.back() == ',') {
            port_name.erase(port_name.size() - 1);
        }
        port_list.push_back(port_name);
    }
    return true;
}

static bool mc_group_proc(const vector<string>& line_list, vector<igmp_mld_entry>& entry_list)
{
    uint32_t group_id = 0;
    vector<string> port_list;
    if (!parse_group_lines(line_list, group_id, port_list)) {
        return false;
    }

    if (!port_list.empty()) {
        for (auto& entry: entry_list) {
            if (entry.group_id == group_id) {
                for (auto& port: port_list) {
                    entry.port_list.insert(port);
                }
            }
        }
    }

    return true;
}

static bool mc_group_proc_all(const vector<string>& line_list, vector<igmp_mld_entry>& entry_list)
{
    uint32_t group_id = 0;
    vector<string> port_list;
    if (!parse_group_lines(line_list, group_id, port_list)) {
        return false;
    }

    if (!port_list.empty() && (group_id != 0x1000001)) {
        igmp_mld_entry entry{0, hal_ip_addr_t{}, hal_ip_addr_t{}, group_id};
        for (auto& port: port_list) {
            entry.port_list.insert(port);
        }
        entry_list.push_back(entry);
    }

    return true;
}

static vector<igmp_mld_entry> mc_entry_list;
static vector<ipmc_entry_t> ipmc_entry_list;

template<typename T>
struct ut_entry_impl
{
};

template<>
struct ut_entry_impl<igmp_mld_entry>
{
    static vector<igmp_mld_entry>& get_entry_list(){return mc_entry_list;}
};

template<>
struct ut_entry_impl<ipmc_entry_t>
{
    static vector<ipmc_entry_t>& get_entry_list(){return ipmc_entry_list;}
};

template<typename T = igmp_mld_entry>
bool run_command(const string& cmd, line_check_func_t check_func, handler_func_t<T> proc_func)
{
    FILE *fp = popen(cmd.c_str(), "r");
    char lnbuf[512];
    if (fp == nullptr) {
        cout << "Failed to open file to run command" << endl;
        return false;
    }

    bool started = false;
    vector<string> line_buf;
    string s;
    auto& entry_list = ut_entry_impl<T>::get_entry_list();
    while(fgets(lnbuf, 512, fp)) {
        s = string{lnbuf};
        auto ret_val = check_func(s);
        if (started) {
            if (ret_val == line_mark_t::NONE) {
                line_buf.push_back(s);
                continue;
            }
            if (ret_val == line_mark_t::END) {
                line_buf.push_back(s);
                started = false;
            }
            if (!proc_func(line_buf, entry_list)) {
                cout << "Failed to process mcast entry" << endl;
                pclose(fp);
                return false;
            }
            line_buf.clear();
            if (ret_val == line_mark_t::START) {
                line_buf.push_back(s);
            }
        } else {
            if (ret_val == line_mark_t::NONE) {
                continue;
            } else if (ret_val == line_mark_t::START) {
                line_buf.push_back(s);
                started = true;
            } else {
                cout << "Invalid line format" << endl;
                continue;
            }
        }
    }
    if (started) {
        if (!proc_func(line_buf, entry_list)) {
            cout << "Failed to process mcast entry" << endl;
            pclose(fp);
            return false;
        }
    }
    pclose(fp);
    return true;
}

template<typename T = igmp_mld_entry>
static void dump_mc_entry_list()
{
    auto& entry_list = ut_entry_impl<T>::get_entry_list();
    for (auto& entry: entry_list) {
        entry.dump(cout);
    }
}

// Give vlan_id as 0 to delete all VLANs
// Give empty interface name to delete entries of specific VLAN
static void cleanup_intf_l2mc_config(hal_vlan_id_t vlan_id, const string& if_name)
{
    cps_api_transaction_params_t params;
    cps_api_object_t             obj;
    cps_api_key_t                keys;

    if (vlan_id == 0 && if_name.empty()) {
        ASSERT_TRUE(false);
    }

    ASSERT_TRUE((obj = cps_api_object_create()) != NULL);
    cps_api_object_guard obj_g (obj);
    ASSERT_TRUE(cps_api_transaction_init(&params) == cps_api_ret_code_OK);

    cps_api_transaction_guard tgd(&params);
    cps_api_key_from_attr_with_qual(&keys, BASE_L2_MCAST_CLEANUP_L2MC_MEMBER_OBJ,
                                    cps_api_qualifier_TARGET);
    cps_api_object_set_key(obj, &keys);
    if (!if_name.empty()) {
        cps_api_object_attr_add(obj, BASE_L2_MCAST_CLEANUP_L2MC_MEMBER_INPUT_IFNAME,
                                if_name.c_str(), if_name.length() + 1);
    }
    if (vlan_id != 0) {
        cps_api_object_attr_add_u32(obj,  BASE_L2_MCAST_CLEANUP_L2MC_MEMBER_INPUT_VLAN_ID, vlan_id);
    }

    ASSERT_TRUE(cps_api_action(&params, obj) == cps_api_ret_code_OK);

    obj_g.release();
    ASSERT_TRUE(cps_api_commit(&params) == cps_api_ret_code_OK);
}

static bool check_shared_group_entry_int(bool ipv4, size_t exp_entry_num, size_t exp_grp_num,
                                         const unordered_set<size_t>& exp_mbr_port_num,
                                         bool copy_to_cpu,
                                         ostringstream& err_msg)
{
    mc_entry_list.clear();
    err_msg.str("");
    if (ipv4) {
        if (!run_command("hshell -c \"ipmc table show\"", igmp_entry_check, igmp_entry_proc)) {
            err_msg << "Failure on running show ipmc table command" << endl;
            return false;
        }
    } else {
        if (!run_command("hshell -c \"ipmc ip6table show\"", mld_entry_check, mld_entry_proc)) {
            err_msg << "Failure on running show ipmc ip6table command" << endl;
            return false;
        }
    }
    if (mc_entry_list.size() != exp_entry_num) {
        err_msg << "There are " << mc_entry_list.size() << " entries, not equal to expected entry number "
                << exp_entry_num << endl;
        return false;
    }
    if (exp_entry_num == 0) {
        return true;
    }
    if (!run_command("hshell -c \"mc show\"", mc_group_check, mc_group_proc)) {
        err_msg << "Failure on running show multicast command" << endl;
        return false;
    }
    unordered_map<uint32_t, size_t> grp_list{};
    for (auto& entry: mc_entry_list) {
        size_t port_cnt = entry.port_list.size();
        if (exp_mbr_port_num.find(port_cnt) == exp_mbr_port_num.end()) {
            err_msg << "Member port number " << port_cnt << " of group " << hex << showbase
                    << entry.group_id << dec << noshowbase
                    << " is not in expected list" << endl;
            err_msg << "Expected list: ";
            for (auto exp_num: exp_mbr_port_num) {
                err_msg << exp_num << ",";
            }
            err_msg << endl;
            return false;
        }
        bool has_cpu_port = false;
        for (auto& port_name: entry.port_list) {
            if (port_name == SDK_CPU_IF_NAME) {
                has_cpu_port = true;
                break;
            }
        }
        if (has_cpu_port != copy_to_cpu) {
            err_msg << "Copy to cpu status mis-match" << endl;
            return false;
        }
        if (grp_list.find(entry.group_id) == grp_list.end()) {
            grp_list.insert(make_pair(entry.group_id, port_cnt));
        } else {
            if (port_cnt != grp_list.at(entry.group_id)) {
                err_msg << "Member port number " << port_cnt << " of group " << hex << showbase
                        << entry.group_id << dec << noshowbase
                        << "is not equal to " << grp_list.at(entry.group_id) << " in cache" << endl;
                return false;
            }
        }
    }
    if (grp_list.size() != exp_grp_num) {
        err_msg << "There are " <<grp_list.size() << " groups, not equal to expected group number "
                << exp_grp_num << endl;
        return false;
    }

    return true;
}

const int MAX_CHECK_COUNT = 20;

static bool check_shared_group_entry(bool ipv4, size_t exp_entry_num = 0, size_t exp_grp_num = 0,
                                     const unordered_set<size_t>& exp_mbr_port_num = {},
                                     bool copy_to_cpu = false)
{
    int check_cnt = 0;
    ostringstream ss;
    while(check_cnt < MAX_CHECK_COUNT) {
        sleep(2);
        if (check_shared_group_entry_int(ipv4, exp_entry_num, exp_grp_num, exp_mbr_port_num,
                                         copy_to_cpu, ss)) {
            return true;
        }
        check_cnt ++;
    }

    cout << "Failure validating multicast entry" << endl;
    cout << ss.str() << endl;
    cout << "Current multicast entires:" << endl;
    dump_mc_entry_list();
    return false;
}

static bool check_shared_group(size_t exp_grp_num, const unordered_set<size_t>& exp_mbr_port_num = {})
{
    int check_cnt = 0;
    while (check_cnt < MAX_CHECK_COUNT) {
        sleep(2);
        mc_entry_list.clear();
        if (!run_command("hshell -c \"mc show\"", mc_group_check, mc_group_proc_all)) {
            cout << "Failure on running show multicast command" << endl;
            return false;
        }
        if (mc_entry_list.size() == exp_grp_num) {
            bool matched = true;
            for (auto& entry: mc_entry_list) {
                auto grp_size = entry.port_list.size();
                if (exp_mbr_port_num.find(grp_size) == exp_mbr_port_num.end()) {
                    matched = false;
                    break;
                }
            }
            if (matched) {
                return true;
            }
        }
        check_cnt ++;
    }
    cout << "Failure validating group" << endl;
    cout << "Group number: " << mc_entry_list.size() << " Expected number: " << exp_grp_num << endl;
    cout << "Group member number: ";
    for (auto& entry: mc_entry_list) {
        cout << entry.port_list.size() << " ";
    }
    cout << endl;
    cout << "Expected member number: ";
    for (auto mbr_num: exp_mbr_port_num) {
        cout << mbr_num << " ";
    }
    cout << endl;
    cout << "Current multicast entires:" << endl;
    dump_mc_entry_list();
    return false;
}

static bool check_group_clear()
{
    return check_shared_group(0);
}

template<typename T>
using check_func_t = bool (*)(uint32_t, const cps_api_object_list_t&, const T&);

template<typename T>
bool get_mc_group(bool ipv4, bool star_g, hal_vlan_id_t* vlan_id, string* group_ip,
                  string* source_ip, check_func_t<T> check_cb, const T& check_data)
{
    cps_api_attr_id_t key_id, vlan_attr_id, gip_attr_id, sip_attr_id;
    const char *all_ip;
    uint32_t af;
    if (ipv4) {
        key_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP;
        vlan_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_VLAN_ID;
        gip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_ADDRESS;
        sip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_SOURCE_ADDRESS;
        all_ip = "0.0.0.0";
        af = AF_INET;
    } else {
        key_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP;
        vlan_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_VLAN_ID;
        gip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_ADDRESS;
        sip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_SOURCE_ADDRESS;
        all_ip = "::";
        af = AF_INET6;
    }
    cps_api_get_params_t gp;
    if (cps_api_get_request_init(&gp) != cps_api_ret_code_OK) {
        return false;
    }
    bool ret_val = false;
    do {
        cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
        if (obj == nullptr) {
            break;
        }

        if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj), key_id, cps_api_qualifier_OBSERVED)) {
            break;
        }
        if (vlan_id != nullptr) {
            cps_api_object_attr_add_u16(obj, vlan_attr_id, *vlan_id);
        }
        if (group_ip != nullptr) {
            cps_api_object_attr_add(obj, gip_attr_id, group_ip->c_str(), group_ip->length() + 1);
        }
        if (!star_g) {
            if (source_ip != nullptr) {
                cps_api_object_attr_add(obj, sip_attr_id, source_ip->c_str(), source_ip->length() + 1);
            } else {
                cps_api_object_attr_add(obj, sip_attr_id, all_ip, strlen(all_ip) + 1);
            }
        }
        if (cps_api_get(&gp) != cps_api_ret_code_OK) {
            break;
        }

        ret_val = check_cb(af, gp.list, check_data);
    } while(0);

    cps_api_get_request_close(&gp);
    return ret_val;
}

struct mc_ut_empty_data_t
{};

static bool check_empty_route_list(uint32_t af, const cps_api_object_list_t& obj_list, const mc_ut_empty_data_t& data)
{
    return cps_api_object_list_size(obj_list) == 0;
}

struct mc_ut_route_key_t
{
    hal_vlan_id_t vlan_id;
    string group_ip;
    string oif_name;

    operator string() const
    {
        ostringstream ss;
        ss << "[VID " << vlan_id << " GRP " << group_ip;
        ss << " OIF ";
        if (oif_name.empty()) {
            ss << "-";
        } else {
            ss << oif_name;
        }
        ss << "]";
        return ss.str();
    }
};

struct _ut_route_key_hash
{
    size_t operator()(const mc_ut_route_key_t& key) const
    {
        size_t h_val = hash<int>()(key.vlan_id);
        h_val <<= 1;
        h_val ^= hash<string>()(key.group_ip);
        h_val <<= 1;
        h_val ^= hash<string>()(key.oif_name);
        return h_val;
    }
};

struct _ut_route_key_equal
{
    bool operator()(const mc_ut_route_key_t& k1, const mc_ut_route_key_t& k2) const
    {
        return k1.vlan_id == k2.vlan_id && k1.group_ip == k2.group_ip && k1.oif_name == k2.oif_name;
    }
};

using mc_ut_route_list_t = unordered_map<mc_ut_route_key_t, unordered_set<string>, _ut_route_key_hash, _ut_route_key_equal>;

static bool check_route_list(uint32_t af, const cps_api_object_list_t& obj_list, const mc_ut_route_list_t& check_list)
{
    cps_api_attr_id_t vlan_attr_id, gip_attr_id, oif_attr_id, src_attr_id, sip_attr_id;
    if (af == AF_INET) {
        gip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_ADDRESS;
        vlan_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_VLAN_ID;
        src_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_SOURCE;
        sip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_SOURCE_ADDRESS;
        oif_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_IGMP_SNOOPING_VLANS_VLAN_GROUP_INTERFACE;
    } else if (af == AF_INET6) {
        gip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_ADDRESS;
        vlan_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_VLAN_ID;
        src_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_SOURCE;
        sip_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_SOURCE_ADDRESS;
        oif_attr_id = IGMP_MLD_SNOOPING_RT_ROUTING_STATE_CONTROL_PLANE_PROTOCOLS_MLD_SNOOPING_VLANS_VLAN_GROUP_INTERFACE;
    } else {
        cout << "Un-supported AF type " << af << endl;
        return false;
    }

    size_t mx = cps_api_object_list_size(obj_list);
    cps_api_object_attr_t attr;
    for (size_t ix = 0; ix < mx; ix ++) {
        auto cps_obj = cps_api_object_list_get(obj_list, ix);
        attr = cps_api_get_key_data(cps_obj, vlan_attr_id);
        if (attr == nullptr) {
            cout << "Failed to get VLAN ID attribute from cps object" << endl;
            return false;
        }
        auto vlan_id = cps_api_object_attr_data_u16(attr);
        attr = cps_api_get_key_data(cps_obj, gip_attr_id);
        if (attr == nullptr) {
            cout << "Failed to get group IP attribute from cps object" << endl;
            return false;
        }
        const char* group_ip = (char*)cps_api_object_attr_data_bin(attr);
        const char* oif_name = "";
        attr = cps_api_get_key_data(cps_obj, oif_attr_id);
        if (attr != nullptr) {
            oif_name = (char*)cps_api_object_attr_data_bin(attr);
        }
        mc_ut_route_key_t route_key{vlan_id, group_ip, oif_name};
        cout << "Checking route " << string(route_key) << " ... ";
        if (check_list.find(route_key) == check_list.end()) {
            cout << "Route key " << string(route_key) << " not found in check list" << endl;
            return false;
        }
        auto& check_src_list = check_list.at(route_key);
        attr = cps_api_get_key_data(cps_obj, src_attr_id);
        if (attr == nullptr) {
            if (check_src_list.find("") == check_src_list.end()) {
                cout << "Route " << string(route_key) << " is not (*,G)" << endl;
                return false;
            }
            cout << "SRC * OK" << endl;
            continue;
        }
        // check on all sources in cps object
        cps_api_object_it_t itor;
        cps_api_object_it_from_attr(attr, &itor);
        cps_api_object_it_inside(&itor);
        size_t src_ip_cnt = 0;
        cout << "SRC ";
        for (; cps_api_object_it_valid(&itor); cps_api_object_it_next(&itor)) {
            cps_api_object_it_t src_it = itor;
            cps_api_object_it_inside(&src_it);
            for (; cps_api_object_it_valid(&src_it); cps_api_object_it_next(&src_it)) {
                cps_api_attr_id_t sub_attr_id = cps_api_object_attr_id(src_it.attr);
                if (sub_attr_id == sip_attr_id) {
                    const char* src_ip_str = (char*)cps_api_object_attr_data_bin(src_it.attr);
                    cout << src_ip_str << ",";
                    if (check_src_list.find(src_ip_str) == check_src_list.end()) {
                        cout << "Source list of route " << string(route_key) << " does not contain IP " << src_ip_str << endl;
                        return false;
                    }
                    src_ip_cnt ++;
                }
            }
        }
        size_t check_src_cnt = check_src_list.size();
        if (check_src_list.find("") != check_src_list.end()) {
            // Including (*,G)
            check_src_cnt --;
        }
        if (check_src_cnt != src_ip_cnt) {
            cout << "Number of source of route " << string(route_key) << " is " << src_ip_cnt << " not equal to check number "
                 << check_src_cnt << endl;
            return false;
        }
        cout << " OK" << endl;
    }

    return true;
}

static bool send_mc_route_update_event(const mc_ut_route_list_t& route_list, bool is_add)
{
    for (auto& route_info: route_list) {
        hal_ip_addr_t ip_addr;
        if (!std_str_to_ip(route_info.first.group_ip.c_str(), &ip_addr)) {
            cout << "Invalid IP format: " << route_info.first.group_ip << endl;
            return false;
        }
        if (ip_addr.af_index != AF_INET && ip_addr.af_index != AF_INET6) {
            cout << "Un-supported AF index " << ip_addr.af_index << endl;
            return false;
        }
        cout << "Request to ";
        if (is_add) {
            cout << "add";
        } else {
            cout << "delete";
        }
        cout << " route: " << string(route_info.first) << " SRC ";
        unordered_set<string> src_ip_list{};
        for (auto& src_ip: route_info.second) {
            if (src_ip.empty()) {
                cout << "-" << endl;
                if (!send_mc_update_event(route_info.first.vlan_id, route_info.first.oif_name, {route_info.first.group_ip},
                                          {}, ip_addr.af_index == AF_INET, false, is_add)) {
                    cout << "Failed to send (*,G) event" << endl;
                    return false;
                }
            } else {
                cout << src_ip << ",";
                src_ip_list.insert(src_ip);
            }
        }
        cout << endl;
        if (!src_ip_list.empty()) {
            if (!send_mc_update_event(route_info.first.vlan_id, route_info.first.oif_name, {route_info.first.group_ip},
                                      src_ip_list, ip_addr.af_index == AF_INET, false, is_add)) {
                cout << "Failed to send (S,G) event" << endl;
                return false;
            }
        }
    }
    return true;
}

// match: igmp, action: trap_to_cpu
TEST(nas_mc_acl, acl_rule_check)
{
    bool chk_vlan = true;
    vector<nas_obj_id_t> chk_table_ids{};
    ASSERT_TRUE(get_acl_tables(chk_table_ids, chk_vlan));
    bool found = false;
    for (auto table_id: chk_table_ids) {
        cout << "Checking on ACL table: " << table_id << endl;
        ASSERT_TRUE(check_igmp_lift_rule(table_id, chk_vlan, TEST_VID, found));
        if (found) {
            cout << "Found ACL rule to lift IGMP packets of VLAN " << TEST_VID << endl;
            break;
        }
    }
    if (!found && chk_vlan) {
        chk_vlan = false;
        cout << "Could not find table with VLAN and IP_PROTOCOl filters" << endl;
        cout << "Try to search for table with IP_PROTOCOL filter only" << endl;
        chk_table_ids.clear();
        ASSERT_TRUE(get_acl_tables(chk_table_ids, chk_vlan));
        for (auto table_id: chk_table_ids) {
            cout << "Checking on ACL table: " << table_id << endl;
            ASSERT_TRUE(check_igmp_lift_rule(table_id, chk_vlan, 0, found));
            if (found) {
                cout << "Found ACL rule to lift IGMP packets of all VLANs" << endl;
                break;
            }
        }
    }

    ASSERT_TRUE(found);
}

TEST(nas_mc_init, create_lag_and_member)
{
    ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::LAG, ROUTE_LAG_IF_NAME,
                                            {LAG_IF_NAME_1, LAG_IF_NAME_2},
                                            oper_type::CREATE));
}

TEST(nas_mc_init, create_vlan_and_member)
{
    string br_name{};
    vector<string> member_list{ROUTE_IF_NAME_1, ROUTE_IF_NAME_2, ROUTE_IF_NAME_3,
                               IGMP_MROUTER_IF_NAME, MLD_MROUTER_IF_NAME,
                               IGMP_MROUTER_IF_NAME_1, MLD_MROUTER_IF_NAME_1,
                               ROUTE_LAG_IF_NAME};
    if (!check_vlan_exists(TEST_VID, br_name)) {
        ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::VLAN, {},
                                                member_list,
                                                oper_type::CREATE, TEST_VID));
        ASSERT_TRUE(check_vlan_exists(TEST_VID, br_name));
        cout << "VLAN bridge " << br_name << " is created" << endl;
        return;
    }
    cout << "Bridge " << br_name << " of VLAN " << TEST_VID << " exists" << endl;
    ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::VLAN, br_name, member_list,
                                            oper_type::SET_MEMBER));
}

TEST(nas_mc_event, init_event_service)
{
    ASSERT_TRUE(event_service_init());
}

TEST(nas_mc_oif, send_mrouter_add_event_before)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, true, true, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, false, true, true));
}

TEST(nas_mc_oif, send_ipv4_route_add_event)
{
    // (*, G)
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4, TEST_NULL_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV4, TEST_NULL_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4,TEST_NULL_LIST, true, false, true));

    // (S, G)
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, true));

    // List of (S, G), 1x3 groups
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4, TEST_SRC_IPV4_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV4, TEST_SRC_IPV4_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4, TEST_SRC_IPV4_LIST,true, false, true));

    // List of (S, G), 3x3 groups
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, true));
}

TEST(nas_mc_oif, send_ipv6_route_add_event)
{
    // (*, G)
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6,TEST_NULL_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV6,TEST_NULL_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6,TEST_NULL_LIST, false, false, true));

    // (S, G)
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, true));

    // List of (S, G), 1x3 groups
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6,TEST_SRC_IPV6_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV6,TEST_SRC_IPV6_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6,TEST_SRC_IPV6_LIST, false, false, true));

    // List of (S, G), 3x3 groups
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, true));
}

TEST(nas_mc_oif, send_mrouter_add_event_after)
{
    // IPv4
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME_1, TEST_NULL_LIST, TEST_NULL_LIST, true, true, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_NULL_LIST, TEST_NULL_LIST, true, true, true));

    // IPv6
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME_1, TEST_NULL_LIST, TEST_NULL_LIST, false, true, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_NULL_LIST, TEST_NULL_LIST, false, true, true));
}

TEST(nas_mc_oif, validate_igmp_entry_before)
{
    ASSERT_TRUE(check_shared_group_entry(true, 14, 1, {6}));
}

TEST(nas_mc_oif, validate_mld_entry_before)
{
    ASSERT_TRUE(check_shared_group_entry(false, 14, 1, {6}));
}

TEST(nas_mc_oif, dump_multicast_entries)
{
    mc_entry_list.clear();
    ASSERT_TRUE(run_command("hshell -c \"ipmc table show\"", igmp_entry_check, igmp_entry_proc));
    ASSERT_TRUE(run_command("hshell -c \"ipmc ip6table show\"", mld_entry_check, mld_entry_proc));
    ASSERT_TRUE(run_command("hshell -c \"mc show\"", mc_group_check, mc_group_proc));
    dump_mc_entry_list();
    mc_entry_list.clear();
}

TEST(nas_mc_oif, send_mrouter_del_event_before)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME_1, TEST_NULL_LIST, TEST_NULL_LIST, true, true, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME_1, TEST_NULL_LIST, TEST_NULL_LIST, false, true, false));
}

TEST(nas_mc_oif, send_ipv4_route_del_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4,TEST_NULL_LIST, true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV4,TEST_NULL_LIST, true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4,TEST_NULL_LIST, true, false, false));

    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, false));

    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4, TEST_SRC_IPV4_LIST,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV4, TEST_SRC_IPV4_LIST,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4, TEST_SRC_IPV4_LIST,true, false, false));

    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, false));
}

TEST(nas_mc_oif, send_ipv6_route_del_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6,TEST_NULL_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV6,TEST_NULL_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6,TEST_NULL_LIST, false, false, false));

    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, false));

    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6,TEST_SRC_IPV6_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV6,TEST_SRC_IPV6_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6,TEST_SRC_IPV6_LIST, false, false, false));

    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, false));
}

TEST(nas_mc_oif, send_mrouter_del_event_after)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, true, true, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_NULL_LIST, TEST_NULL_LIST, true, true, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, false, true, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_NULL_LIST, TEST_NULL_LIST, false, true, false));
}

TEST(nas_mc_oif, validate_igmp_entry_after)
{
    ASSERT_TRUE(check_shared_group_entry(true));
}

TEST(nas_mc_oif, validate_mld_entry_after)
{
    ASSERT_TRUE(check_shared_group_entry(false));
    ASSERT_TRUE(check_group_clear());
}

TEST(nas_mc_oif, send_one_port_route_add_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4_LIST, TEST_NULL_LIST, true, false, true));
}

TEST(nas_mc_oif, validate_one_port_route)
{
    ASSERT_TRUE(check_shared_group_entry(true, 3, 1, {1}));
}

TEST(nas_mc_oif, send_one_port_route_del_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4_LIST, TEST_NULL_LIST, true, false, false));
}

TEST(nas_mc_oif, validate_one_port_route_clear)
{
    ASSERT_TRUE(check_shared_group_entry(true));
    ASSERT_TRUE(check_group_clear());
}

TEST(nas_mc_oif, send_one_port_route_add_event_1)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4_LIST, TEST_NULL_LIST, true, false, true));
}

TEST(nas_mc_oif, validate_one_port_route_1)
{
    ASSERT_TRUE(check_shared_group_entry(true, 3, 1, {1}));
}

TEST(nas_mc_oif, remove_port_from_vlan)
{
    string br_name{};
    vector<string> member_list{ROUTE_IF_NAME_2, ROUTE_IF_NAME_3,
                               IGMP_MROUTER_IF_NAME, MLD_MROUTER_IF_NAME,
                               IGMP_MROUTER_IF_NAME_1, MLD_MROUTER_IF_NAME_1,
                               ROUTE_LAG_IF_NAME};
    ASSERT_TRUE(check_vlan_exists(TEST_VID, br_name));
    ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::VLAN, br_name, member_list,
                                            oper_type::SET_MEMBER));
}

TEST(nas_mc_oif, validate_one_port_route_clear_1)
{
    ASSERT_TRUE(check_shared_group_entry(true));
    ASSERT_TRUE(check_group_clear());
}

TEST(nas_mc_oif, add_port_back_to_vlan)
{
    string br_name{};
    vector<string> member_list{ROUTE_IF_NAME_1, ROUTE_IF_NAME_2, ROUTE_IF_NAME_3,
                               IGMP_MROUTER_IF_NAME, MLD_MROUTER_IF_NAME,
                               IGMP_MROUTER_IF_NAME_1, MLD_MROUTER_IF_NAME_1,
                               ROUTE_LAG_IF_NAME};
    ASSERT_TRUE(check_vlan_exists(TEST_VID, br_name));
    ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::VLAN, br_name, member_list,
                                            oper_type::SET_MEMBER));
}

TEST(nas_mc_oif, validate_one_port_route_clear_2)
{
    ASSERT_TRUE(check_shared_group_entry(true));
    ASSERT_TRUE(check_group_clear());
}

// Test on route port the same as mrouter port

TEST(nas_mc_mrouter_oif, send_mrouter_add_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, true, true, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, false, true, true));
}

TEST(nas_mc_mrouter_oif, send_route_add_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, true));

    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, true));
}

TEST(nas_mc_mrouter_oif, validate_entry)
{
    ASSERT_TRUE(check_shared_group_entry(true, 1, 1, {5}));
    ASSERT_TRUE(check_shared_group_entry(false, 1, 1, {5}));
}

TEST(nas_mc_mrouter_oif, send_route_del_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME, TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, false));

    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME, TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, false));
}

TEST(nas_mc_mrouter_oif, send_mrouter_del_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, true, true, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, false, true, false));
}

TEST(nas_mc_mrouter_oif, validate_entry_cleanup)
{
    ASSERT_TRUE(check_shared_group_entry(true));
    ASSERT_TRUE(check_shared_group_entry(false));
    ASSERT_TRUE(check_group_clear());
}

// Test on non-OIF multicast routing configuration

TEST(nas_mc_non_oif, send_ipv4_route_add_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_NULL_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_SRC_IPV4_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, true));
}

TEST(nas_mc_non_oif, send_ipv6_route_add_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_NULL_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_SRC_IPV6_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, true));
}

// All entries created should not link to group with member ports
TEST(nas_mc_non_oif, validate_igmp_entry)
{
    ASSERT_TRUE(check_shared_group_entry(true, 14, 1, {0}));
}

TEST(nas_mc_non_oif, validate_mld_entry)
{
    ASSERT_TRUE(check_shared_group_entry(false, 14, 1, {0}));
}

// Add mrouter port to make non-OIF entry not use default group

TEST(nas_mc_non_oif, send_mrouter_add_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, true, true, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, false, true, true));
}

// Non-OIF entries should link to group with mrouter port members
TEST(nas_mc_non_oif, validate_igmp_entry_with_mrouter)
{
    ASSERT_TRUE(check_shared_group_entry(true, 14, 1, {1}));
}

TEST(nas_mc_non_oif, validate_mld_entry_with_mrouter)
{
    ASSERT_TRUE(check_shared_group_entry(false, 14, 1, {1}));
}

// Delete mrouter port to make non-OIF entry use default group again

TEST(nas_mc_non_oif, send_mrouter_del_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, true, true, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, false, true, false));
}

// Non-OIF entries should be changed back to link to group with no port member
TEST(nas_mc_non_oif, validate_igmp_entry_no_mrouter)
{
    ASSERT_TRUE(check_shared_group_entry(true, 14, 1, {0}));
}

TEST(nas_mc_non_oif, validate_mld_entry_no_mrouter)
{
    ASSERT_TRUE(check_shared_group_entry(false, 14, 1, {0}));
}

TEST(nas_mc_non_oif, send_ipv4_route_del_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_NULL_LIST,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_SRC_IPV4_LIST,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, false));
}

TEST(nas_mc_non_oif, send_ipv6_route_del_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_NULL_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_SRC_IPV6_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, false));
}

TEST(nas_mc_non_oif, validate_igmp_entry_after)
{
    ASSERT_TRUE(check_shared_group_entry(true));
}

TEST(nas_mc_non_oif, validate_mld_entry_after)
{
    ASSERT_TRUE(check_shared_group_entry(false));
    ASSERT_TRUE(check_group_clear());
}

TEST(nas_mc_rpc, check_clear_intf_entries)
{
    // Create non-OIF entry
    cout << "Create non-OIF entries" << endl;
    // IPv4
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_NULL_LIST, true, false, true));
    // IPv6
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6, TEST_NULL_LIST, false, false, true));

    // Create regular entry
    cout << "Create OIF entries" << endl;
    // IPv4 3x3
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, true));
    // IPv6 3x3
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, true));

    // Add mrouter
    cout << "Add mrouter ports" << endl;
    // IPv4
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, true, true, true));
    // IPv6
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, false, true, true));

    // Check entries
    cout << "Check created entries before entry member cleanup" << endl;
    ASSERT_TRUE(check_shared_group_entry(true, 10, 2, {1, 5}));
    ASSERT_TRUE(check_shared_group_entry(false, 10, 2, {1, 5}));

    // Clear intf entries
    cout << "Clear entries for mrouter interface " << MLD_MROUTER_IF_NAME << endl;
    cleanup_intf_l2mc_config(TEST_VID, MLD_MROUTER_IF_NAME);

    cout << "Clear entries for route interface " << ROUTE_IF_NAME_1 << " and " << ROUTE_LAG_IF_NAME << endl;
    cleanup_intf_l2mc_config(TEST_VID, ROUTE_IF_NAME_1);
    cleanup_intf_l2mc_config(TEST_VID, ROUTE_LAG_IF_NAME);

    // Check entries
    cout << "Check created entries after entry member cleanup" << endl;
    ASSERT_TRUE(check_shared_group_entry(true, 10, 2, {1, 2}));
    ASSERT_TRUE(check_shared_group_entry(false, 10, 2, {0, 2}));

    cout << "Clear entries for route interface " << ROUTE_IF_NAME_3 << endl;
    cleanup_intf_l2mc_config(TEST_VID, ROUTE_IF_NAME_3);

    // No host member of IPv4 regular entries, they should be deleted
    cout << "Check entries after interface cleanup" << endl;
    ASSERT_TRUE(check_shared_group_entry(true, 1, 1, {1}));
    ASSERT_TRUE(check_shared_group_entry(false, 10, 2, {0, 1}));

    // Delete entries
    cout << "Delete all entries" << endl;
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_NULL_LIST,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6, TEST_NULL_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, false));

    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, true, true, false));

    // Check entries
    cout << "Check if all entries were deleted" << endl;
    ASSERT_TRUE(check_shared_group_entry(true));
    ASSERT_TRUE(check_shared_group_entry(false));
    ASSERT_TRUE(check_group_clear());
}

TEST(nas_mc_rpc, check_clear_vlan_entries)
{
    // Create regular entry
    cout << "Create OIF entries" << endl;
    // IPv4 3x3
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, true));
    // IPv6 3x3
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, true));

    // Check entries
    cout << "Check created entries before VLAN cleanup" << endl;
    ASSERT_TRUE(check_shared_group_entry(true, 9, 1, {4}));
    ASSERT_TRUE(check_shared_group_entry(false, 9, 1, {4}));

    cout << "Clear entries for VLAN " << TEST_VID << endl;
    cleanup_intf_l2mc_config(TEST_VID, "");

    // Check entries after cleanup
    cout << "Check created entries after VLAN cleanup" << endl;
    ASSERT_TRUE(check_shared_group_entry(true));
    ASSERT_TRUE(check_shared_group_entry(false));
    ASSERT_TRUE(check_group_clear());
}

TEST(nas_mc_copy_to_cpu, send_ipv4_route_add_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, true));

    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_SRC_IPV4_LIST,true, false, true));
}

TEST(nas_mc_copy_to_cpu, send_ipv6_route_add_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, true));

    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_SRC_IPV6_LIST, false, false, true));
}

TEST(nas_mc_copy_to_cpu, validate_igmp_entry_before)
{
    ASSERT_TRUE(check_shared_group_entry(true, 12, 2, {0, 4}));
}

TEST(nas_mc_copy_to_cpu, validate_mld_entry_before)
{
    ASSERT_TRUE(check_shared_group_entry(false, 12, 2, {0, 4}));
}

// Enable PIM
TEST(nas_mc_copy_to_cpu, send_ipv4_pim_enable)
{
    ASSERT_TRUE(send_mc_update_pim_status(TEST_VID, true, true));
}

TEST(nas_mc_copy_to_cpu, validate_igmp_entry_pim_enable)
{
    ASSERT_TRUE(check_shared_group_entry(true, 12, 2, {1, 5}, true));
}

TEST(nas_mc_copy_to_cpu, validate_mld_entry_no_change)
{
    ASSERT_TRUE(check_shared_group_entry(false, 12, 2, {0, 4}));
}

TEST(nas_mc_copy_to_cpu, send_ipv6_pim_enable)
{
    ASSERT_TRUE(send_mc_update_pim_status(TEST_VID, false, true));
}

TEST(nas_mc_copy_to_cpu, validate_mld_entry_pim_enable)
{
    ASSERT_TRUE(check_shared_group_entry(false, 12, 2, {1, 5}, true));
}

TEST(nas_mc_copy_to_cpu, send_route_add_event_pim_enable)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_NULL_LIST,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_NULL_LIST, false, false, true));
}

TEST(nas_mc_copy_to_cpu, validate_entry_after_new_route_add)
{
    ASSERT_TRUE(check_shared_group_entry(true, 13, 2, {1, 5}, true));
    ASSERT_TRUE(check_shared_group_entry(false, 13, 2, {1, 5}, true));
}

// Disable PIM
TEST(nas_mc_copy_to_cpu, send_ipv4_pim_disable)
{
    ASSERT_TRUE(send_mc_update_pim_status(TEST_VID, true, false));
}

TEST(nas_mc_copy_to_cpu, send_ipv6_pim_disable)
{
    ASSERT_TRUE(send_mc_update_pim_status(TEST_VID, false, false));
}

TEST(nas_mc_copy_to_cpu, send_route_add_event_pim_disable)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, true));
}

TEST(nas_mc_copy_to_cpu, validate_igmp_entry_pim_disable)
{
    ASSERT_TRUE(check_shared_group_entry(true, 14, 2, {0, 4}, false));
}

TEST(nas_mc_copy_to_cpu, validate_mld_entry_pim_disable)
{
    ASSERT_TRUE(check_shared_group_entry(false, 14, 2, {0, 4}, false));
}

TEST(nas_mc_copy_to_cpu, send_ipv4_route_del_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_1, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV4_LIST, TEST_SRC_IPV4_LIST,true, false, false));

    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_NULL_LIST,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_SRC_IPV4,true, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV4, TEST_SRC_IPV4_LIST,true, false, false));
}

TEST(nas_mc_copy_to_cpu, send_ipv6_route_del_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_2, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_IF_NAME_3, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, ROUTE_LAG_IF_NAME, TEST_GRP_IPV6_LIST,TEST_SRC_IPV6_LIST, false, false, false));

    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_NULL_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_SRC_IPV6, false, false, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, "", TEST_GRP_IPV6,TEST_SRC_IPV6_LIST, false, false, false));
}

TEST(nas_mc_copy_to_cpu, validate_igmp_entry_after)
{
    ASSERT_TRUE(check_shared_group_entry(true));
}

TEST(nas_mc_copy_to_cpu, validate_mld_entry_after)
{
    ASSERT_TRUE(check_shared_group_entry(false));
    ASSERT_TRUE(check_group_clear());
}

static const string& operator+(const unordered_set<string>& str_list, size_t idx)
{
    size_t i = 0;
    for (auto& item: str_list) {
        if (idx == i) {
            return item;
        }
        i ++;
    }
    throw out_of_range("Invalid index given");
}

static unordered_set<string> operator+(const unordered_set<string>& l1, const unordered_set<string>& l2)
{
    unordered_set<string> ret_list{};
    if (l1.empty()) {
        ret_list.insert("");
    } else {
        ret_list.insert(l1.begin(), l1.end());
    }
    if (l2.empty()) {
        ret_list.insert("");
    } else {
        ret_list.insert(l2.begin(), l2.end());
    }

    return ret_list;
}

const mc_ut_route_list_t test_ipv4_route_list = {
    {{TEST_VID, TEST_GRP_IPV4_LIST + 0, ROUTE_IF_NAME_1}, TEST_SRC_IPV4_LIST},
    {{TEST_VID, TEST_GRP_IPV4_LIST + 1, ROUTE_IF_NAME_1}, TEST_SRC_IPV4_LIST},
    {{TEST_VID, TEST_GRP_IPV4_LIST + 2, ROUTE_IF_NAME_1}, TEST_SRC_IPV4_LIST},
    {{TEST_VID, TEST_GRP_IPV4_LIST + 0, ROUTE_IF_NAME_3}, TEST_SRC_IPV4_LIST},
    {{TEST_VID, TEST_GRP_IPV4_LIST + 1, ROUTE_IF_NAME_3}, TEST_SRC_IPV4_LIST},
    {{TEST_VID, TEST_GRP_IPV4_LIST + 2, ROUTE_IF_NAME_3}, TEST_SRC_IPV4_LIST},
    {{TEST_VID, TEST_GRP_IPV4_LIST + 0, ROUTE_LAG_IF_NAME}, TEST_SRC_IPV4_LIST},
    {{TEST_VID, TEST_GRP_IPV4_LIST + 1, ROUTE_LAG_IF_NAME}, TEST_SRC_IPV4_LIST},
    {{TEST_VID, TEST_GRP_IPV4_LIST + 2, ROUTE_LAG_IF_NAME}, TEST_SRC_IPV4_LIST},
    {{TEST_VID, TEST_GRP_IPV4 + 0, ""}, TEST_NULL_LIST + TEST_SRC_IPV4 + TEST_SRC_IPV4_LIST}
};

const mc_ut_route_list_t test_ipv6_route_list = {
    {{TEST_VID, TEST_GRP_IPV6_LIST + 0, ROUTE_IF_NAME_2}, TEST_SRC_IPV6_LIST},
    {{TEST_VID, TEST_GRP_IPV6_LIST + 1, ROUTE_IF_NAME_2}, TEST_SRC_IPV6_LIST},
    {{TEST_VID, TEST_GRP_IPV6_LIST + 2, ROUTE_IF_NAME_2}, TEST_SRC_IPV6_LIST},
    {{TEST_VID, TEST_GRP_IPV6_LIST + 0, ROUTE_IF_NAME_3}, TEST_SRC_IPV6_LIST},
    {{TEST_VID, TEST_GRP_IPV6_LIST + 1, ROUTE_IF_NAME_3}, TEST_SRC_IPV6_LIST},
    {{TEST_VID, TEST_GRP_IPV6_LIST + 2, ROUTE_IF_NAME_3}, TEST_SRC_IPV6_LIST},
    {{TEST_VID, TEST_GRP_IPV6_LIST + 0, ROUTE_LAG_IF_NAME}, TEST_SRC_IPV6_LIST},
    {{TEST_VID, TEST_GRP_IPV6_LIST + 1, ROUTE_LAG_IF_NAME}, TEST_SRC_IPV6_LIST},
    {{TEST_VID, TEST_GRP_IPV6_LIST + 2, ROUTE_LAG_IF_NAME}, TEST_SRC_IPV6_LIST},
    {{TEST_VID, TEST_GRP_IPV6 + 0, ""}, TEST_NULL_LIST + TEST_SRC_IPV6 +  TEST_SRC_IPV6_LIST}
};

TEST(nas_mc_get, send_ipv4_route_add_event)
{
    ASSERT_TRUE(send_mc_route_update_event(test_ipv4_route_list, true));
}

TEST(nas_mc_get, send_ipv6_route_add_event)
{
    ASSERT_TRUE(send_mc_route_update_event(test_ipv6_route_list, true));
}

TEST(nas_mc_get, get_and_check_ipv4_route)
{
    sleep(5);
    hal_vlan_id_t vlan_id = TEST_VID;
    ASSERT_TRUE(get_mc_group(true, true, &vlan_id, nullptr, nullptr,
                             check_route_list, test_ipv4_route_list));
    ASSERT_TRUE(get_mc_group(true, false, &vlan_id, nullptr, nullptr,
                             check_route_list, test_ipv4_route_list));
}

TEST(nas_mc_get, get_and_check_ipv6_route)
{
    hal_vlan_id_t vlan_id = TEST_VID;
    ASSERT_TRUE(get_mc_group(false, true, &vlan_id, nullptr, nullptr,
                             check_route_list, test_ipv6_route_list));
    ASSERT_TRUE(get_mc_group(false, false, &vlan_id, nullptr, nullptr,
                             check_route_list, test_ipv6_route_list));
}

TEST(nas_mc_get, send_ipv4_route_del_event)
{
    ASSERT_TRUE(send_mc_route_update_event(test_ipv4_route_list, false));
}

TEST(nas_mc_get, send_ipv6_route_del_event)
{
    ASSERT_TRUE(send_mc_route_update_event(test_ipv6_route_list, false));
}

TEST(nas_mc_get, validate_igmp_entry_after)
{
    ASSERT_TRUE(check_shared_group_entry(true));
}

TEST(nas_mc_get, validate_mld_entry_after)
{
    ASSERT_TRUE(check_shared_group_entry(false));
    ASSERT_TRUE(check_group_clear());
}

TEST(nas_mc_get, check_ipv4_route_cleared)
{
    hal_vlan_id_t vlan_id = TEST_VID;
    ASSERT_TRUE(get_mc_group(true, true, &vlan_id, nullptr, nullptr,
                             check_empty_route_list, mc_ut_empty_data_t{}));
    ASSERT_TRUE(get_mc_group(true, false, &vlan_id, nullptr, nullptr,
                             check_empty_route_list, mc_ut_empty_data_t{}));
}

TEST(nas_mc_get, check_ipv6_route_cleared)
{
    hal_vlan_id_t vlan_id = TEST_VID;
    ASSERT_TRUE(get_mc_group(false, true, &vlan_id, nullptr, nullptr,
                             check_empty_route_list, mc_ut_empty_data_t{}));
    ASSERT_TRUE(get_mc_group(false, false, &vlan_id, nullptr, nullptr,
                             check_empty_route_list, mc_ut_empty_data_t{}));
}

static bool get_vlan_flood_restr_status(hal_vlan_id_t vlan_id, bool& enabled)
{
    FILE *fp = popen("hshell -c \"dump VLAN\"", "r");
    if (fp == nullptr) {
        cout << "Failure on running dump VLAN command" << endl;
        return false;
    }
    char lnbuf[512];
    int vlan_prof_id = -1;
    regex pat{R"(^VLAN\.ipipe\d+\[(\d+)\]: .+,VLAN_PROFILE_PTR=(\d+),)"};
    while(fgets(lnbuf, sizeof(lnbuf), fp)) {
        smatch matches;
        string line_str{lnbuf};
        if (regex_search(line_str, matches, pat)) {
            if (matches.size() > 2 && matches[1].matched && matches[2].matched) {
                auto vid = stoi(matches[1].str());
                if (vid == vlan_id) {
                    vlan_prof_id = stoi(matches[2].str());
                    break;
                }
            }
        }
    }
    pclose(fp);
    if (vlan_prof_id < 0) {
        cout << "Unable to find profile ID for VLAN " << vlan_id << endl;
        return false;
    }
    sprintf(lnbuf, "hshell -c \"dump VLAN_PROFILE_2 %d\"", vlan_prof_id);
    fp = popen(lnbuf, "r");
    if (fp == nullptr) {
        cout << "Failure on running dump VLAN profile command for ID " << vlan_prof_id << endl;
        return false;
    }
    regex pat1{R"(^VLAN_PROFILE_2\.ipipe\d+\[\d+\]: .+,UNKNOWN_MCAST_MASK_SEL=(\d+),)"};
    bool found = false;
    while(fgets(lnbuf, sizeof(lnbuf), fp)) {
        smatch matches;
        string line_str{lnbuf};
        if (regex_search(line_str, matches, pat1)) {
            if (matches.size() > 1 && matches[1].matched) {
                auto mask_sel = stoi(matches[1].str());
                enabled = (mask_sel != 0);
                found = true;
                break;
            }
        }
    }
    pclose(fp);
    if (!found) {
        cout << "Unable to find VLAN profile info" << endl;
        return false;
    }

    return true;
}

using vlan_status_list_t = vector<pair<hal_vlan_id_t, bool>>;

static bool set_flood_restrict_status(const vlan_status_list_t& status_list, bool bulk_mode = true)
{
    vector<cps_api_object_t> obj_list{};
    if (bulk_mode) {
        cps_api_object_guard og(cps_api_object_create());
        auto obj = og.get();
        if (obj == nullptr) {
            cout << "Failed to create CPS object" << endl;
            return false;
        }
        if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj), BASE_L2_MCAST_FLOOD_RESTRICT_OBJ,
                                             cps_api_qualifier_TARGET)) {
            cout << "Failed to initiate CPS object key" << endl;
            return false;
        }
        cps_api_attr_id_t ids[3] = {BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS, 0, 0};
        size_t attr_idx = 0;
        for (auto& vlan_status: status_list) {
            ids[1] = attr_idx;
            ids[2] = BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS_VLAN_ID;
            if (!cps_api_object_e_add(obj, ids, 3, cps_api_object_ATTR_T_U16, &vlan_status.first, sizeof(uint16_t))) {
                cout << "Failed to set CPS object VLAN attribute" << endl;
                return false;
            }
            ids[2] = BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS_ENABLE;
            uint32_t enabled = static_cast<uint32_t>(vlan_status.second);
            if (!cps_api_object_e_add(obj, ids, 3, cps_api_object_ATTR_T_U32, &enabled, sizeof(uint32_t))) {
                cout << "Failed to set CPS object status attribute" << endl;
                return false;
            }
            attr_idx ++;
        }
        obj_list.push_back(og.release());
    } else {
        for (auto& vlan_status: status_list) {
            cps_api_object_guard og(cps_api_object_create());
            auto obj = og.get();
            if (obj == nullptr) {
                cout << "Failed to create CPS object" << endl;
                continue;
            }
            if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj), BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS,
                                                 cps_api_qualifier_TARGET)) {
                cout << "Failed to initiate CPS object key" << endl;
                continue;
            }
            if (!cps_api_object_attr_add_u16(obj, BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS_VLAN_ID, vlan_status.first)) {
                cout << "Failed to set CPS object VLAN attribute" << endl;
                continue;
            }
            if (!cps_api_object_attr_add_u32(obj, BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS_ENABLE, vlan_status.second)) {
                cout << "Failed to set CPS object status attribute" << endl;
                continue;
            }
            obj_list.push_back(og.release());
        }
    }

    bool ret_val = true;
    for (auto obj: obj_list) {
        cps_api_transaction_params_t tr;
        if (cps_api_transaction_init(&tr) != cps_api_ret_code_OK) {
            cout << "Failed to initiate transaction" << endl;
            cps_api_object_delete(obj);
            ret_val = false;
            continue;
        }
        cps_api_set(&tr, obj);
        if (cps_api_commit(&tr) != cps_api_ret_code_OK) {
            cout << "Failed to commit" << endl;
            ret_val = false;
        }
        cps_api_transaction_close(&tr);
    }

    return ret_val;
}

static bool cps_get_flood_restrict_status(vlan_status_list_t& status_list)
{
    cps_api_get_params_t gp;
    if (cps_api_get_request_init(&gp) != cps_api_ret_code_OK) {
        cout << "Failed to initiate cps reqeust" << endl;
        return false;
    }
    cps_api_get_request_guard gpg{&gp};
    cps_api_object_t flt_obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if (flt_obj == nullptr) {
        cout << "Failed to append object to filter list" << endl;
        return false;
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(flt_obj),
                                         BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS,
                                         cps_api_qualifier_TARGET)) {
        cout << "Failed to generate object key" << endl;
        return false;
    }
    if (!status_list.empty()) {
        auto vlan_id = status_list.begin()->first;
        cps_api_object_attr_add_u16(flt_obj, BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS_VLAN_ID, vlan_id);
        status_list.clear();
    }

    if (cps_api_get(&gp) != cps_api_ret_code_OK) {
        cout << "Failure on running CPS get request" << endl;
        return false;
    }

    size_t mx = cps_api_object_list_size(gp.list);
    cps_api_object_t obj;
    for (size_t ix = 0; ix < mx; ix ++) {
        obj = cps_api_object_list_get(gp.list, ix);
        cps_api_object_attr_t vlan_attr = cps_api_get_key_data(obj,
                                BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS_VLAN_ID);
        cps_api_object_attr_t status_attr = cps_api_object_attr_get(obj,
                                BASE_L2_MCAST_FLOOD_RESTRICT_VLAN_STATUS_ENABLE);
        if (vlan_attr == nullptr || status_attr == nullptr) {
            continue;
        }
        auto vlan_id = cps_api_object_attr_data_u16(vlan_attr);
        bool status = static_cast<bool>(cps_api_object_attr_data_u32(status_attr));
        status_list.push_back(make_pair(vlan_id, status));
    }

    return true;
}

TEST(nas_mc_flood_restr, send_mrouter_add_event_before)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, true, true, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, false, true, true));
}

TEST(nas_mc_flood_restr, enable_flood_restrict)
{
    ASSERT_TRUE(set_flood_restrict_status(vlan_status_list_t{{TEST_VID, true}}));
}

TEST(nas_mc_flood_restr, check_flood_restrict_enable)
{
    bool enabled;
    ASSERT_TRUE(get_vlan_flood_restr_status(TEST_VID, enabled));
    ASSERT_TRUE(enabled);
}

TEST(nas_mc_flood_restr, check_flood_restrict_enable_with_cps)
{
    // Test get all VLAN status
    vlan_status_list_t status_list{};
    ASSERT_TRUE(cps_get_flood_restrict_status(status_list));
    ASSERT_FALSE(status_list.empty());
    auto itor = find_if(status_list.begin(), status_list.end(), [](const pair<hal_vlan_id_t, bool>& val){return val.first == TEST_VID;});
    ASSERT_TRUE(itor != status_list.end());
    ASSERT_TRUE(itor->second);

    // Test get one VLAN status
    status_list.clear();
    status_list.push_back(make_pair(TEST_VID, false));
    ASSERT_TRUE(cps_get_flood_restrict_status(status_list));
    ASSERT_EQ(status_list.size(), 1);
    ASSERT_EQ(status_list.begin()->first, TEST_VID);
    ASSERT_TRUE(status_list.begin()->second);

    // Test get non-existing VLAN status
    status_list.clear();
    status_list.push_back(make_pair(TEST_VID + 1, false));
    ASSERT_FALSE(cps_get_flood_restrict_status(status_list));
}

TEST(nas_mc_flood_restr, send_mrouter_add_event_after)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME_1, TEST_NULL_LIST, TEST_NULL_LIST, true, true, true));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME_1, TEST_NULL_LIST, TEST_NULL_LIST, false, true, true));
}

TEST(nas_mc_flood_restr, check_group)
{
    ASSERT_TRUE(check_shared_group(1, {4}));
}

TEST(nas_mc_flood_restr, disable_flood_restrict)
{
    ASSERT_TRUE(set_flood_restrict_status(vlan_status_list_t{{TEST_VID, false}}));
}

TEST(nas_mc_flood_restr, check_flood_restrict_disable)
{
    bool enabled;
    ASSERT_TRUE(get_vlan_flood_restr_status(TEST_VID, enabled));
    ASSERT_FALSE(enabled);
}

TEST(nas_mc_flood_restr, check_flood_restrict_disable_with_cps)
{
    // Test get all VLAN status
    vlan_status_list_t status_list{};
    ASSERT_TRUE(cps_get_flood_restrict_status(status_list));
    ASSERT_FALSE(status_list.empty());
    auto itor = find_if(status_list.begin(), status_list.end(), [](const pair<hal_vlan_id_t, bool>& val){return val.first == TEST_VID;});
    ASSERT_TRUE(itor != status_list.end());
    ASSERT_FALSE(itor->second);

    // Test get one VLAN status
    status_list.clear();
    status_list.push_back(make_pair(TEST_VID, false));
    ASSERT_TRUE(cps_get_flood_restrict_status(status_list));
    ASSERT_EQ(status_list.size(), 1);
    ASSERT_EQ(status_list.begin()->first, TEST_VID);
    ASSERT_FALSE(status_list.begin()->second);

    // Test get non-existing VLAN status
    status_list.clear();
    status_list.push_back(make_pair(TEST_VID + 1, false));
    ASSERT_FALSE(cps_get_flood_restrict_status(status_list));
}

TEST(nas_mc_flood_restr, check_group_clear)
{
    ASSERT_TRUE(check_group_clear());
}

TEST(nas_mc_flood_restr, send_mrouter_del_event)
{
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, true, true, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME, TEST_NULL_LIST, TEST_NULL_LIST, false, true, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, IGMP_MROUTER_IF_NAME_1, TEST_NULL_LIST, TEST_NULL_LIST, true, true, false));
    ASSERT_TRUE(send_mc_update_event(TEST_VID, MLD_MROUTER_IF_NAME_1, TEST_NULL_LIST, TEST_NULL_LIST, false, true, false));
}

// UT environment cleanup
TEST(nas_mc_cleanup, deinit_event_service)
{
    ASSERT_TRUE(event_service_deinit());
}

TEST(nas_mc_cleanup, delete_vlan)
{
    string br_name{};
    if (check_vlan_exists(TEST_VID, br_name)) {
        ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::VLAN, br_name, {}, oper_type::DELETE));
    }
}

TEST(nas_mc_cleanup, delete_lag)
{
    ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::LAG, ROUTE_LAG_IF_NAME,
                {LAG_IF_NAME_1, LAG_IF_NAME_2}, oper_type::DELETE));
    ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::LAG, ROUTE_LAG_IF_NAME, {}, oper_type::DELETE));
}

static vector<string> vlan_mbr_list_1 = {"e101-001-0", "e101-002-0", "e101-003-0"};
static vector<string> vlan_mbr_list_2 = {"e101-001-0", "e101-003-0"};

static string del_if_name{"e101-002-0"};

static unordered_map<hal_vlan_id_t, tuple<vector<string>, string, string>> test_vlan_list {
    {100, {vlan_mbr_list_1, "230.1.1.1", "1.1.1.1"}},
    {200, {vlan_mbr_list_1, "231.2.2.2", "2.2.2.2"}},
    {300, {vlan_mbr_list_2, "232.3.3.3", "3.3.3.3"}},
};

TEST(nas_mc_multi_vlan, create_vlan)
{
    for (auto& vlan_entry: test_vlan_list) {
        ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::VLAN, {}, get<0>(vlan_entry.second),
                                                oper_type::CREATE, vlan_entry.first, true));
        string br_name;
        ASSERT_TRUE(check_vlan_exists(vlan_entry.first, br_name));
    }
}

TEST(nas_mc_multi_vlan, init_event_service)
{
    ASSERT_TRUE(event_service_init());
}

TEST(nas_mc_multi_vlan, send_route_add_event)
{
    for (auto& vlan_entry: test_vlan_list) {
        for (auto& if_name: get<0>(vlan_entry.second)) {
            ASSERT_TRUE(send_mc_update_event(vlan_entry.first, if_name,
                                            {get<1>(vlan_entry.second)}, {get<2>(vlan_entry.second)},
                                            true, false, true));
        }
    }
    ASSERT_TRUE(check_shared_group_entry(true, 3, 2, {2, 3}));
}

TEST(nas_mc_multi_vlan, delete_interface)
{
    cleanup_intf_l2mc_config(0, del_if_name);
    ASSERT_TRUE(check_shared_group_entry(true, 3, 1, {2}));
}

TEST(nas_mc_multi_vlan, send_route_del_event)
{
    for (auto& vlan_entry: test_vlan_list) {
        for (auto& if_name: get<0>(vlan_entry.second)) {
            if (if_name == del_if_name) {
                continue;
            }
            ASSERT_TRUE(send_mc_update_event(vlan_entry.first, if_name,
                                            {get<1>(vlan_entry.second)}, {get<2>(vlan_entry.second)},
                                            true, false, false));
        }
    }
}

TEST(nas_mc_multi_vlan, validate_entry_cleanup)
{
    ASSERT_TRUE(check_shared_group_entry(true));
    ASSERT_TRUE(check_group_clear());
}

TEST(nas_mc_multi_vlan, send_one_port_route_add_event)
{
    for (auto& vlan_entry: test_vlan_list) {
        if (vlan_entry.first == 300) {
            continue;
        }
        ASSERT_TRUE(send_mc_update_event(vlan_entry.first, del_if_name,
                                        {get<1>(vlan_entry.second)}, {get<2>(vlan_entry.second)},
                                        true, false, true));
    }
    ASSERT_TRUE(check_shared_group_entry(true, 2, 1, {1}));
}

TEST(nas_mc_multi_vlan, remove_port_from_vlan)
{
    string br_name{};
    vector<string> mbr_list{};
    for (auto& vlan_entry: test_vlan_list) {
        if (vlan_entry.first == 300) {
            continue;
        }
        ASSERT_TRUE(check_vlan_exists(vlan_entry.first, br_name));
        mbr_list.clear();
        for (auto if_name: get<0>(vlan_entry.second)) {
            if (if_name != del_if_name) {
                mbr_list.push_back(if_name);
            }
        }
        ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::VLAN, br_name, mbr_list,
                                                oper_type::SET_MEMBER, 0, true));
    }
}

TEST(nas_mc_multi_vlan, validate_entry_cleanup_1)
{
    ASSERT_TRUE(check_shared_group_entry(true));
    ASSERT_TRUE(check_group_clear());
}

TEST(nas_mc_multi_vlan, deinit_event_service)
{
    ASSERT_TRUE(event_service_deinit());
}

TEST(nas_mc_multi_vlan, delete_vlan)
{
    for (auto& vlan_entry: test_vlan_list) {
        string br_name{};
        if (check_vlan_exists(vlan_entry.first, br_name)) {
            ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::VLAN, br_name, {}, oper_type::DELETE));
        }
    }
}

static string test_vrf_name{"default"};
static hal_vlan_id_t iif_vlan_id = 100;
static hal_vlan_id_t oif_vlan_id = 200;
static unordered_map<hal_vlan_id_t, vector<string>> ipmc_test_vlan_list {
    {iif_vlan_id, {"e101-001-0", "e101-002-0", "e101-003-0", "e101-004-0"}},
    {oif_vlan_id, {"e101-005-0", "e101-006-0", "e101-007-0", "e101-008-0"}}
};

static bool set_pim_status(string vrf_name, uint32_t af, bool global, string br_name, bool enable)
{
    cps_api_object_guard og(cps_api_object_create());
    auto obj = og.get();
    if (obj == nullptr) {
        cout << "Failed to create CPS object" << endl;
        return false;
    }
    if (global) {
        if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj), L3_MCAST_GLOBAL_OBJ,
                                             cps_api_qualifier_TARGET)) {
            cout << "Failed to initiate CPS object key" << endl;
            return false;
        }
        cps_api_object_attr_add(obj, L3_MCAST_GLOBAL_VRF_NAME, vrf_name.c_str(), vrf_name.length() + 1);
        cps_api_object_attr_add_u32(obj, L3_MCAST_GLOBAL_AF, af);
        cps_api_object_attr_add(obj, L3_MCAST_GLOBAL_STATUS, &enable, sizeof(enable));
    } else {
        if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj), L3_MCAST_INTERFACES_INTERFACE,
                                             cps_api_qualifier_TARGET)) {
            cout << "Failed to initiate CPS object key" << endl;
            return false;
        }
        cps_api_object_attr_add(obj, L3_MCAST_INTERFACES_INTERFACE_VRF_NAME, vrf_name.c_str(), vrf_name.length() + 1);
        cps_api_object_attr_add_u32(obj, L3_MCAST_INTERFACES_INTERFACE_AF, af);
        cps_api_object_attr_add(obj, L3_MCAST_INTERFACES_INTERFACE_NAME, br_name.c_str(), br_name.length() + 1);
        cps_api_object_attr_add(obj, L3_MCAST_INTERFACES_INTERFACE_STATUS, &enable, sizeof(enable));
    }

    cps_api_transaction_params_t tr;
    if (cps_api_transaction_init(&tr) != cps_api_ret_code_OK) {
        cout << "Failed to initiate transaction" << endl;
        return false;
    }
    bool ret_val = true;
    cps_api_set(&tr, og.release());
    if (cps_api_commit(&tr) != cps_api_ret_code_OK) {
        cout << "Failed to commit" << endl;
        ret_val = false;
    }
    cps_api_transaction_close(&tr);
    return ret_val;
}

static bool npu_to_system_ifname(const string& npu_name, string& sys_name)
{
    auto itor = find_if(npu_name.begin(), npu_name.end(),
                       [](unsigned char c)->bool{return isdigit(c);});
    if (itor == npu_name.end()) {
        cout << "Invalid interface name: " << npu_name << endl;
        return false;
    }
    size_t pos = itor - npu_name.begin();
    string prefix{npu_name, 0, pos};
    int port_num = stoi(string{npu_name, pos});
    if (prefix == "xe") {
        sys_name.assign("e101-");
        int fp_id = port_num / 4 + 1;
        char tmp_buf[10];
        sprintf(tmp_buf, "%03d", fp_id);
        sys_name.append(tmp_buf);
        sys_name.append("-0");
    } else if (prefix == "cpu") {
        sys_name.assign("npu-");
        sys_name.append(to_string(port_num));
    } else {
        return false;
    }

    return true;
}


static bool parse_ipmc_group_lines(const vector<string>& line_list, uint32_t& group_id,
                                   ipmc_port_list_t& port_list)
{
    if (line_list.empty()) {
        return false;
    }
    istringstream iss{line_list[0]};
    vector<string> tokens{istream_iterator<string>(iss), {}};
    if (tokens.size() < 3) {
        return false;
    }
    group_id = stoul(tokens[1], 0, 16);

    for (size_t idx = 1; idx < line_list.size(); idx ++) {
        istringstream iss{line_list[idx]};
        vector<string> tokens{istream_iterator<string>{iss}, {}};
        if (tokens.size() < 5) {
            continue;
        }
        auto port_name = tokens[1];
        if (port_name.back() == ',') {
            port_name.erase(port_name.size() - 1);
        }
        string if_name{};
        if (!npu_to_system_ifname(port_name, if_name)) {
            continue;
        }
        int encap_id = stoi(tokens[4]);
        port_list[encap_id].insert(if_name);
    }
    return true;
}

static bool mc_ipmc_group_proc(const vector<string>& line_list, vector<ipmc_entry_t>& entry_list)
{
    uint32_t group_id = 0;
    ipmc_port_list_t port_list;
    if (!parse_ipmc_group_lines(line_list, group_id, port_list)) {
        return false;
    }

    if (!port_list.empty()) {
        for (auto& entry: entry_list) {
            if (entry.group_id == group_id) {
                entry.port_list = port_list;
            }
        }
    }

    return true;
}

struct ut_chk_ipmc_entry_t
{
    hal_vlan_id_t vlan_id;
    string grp_ip;
    string src_ip;
    set<string> rpf_port_list;
    vector<set<string>> ipmc_port_list;
};

using ut_chk_ipmc_entry_list = vector<ut_chk_ipmc_entry_t>;

bool operator==(const hal_ip_addr_t& a1, const hal_ip_addr_t& a2)
{
    return _ip_addr_key_equal()(a1, a2);
}

static bool check_ipmc_entry_group_int(bool ipv4, const ut_chk_ipmc_entry_list& chk_list, ostream& err_msg)
{
    ipmc_entry_list.clear();
    if (ipv4) {
        if (!run_command<ipmc_entry_t>("hshell -c \"ipmc table show\"", igmp_entry_check, igmp_entry_proc)) {
            err_msg << "Failure running show ipmc table command" << endl;
            return false;
        }
    } else {
        if (!run_command<ipmc_entry_t>("hshell -c \"ipmc ip6table show\"", mld_entry_check, mld_entry_proc)) {
            err_msg << "Failure running show ipmc table command" << endl;
            return false;
        }
    }
    if (!run_command("hshell -c \"mc show\"", mc_group_check, mc_ipmc_group_proc)) {
        err_msg << "Failure on running show multicast command" << endl;
        return false;
    }

    for (auto& chk_entry: chk_list) {
        bool entry_found = false;
        hal_ip_addr_t grp_ip;
        if (!std_str_to_ip(chk_entry.grp_ip.c_str(), &grp_ip)) {
            return false;
        }
        hal_ip_addr_t src_ip;
        if (!std_str_to_ip(chk_entry.src_ip.c_str(), &src_ip)) {
            return false;
        }
        for (auto& entry: ipmc_entry_list) {
            if (chk_entry.vlan_id == entry.vlan_id && grp_ip == entry.mc_ip && src_ip == entry.src_ip) {
                entry_found = true;
                if (!chk_entry.rpf_port_list.empty()) {
                    if (entry.port_list.find(-1) == entry.port_list.end()) {
                        err_msg << "No RPF group in read entry" << endl;
                        return false;
                    }
                    if (chk_entry.rpf_port_list != entry.port_list.at(-1)) {
                        err_msg << "RPF group not match for check and read entry" << endl;
                        return false;
                    }
                }
                size_t ipmc_grp_cnt = entry.port_list.size();
                if (entry.port_list.find(-1) != entry.port_list.end()) {
                    ipmc_grp_cnt -= 1;
                }
                if (ipmc_grp_cnt != chk_entry.ipmc_port_list.size()) {
                    return false;
                }
                for (auto& chk_port_list: chk_entry.ipmc_port_list) {
                    bool plist_found = false;
                    for (auto& port_list: entry.port_list) {
                        if (port_list.first == -1) {
                            continue;
                        }
                        if (port_list.second == chk_port_list) {
                            plist_found = true;
                            break;
                        }
                    }
                    if (!plist_found) {
                        return false;
                    }
                }
                break;
            }
        }
        if (!entry_found) {
            err_msg << "Check entry not found in read list" << endl;
            return false;
        }
    }

    return true;
}

static bool check_ipmc_entry_group(bool ipv4, const ut_chk_ipmc_entry_list& chk_list)
{
    int check_cnt = 0;
    ostringstream ss;
    while(check_cnt < MAX_CHECK_COUNT) {
        sleep(2);
        if (check_ipmc_entry_group_int(ipv4, chk_list, ss)) {
            return true;
        }
        check_cnt ++;
    }
    cout << "Failure validating IPMC entry" << endl;
    cout << ss.str() << endl;
    cout << "Current IPMC entires:" << endl;
    dump_mc_entry_list<ipmc_entry_t>();
    return false;
}

static bool set_ipmc_route_entry(const string& vrf_name, const hal_ip_addr_t& grp_ip, bool is_xg, const hal_ip_addr_t& src_ip,
                                 const string& iif_name, const vector<pair<string, string>>& oif_list, bool copy_to_cpu,
                                 bool is_add)
{
    cps_api_object_guard og(cps_api_object_create());
    auto obj = og.get();
    if (obj == nullptr) {
        cout << "Failed to create CPS object" << endl;
        return false;
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj), L3_MCAST_ROUTES_ROUTE,
                                         cps_api_qualifier_TARGET)) {
        cout << "Failed to initiate CPS object key" << endl;
        return false;
    }

    if (!is_xg && (grp_ip.af_index != src_ip.af_index)) {
        cout << "Source IP and group IP have different AF type" << endl;
        return false;
    }
    uint32_t af = grp_ip.af_index;
    cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_VRF_NAME, vrf_name.c_str(), vrf_name.length() + 1);
    cps_api_object_attr_add_u32(obj, L3_MCAST_ROUTES_ROUTE_AF, af);
    if (af == AF_INET) {
        cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_GROUP_IP, &grp_ip.u.v4_addr, sizeof(grp_ip.u.v4_addr));
        if (!is_xg) {
            cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_SOURCE_IP, &src_ip.u.v4_addr, sizeof(src_ip.u.v4_addr));
        }
    } else {
        cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_GROUP_IP, &grp_ip.u.v6_addr, sizeof(grp_ip.u.v6_addr));
        if (!is_xg) {
            cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_SOURCE_IP, &src_ip.u.v6_addr, sizeof(src_ip.u.v6_addr));
        }
    }
    cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_IIF_NAME, iif_name.c_str(), iif_name.length() + 1);
    cps_api_attr_id_t ids[3] = {L3_MCAST_ROUTES_ROUTE_OIF, 0, 0};
    size_t attr_idx = 0;
    for (auto& oif_info: oif_list) {
        ids[1] = attr_idx;
        ids[2] = L3_MCAST_ROUTES_ROUTE_OIF_NAME;
        cps_api_object_e_add(obj, ids, 3, cps_api_object_ATTR_T_BIN, oif_info.first.c_str(), oif_info.first.length() + 1);
        if (!oif_info.second.empty()) {
            ids[2] = L3_MCAST_ROUTES_ROUTE_OIF_EXCLUDE_INTERFACE;
            cps_api_object_e_add(obj, ids, 3, cps_api_object_ATTR_T_BIN, oif_info.second.c_str(), oif_info.second.length() + 1);
        }
    }
    if (is_xg) {
        cps_api_object_attr_add_u32(obj, L3_MCAST_ROUTES_ROUTE_RT_TYPE, L3_MCAST_ROUTE_TYPE_XG);
    } else {
        cps_api_object_attr_add_u32(obj, L3_MCAST_ROUTES_ROUTE_RT_TYPE, L3_MCAST_ROUTE_TYPE_SG);
    }
    cps_api_object_attr_add_u32(obj, L3_MCAST_ROUTES_ROUTE_DATA_TO_CPU, static_cast<uint32_t>(copy_to_cpu));

    cps_api_transaction_params_t tr;
    if (cps_api_transaction_init(&tr) != cps_api_ret_code_OK) {
        cout << "Failed to initiate transaction" << endl;
        return false;
    }
    bool ret_val = true;
    if (is_add) {
        cps_api_create(&tr, og.release());
    } else {
        cps_api_delete(&tr, og.release());
    }
    if (cps_api_commit(&tr) != cps_api_ret_code_OK) {
        cout << "Failed to commit" << endl;
        ret_val = false;
    }
    cps_api_transaction_close(&tr);
    return ret_val;
}

// in_vlan, grp_ip, src_ip, out_vid_list, copy_to_cpu
static vector<tuple<hal_vlan_id_t, string, string, vector<pair<hal_vlan_id_t, string>>, bool>> ut_ipmc_entry_list {
    {iif_vlan_id, "230.1.1.2", "", {{oif_vlan_id, ""}}, false},
    {iif_vlan_id, "230.1.1.2", "1.2.3.4", {{oif_vlan_id, ""}}, false},
    {iif_vlan_id, "ff0f::2002", "", {{oif_vlan_id, ""}}, false},
    {iif_vlan_id, "ff0f::2002", "6666::8888", {{oif_vlan_id, ""}}, false}
};

static void set_ipmc_entry_from_list(bool is_add)
{
    for (auto& entry_info: ut_ipmc_entry_list) {
        string iif_name;
        ASSERT_TRUE(check_vlan_exists(get<0>(entry_info), iif_name));
        hal_ip_addr_t grp_ip;
        ASSERT_TRUE(std_str_to_ip(get<1>(entry_info).c_str(), &grp_ip));
        bool is_xg = true;
        hal_ip_addr_t src_ip;
        if (!get<2>(entry_info).empty()) {
            is_xg = false;
            ASSERT_TRUE(std_str_to_ip(get<2>(entry_info).c_str(), &src_ip));
        }
        vector<pair<string, string>> oif_list;
        for (auto& oif_info: get<3>(entry_info)) {
            string oif_name;
            ASSERT_TRUE(check_vlan_exists(oif_info.first, oif_name));
            oif_list.push_back(make_pair(oif_name, oif_info.second));
        }
        ASSERT_TRUE(set_ipmc_route_entry(test_vrf_name, grp_ip, is_xg, src_ip, iif_name, oif_list,
                                         get<4>(entry_info), is_add));
    }
}

TEST(nas_mc_flood_restr_ipmc, create_vlan)
{
    for (auto& vlan_entry: ipmc_test_vlan_list) {
        ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::VLAN, {}, vlan_entry.second,
                                                oper_type::CREATE, vlan_entry.first));
        string br_name;
        ASSERT_TRUE(check_vlan_exists(vlan_entry.first, br_name));
    }
}

TEST(nas_mc_flood_restr_ipmc, enable_pim) {
    ASSERT_TRUE(set_pim_status(test_vrf_name, AF_INET, true, "", true));
    ASSERT_TRUE(set_pim_status(test_vrf_name, AF_INET6, true, "", true));
    for (auto& vlan_entry: ipmc_test_vlan_list) {
        string br_name{};
        if (check_vlan_exists(vlan_entry.first, br_name)) {
            ASSERT_TRUE(set_pim_status(test_vrf_name, AF_INET, false, br_name, true));
            ASSERT_TRUE(set_pim_status(test_vrf_name, AF_INET6, false, br_name, true));
        }
    }
}

TEST(nas_mc_flood_restr_ipmc, add_ipmc_route_entry)
{
    set_ipmc_entry_from_list(true);
}

TEST(nas_mc_flood_restr_ipmc, check_route_entry_flood_restr_disable)
{
    ut_chk_ipmc_entry_list chk_ipv4_list {
        {iif_vlan_id, "230.1.1.2", "0.0.0.0", {"e101-001-0", "e101-002-0", "e101-003-0", "e101-004-0"}, {{"e101-005-0", "e101-006-0", "e101-007-0", "e101-008-0"}}},
        {iif_vlan_id, "230.1.1.2", "1.2.3.4", {"e101-001-0", "e101-002-0", "e101-003-0", "e101-004-0"}, {{"e101-005-0", "e101-006-0", "e101-007-0", "e101-008-0"}}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(true, chk_ipv4_list));
    ut_chk_ipmc_entry_list chk_ipv6_list {
        {iif_vlan_id, "ff0f::2002", "::", {"e101-001-0", "e101-002-0", "e101-003-0", "e101-004-0"}, {{"e101-005-0", "e101-006-0", "e101-007-0", "e101-008-0"}}},
        {iif_vlan_id, "ff0f::2002", "6666::8888", {"e101-001-0", "e101-002-0", "e101-003-0", "e101-004-0"}, {{"e101-005-0", "e101-006-0", "e101-007-0", "e101-008-0"}}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(false, chk_ipv6_list));
}

TEST(nas_mc_flood_restr_ipmc, enable_flood_restrict_iif)
{
    ASSERT_TRUE(set_flood_restrict_status(vlan_status_list_t{{iif_vlan_id, true}}));
}

TEST(nas_mc_flood_restr_ipmc, check_route_entry_flood_restr_enable_iif)
{
    ut_chk_ipmc_entry_list chk_ipv4_list {
        {iif_vlan_id, "230.1.1.2", "0.0.0.0", {}, {{"e101-005-0", "e101-006-0", "e101-007-0", "e101-008-0"}}},
        {iif_vlan_id, "230.1.1.2", "1.2.3.4", {}, {{"e101-005-0", "e101-006-0", "e101-007-0", "e101-008-0"}}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(true, chk_ipv4_list));
    ut_chk_ipmc_entry_list chk_ipv6_list {
        {iif_vlan_id, "ff0f::2002", "::", {}, {{"e101-005-0", "e101-006-0", "e101-007-0", "e101-008-0"}}},
        {iif_vlan_id, "ff0f::2002", "6666::8888", {}, {{"e101-005-0", "e101-006-0", "e101-007-0", "e101-008-0"}}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(false, chk_ipv6_list));
}

TEST(nas_mc_flood_restr_ipmc, send_mrouter_add_event_iif)
{
    ASSERT_TRUE(send_mc_update_event(iif_vlan_id, "e101-001-0", TEST_NULL_LIST, TEST_NULL_LIST, true, true, true));
    ASSERT_TRUE(send_mc_update_event(iif_vlan_id, "e101-002-0", TEST_NULL_LIST, TEST_NULL_LIST, false, true, true));
}

TEST(nas_mc_flood_restr_ipmc, check_route_entry_flood_restr_enable_iif_mrouter)
{
    ut_chk_ipmc_entry_list chk_ipv4_list {
        {iif_vlan_id, "230.1.1.2", "0.0.0.0", {"e101-001-0"}, {{"e101-005-0", "e101-006-0", "e101-007-0", "e101-008-0"}}},
        {iif_vlan_id, "230.1.1.2", "1.2.3.4", {"e101-001-0"}, {{"e101-005-0", "e101-006-0", "e101-007-0", "e101-008-0"}}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(true, chk_ipv4_list));
    ut_chk_ipmc_entry_list chk_ipv6_list {
        {iif_vlan_id, "ff0f::2002", "::", {"e101-002-0"}, {{"e101-005-0", "e101-006-0", "e101-007-0", "e101-008-0"}}},
        {iif_vlan_id, "ff0f::2002", "6666::8888", {"e101-002-0"}, {{"e101-005-0", "e101-006-0", "e101-007-0", "e101-008-0"}}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(false, chk_ipv6_list));
}

TEST(nas_mc_flood_restr_ipmc, send_mrouter_add_event_oif)
{
    ASSERT_TRUE(send_mc_update_event(oif_vlan_id, "e101-005-0", TEST_NULL_LIST, TEST_NULL_LIST, true, true, true));
    ASSERT_TRUE(send_mc_update_event(oif_vlan_id, "e101-006-0", TEST_NULL_LIST, TEST_NULL_LIST, false, true, true));
}

TEST(nas_mc_flood_restr_ipmc, enable_flood_restrict_oif)
{
    sleep(2);
    ASSERT_TRUE(set_flood_restrict_status(vlan_status_list_t{{oif_vlan_id, true}}));
}

TEST(nas_mc_flood_restr_ipmc, check_route_entry_flood_restr_enable_oif)
{
    ut_chk_ipmc_entry_list chk_ipv4_list {
        {iif_vlan_id, "230.1.1.2", "0.0.0.0", {"e101-001-0"}, {{"e101-005-0"}}},
        {iif_vlan_id, "230.1.1.2", "1.2.3.4", {"e101-001-0"}, {{"e101-005-0"}}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(true, chk_ipv4_list));
    ut_chk_ipmc_entry_list chk_ipv6_list {
        {iif_vlan_id, "ff0f::2002", "::", {"e101-002-0"}, {{"e101-006-0"}}},
        {iif_vlan_id, "ff0f::2002", "6666::8888", {"e101-002-0"}, {{"e101-006-0"}}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(false, chk_ipv6_list));
}

TEST(nas_mc_flood_restr_ipmc, send_route_add_event)
{
    ASSERT_TRUE(send_mc_update_event(iif_vlan_id, "e101-003-0", {"230.1.1.2"}, TEST_NULL_LIST, true, false, true));
    ASSERT_TRUE(send_mc_update_event(iif_vlan_id, "e101-004-0", {"230.1.1.2"}, TEST_NULL_LIST, true, false, true));
    ASSERT_TRUE(send_mc_update_event(oif_vlan_id, "e101-007-0", {"230.1.1.2"}, {"1.2.3.4"}, true, false, true));
    ASSERT_TRUE(send_mc_update_event(oif_vlan_id, "e101-008-0", {"230.1.1.2"}, {"1.2.3.4"}, true, false, true));

    ASSERT_TRUE(send_mc_update_event(iif_vlan_id, "e101-003-0", {"ff0f::2002"}, TEST_NULL_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(iif_vlan_id, "e101-004-0", {"ff0f::2002"}, TEST_NULL_LIST, false, false, true));
    ASSERT_TRUE(send_mc_update_event(oif_vlan_id, "e101-007-0", {"ff0f::2002"}, {"6666::8888"}, false, false, true));
    ASSERT_TRUE(send_mc_update_event(oif_vlan_id, "e101-008-0", {"ff0f::2002"}, {"6666::8888"}, false, false, true));
}

TEST(nas_mc_flood_restr_ipmc, check_route_entry_flood_restr_with_snoop_route)
{
    ut_chk_ipmc_entry_list chk_ipv4_list {
        {iif_vlan_id, "230.1.1.2", "0.0.0.0", {"e101-001-0", "e101-003-0", "e101-004-0"}, {{"e101-005-0"}}},
        // if no (S, G) route, (*, G) route member will be used
        {iif_vlan_id, "230.1.1.2", "1.2.3.4", {"e101-001-0", "e101-003-0", "e101-004-0"}, {{"e101-005-0", "e101-007-0", "e101-008-0"}}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(true, chk_ipv4_list));
    ut_chk_ipmc_entry_list chk_ipv6_list {
        {iif_vlan_id, "ff0f::2002", "::", {"e101-002-0", "e101-003-0", "e101-004-0"}, {{"e101-006-0"}}},
        // if no (S, G) route, (*, G) route member will be used
        {iif_vlan_id, "ff0f::2002", "6666::8888", {"e101-002-0", "e101-003-0", "e101-004-0"}, {{"e101-006-0", "e101-007-0", "e101-008-0"}}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(false, chk_ipv6_list));
}

// delete all mrouter port
TEST(nas_mc_flood_restr_ipmc, send_mrouter_del_event)
{
    ASSERT_TRUE(send_mc_update_event(iif_vlan_id, "e101-001-0", TEST_NULL_LIST, TEST_NULL_LIST, true, true, false));
    ASSERT_TRUE(send_mc_update_event(iif_vlan_id, "e101-002-0", TEST_NULL_LIST, TEST_NULL_LIST, false, true, false));
    ASSERT_TRUE(send_mc_update_event(oif_vlan_id, "e101-005-0", TEST_NULL_LIST, TEST_NULL_LIST, true, true, false));
    ASSERT_TRUE(send_mc_update_event(oif_vlan_id, "e101-006-0", TEST_NULL_LIST, TEST_NULL_LIST, false, true, false));
}

TEST(nas_mc_flood_restr_ipmc, check_route_entry_flood_restr_with_snoop_route_no_mrouter)
{
    ut_chk_ipmc_entry_list chk_ipv4_list {
        {iif_vlan_id, "230.1.1.2", "0.0.0.0", {"e101-003-0", "e101-004-0"}, {}},
        {iif_vlan_id, "230.1.1.2", "1.2.3.4", {}, {{"e101-007-0", "e101-008-0"}}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(true, chk_ipv4_list));
    ut_chk_ipmc_entry_list chk_ipv6_list {
        {iif_vlan_id, "ff0f::2002", "::", {"e101-003-0", "e101-004-0"}, {}},
        {iif_vlan_id, "ff0f::2002", "6666::8888", {}, {{"e101-007-0", "e101-008-0"}}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(false, chk_ipv6_list));
}

TEST(nas_mc_flood_restr_ipmc, send_route_del_event)
{
    ASSERT_TRUE(send_mc_update_event(iif_vlan_id, "e101-003-0", {"230.1.1.2"}, TEST_NULL_LIST, true, false, false));
    ASSERT_TRUE(send_mc_update_event(iif_vlan_id, "e101-004-0", {"230.1.1.2"}, TEST_NULL_LIST, true, false, false));
    ASSERT_TRUE(send_mc_update_event(oif_vlan_id, "e101-007-0", {"230.1.1.2"}, {"1.2.3.4"}, true, false, false));
    ASSERT_TRUE(send_mc_update_event(oif_vlan_id, "e101-008-0", {"230.1.1.2"}, {"1.2.3.4"}, true, false, false));

    ASSERT_TRUE(send_mc_update_event(iif_vlan_id, "e101-003-0", {"ff0f::2002"}, TEST_NULL_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(iif_vlan_id, "e101-004-0", {"ff0f::2002"}, TEST_NULL_LIST, false, false, false));
    ASSERT_TRUE(send_mc_update_event(oif_vlan_id, "e101-007-0", {"ff0f::2002"}, {"6666::8888"}, false, false, false));
    ASSERT_TRUE(send_mc_update_event(oif_vlan_id, "e101-008-0", {"ff0f::2002"}, {"6666::8888"}, false, false, false));
}

TEST(nas_mc_flood_restr_ipmc, check_route_entry_flood_restr_enable_no_snoop_route)
{
    ut_chk_ipmc_entry_list chk_ipv4_list {
        {iif_vlan_id, "230.1.1.2", "0.0.0.0", {}, {}},
        {iif_vlan_id, "230.1.1.2", "1.2.3.4", {}, {}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(true, chk_ipv4_list));
    ut_chk_ipmc_entry_list chk_ipv6_list {
        {iif_vlan_id, "ff0f::2002", "::", {}, {}},
        {iif_vlan_id, "ff0f::2002", "6666::8888", {}, {}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(false, chk_ipv6_list));
}

TEST(nas_mc_flood_restr_ipmc, disable_flood_restrict)
{
    ASSERT_TRUE(set_flood_restrict_status(vlan_status_list_t{{iif_vlan_id, false}}));
    ASSERT_TRUE(set_flood_restrict_status(vlan_status_list_t{{oif_vlan_id, false}}));
}

TEST(nas_mc_flood_restr_ipmc, check_route_entry_flood_restr_cleanup)
{
    ut_chk_ipmc_entry_list chk_ipv4_list {
        {iif_vlan_id, "230.1.1.2", "0.0.0.0", {"e101-001-0", "e101-002-0", "e101-003-0", "e101-004-0"}, {{"e101-005-0", "e101-006-0", "e101-007-0", "e101-008-0"}}},
        {iif_vlan_id, "230.1.1.2", "1.2.3.4", {"e101-001-0", "e101-002-0", "e101-003-0", "e101-004-0"}, {{"e101-005-0", "e101-006-0", "e101-007-0", "e101-008-0"}}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(true, chk_ipv4_list));
    ut_chk_ipmc_entry_list chk_ipv6_list {
        {iif_vlan_id, "ff0f::2002", "::", {"e101-001-0", "e101-002-0", "e101-003-0", "e101-004-0"}, {{"e101-005-0", "e101-006-0", "e101-007-0", "e101-008-0"}}},
        {iif_vlan_id, "ff0f::2002", "6666::8888", {"e101-001-0", "e101-002-0", "e101-003-0", "e101-004-0"}, {{"e101-005-0", "e101-006-0", "e101-007-0", "e101-008-0"}}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(false, chk_ipv6_list));
}

TEST(nas_mc_flood_restr_ipmc, del_ipmc_route_entry)
{
    set_ipmc_entry_from_list(false);
}

TEST(nas_mc_flood_restr_ipmc, add_ipmc_route_entry_1)
{
    set_ipmc_entry_from_list(true);
}

TEST(nas_mc_flood_restr_ipmc, enable_flood_restrict_iif_oif)
{
    ASSERT_TRUE(set_flood_restrict_status(vlan_status_list_t{{iif_vlan_id, true}, {oif_vlan_id, true}}));
}

TEST(nas_mc_flood_restr_ipmc, check_route_entry_flood_restr_enable_iif_oif)
{
    ut_chk_ipmc_entry_list chk_ipv4_list {
        {iif_vlan_id, "230.1.1.2", "0.0.0.0", {}, {}},
        {iif_vlan_id, "230.1.1.2", "1.2.3.4", {}, {}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(true, chk_ipv4_list));
    ut_chk_ipmc_entry_list chk_ipv6_list {
        {iif_vlan_id, "ff0f::2002", "::", {}, {}},
        {iif_vlan_id, "ff0f::2002", "6666::8888", {}, {}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(false, chk_ipv6_list));
}

TEST(nas_mc_flood_restr_ipmc, send_mld_mrouter_add_event_iif_oif)
{
    ASSERT_TRUE(send_mc_update_event(iif_vlan_id, "e101-001-0", TEST_NULL_LIST, TEST_NULL_LIST, false, true, true));
    ASSERT_TRUE(send_mc_update_event(oif_vlan_id, "e101-005-0", TEST_NULL_LIST, TEST_NULL_LIST, false, true, true));
}

TEST(nas_mc_flood_restr_ipmc, check_route_entry_mld_mrouter)
{
    ut_chk_ipmc_entry_list chk_ipv4_list {
        {iif_vlan_id, "230.1.1.2", "0.0.0.0", {}, {}},
        {iif_vlan_id, "230.1.1.2", "1.2.3.4", {}, {}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(true, chk_ipv4_list));
    ut_chk_ipmc_entry_list chk_ipv6_list {
        {iif_vlan_id, "ff0f::2002", "::", {"e101-001-0"}, {{"e101-005-0"}}},
        {iif_vlan_id, "ff0f::2002", "6666::8888", {"e101-001-0"}, {{"e101-005-0"}}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(false, chk_ipv6_list));
}

TEST(nas_mc_flood_restr_ipmc, send_igmp_mrouter_add_event_iif_oif)
{
    ASSERT_TRUE(send_mc_update_event(iif_vlan_id, "e101-001-0", TEST_NULL_LIST, TEST_NULL_LIST, true, true, true));
    ASSERT_TRUE(send_mc_update_event(oif_vlan_id, "e101-005-0", TEST_NULL_LIST, TEST_NULL_LIST, true, true, true));
}

TEST(nas_mc_flood_restr_ipmc, check_route_entry_igmp_mld_mrouter)
{
    ut_chk_ipmc_entry_list chk_ipv4_list {
        {iif_vlan_id, "230.1.1.2", "0.0.0.0", {"e101-001-0"}, {{"e101-005-0"}}},
        {iif_vlan_id, "230.1.1.2", "1.2.3.4", {"e101-001-0"}, {{"e101-005-0"}}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(true, chk_ipv4_list));
    ut_chk_ipmc_entry_list chk_ipv6_list {
        {iif_vlan_id, "ff0f::2002", "::", {"e101-001-0"}, {{"e101-005-0"}}},
        {iif_vlan_id, "ff0f::2002", "6666::8888", {"e101-001-0"}, {{"e101-005-0"}}}
    };
    ASSERT_TRUE(check_ipmc_entry_group(false, chk_ipv6_list));
}

TEST(nas_mc_flood_restr_ipmc, send_mrouter_del_event_iif_oif)
{
    ASSERT_TRUE(send_mc_update_event(iif_vlan_id, "e101-001-0", TEST_NULL_LIST, TEST_NULL_LIST, true, true, false));
    ASSERT_TRUE(send_mc_update_event(oif_vlan_id, "e101-005-0", TEST_NULL_LIST, TEST_NULL_LIST, true, true, false));
    ASSERT_TRUE(send_mc_update_event(iif_vlan_id, "e101-001-0", TEST_NULL_LIST, TEST_NULL_LIST, false, true, false));
    ASSERT_TRUE(send_mc_update_event(oif_vlan_id, "e101-005-0", TEST_NULL_LIST, TEST_NULL_LIST, false, true, false));
}

TEST(nas_mc_flood_restr_ipmc, disable_flood_restrict_iif_oif)
{
    ASSERT_TRUE(set_flood_restrict_status(vlan_status_list_t{{iif_vlan_id, false}, {oif_vlan_id, false}}));
}

TEST(nas_mc_flood_restr_ipmc, del_ipmc_route_entry_1)
{
    set_ipmc_entry_from_list(false);
}

TEST(nas_mc_flood_restr_ipmc, disable_pim) {
    for (auto& vlan_entry: ipmc_test_vlan_list) {
        string br_name{};
        if (check_vlan_exists(vlan_entry.first, br_name)) {
            ASSERT_TRUE(set_pim_status(test_vrf_name, AF_INET, false, br_name, false));
            ASSERT_TRUE(set_pim_status(test_vrf_name, AF_INET6, false, br_name, false));
        }
    }
    ASSERT_TRUE(set_pim_status(test_vrf_name, AF_INET, true, "", false));
    ASSERT_TRUE(set_pim_status(test_vrf_name, AF_INET6, true, "", false));
}

TEST(nas_mc_flood_restr_ipmc, delete_vlan)
{
    for (auto& vlan_entry: ipmc_test_vlan_list) {
        string br_name{};
        if (check_vlan_exists(vlan_entry.first, br_name)) {
            ASSERT_TRUE(set_vlan_or_lag_with_member(intf_type::VLAN, br_name, {}, oper_type::DELETE));
        }
    }
}

int main(int argc, char *argv[])

{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
