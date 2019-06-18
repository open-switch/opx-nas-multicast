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
 * filename: nas_mc_l3_cache.h
 */

#ifndef __NAS_MC_L3_CACHE_H__
#define __NAS_MC_L3_CACHE_H__


#include "ds_common_types.h"
#include "std_error_codes.h"
#include "std_llist.h"
#include "nas_types.h"
#include "hal_if_mapping.h"
#include "nas_vrf_utils.h"
#include "nas_ndi_router_interface.h"
#include "cps_api_operation.h"
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <memory>
#include <list>
#include <deque>
#include <utility>

/* Cache */

typedef enum vlan_member_type_e {
    tagged,
    untagged,
} vlan_member_type_t;

// Interface cache
typedef struct _if_str_s {
    std::string if_name;
    hal_ifindex_t if_index;
    std::string vrf_name;
    hal_vrf_id_t vrf_id;
    nas_int_type_t if_type;
    hal_vlan_id_t  vlan_id;
    ndi_rif_id_t rif_id;
    bool v4_pim_valid;
    bool v4_pim_status;
    bool v6_pim_valid;
    bool v6_pim_status;
}if_str_t;

struct intf_id_cache_key_t {
    hal_ifindex_t if_index;
    hal_vrf_id_t  vrf_id;
};

// VRF Cache

typedef struct _vrf_str_s {
    std::string vrf_name;
    nas_obj_id_t vrf_obj_id;
    bool v4_mcast_valid;
    bool v4_mcast_status;
    bool v6_mcast_valid;
    bool v6_mcast_status;
}vrf_str_t;

typedef std::unordered_set<hal_ifindex_t> mcast_intf_mlist_t;
typedef std::unordered_map<std::string, mcast_intf_mlist_t> mcast_intf_mlist_map_t;
typedef std::pair<std::string, mcast_intf_mlist_t> mcast_intf_mlist_map_pair_t;

typedef void (*mcast_vrf_obj_get_cb)(vrf_str_t &vrf_info, cps_api_get_params_t *param,
                                     cps_api_qualifier_t qual);
void mcast_vrf_cache_for_each_entry_cps_get(cps_api_get_params_t *param, cps_api_qualifier_t qual,
                                            mcast_vrf_obj_get_cb fn);
bool mcast_vrf_cache_get (uint32_t vrf_id, vrf_str_t &_vrf_info);
bool mcast_vrf_cache_get (std::string vrf_name, vrf_str_t &_vrf_info);
bool mcast_vrf_cache_update (uint32_t vrf_id, vrf_str_t *vrf_info);



typedef void (*mcast_intf_obj_get_cb)(if_str_t &intf_info, cps_api_get_params_t *param,
                                      cps_api_qualifier_t qual, bool af_valid, BASE_CMN_AF_TYPE_t af);
void mcast_intf_cache_for_each_entry_cps_get(cps_api_get_params_t *param, cps_api_qualifier_t qual,
                                             mcast_intf_obj_get_cb fn, bool vrf_valid, hal_vrf_id_t vrf_id,
                                             bool af_valid, BASE_CMN_AF_TYPE_t af);

void mcast_intf_cache_get_all_interfaces_for_vrf(hal_vrf_id_t vrf_id, std::list<std::string>& vrf_intf_list);
bool mcast_intf_cache_get (std::string if_name, if_str_t &_intf_info);
bool mcast_intf_cache_update (std::string if_name, if_str_t *intf_info);
bool mcast_intf_cache_get (intf_id_cache_key_t &key, if_str_t &_intf_info);
bool mcast_intf_cache_get_rif_id (hal_vrf_id_t vrf_id, hal_ifindex_t if_index,
                                  ndi_rif_id_t *rif_id);

void mcast_intf_mlist_map_update (std::string if_name, vlan_member_type_t mtype,
                                  hal_ifindex_t mem_index, bool add);

bool mcast_intf_mlist_map_clear (std::string if_name);

bool mcast_intf_mlist_map_mlist_get (std::string if_name, vlan_member_type_t mtype,
                                     std::unordered_set<hal_ifindex_t> & intf_list);

void mcast_vlan_member_port_delete (hal_ifindex_t mem_index, std::list<std::string>& vlan_if_name_list);

#ifdef __cplusplus
extern "C" {
#endif
    /*
     * Declare any functions need exter C linkage.
     */

#ifdef __cplusplus
}
#endif

#endif
