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
 * filename: nas_l2_mc_api.h
 */

#ifndef __NAS_L2_MC_API_H__
#define __NAS_L2_MC_API_H__

#include "dell-base-common.h"
#include "ds_common_types.h"
#include "std_error_codes.h"
#include <set>

t_std_error nas_mc_l2_snooped_port_list_cache_get (npu_id_t npu_id, hal_vlan_id_t vlan_id,
                                                   BASE_CMN_AF_TYPE_t af, bool is_xg,
                                                   hal_ip_addr_t grp_ip, hal_ip_addr_t src_ip,
                                                   std::set<hal_ifindex_t> &if_list);
void nas_mc_update_pim_status(hal_vlan_id_t vlan_id, uint32_t af, bool status);

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
