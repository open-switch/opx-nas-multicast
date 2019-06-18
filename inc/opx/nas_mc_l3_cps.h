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
 * filename: nas_mc_l3_cps.h
 */

#ifndef __NAS_MC_L3_CPS_H__
#define __NAS_MC_L3_CPS_H__


#include "std_error_codes.h"
#include "event_log.h"
#include "cps_api_errors.h"
#include "l3-multicast.h"
#include "ds_common_types.h"
#include <string>

typedef struct l3_mcast_route_cps_key_s {
    std::string            vrf_name;
    bool                   vrf_name_valid;
    BASE_CMN_AF_TYPE_t     af;
    bool                   af_valid;
    hal_ip_addr_t          src_ip;
    bool                   src_ip_valid;
    hal_ip_addr_t          grp_ip;
    bool                   grp_ip_valid;
    L3_MCAST_ROUTE_TYPE_t  rt_type;
    bool                   rt_type_valid;
} l3_mcast_route_cps_key_t;

cps_api_return_code_t mcast_snoop_vlan_update_event_handler(const char *vlan_if_name, uint32_t af);
cps_api_return_code_t mcast_snoop_route_update_event_handler(const char *vlan_if_name, uint32_t af,
                    const hal_ip_addr_t *group_addr, const hal_ip_addr_t *source_addr);

cps_api_return_code_t handle_l3_mcast_interface_config (cps_api_operation_types_t op, cps_api_object_it_t it);
cps_api_return_code_t mcast_l3_cps_init(void);

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Declare functions which need C extern linkage.
 */

#ifdef __cplusplus
}
#endif

#endif
