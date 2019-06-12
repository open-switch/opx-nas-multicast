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
 * filename: nas_mc_l3_ndi.h
 */

#include "stddef.h"
#include "std_error_codes.h"
#include "nas_mc_repl_grp_db.h"
#include "nas_ndi_ipmc.h"

#ifndef __NAS_MC_L3_NDI_H__
#define __NAS_MC_L3_NDI_H__

t_std_error mcast_l3_repl_grp_entry_add (hal_vrf_id_t vrf_id, mcast_if_list_t *expanded_iif_list,
                                         mcast_if_list_t *expanded_oif_list, bool cptocpu,
                                         nas_mcast_obj_id_t &obj_id);
t_std_error mcast_l3_repl_grp_entry_delete (nas_mcast_obj_id_t repl_grp_id);
t_std_error mcast_l3_check_and_delete_repl_grp_entry_delete(nas_mcast_obj_id_t repl_grp_id);

t_std_error hal_mc_l3_repl_grp_entry_add (uint32_t vrf_id, mcast_if_list_t *expanded_iif_list,
                                          mcast_if_list_t *expanded_oif_list,
                                          mcast_repl_grp_id_list_t &repl_grp_id_list);

t_std_error hal_mc_l3_repl_grp_entry_del (nas_mcast_obj_id_t repl_grp_id);

t_std_error hal_mc_l3_route_add(mc_route_t *rt_info);
t_std_error hal_mc_l3_route_update(mc_route_t *rt_info);
t_std_error hal_mc_l3_route_delete(mc_route_t *rt_info);

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
