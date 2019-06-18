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
 * filename: nas_mc_repl_grp.cpp
 */

#include "nas_mc_l3_util.h"
#include "nas_types.h"
#include "nas_vrf_utils.h"
#include "std_utils.h"
#include "nas_base_utils.h"
#include "nas_mc_repl_grp_db.h"
#include "nas_mc_l3_ndi.h"
#include "nas_switch.h"


/*
 * Replication group entry management functions
 */

t_std_error mcast_l3_repl_grp_entry_add (hal_vrf_id_t vrf_id, mcast_if_list_t *expanded_iif_list,
                                         mcast_if_list_t *expanded_oif_list, bool cptocpu,
                                         nas_mcast_obj_id_t &obj_id)
{
    nas_mcast_obj_id_t repl_grp_id = NAS_MC_INVALID_REPL_GRP_ID;
    mcast_repl_grp_id_list_t repl_grp_id_list;

    if (hal_mc_l3_repl_grp_entry_add (vrf_id, expanded_iif_list,
                                      expanded_oif_list,
                                      repl_grp_id_list) != STD_ERR_OK)
    {
        NAS_MC_L3_LOG_ERR ("REPL-GRP", "Repl. group entry add failed in NDI ");

        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    if (!mcast_repl_grp_db_entry_add (MCAST_L3, vrf_id, expanded_iif_list,
                expanded_oif_list, cptocpu, repl_grp_id_list, repl_grp_id))
    {
        NAS_MC_L3_LOG_ERR ("REPL-GRP", "Repl. group entry add failed "
                           "during DB add");

        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    NAS_MC_L3_LOG_ERR ("REPL-GRP", "Repl. group entry add success "
                       "repl_grp_id:0x%lx", repl_grp_id);

    obj_id = repl_grp_id;
    return STD_ERR_OK;
}

// delete repl. group entry from NDI and repl. group DB.
// caller has to make sure if ref_cnt is 0 before calling this.
t_std_error mcast_l3_repl_grp_entry_delete (nas_mcast_obj_id_t repl_grp_id)
{
    NAS_MC_L3_LOG_DEBUG ("REPL-GRP", "Repl. group delete, "
            "repl_grp_id:0x%lx ", repl_grp_id);

    if(hal_mc_l3_repl_grp_entry_del(repl_grp_id) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR ("REPL-GRP", "Repl. group delete failed in NDI, "
                "repl_grp_id:0x%lx", repl_grp_id);

        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    //delete repl. group entry in db
    mcast_repl_grp_db_entry_delete (repl_grp_id);

    NAS_MC_L3_LOG_DEBUG ("REPL-GRP", "Repl. group check and delete success, "
            "repl_grp_id:0x%lx ", repl_grp_id);

    return STD_ERR_OK;
}

// check and delete repl. group entry
t_std_error mcast_l3_check_and_delete_repl_grp_entry_delete (nas_mcast_obj_id_t repl_grp_id)
{
    uint32_t ref_cnt = 0;

    // check if ref count is 0, then delete the repl. group entry
    if (!mcast_repl_grp_db_ref_cnt_op (repl_grp_id, MCAST_RGRP_REF_CNT_GET, ref_cnt)) {
        NAS_MC_L3_LOG_ERR ("REPL-GRP", "Repl. group check and delete failed "
                "in retrieving repl_grp_id:0x%lx ",
                repl_grp_id);

        return STD_ERR(MCAST_L3, FAIL, 0);

    }
    NAS_MC_L3_LOG_DEBUG ("REPL-GRP", "Repl. group check and delete, "
            "repl. group id:0x%lx, ref_cnt:%d ",
            repl_grp_id, ref_cnt);

    if (ref_cnt == 0) {
        return (mcast_l3_repl_grp_entry_delete (repl_grp_id));
    }

    return STD_ERR_OK;
}
