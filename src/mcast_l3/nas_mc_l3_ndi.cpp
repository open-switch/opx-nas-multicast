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
 * filename: nas_mc_l3_ndi.cpp
 */

#include "nas_types.h"
#include "nas_mc_l3_util.h"
#include "nas_mc_l3_msg.h"
#include "nas_mc_l3_cache.h"
#include "nas_mc_l3_walker.h"
#include "nas_mc_repl_grp_db.h"
#include "nas_mc_l3_ndi.h"
#include "nas_ndi_mcast.h"
#include "nas_ndi_ipmc.h"
#include "nas_switch.h"
#include "std_utils.h"
#include "std_ip_utils.h"


static t_std_error hal_mc_l3_repl_grp_get_ndi_mc_grp_mbr (hal_vrf_id_t vrf_id,
                                                   const mcast_if_list_t *expanded_if_list,
                                                   ndi_mc_grp_mbr_t **ndi_mc_grp,
                                                   size_t *ndi_mc_grp_mbr_cnt)
{
    size_t mbr_port_count = 0;
    ndi_rif_id_t rif_id;
    //intf_id_cache_key_t key;
    //if_str_t            intf_info;
    interface_ctrl_t      intf_info;

    *ndi_mc_grp_mbr_cnt = 0;

    if ((expanded_if_list == NULL) ||
        (ndi_mc_grp == NULL) ||
        (ndi_mc_grp_mbr_cnt == NULL)) {

        return STD_ERR_OK;
    }
    auto mbr_list_count = expanded_if_list->size();

    NAS_MC_L3_LOG_DEBUG ("NDI", "Repl. group mc_grp_mbr info "
                         "vrf_id:%ld, mbr_list_count:%d", vrf_id, mbr_list_count);

    if (mbr_list_count == 0) {
        *ndi_mc_grp = nullptr;
        *ndi_mc_grp_mbr_cnt = 0;
        return STD_ERR_OK;
    }

    std::unique_ptr<ndi_mc_grp_mbr_t[]> mbr_list_ptr{new ndi_mc_grp_mbr_t[mbr_list_count]};
    std::vector<std::unique_ptr<ndi_sw_port_t[]>> mbr_port_list_ptr(mbr_list_count);

    auto mbr_it = expanded_if_list->begin();
    for (int mbr_idx = 0;mbr_it != expanded_if_list->end(); ++mbr_it, ++mbr_idx) {

        NAS_MC_L3_LOG_DEBUG ("NDI", "IF: %d ", mbr_it->first);

        if (!mcast_intf_cache_get_rif_id (vrf_id, mbr_it->first,
                    &rif_id)) {
            NAS_MC_L3_LOG_ERR ("NDI", "Repl. group create failed in "
                    "RPF rif id get for Vrf:%d, IF:%d ",
                    vrf_id, mbr_it->first);

            return STD_ERR(MCAST_L3, FAIL, 0);
        }

        mbr_list_ptr[mbr_idx].rif_id = rif_id;

        mbr_port_count = mbr_it->second.size();
        NAS_MC_L3_LOG_DEBUG ("NDI", "IF: %d RIF:0x%lx, mbr_port_count:%d ",
                             mbr_it->first, rif_id, mbr_port_count);
        if (mbr_port_count == 0) {
            mbr_list_ptr[mbr_idx].port_list.port_count = 0;
            mbr_list_ptr[mbr_idx].port_list.list = nullptr;
            continue;
        }

        mbr_port_list_ptr[mbr_idx] = std::unique_ptr<ndi_sw_port_t[]>{new ndi_sw_port_t[mbr_port_count]};
        mbr_list_ptr[mbr_idx].port_list.port_count = mbr_port_count;
        mbr_list_ptr[mbr_idx].port_list.list = mbr_port_list_ptr[mbr_idx].get();

        mcast_if_set_t::iterator mbr_port_it = mbr_it->second.begin();

        hal_ifindex_t if_index;
        for( int mbr_port_idx = 0;mbr_port_it != mbr_it->second.end(); ++mbr_port_it, ++mbr_port_idx) {
            if_index = *mbr_port_it;

            memset(&intf_info,0,sizeof(intf_info));
            // for l2 ports always use default vrf-id during lookup
            intf_info.vrf_id = NAS_DEFAULT_VRF_ID;
            intf_info.if_index = if_index;
            intf_info.q_type = HAL_INTF_INFO_FROM_IF;

            if (dn_hal_get_interface_info (&intf_info)) {
                NAS_MC_L3_LOG_ERR ("NDI", "Repl. group create failed in "
                        "Intf member info get for Vrf:%d, Ifx:%d Mbr Ifx:%d",
                        vrf_id, mbr_it->first, if_index);

                return STD_ERR(MCAST_L3, FAIL, 0);
            }

            switch (intf_info.int_type) {
                case nas_int_type_PORT:
                    mbr_list_ptr[mbr_idx].port_list.list[mbr_port_idx].port_type = NDI_SW_PORT_NPU_PORT;
                    mbr_list_ptr[mbr_idx].port_list.list[mbr_port_idx].u.npu_port.npu_id = intf_info.npu_id;
                    mbr_list_ptr[mbr_idx].port_list.list[mbr_port_idx].u.npu_port.npu_port = intf_info.port_id;

                    NAS_MC_L3_LOG_DEBUG ("NDI", "IF Mbr IfType:%d, npu_id:%d, port_id:%d",
                                         intf_info.int_type, intf_info.npu_id, intf_info.port_id);
                    break;
                case nas_int_type_LAG:
                    mbr_list_ptr[mbr_idx].port_list.list[mbr_port_idx].port_type = NDI_SW_PORT_LAG;
                    mbr_list_ptr[mbr_idx].port_list.list[mbr_port_idx].u.lag = intf_info.lag_id;

                    NAS_MC_L3_LOG_DEBUG ("NDI", "IF Mbr IfType:%d, lag_id:0x%lx",
                                         intf_info.int_type, intf_info.lag_id);
                    break;
                default:
                    break;
            }
        }
    }

    *ndi_mc_grp = mbr_list_ptr.release();
    *ndi_mc_grp_mbr_cnt = mbr_list_count;
    for (auto& mbr_port_ptr: mbr_port_list_ptr) {
        mbr_port_ptr.release();
    }

    return STD_ERR_OK;
}
static void hal_mc_l3_repl_grp_cleanup_ndi_mc_grp_mbr(ndi_mc_grp_mbr_t *ndi_mc_grp,
                                                      size_t ndi_mc_grp_mbr_cnt)
{
    if (ndi_mc_grp_mbr_cnt == 0 || ndi_mc_grp == nullptr) {
        return;
    }
    for (size_t idx = 0; idx < ndi_mc_grp_mbr_cnt; idx++) {
        if (ndi_mc_grp[idx].port_list.list != nullptr) {
            delete[] ndi_mc_grp[idx].port_list.list;
            ndi_mc_grp[idx].port_list.list = nullptr;
        }
    }
    delete[] ndi_mc_grp;
}

// Add repl. group in NDI
t_std_error hal_mc_l3_repl_grp_entry_add (hal_vrf_id_t vrf_id, mcast_if_list_t *expanded_iif_list,
                                          mcast_if_list_t *expanded_oif_list,
                                          mcast_repl_grp_id_list_t &repl_grp_id_list)
{
    size_t npu_id;
    size_t rpf_grp_mbr_cnt = 0;
    size_t ipmc_grp_mbr_cnt = 0;
    size_t max_npu = nas_switch_get_max_npus();
    ndi_obj_id_t repl_group_id;
    ndi_mc_grp_mbr_t *rpf_grp = NULL;
    ndi_mc_grp_mbr_t *ipmc_grp = NULL;


    if (hal_mc_l3_repl_grp_get_ndi_mc_grp_mbr (vrf_id,
                                               expanded_iif_list,
                                               &rpf_grp, &rpf_grp_mbr_cnt)
            != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR ("NDI", "Repl. group create failed in "
                           "RPF group member info get");
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    if (rpf_grp_mbr_cnt != 1) {
        NAS_MC_L3_LOG_ERR ("NDI", "Repl. group should only contain 1 RPF member, not %ld",
                           rpf_grp_mbr_cnt);
        return STD_ERR(MCAST_L3, PARAM, 0);
    }

    if (hal_mc_l3_repl_grp_get_ndi_mc_grp_mbr (vrf_id,
                                               expanded_oif_list,
                                               &ipmc_grp, &ipmc_grp_mbr_cnt)
            != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR ("NDI", "Repl. group create failed in "
                           "IPMC group member info get");
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    NAS_MC_L3_LOG_INFO ("NDI", "Repl. group create called with "
            "RPF group mbr count:%ld, "
            "IPMC group mbr count:%ld ",
            rpf_grp_mbr_cnt, ipmc_grp_mbr_cnt);

    t_std_error rc = STD_ERR_OK;

    for(npu_id = 0; npu_id < max_npu; npu_id++) {

        if(ndi_create_repl_group (npu_id, REPL_GROUP_OWNER_IPMC, rpf_grp,
                                  ipmc_grp_mbr_cnt, ipmc_grp,
                                  &repl_group_id) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR ("NDI", "Repl. group create failed.");

            rc = STD_ERR(MCAST_L3, FAIL, 0);
            break;
        }
        repl_grp_id_list.insert(mcast_repl_grp_id_list_pair_t(npu_id, repl_group_id));
    }

    hal_mc_l3_repl_grp_cleanup_ndi_mc_grp_mbr (rpf_grp, rpf_grp_mbr_cnt);
    hal_mc_l3_repl_grp_cleanup_ndi_mc_grp_mbr (ipmc_grp, ipmc_grp_mbr_cnt);

    return rc;
}


// Del repl. group in NDI
t_std_error hal_mc_l3_repl_grp_entry_del (nas_mcast_obj_id_t repl_grp_id)
{
    size_t npu_id;
    size_t max_npu = nas_switch_get_max_npus();
    ndi_obj_id_t ndi_repl_grp_id = 0;

    NAS_MC_L3_LOG_INFO ("REPL-GRP", "Repl. group delete, "
            "repl. group id:0x%lx ", repl_grp_id);

    for(npu_id = 0; npu_id < max_npu; npu_id++) {
        if (mcast_repl_grp_db_entry_get_ndi_obj_id (npu_id, repl_grp_id, &ndi_repl_grp_id) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR ("REPL-GRP", "Repl. group delete failed in get NDI id, "
                    "repl. group id:0x%lx, npu_id:%ld",
                    repl_grp_id, npu_id);

            return STD_ERR(MCAST_L3, FAIL, 0);
        }

        if(ndi_delete_repl_group(npu_id, ndi_repl_grp_id) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR ("REPL-GRP", "Repl. group delete failed in NDI, "
                    "repl. group id:0x%lx, npu_id:%ld, ndi_id:0x%lx",
                    repl_grp_id, npu_id, ndi_repl_grp_id);

            return STD_ERR(MCAST_L3, FAIL, 0);
        }
    }

    return STD_ERR_OK;
}


// Add route in NDI
t_std_error hal_mc_l3_route_add (mc_route_t *rt_info)
{
    size_t npu_id;
    ndi_ipmc_entry_t ndi_ipmc_entry;
    size_t max_npu = nas_switch_get_max_npus();
    ndi_rif_id_t iif_rif_id;

    //set the status to pending until the route programming to NDI is complete,
    //failure stauts will be set accordingly.
    rt_info->status = rt_status_t::PENDING_IN_QUEUE;

    memset (&ndi_ipmc_entry, 0, sizeof (ndi_ipmc_entry_t));

    vrf_str_t vrf_tmp;
    if (mcast_vrf_cache_get(rt_info->vrf_id, vrf_tmp) != true) {
        NAS_MC_L3_LOG_ERR ("NDI", "Route Add failed, VRF info not found, "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d",
                rt_info->vrf_id, rt_info->af, rt_info->rtype,
                MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                rt_info->iif_id,
                (int)rt_info->status);

        return STD_ERR(MCAST_L3, FAIL, 0);
    }
    if (!mcast_intf_cache_get_rif_id (rt_info->vrf_id, rt_info->iif_id,
                &iif_rif_id)) {
        NAS_MC_L3_LOG_ERR ("NDI", "Route Add failed, RIF info not found for IIF, "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d",
                rt_info->vrf_id, rt_info->af, rt_info->rtype,
                MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                rt_info->iif_id,
                (int)rt_info->status);
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    ndi_ipmc_entry.iif_rif_id = iif_rif_id;
    ndi_ipmc_entry.vrf_id = vrf_tmp.vrf_obj_id;
    ndi_ipmc_entry.type = (ndi_ipmc_entry_type_t) ((rt_info->rtype == L3_MCAST_ROUTE_TYPE_XG) ? NAS_NDI_IPMC_ENTRY_TYPE_XG :
                           ((rt_info->rtype == L3_MCAST_ROUTE_TYPE_SG) ||(rt_info->rtype == L3_MCAST_ROUTE_TYPE_SGRPT)) ? NAS_NDI_IPMC_ENTRY_TYPE_SG : 0);

    ndi_ipmc_entry.copy_to_cpu = rt_info->copy_to_cpu;
    memcpy (&ndi_ipmc_entry.dst_ip, &rt_info->grp_ip, sizeof (hal_ip_addr_t));
    memcpy (&ndi_ipmc_entry.src_ip, &rt_info->src_ip, sizeof (hal_ip_addr_t));

    ndi_obj_id_t ndi_repl_grp_id = 0;
    for(npu_id = 0; npu_id < max_npu; npu_id++) {

        if (mcast_repl_grp_db_entry_get_ndi_obj_id (npu_id, rt_info->repl_grp_id, &ndi_repl_grp_id) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR ("NDI", "Route Add failed, "
                    "failure in retrieving NDI repl. group id for "
                    "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d, nas_obj_id:0x%lx",
                    rt_info->vrf_id, rt_info->af, rt_info->rtype,
                    MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                    MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                    rt_info->iif_id, (int)rt_info->status, rt_info->repl_grp_id);

            rt_info->status = rt_status_t::REPL_GRP_PROG_FAIL;

            return STD_ERR(MCAST_L3, FAIL, 0);
        }

        ndi_ipmc_entry.repl_group_id = ndi_repl_grp_id;

        if(ndi_ipmc_entry_create (npu_id, &ndi_ipmc_entry) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR ("NDI", "Route Add failed, "
                    "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, IIF RIF id 0x%lx status:%d",
                    rt_info->vrf_id, rt_info->af, rt_info->rtype,
                    MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                    MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                    rt_info->iif_id, iif_rif_id,
                    (int)rt_info->status);

            rt_info->status = rt_status_t::IPMC_PROG_FAIL;

            // if route add fails, the replication group can be newly created.
            // check and delete repl. group entry if ref count is 0, otherwise
            // replication group will be stale.
            if (mcast_l3_check_and_delete_repl_grp_entry_delete (rt_info->repl_grp_id) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR ("NDI", "NDI repl. group check and delete failed, "
                        "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d, nas_obj_id:0x%lx",
                        rt_info->vrf_id, rt_info->af, rt_info->rtype,
                        MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                        MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                        rt_info->iif_id, (int)rt_info->status,
                        rt_info->repl_grp_id);
            }
            return STD_ERR(MCAST_L3, FAIL, 0);
        }
    }

    uint32_t ref_cnt = 0;
    // increment repl. group entry ref count
    if (!mcast_repl_grp_db_ref_cnt_op (rt_info->repl_grp_id, MCAST_RGRP_REF_CNT_INC, ref_cnt)) {
        NAS_MC_L3_LOG_ERR ("NDI", "Repl. group Add failed "
                "in incrementing reference count, "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d, nas_obj_id:0x%lx",
                rt_info->vrf_id, rt_info->af, rt_info->rtype,
                MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                rt_info->iif_id, (int)rt_info->status,
                rt_info->repl_grp_id);

        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    rt_info->status = rt_status_t::PROG_SUCCEED;

    //update npu programming status to true
    rt_info->npu_prg_status = true;

    return STD_ERR_OK;
}


// Update route in NDI
t_std_error hal_mc_l3_route_update (mc_route_t *rt_info)
{
    size_t npu_id;
    ndi_ipmc_entry_t ndi_ipmc_entry;
    size_t max_npu = nas_switch_get_max_npus();
    ndi_rif_id_t iif_rif_id;

    if (rt_info->repl_grp_id == NAS_MC_INVALID_REPL_GRP_ID) {
        NAS_MC_L3_LOG_ERR ("NDI", "Route Update skipped, invalid repl. grp id, "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d, repl_grp_id:0x%lx",
                rt_info->vrf_id, rt_info->af, rt_info->rtype,
                MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                rt_info->iif_id, (int)rt_info->status,
                rt_info->repl_grp_id);

        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    memset (&ndi_ipmc_entry, 0, sizeof (ndi_ipmc_entry_t));

    vrf_str_t vrf_tmp;
    if (mcast_vrf_cache_get(rt_info->vrf_id, vrf_tmp) != true) {
        NAS_MC_L3_LOG_ERR ("NDI", "Route Update failed, VRF info not found, "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d",
                rt_info->vrf_id, rt_info->af, rt_info->rtype,
                MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                rt_info->iif_id,
                (int)rt_info->status);

        return STD_ERR(MCAST_L3, FAIL, 0);
    }
    if (!mcast_intf_cache_get_rif_id (rt_info->vrf_id, rt_info->iif_id,
                &iif_rif_id)) {
        NAS_MC_L3_LOG_ERR ("NDI", "Route update failed, RIF info not found for IIF, "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d",
                rt_info->vrf_id, rt_info->af, rt_info->rtype,
                MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                rt_info->iif_id,
                (int)rt_info->status);
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    ndi_ipmc_entry.iif_rif_id = iif_rif_id;
    ndi_ipmc_entry.vrf_id = vrf_tmp.vrf_obj_id;
    ndi_ipmc_entry.type = (ndi_ipmc_entry_type_t) ((rt_info->rtype == L3_MCAST_ROUTE_TYPE_XG) ? NAS_NDI_IPMC_ENTRY_TYPE_XG :
                           ((rt_info->rtype == L3_MCAST_ROUTE_TYPE_SG) || (rt_info->rtype == L3_MCAST_ROUTE_TYPE_SGRPT)) ? NAS_NDI_IPMC_ENTRY_TYPE_SG : 0);

    ndi_ipmc_entry.copy_to_cpu = rt_info->copy_to_cpu;
    memcpy (&ndi_ipmc_entry.dst_ip, &rt_info->grp_ip, sizeof (hal_ip_addr_t));
    memcpy (&ndi_ipmc_entry.src_ip, &rt_info->src_ip, sizeof (hal_ip_addr_t));

    ndi_obj_id_t ndi_repl_grp_id = 0;
    for(npu_id = 0; npu_id < max_npu; npu_id++) {

        if (mcast_repl_grp_db_entry_get_ndi_obj_id (npu_id, rt_info->repl_grp_id, &ndi_repl_grp_id) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR ("NDI", "Route Update failed, "
                    "failure in retrieving NDI repl. group id for "
                    "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d, nas_obj_id:0x%lx",
                    rt_info->vrf_id, rt_info->af, rt_info->rtype,
                    MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                    MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                    rt_info->iif_id, (int)rt_info->status, rt_info->repl_grp_id);

            rt_info->status = rt_status_t::REPL_GRP_PROG_FAIL;

            return STD_ERR(MCAST_L3, FAIL, 0);
        }

        ndi_ipmc_entry.repl_group_id = ndi_repl_grp_id;

        //Route update type to NDI is always sent as NAS_NDI_IPMC_UPD_REPL_GRP.
        //this is done because for NAS even if only cpToCpu changes, it would result in
        //allocating new repl. grp id and hence it would be triggered as update.
        if(ndi_ipmc_entry_update (npu_id, &ndi_ipmc_entry, NAS_NDI_IPMC_UPD_REPL_GRP) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR ("NDI", "Route Update failed, "
                    "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, IIF RIF Id 0x%lx status:%d",
                    rt_info->vrf_id, rt_info->af, rt_info->rtype,
                    MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                    MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                    rt_info->iif_id,iif_rif_id,
                    (int)rt_info->status);

            rt_info->status = rt_status_t::IPMC_PROG_FAIL;

            // if route update fails, the replication group can be newly created.
            // check and delete repl. group entry if ref count is 0, otherwise
            // replication group will be stale.
            if (mcast_l3_check_and_delete_repl_grp_entry_delete (rt_info->repl_grp_id) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR ("NDI", "NDI repl. group check and delete failed, "
                        "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d, nas_obj_id:0x%lx",
                        rt_info->vrf_id, rt_info->af, rt_info->rtype,
                        MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                        MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                        rt_info->iif_id, (int)rt_info->status,
                        rt_info->repl_grp_id);
            }
            return STD_ERR(MCAST_L3, FAIL, 0);
        }
    }

    uint32_t ref_cnt = 0;
    // increment repl. group entry ref count
    if (!mcast_repl_grp_db_ref_cnt_op (rt_info->repl_grp_id, MCAST_RGRP_REF_CNT_INC, ref_cnt)) {
        NAS_MC_L3_LOG_ERR ("NDI", "Route Update failed, repl. group ref count incr failed, "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d, repl_grp_id:0x%lx",
                rt_info->vrf_id, rt_info->af, rt_info->rtype,
                MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                rt_info->iif_id, (int)rt_info->status,
                rt_info->repl_grp_id);

        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    rt_info->status = rt_status_t::PROG_SUCCEED;

    //update npu programming status to true
    rt_info->npu_prg_status = true;

    return STD_ERR_OK;
}


// Delete route from NDI
t_std_error hal_mc_l3_route_delete(mc_route_t *rt_info)
{
    size_t npu_id;
    ndi_ipmc_entry_t ndi_ipmc_entry;
    size_t max_npu = nas_switch_get_max_npus();
    ndi_rif_id_t iif_rif_id;

    // if route is programmed in NPU , delete it, the update or previous operation
    // on the route might have failed, but once route in NPU, delete it
    if (rt_info->npu_prg_status != true) {
        NAS_MC_L3_LOG_DEBUG ("NDI", "Route delete skipped, not configured in NPU, "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d",
                rt_info->vrf_id, rt_info->af, rt_info->rtype,
                MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                rt_info->iif_id,
                rt_info->status);

        return STD_ERR_OK;
    }

    memset (&ndi_ipmc_entry, 0, sizeof (ndi_ipmc_entry_t));

    vrf_str_t vrf_tmp;
    if (mcast_vrf_cache_get(rt_info->vrf_id, vrf_tmp) != true) {
        NAS_MC_L3_LOG_ERR ("NDI", "Route delete failed, VRF info not found, "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d",
                rt_info->vrf_id, rt_info->af, rt_info->rtype,
                MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                rt_info->iif_id,
                (int)rt_info->status);

        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    if (!mcast_intf_cache_get_rif_id (rt_info->vrf_id, rt_info->iif_id,
                &iif_rif_id)) {
        NAS_MC_L3_LOG_ERR ("NDI", "Route delete failed, RIF info not found for IIF, "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d",
                rt_info->vrf_id, rt_info->af, rt_info->rtype,
                MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                rt_info->iif_id,
                (int)rt_info->status);
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    ndi_ipmc_entry.iif_rif_id = iif_rif_id;
    ndi_ipmc_entry.vrf_id = vrf_tmp.vrf_obj_id;
    ndi_ipmc_entry.type = (ndi_ipmc_entry_type_t) ((rt_info->rtype == L3_MCAST_ROUTE_TYPE_XG) ? NAS_NDI_IPMC_ENTRY_TYPE_XG :
                           ((rt_info->rtype == L3_MCAST_ROUTE_TYPE_SG) ||(rt_info->rtype == L3_MCAST_ROUTE_TYPE_SGRPT))? NAS_NDI_IPMC_ENTRY_TYPE_SG : 0);

    memcpy (&ndi_ipmc_entry.dst_ip, &rt_info->grp_ip, sizeof (hal_ip_addr_t));
    memcpy (&ndi_ipmc_entry.src_ip, &rt_info->src_ip, sizeof (hal_ip_addr_t));

    ndi_obj_id_t ndi_repl_grp_id = 0;
    for(npu_id = 0; npu_id < max_npu; npu_id++) {

        if (mcast_repl_grp_db_entry_get_ndi_obj_id (npu_id, rt_info->repl_grp_id, &ndi_repl_grp_id) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR ("NDI", "NDI route delete failed, "
                    "failure in retrieving NDI repl. group id for "
                    "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d, nas_obj_id:0x%lx",
                    rt_info->vrf_id, rt_info->af, rt_info->rtype,
                    MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                    MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                    rt_info->iif_id, (int)rt_info->status, rt_info->repl_grp_id);

            return STD_ERR(MCAST_L3, FAIL, 0);
        }

        ndi_ipmc_entry.repl_group_id = ndi_repl_grp_id;

        if(ndi_ipmc_entry_delete (npu_id, &ndi_ipmc_entry) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR ("NDI", "NDI route delete failed, "
                    "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, IIF RIF Id 0x%lx status:%d",
                    rt_info->vrf_id, rt_info->af, rt_info->rtype,
                    MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                    MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                    rt_info->iif_id, iif_rif_id,
                    (int)rt_info->status);

            rt_info->status = rt_status_t::IPMC_DEL_FAIL;

            return STD_ERR(MCAST_L3, FAIL, 0);
        }
    }
    rt_info->status = rt_status_t::NOT_PRGM_IN_NPU;
    /* explicitly set NPU program status */
    rt_info->npu_prg_status = 0;

    uint32_t ref_cnt = 0;
    // decrement repl. group entry ref count
    if (!mcast_repl_grp_db_ref_cnt_op (rt_info->repl_grp_id, MCAST_RGRP_REF_CNT_DEC, ref_cnt)) {
        NAS_MC_L3_LOG_ERR ("NDI", "Repl. group delete failed "
                "in decrementing reference count, "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d, nas_obj_id:0x%lx",
                rt_info->vrf_id, rt_info->af, rt_info->rtype,
                MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                rt_info->iif_id, (int)rt_info->status,
                rt_info->repl_grp_id);

        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    // check and delete repl. group entry if ref count is 0
    if (mcast_l3_check_and_delete_repl_grp_entry_delete (rt_info->repl_grp_id) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR ("NDI", "NDI repl. group check and delete failed, "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d, nas_obj_id:0x%lx",
                rt_info->vrf_id, rt_info->af, rt_info->rtype,
                MC_IP_ADDR_TO_STR(&rt_info->src_ip),
                MC_IP_ADDR_TO_STR(&rt_info->grp_ip),
                rt_info->iif_id, (int)rt_info->status,
                rt_info->repl_grp_id);

        rt_info->status = rt_status_t::REPL_GRP_DEL_FAIL;

        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    //reset repl. group id
    rt_info->repl_grp_id = NAS_MC_INVALID_REPL_GRP_ID;

    //update npu programming status to false
    rt_info->npu_prg_status = false;

    return STD_ERR_OK;
}
