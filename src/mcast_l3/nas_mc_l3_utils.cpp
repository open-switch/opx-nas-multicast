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
 * filename: nas_mc_l3_utils.cpp
 */

#include "cps_api_errors.h"
#include "cps_api_object.h"
#include "hal_if_mapping.h"
#include "nas_mc_l3_util.h"
#include "nas_mc_l3_cache.h"
#include "nas_mc_l3_walker.h"
#include "nas_mc_l3_ndi.h"
#include "nas_switch.h"
#include "nas_types.h"
#include "nas_ndi_router_interface.h"
#include "l3-multicast.h"
#include "nas_l2_mc_api.h"
#include "nas_mc_l3_cps.h"
#include "std_utils.h"
#include "std_ip_utils.h"
#include "sys/socket.h"
#include <iostream>
#include <sstream>

/* Min. threshold percent of route messages to be processed from message queue
 * before signalling walker thread.
 */
#define NAS_RT_WALKER_SIG_MIN_THRESHOLD_PERCENT 30


static void mcast_trigger_route_updates_for_intf (hal_vrf_id_t vrf_id, uint32_t af, hal_ifindex_t if_index,
                                                  bool is_sync_msg, bool is_iif_oif_remove);

static uint8_t   ga_mc_rt_scratch_buf [MC_IP_NUM_SCRATCH_BUF][MC_IP_MAX_SCRATCH_BUFSZ];
static uint32_t  g_mc_rt_scratch_buf_index = 0;

uint8_t  *mc_rt_get_scratch_buf ()
{
    g_mc_rt_scratch_buf_index++;

    if (g_mc_rt_scratch_buf_index >= MC_IP_NUM_SCRATCH_BUF) {
        g_mc_rt_scratch_buf_index = 0;
    }

    return ga_mc_rt_scratch_buf [g_mc_rt_scratch_buf_index];
}

static bool intf_id_from_name(const std::string& name,
                              hal_ifindex_t& ifindex)
{
    interface_ctrl_t info;
    memset(&info, 0, sizeof(info));
    safestrncpy(info.if_name, name.c_str(), sizeof(info.if_name));
    info.q_type = HAL_INTF_INFO_FROM_IF_NAME;
    if (dn_hal_get_interface_info(&info)!=STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("UTILS", "Failed to get interface info for ifindex %s",
                          name.c_str());
        return false;
    }
    ifindex = info.if_index;

    return true;
}


static cps_api_return_code_t _vrf_process_mcast_status_disable(std::string vrf_name, uint32_t af)
{
    hal_vrf_id_t vrf_id;
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    l3_mcast_route_cps_key_t rt_cps_key;
    std::list<std::string> vrf_intf_list;

    memset(&rt_cps_key, 0, sizeof(rt_cps_key));

    rt_cps_key.vrf_name = vrf_name;
    rt_cps_key.vrf_name_valid = true;
    rt_cps_key.af = (BASE_CMN_AF_TYPE_t) af;
    rt_cps_key.af_valid = true;

    if (mcast_l3_util_clear_routes (rt_cps_key) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("MSG", "Failed in VRF(%s) Mcast status disable, "
                "Mcast l3 routes delete failed.", vrf_name.c_str());
        return cps_api_ret_code_ERR;
    }

    if (nas_get_vrf_internal_id_from_vrf_name(vrf_name.c_str(), &vrf_id) != STD_ERR_OK) {
        NAS_MC_L3_LOG_DEBUG("MSG", "VRF(%s) not found in cache, "
                "skipping VRF Mcast status disable", vrf_name.c_str());
        return cps_api_ret_code_ERR;
    }

    mcast_intf_cache_get_all_interfaces_for_vrf(vrf_id, vrf_intf_list);

    std::string if_name;

    t_mcast_msg_uptr pmsg_uptr = mcast_alloc_mem_msg(PIM_STATUS);
    pim_status_t *pmsg = dynamic_cast<pim_status_t*>(pmsg_uptr.get());
    if (pmsg == NULL) {
        NAS_MC_L3_LOG_ERR("MSG", "Failed in VRF(%s) Mcast disable, "
                "MSG allocation failure for PIM disable.", vrf_name.c_str());
        return cps_api_ret_code_ERR;
    }
    pmsg->vrf_name = vrf_name;
    pmsg->af       = af;
    pmsg->op = rt_op::DELETE;
    pmsg->pim_status = false;

    for (auto intf_it = vrf_intf_list.begin();
         intf_it != vrf_intf_list.end(); ++intf_it)
    {
        if_name = *intf_it;

        pmsg->intf_name.assign((const char*) if_name.c_str());
        if (_set_pim_status(pmsg, 0) != cps_api_ret_code_OK) {
            NAS_MC_L3_LOG_ERR("MSG", "Failed in VRF(%s) Mcast disable, "
                    "during interface(%s) PIM disable",
                    vrf_name.c_str(), if_name.c_str());
            rc = cps_api_ret_code_ERR;
        }
    }

    return rc;
}


cps_api_return_code_t _set_global_mcast_status(t_mcast_msg *p_msg, uint32_t num_msgs_in_queue)
{
    bool vrf_present = true;
    bool cache_update, sai_update;
    auto st = dynamic_cast<global_mcast_status_t*>(p_msg);

    cache_update = sai_update = false;

    /* Program NPU and Populate VRF Cache*/
    size_t max_npu = nas_switch_get_max_npus();
    nas_obj_id_t ndi_vrf_oid;
    ndi_vr_entry_t vr_entry;                  // Used for ndi calls

    // Check if we have the vrf entry in cache
    if (nas_get_vrf_internal_id_from_vrf_name(st->vrf_name.c_str(), &st->vrf_id) != STD_ERR_OK)
    {
        NAS_MC_L3_LOG_ERR("MSG", "VRF(%s), af(%d) not found in cache, "
                "skipping VRF Mcast status set",
                st->vrf_name.c_str(), st->af);
        return cps_api_ret_code_ERR;
    }

    vrf_str_t vrf_tmp;
    memset(&vrf_tmp, 0, sizeof(vrf_tmp));
    if (mcast_vrf_cache_get(st->vrf_name, vrf_tmp) != true) {
        vrf_present = false;
        vrf_tmp.vrf_name.assign(st->vrf_name);
        cache_update = true;
    }

    if (!vrf_present) {
        if (st->op == rt_op::DELETE) {
            NAS_MC_L3_LOG_ERR("MSG",
                    "VRF(%s), af(%d) instance not present in local cache, "
                    "ignoring MCAST status delete event",
                    st->vrf_name.c_str(), st->af);
            return cps_api_ret_code_ERR;
        }

        if( nas_get_vrf_obj_id_from_vrf_name(st->vrf_name.c_str(), &ndi_vrf_oid) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR("MSG", "Get VRF Object ID failure for VRF:%s", st->vrf_name.c_str());
            return cps_api_ret_code_ERR;
        }
        vrf_tmp.vrf_obj_id = ndi_vrf_oid;
    } else {
        ndi_vrf_oid = vrf_tmp.vrf_obj_id;
    }

    memset(&vr_entry, 0, sizeof(ndi_vr_entry_t));

    if(st->af == AF_INET) {
        if (vrf_tmp.v4_mcast_valid != true) {
            if ((st->op == rt_op::DELETE) && (!st->mcast_status)) {
                NAS_MC_L3_LOG_ERR ("msg",
                        "VRF(%s), af(%d) instance not created, "
                        "ignoring MCAST status delete event",
                        st->vrf_name.c_str(), st->af);
                return cps_api_ret_code_OK;
            }
            cache_update = vrf_tmp.v4_mcast_valid = true;
        }
        if (vrf_tmp.v4_mcast_status != st->mcast_status) {
            vr_entry.flags = NDI_VR_ATTR_MCAST_ADMIN_V4_STATE;
            vr_entry.v4_mcast_admin_state = vrf_tmp.v4_mcast_status = st->mcast_status;
            cache_update = sai_update = true;
        }
    } else if(st->af == AF_INET6) {
        if (vrf_tmp.v6_mcast_valid != true) {
            if ((st->op == rt_op::DELETE) && (!st->mcast_status)) {
                NAS_MC_L3_LOG_ERR ("msg",
                        "VRF(%s), af(%d) instance not created, "
                        "ignoring MCAST status delete event",
                        st->vrf_name.c_str(), st->af);
                return cps_api_ret_code_OK;
            }

            cache_update = vrf_tmp.v6_mcast_valid = true;
        }
        if (vrf_tmp.v6_mcast_status != st->mcast_status) {
            vr_entry.flags = NDI_VR_ATTR_MCAST_ADMIN_V6_STATE;
            vr_entry.v6_mcast_admin_state = vrf_tmp.v6_mcast_status = st->mcast_status;
            cache_update = sai_update = true;
        }
    } else {
        NAS_MC_L3_LOG_ERR("MSG", "Unsupported address family");
        return cps_api_ret_code_ERR;
    }

    if (sai_update == true) {
        if (!st->mcast_status) {
            if (_vrf_process_mcast_status_disable(st->vrf_name, st->af) != cps_api_ret_code_OK) {
                NAS_MC_L3_LOG_ERR("MSG", "VRF(%s), af(%d) Mcast disable failed",
                        st->vrf_name.c_str(), st->af);
                return cps_api_ret_code_ERR;
            }
        }

        for(size_t npu_id = 0; npu_id < max_npu; npu_id++) {
            vr_entry.npu_id = npu_id;
            vr_entry.vrf_id = ndi_vrf_oid;

            if(ndi_route_vr_set_attribute(&vr_entry) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR("MSG", "NDI VR SET Mcast status flags failed for VRF:%s",
                        st->vrf_name.c_str());
                return cps_api_ret_code_ERR;
            }
        }
    }

    if (st->op == rt_op::DELETE) {
        if (!vrf_tmp.v4_mcast_status)
            vrf_tmp.v4_mcast_valid = false;
        if (!vrf_tmp.v6_mcast_status)
            vrf_tmp.v6_mcast_valid = false;
    }

    if ((cache_update == true) || (st->op == rt_op::DELETE)) {
        //delete the VRF instance from cache if both v4 & v6 mcast_valid flag is false.
        if (!vrf_tmp.v4_mcast_valid && !vrf_tmp.v6_mcast_valid) {
            if (mcast_vrf_cache_update(st->vrf_id, NULL) == false) {
                NAS_MC_L3_LOG_ERR("MSG",
                        "VRF(%s) instance delete failed in VRF cache delete",
                        st->vrf_name.c_str());
                return cps_api_ret_code_ERR;
            }
        } else {
            if (mcast_vrf_cache_update(st->vrf_id, &vrf_tmp) != true) {
                NAS_MC_L3_LOG_ERR("MSG",
                        "VRF(%s) instance cache update failed while updating for af(%d)",
                        st->vrf_name.c_str(), st->af);
                return cps_api_ret_code_ERR;
            }
        }
    }

    return cps_api_ret_code_OK;
}

static t_std_error _mcast_fill_rif_params (npu_id_t npu_id,
                         if_str_t &intf, ndi_rif_entry_t &rif_entry)
{
    interface_ctrl_t    intf_ctrl;
    ndi_vrf_id_t        ndi_vr_oid = 0;

    memset (&rif_entry, 0, sizeof (ndi_rif_entry_t));
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    if (nas_get_vrf_obj_id_from_vrf_name(intf.vrf_name.c_str(), &ndi_vr_oid) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("MSG",
                "RIF create failed for VRF:%s, Intf:%s, in VRF object get ",
                intf.vrf_name.c_str(), intf.if_name.c_str());
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    rif_entry.npu_id = npu_id;
    rif_entry.vrf_id = ndi_vr_oid;

    safestrncpy(intf_ctrl.if_name, intf.if_name.c_str(), sizeof(intf_ctrl.if_name));
    intf_ctrl.vrf_id = intf.vrf_id;
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;

    if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("MSG",
                "RIF fill params failed for interface vrf_id:%d, if_name:%s",
                intf.vrf_id, intf.if_name.c_str());
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    if(intf_ctrl.int_type == nas_int_type_MACVLAN) {
        hal_vrf_id_t parent_vrf_id = intf_ctrl.l3_intf_info.vrf_id;
        hal_ifindex_t parent_if_index = intf_ctrl.l3_intf_info.if_index;

        if (parent_if_index != 0) {
            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
            intf_ctrl.vrf_id = parent_vrf_id;
            intf_ctrl.if_index = parent_if_index;

            if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR("MSG",
                        "RIF fill params failed to fetch parent RIF info for VRF:%d, if-index:%d",
                        parent_vrf_id, parent_if_index);
                return STD_ERR(MCAST_L3, FAIL, 0);
            }
        }
    }
    if(intf_ctrl.int_type == nas_int_type_PORT) {
        rif_entry.rif_type = NDI_RIF_TYPE_PORT;
        rif_entry.attachment.port_id.npu_id = npu_id;
        rif_entry.attachment.port_id.npu_port = intf_ctrl.port_id;
    } else if(intf_ctrl.int_type == nas_int_type_LAG) {
        rif_entry.rif_type = NDI_RIF_TYPE_LAG;
        rif_entry.attachment.lag_id = intf_ctrl.lag_id;
    } else if(intf_ctrl.int_type == nas_int_type_VLAN) {
        rif_entry.rif_type = NDI_RIF_TYPE_VLAN;
        rif_entry.attachment.vlan_id = intf_ctrl.vlan_id;
    } else {
        /* Mulitcast is not support on other interface types for now */
        NAS_MC_L3_LOG_ERR("MSG",
                "RIF create failed for intf:%s, invalid interface type:%d ",
                intf.if_name.c_str(), intf_ctrl.int_type);
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    if (intf.v4_pim_valid == true) {
        rif_entry.flags = NDI_RIF_ATTR_PIMV2_STATE;
        rif_entry.pimv2_state = intf.v4_pim_status;
    }
    if (intf.v6_pim_valid == true) {
        rif_entry.flags = NDI_RIF_ATTR_PIMV6_STATE;
        rif_entry.pimv6_state= intf.v6_pim_status;
    }
    return STD_ERR_OK;
}

static t_std_error _mcast_rif_create (if_str_t &intf, ndi_rif_id_t &rif_id)
{
    ndi_rif_entry_t rif_entry;

    //handle multi-npu as needed
    if (_mcast_fill_rif_params (0, intf, rif_entry) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("MSG",
                "RIF create failed in fill param for ifname:%s",
                intf.if_name.c_str());

        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    if (ndi_rif_create(&rif_entry, &rif_id) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("MSG",
                "RIF create failed in NDI for ifname:%s",
                intf.if_name.c_str());

        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    return STD_ERR_OK;
}

static t_std_error _mcast_rif_update (ndi_rif_id_t rif_id, uint32_t af, bool status)
{
    ndi_rif_entry_t rif_entry;
    memset (&rif_entry, 0, sizeof (ndi_rif_entry_t));

    /* Handle Multiple NPUs ? */
    rif_entry.npu_id = 0;
    rif_entry.rif_id = rif_id;

    if (af == AF_INET) {
        rif_entry.flags = NDI_RIF_ATTR_PIMV2_STATE;
        rif_entry.pimv2_state = status;
    } else if (af == AF_INET6) {
        rif_entry.flags = NDI_RIF_ATTR_PIMV6_STATE;
        rif_entry.pimv6_state = status;
    }
    if (ndi_rif_set_attribute(&rif_entry) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("MSG", "NDI RIF SET flags failure");
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    NAS_MC_L3_LOG_DEBUG("MSG",
            "RIF updated for PIM status, af:%d, RIF Id:0x%lx, status:%d",
            af, rif_id, status);
    return STD_ERR_OK;
}


static t_std_error _mcast_rif_delete (ndi_rif_id_t rif_id)
{
    npu_id_t npu_id = 0;

    if (rif_id == INVALID_RIF_ID)
        return STD_ERR_OK;

    if (ndi_rif_delete(npu_id, rif_id) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("MSG",
                "RIF delete failed in NDI for npu:%d, RIF:0x%lx",
                npu_id, rif_id);

        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    return STD_ERR_OK;
}

cps_api_return_code_t _set_pim_status(t_mcast_msg *p_msg, uint32_t num_msgs_in_queue)
{
    bool       v4_mc_status  = false;
    bool       v6_mc_status  = false;
    bool       intf_present = true;
    bool       cache_update = false;
    bool       sai_update = false;
    if_str_t   intf_tmp;
    auto       st = dynamic_cast<pim_status_t*>(p_msg);

    memset(&intf_tmp, 0, sizeof(intf_tmp));

    // if Mcast is disabled on this VRF for the given AF, then ignore the PIM config
    if (mcast_get_vrf_mcast_status (st->vrf_name,
                &v4_mc_status, &v6_mc_status) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "VRF(%s) not found in local cache, "
                "skipping PIM status config for intf:%s ",
                st->vrf_name.c_str(), st->intf_name.c_str());

        return cps_api_ret_code_ERR;
    }

    if (((st->af == AF_INET) && !v4_mc_status) ||
            ((st->af == AF_INET6) && !v6_mc_status)) {
        NAS_MC_L3_LOG_ERR("CPS", "VRF(%s) MCAST disabled for af:%d, "
                "skipping PIM status config for intf:%s ",
                st->vrf_name.c_str(), st->af, st->intf_name.c_str());
        return cps_api_ret_code_ERR;
    }

    // Check if we have the interface entry in cache
    if (mcast_intf_cache_get(st->intf_name, intf_tmp) == false) {

        NAS_MC_L3_LOG_DEBUG("MSG",
                "PIM status config - Interface(%s) not found, "
                "input PIM status:%d. Adding interface entry in local cache",
                st->intf_name.c_str(), st->pim_status);

        interface_ctrl_t    intf_ctrl;
        memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

        intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
        memcpy (intf_ctrl.if_name, st->intf_name.c_str(), sizeof (intf_ctrl.if_name));

        if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR("MSG",
                    "Hal get interface info (%s) failure in PIM status config",
                    intf_ctrl.if_name);
            return cps_api_ret_code_ERR;
        }

        intf_tmp.vrf_name.assign(st->vrf_name);
        intf_tmp.if_name.assign(st->intf_name);
        intf_tmp.rif_id = INVALID_RIF_ID;

        intf_tmp.if_index = intf_ctrl.if_index;
        intf_tmp.vrf_id = intf_ctrl.vrf_id;
        intf_tmp.if_type = intf_ctrl.int_type;
        intf_tmp.vlan_id = intf_ctrl.vlan_id;

        //if mac-vlan interface, then fetch parent info
        if(intf_ctrl.int_type == nas_int_type_MACVLAN) {
            hal_vrf_id_t parent_vrf_id = intf_ctrl.l3_intf_info.vrf_id;
            hal_ifindex_t parent_if_index = intf_ctrl.l3_intf_info.if_index;

            if (parent_if_index != 0) {
                memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
                intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
                intf_ctrl.vrf_id = parent_vrf_id;
                intf_ctrl.if_index = parent_if_index;

                if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                    NAS_MC_L3_LOG_ERR("MSG",
                            "Hal get interface info (%s) failure for "
                            "parent info VRF:%d, if_index:%d, in PIM status config",
                            st->intf_name.c_str(), parent_vrf_id, parent_if_index);
                    return cps_api_ret_code_ERR;
                }

                intf_tmp.vlan_id = intf_ctrl.vlan_id;
            }
        }

        cache_update = true;
        intf_present = false;
    }
    if (st->op == rt_op::DELETE) {
        if (!intf_present) {
            NAS_MC_L3_LOG_ERR("MSG",
                    "Interface(%s) not present in local cache, "
                    "ignoring PIM status delete event",
                    st->intf_name.c_str());
            return cps_api_ret_code_OK;
        }
        st->pim_status = false;
    }

    if(st->af == AF_INET) {
        if (intf_tmp.v4_pim_valid != true) {
            if ((st->op == rt_op::DELETE) && (!st->pim_status)) {
                NAS_MC_L3_LOG_ERR ("msg",
                        "Interface(%s) instance not created for af:%d, "
                        "ignoring PIM status delete event",
                        st->intf_name.c_str(), st->af);
                return cps_api_ret_code_OK;
            }
            cache_update = intf_tmp.v4_pim_valid = true;
        }
        if(st->pim_status != intf_tmp.v4_pim_status) {
            intf_tmp.v4_pim_status = st->pim_status;
            cache_update = sai_update = true;
        }
    } else if(st->af == AF_INET6) {
        if (intf_tmp.v6_pim_valid != true) {
            if ((st->op == rt_op::DELETE) && (!st->pim_status)) {
                NAS_MC_L3_LOG_ERR ("msg",
                        "Interface(%s) instance not created for af:%d, "
                        "ignoring PIM status delete event",
                        st->intf_name.c_str(), st->af);
                return cps_api_ret_code_OK;
            }

            cache_update = intf_tmp.v6_pim_valid = true;
        }
        if(st->pim_status != intf_tmp.v6_pim_status) {
            intf_tmp.v6_pim_status = st->pim_status;
            cache_update = sai_update = true;
        }
    } else {
        NAS_MC_L3_LOG_ERR("MSG", "Unsupported address family");
        return cps_api_ret_code_ERR;
    }

    if ((sai_update == true) && (!st->pim_status)) {
        /* When PIM is disabled on an interface,
         * check for routes with IIF/OIF matching this interface
         * and update the route.
         */
        // for PIM disable on an interface, set is_iif_oif_remove to true
        mcast_trigger_route_updates_for_intf (intf_tmp.vrf_id, st->af, intf_tmp.if_index, true, true);
    }

    if (sai_update == true) {
        if (!intf_tmp.v4_pim_status && !intf_tmp.v6_pim_status) { //delete
            if (_mcast_rif_update (intf_tmp.rif_id, st->af, st->pim_status) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR("MSG",
                        "PIM status disable failed in RIF update for af:%d, ifname:%s",
                        st->af, st->intf_name.c_str());
                return cps_api_ret_code_ERR;
            }

            if (_mcast_rif_delete (intf_tmp.rif_id) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR("MSG",
                        "PIM status config failed in RIF delete for af:%d, ifname:%s",
                        st->af, st->intf_name.c_str());
                return cps_api_ret_code_ERR;
            }
            NAS_MC_L3_LOG_DEBUG("MSG",
                    "PIM status config success in RIF(0x%lx) delete for af:%d, ifname:%s",
                    intf_tmp.rif_id, st->af, st->intf_name.c_str());
            intf_tmp.rif_id = INVALID_RIF_ID;
        } else if(intf_tmp.v4_pim_status || intf_tmp.v6_pim_status) {
            if (intf_tmp.rif_id == INVALID_RIF_ID) { //create
                ndi_rif_id_t rif_id;
                if (_mcast_rif_create (intf_tmp, rif_id) != STD_ERR_OK) {
                    NAS_MC_L3_LOG_ERR("MSG",
                            "PIM status config failed in RIF create for af:%d, ifname:%s",
                            st->af, st->intf_name.c_str());
                    return cps_api_ret_code_ERR;
                }

                intf_tmp.rif_id = rif_id;

                NAS_MC_L3_LOG_DEBUG("MSG",
                        "PIM status config success in RIF(0x%lx) create for af:%d, ifname:%s",
                        intf_tmp.rif_id, st->af, st->intf_name.c_str());
            } else { //update
                if (_mcast_rif_update (intf_tmp.rif_id, st->af, st->pim_status) != STD_ERR_OK) {
                    NAS_MC_L3_LOG_ERR("MSG",
                            "PIM status config failed in RIF update for af:%d, ifname:%s",
                            st->af, st->intf_name.c_str());
                    return cps_api_ret_code_ERR;
                }

                NAS_MC_L3_LOG_DEBUG("MSG",
                        "PIM status config success in RIF(0x%lx) update for af:%d, ifname:%s",
                        intf_tmp.rif_id, st->af, st->intf_name.c_str());
            }
        }
    }

    if (st->op == rt_op::DELETE) {
        if (!intf_tmp.v4_pim_status)
            intf_tmp.v4_pim_valid = false;
        if (!intf_tmp.v6_pim_status)
            intf_tmp.v6_pim_valid = false;
    }

    if ((cache_update == true) || (st->op == rt_op::DELETE)) {
        //delete the interface instance from cache if both v4 & v6 pim_valid flag is false.
        if (!intf_tmp.v4_pim_valid && !intf_tmp.v6_pim_valid) {
            if (mcast_intf_cache_update(st->intf_name, NULL) == false) {
                NAS_MC_L3_LOG_ERR("MSG",
                        "PIM interface instance delete failed in intf cache delete for ifname:%s",
                        st->intf_name.c_str());
                return cps_api_ret_code_ERR;
            }
        } else {
            if (mcast_intf_cache_update(st->intf_name, &intf_tmp) == false) {
                NAS_MC_L3_LOG_ERR("MSG",
                        "PIM status config failed in intf cache update for ifname:%s",
                        st->intf_name.c_str());
                return cps_api_ret_code_ERR;
            }
        }
    }

    if ((cache_update == true) || (sai_update == true)) {
        /* Update snooping about PIM status change, for VLAN's only */
        if ((intf_tmp.if_type == nas_int_type_VLAN) ||
            (intf_tmp.if_type == nas_int_type_MACVLAN)) {
            NAS_MC_L3_LOG_INFO("MSG", "Update PIM status with snooping for "
                               "af:%d, ifname:%s, type:%d, vlan:%d, PIM status:%d",
                                st->af, st->intf_name.c_str(), intf_tmp.if_type,
                                intf_tmp.vlan_id, st->pim_status);
            nas_mc_update_pim_status(intf_tmp.vlan_id, st->af, st->pim_status);
        }
    }
    return cps_api_ret_code_OK;
}



static t_std_error _program_route_del (mc_route_t *rt)
{
    NAS_MC_L3_LOG_INFO ("MSG", "Received Mcast Route Delete event "
            "VRF:%d, AF:%d, Route Type:%d, (%s,%s), IIF:%d",
            rt->vrf_id, rt->af, rt->rtype,
            MC_IP_ADDR_TO_STR(&rt->src_ip),
            MC_IP_ADDR_TO_STR(&rt->grp_ip),
            rt->iif_id);

    // remove route node from walker to avoid processing for a deleted route
    mcast_remove_rt_event_from_walker_pending_evt_list (rt);

    if (hal_mc_l3_route_delete(rt) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("MSG", "NDI returned failure in route delete. "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d",
                rt->vrf_id, rt->af, rt->rtype,
                MC_IP_ADDR_TO_STR(&rt->src_ip),
                MC_IP_ADDR_TO_STR(&rt->grp_ip),
                rt->iif_id);
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    if (nas_mc_l3_route_db_delete(*rt) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("MSG", "Failed to delete route from DB");
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    return STD_ERR_OK;
}


t_std_error _program_route_add_or_update(mc_route_t *mc_rt, bool is_sync)
{
    t_std_error rc = STD_ERR(MCAST_L3, FAIL, 0);

    nas_mcast_obj_id_t old_repl_grp_id = NAS_MC_INVALID_REPL_GRP_ID;
    nas_mcast_obj_id_t repl_grp_id = NAS_MC_INVALID_REPL_GRP_ID;
    mcast_if_list_t expanded_iif_list;
    mcast_if_list_t expanded_oif_list;

    if (!mc_rt) {
        NAS_MC_L3_LOG_ERR("ROUTE",
                "Invalid input param for route event");
        return rc;
    }

    NAS_MC_L3_LOG_INFO ("ROUTE", "Received Mcast Route event "
            "VRF:%d, AF:%d, Route Type:%d, (%s,%s), IIF:%d",
            mc_rt->vrf_id, mc_rt->af, mc_rt->rtype,
            MC_IP_ADDR_TO_STR(&mc_rt->src_ip),
            MC_IP_ADDR_TO_STR(&mc_rt->grp_ip),
            mc_rt->iif_id);

    if (is_sync) {
        /* This route will get updated here synchronously, so remove from the Walker.*/
        mcast_remove_rt_event_from_walker_pending_evt_list(mc_rt);
        NAS_MC_L3_LOG_INFO ("MSG", "Synchronous route update, remove from walker, if present");
    }

    if (!route_iif_oif_expand (mc_rt, expanded_iif_list, expanded_oif_list)) {
        NAS_MC_L3_LOG_ERR("ROUTE", "Route processing failed during IIF/OIF expansion, "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d, repl GrpID:0x%lx",
                mc_rt->vrf_id, mc_rt->af, mc_rt->rtype,
                MC_IP_ADDR_TO_STR(&mc_rt->src_ip),
                MC_IP_ADDR_TO_STR(&mc_rt->grp_ip),
                mc_rt->iif_id, (int)mc_rt->status, mc_rt->repl_grp_id);
        return rc;
    }
    mcast_dump_expanded_if_list(expanded_iif_list);
    mcast_dump_expanded_if_list(expanded_oif_list);

    repl_grp_entry_t *new_repl_grp_entry = mcast_repl_grp_db_entry_get (MCAST_L3,
                                              mc_rt->vrf_id, &expanded_iif_list,
                                              &expanded_oif_list, mc_rt->copy_to_cpu);

    /* create the repl. grp entry in NDI if no repl. grp entry exists
     * for given IIF/OIF and then create/update route with the
     * returned repl. grp in NDI.
     * if returned repl. grp id is different from current repl. grp id, then
     * create/update route with the returned repl. grp in NDI.
     */
    if (new_repl_grp_entry == NULL) {

        rc = mcast_l3_repl_grp_entry_add (mc_rt->vrf_id, &expanded_iif_list,
                &expanded_oif_list, mc_rt->copy_to_cpu, repl_grp_id);

        if (rc != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR("ROUTE", "Route add failed in repl. grp entry add, "
                    "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d",
                    mc_rt->vrf_id, mc_rt->af, mc_rt->rtype,
                    MC_IP_ADDR_TO_STR(&mc_rt->src_ip),
                    MC_IP_ADDR_TO_STR(&mc_rt->grp_ip),
                    mc_rt->iif_id);

            mc_rt->status = rt_status_t::REPL_GRP_PROG_FAIL;
            return rc;
        }
    } else {
        repl_grp_id = new_repl_grp_entry->mc_repl_id;
    }

    if ((mc_rt->repl_grp_id == repl_grp_id) && (mc_rt->npu_prg_status)) {
        NAS_MC_L3_LOG_ERR("WALKER", "Route add/update skipped, same replication Group "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d repl GrpID %ld" ,
                mc_rt->vrf_id, mc_rt->af, mc_rt->rtype,
                MC_IP_ADDR_TO_STR(&mc_rt->src_ip),
                MC_IP_ADDR_TO_STR(&mc_rt->grp_ip),
                mc_rt->iif_id, repl_grp_id);
        return STD_ERR_OK;
    }

    if (mc_rt->npu_prg_status == false) {

        if (repl_grp_id == NAS_MC_INVALID_REPL_GRP_ID) {
            NAS_MC_L3_LOG_ERR("ROUTE", "Route add skipped, replication group is invalid, "
                    "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d repl GrpID:0x%lx" ,
                    mc_rt->vrf_id, mc_rt->af, mc_rt->rtype,
                    MC_IP_ADDR_TO_STR(&mc_rt->src_ip),
                    MC_IP_ADDR_TO_STR(&mc_rt->grp_ip),
                    mc_rt->iif_id, repl_grp_id);
            mc_rt->status = rt_status_t::REPL_GRP_PROG_FAIL;
            return STD_ERR(MCAST_L3, FAIL, 0);
        }

        mc_rt->repl_grp_id = repl_grp_id;

        //Route not yet configured in NDI; trigger route add to NDI.
        if ((rc = hal_mc_l3_route_add (mc_rt)) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR("ROUTE", "Route add failed in NDI, "
                    "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d",
                    mc_rt->vrf_id, mc_rt->af, mc_rt->rtype,
                    MC_IP_ADDR_TO_STR(&mc_rt->src_ip),
                    MC_IP_ADDR_TO_STR(&mc_rt->grp_ip),
                    mc_rt->iif_id);
            return rc;
        }
        NAS_MC_L3_LOG_INFO ("ROUTE", "Route Add success, "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d, "
                "repl GrpID:0x%lx, npu_prg_done:%d",
                mc_rt->vrf_id, mc_rt->af, mc_rt->rtype,
                MC_IP_ADDR_TO_STR(&mc_rt->src_ip),
                MC_IP_ADDR_TO_STR(&mc_rt->grp_ip),
                mc_rt->iif_id, (int)mc_rt->status,
                mc_rt->repl_grp_id, mc_rt->npu_prg_status);


    } else {
        //cache the repl. grp id for updating ref count in case of route updates.
        if (repl_grp_id == NAS_MC_INVALID_REPL_GRP_ID) {
            NAS_MC_L3_LOG_ERR("ROUTE", "Route update skipped, replication group is invalid, "
                    "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d new repl GrpID:0x%lx",
                    mc_rt->vrf_id, mc_rt->af, mc_rt->rtype,
                    MC_IP_ADDR_TO_STR(&mc_rt->src_ip),
                    MC_IP_ADDR_TO_STR(&mc_rt->grp_ip),
                    mc_rt->iif_id, repl_grp_id);
            return rc;
        } else if (repl_grp_id == mc_rt->repl_grp_id) {
            //if repl. grp id's are same, then skip update to NDI.
            NAS_MC_L3_LOG_ERR("ROUTE", "Route update skipped, replication group is same, "
                    "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d new repl GrpID:0x%lx",
                    mc_rt->vrf_id, mc_rt->af, mc_rt->rtype,
                    MC_IP_ADDR_TO_STR(&mc_rt->src_ip),
                    MC_IP_ADDR_TO_STR(&mc_rt->grp_ip),
                    mc_rt->iif_id, repl_grp_id);
            return STD_ERR_OK;
        }

        old_repl_grp_id = mc_rt->repl_grp_id;

        mc_rt->repl_grp_id = repl_grp_id;

        //Route update to NDI
        if ((rc = hal_mc_l3_route_update (mc_rt)) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR("ROUTE", "Route update failed in NDI, "
                    "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d, new repl GrpID:0x%lx",
                    mc_rt->vrf_id, mc_rt->af, mc_rt->rtype,
                    MC_IP_ADDR_TO_STR(&mc_rt->src_ip),
                    MC_IP_ADDR_TO_STR(&mc_rt->grp_ip),
                    mc_rt->iif_id, (int)mc_rt->status, mc_rt->repl_grp_id);

            mc_rt->repl_grp_id = old_repl_grp_id;

            return STD_ERR(MCAST_L3, FAIL, 0);
        }

        uint32_t ref_cnt = 0;
        // decrement repl. group entry ref count for old_repl_grp_id.
        if (!mcast_repl_grp_db_ref_cnt_op (old_repl_grp_id, MCAST_RGRP_REF_CNT_DEC, ref_cnt)) {
            NAS_MC_L3_LOG_ERR ("ROUTE", "Route update failed during "
                    "repl. group ref count decr, "
                    "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d, old repl GrpID:0x%lx",
                    mc_rt->vrf_id, mc_rt->af, mc_rt->rtype,
                    MC_IP_ADDR_TO_STR(&mc_rt->src_ip),
                    MC_IP_ADDR_TO_STR(&mc_rt->grp_ip),
                    mc_rt->iif_id, (int)mc_rt->status,
                    mc_rt->repl_grp_id);

            return STD_ERR(MCAST_L3, FAIL, 0);
        }

        if ((rc = mcast_l3_check_and_delete_repl_grp_entry_delete (old_repl_grp_id)) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR ("ROUTE", "Route update failed during "
                    "repl. group check and delete, "
                    "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d, old repl GrpID:0x%lx",
                    mc_rt->vrf_id, mc_rt->af, mc_rt->rtype,
                    MC_IP_ADDR_TO_STR(&mc_rt->src_ip),
                    MC_IP_ADDR_TO_STR(&mc_rt->grp_ip),
                    mc_rt->iif_id, (int)mc_rt->status,
                    old_repl_grp_id);

            mc_rt->status = rt_status_t::REPL_GRP_DEL_FAIL;

            return rc;
        }
        NAS_MC_L3_LOG_INFO ("ROUTE", "Route Update success, "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d, repl GrpID:0x%lx, npu_prg_done:%d",
                mc_rt->vrf_id, mc_rt->af, mc_rt->rtype,
                MC_IP_ADDR_TO_STR(&mc_rt->src_ip),
                MC_IP_ADDR_TO_STR(&mc_rt->grp_ip),
                mc_rt->iif_id, (int)mc_rt->status,
                mc_rt->repl_grp_id, mc_rt->npu_prg_status);
    }
    mc_rt->status = rt_status_t::PROG_SUCCEED;

    return STD_ERR_OK;
}

static bool _remove_oif_from_route (mc_route_t *route_ptr,
                                    hal_ifindex_t remove_oif)
{
    bool oif_removed = false;
    // walk thru route OIF to check for match with the input interface
    for (auto oif_ix = route_ptr->oif_list.begin(); oif_ix != route_ptr->oif_list.end() ;) {

        if (remove_oif == oif_ix->first) {
            /* PIM is disabled on the OIF,
             * then remove the OIF from route.
             */
            NAS_MC_L3_LOG_DEBUG ("EVENT", "Vrf:%d, Af:%d, Intf:%d "
                    "removing OIF from route ",
                    route_ptr->vrf_id, route_ptr->af, remove_oif);

          oif_ix = route_ptr->oif_list.erase(oif_ix);
          oif_removed = true;
          break;
        } else {
          oif_ix ++;
        }
    }

    //check if PIM disabled on all OIF's and if so just log it.
    if (route_ptr->oif_list.size() == 0) {
        NAS_MC_L3_LOG_DEBUG ("EVENT", "Empty route OIF");
    }
    return oif_removed;
}

static void mcast_trigger_route_updates_for_intf (hal_vrf_id_t vrf_id, uint32_t af, hal_ifindex_t if_index,
                                                  bool is_sync_msg, bool is_iif_oif_remove)
{
    bool resume_walker = false;

    auto vlan_routes = nas_mc_l3_route_db_get(&vrf_id, &af, nullptr, nullptr, nullptr, nullptr);

    NAS_MC_L3_LOG_INFO ("MSG",
            "Interface event, trigger route update for all routes "
            "vrf:%d af:%d, IIF/OIF:%d, is_sync_msg:%d, is_iif_oif_remove:%d",
            vrf_id, af, if_index, is_sync_msg, is_iif_oif_remove);

    /* For interface is removed because of
     * PIM disabled on interface or
     * interface mode change from L3 to L2, then check if
     * 1. IIF match, then delete the route from cache & NDI,
     * 2. OIF match, then remove OIF from the route and
     *    if is_sync_msg is false, then enqueue route to walker to update cache & NDI,
     *    else process route update synchronously, and remove the from walker if present.
     *
     * If it's VLAN member update event, then check if
     * 1. affected VLAN matches IIF or OIF, update route synchronously based on is_sync_msg flag,
     * 2. if is_sync_msg is false, then enqueue route to walker to update cache & NDI,
     *    else process route update synchronously, and remove from walker if present.
     */

    for (auto route_ptr: vlan_routes) {

        if (is_iif_oif_remove) {

            if (if_index == route_ptr->iif_id) {
                //IIF match, then delete route.
                NAS_MC_L3_LOG_DEBUG ("MSG", "Vrf:%d, af:%d, Intf:%d "
                        "deleting route ", route_ptr->vrf_id, route_ptr->af, if_index);

                if (_program_route_del (route_ptr) != STD_ERR_OK) {
                    NAS_MC_L3_LOG_ERR("MSG", "Failed to delete route during Interface event");
                }

                continue;
            } else if (_remove_oif_from_route (route_ptr, if_index) == false) {
                if (route_ptr->walker_pending_evt_list_tracker_index == 0) {
                    /* Route does not have this in OIF or its not present in walker
                       no update needed for this route */
                    continue;
                }
            }
        } else {
            /* VLAN Member update case, as route walk is done for VRF and AF, check the interface getting
               affected has to be IIF or OIF, otherwise skip, otherwise routes will be added to walker and
               walker has to act on this even though there is no change. */
            if ((if_index != route_ptr->iif_id) && (route_ptr->oif_list.find(if_index) == route_ptr->oif_list.end())) {
                NAS_MC_L3_LOG_DEBUG("MSG",
                        "Interface %d not IIF or in OIF skip route update: %s",if_index,
                         std::string(*route_ptr).c_str());
                continue;
            }
        }

        NAS_MC_L3_LOG_DEBUG("MSG",
                "Interface event triggering route update: %s",
                std::string(*route_ptr).c_str());

        if (is_sync_msg) {
            _program_route_add_or_update (route_ptr,true);
        } else {
            // add route to walker list only if async processing is required.
            if (mcast_enqueue_rt_event_to_walker_pending_evt_list(route_ptr) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR("MSG", "Failed to enqueue route for "
                        "vrf:%d af:%d with IIF/OIF member %d",
                        vrf_id, af, if_index);
            }
            resume_walker = true;
        }
    }

    // trigger walker only if required.
    if (resume_walker)
        mcast_resume_rt_walker_thread();
}

static void mcast_trigger_route_updates_for_snoop_upd (hal_vrf_id_t vrf_id, hal_ifindex_t if_index, uint32_t af,
                                    hal_ip_addr_t group_addr, bool is_xg, hal_ip_addr_t source_addr)
{
    bool resume_walker = false;
    std::pair<hal_vrf_id_t, hal_ifindex_t> l3_intf{vrf_id, if_index};

    const hal_ip_addr_t* source_addr_p = is_xg ? nullptr : &source_addr;
    L3_MCAST_ROUTE_TYPE_t route_type = is_xg ? L3_MCAST_ROUTE_TYPE_XG : L3_MCAST_ROUTE_TYPE_SG;

    NAS_MC_L3_LOG_INFO ("MSG",
            "Snoop (%s,%s) route update event vrf:%d  IIF/OIF:%d ",
            is_xg ? "*":MC_IP_ADDR_TO_STR(&source_addr), MC_IP_ADDR_TO_STR(&group_addr),
            vrf_id, if_index);

    std::vector<mc_route_t*> vlan_routes;

    if (is_xg) {
        /* if its snooping (*,G) update, walk L3 (*,G),(S,G) and (S,G Rpt) routes.*/
        vlan_routes = nas_mc_l3_route_db_get(nullptr, &af, nullptr, &group_addr, source_addr_p, &l3_intf);
        if (vlan_routes.empty()) {
            NAS_MC_L3_LOG_INFO ("MSG",
                    "Snoop (*,G) route update event, No (*,G), (S,G) and (S,G Rpt) routes present"
                    "vrf:%d af:%d, IIF/OIF:%d ",
                    vrf_id, af, if_index);
            return;
        }
    } else {
        /* if its snooping (S,G) update, walk L3 (S,G) routes, if no (S,G) entries, check and update SGRPT routes.*/
        vlan_routes = nas_mc_l3_route_db_get(nullptr, &af, &route_type, &group_addr, source_addr_p, &l3_intf);
        if (vlan_routes.empty()) {
            NAS_MC_L3_LOG_INFO ("MSG",
                    "Snoop (S,G) route update event, (S,G) route not present, check and update (S,G Rpt) routes "
                    "vrf:%d af:%d, IIF/OIF:%d ",
                    vrf_id, af, if_index);

            route_type = L3_MCAST_ROUTE_TYPE_SGRPT;
            vlan_routes = nas_mc_l3_route_db_get(nullptr, &af, &route_type, &group_addr, source_addr_p, &l3_intf);
            if (vlan_routes.empty()) {
                NAS_MC_L3_LOG_INFO ("MSG",
                        "Snoop (S,G) route update event, no (S,G) and (S,G Rpt) routes present"
                        "vrf:%d af:%d, IIF/OIF:%d ",
                        vrf_id, af, if_index);
                return;
            }
        }
    }

    for (auto route_ptr: vlan_routes) {

        NAS_MC_L3_LOG_DEBUG("MSG",
                "Snooping event triggering route update: %s",
                std::string(*route_ptr).c_str());

        // add route to walker list only if async processing is required.
        if (mcast_enqueue_rt_event_to_walker_pending_evt_list(route_ptr) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR("MSG", "Failed to enqueue route for "
                    "vrf:%d af:%d with VLAN interface name %s",
                    vrf_id, af, if_index);
        }
        resume_walker = true;
    }

    // trigger walker only if required.
    if (resume_walker)
        mcast_resume_rt_walker_thread();
}



t_std_error mcast_get_vrf_mcast_status (std::string vrf_name,
                                        bool *p_ret_v4_mc_status,
                                        bool *p_ret_v6_mc_status)
{
    vrf_str_t _vrf_info;

    memset (&_vrf_info, 0, sizeof (_vrf_info));

    *p_ret_v4_mc_status = false;
    *p_ret_v6_mc_status = false;

    if (!mcast_vrf_cache_get (vrf_name, _vrf_info))
    {
        NAS_MC_L3_LOG_ERR("UTIL",
                "VRF(%s) not found in cache. ", vrf_name.c_str());
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    if (_vrf_info.v4_mcast_valid && _vrf_info.v4_mcast_status)
    {
        *p_ret_v4_mc_status = true;
    }
    if (_vrf_info.v6_mcast_valid && _vrf_info.v6_mcast_status)
    {
        *p_ret_v6_mc_status = true;
    }

    return STD_ERR_OK;
}

t_std_error mcast_get_pim_status (std::string if_name,
                                  bool *p_ret_v4_pim_status,
                                  bool *p_ret_v6_pim_status)
{
    if_str_t _intf_info;

    memset (&_intf_info, 0, sizeof (_intf_info));

    *p_ret_v4_pim_status = false;
    *p_ret_v6_pim_status = false;
    if (!mcast_intf_cache_get (if_name, _intf_info))
    {
        NAS_MC_L3_LOG_DEBUG("UTIL",
                          "Interface not found in cache, if_name:%s",
                          if_name.c_str());
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    if (_intf_info.v4_pim_valid)
        *p_ret_v4_pim_status = _intf_info.v4_pim_status;
    if (_intf_info.v6_pim_valid)
        *p_ret_v6_pim_status = _intf_info.v6_pim_status;

    return STD_ERR_OK;
}


t_std_error mcast_get_pim_status (hal_vrf_id_t vrf_id, hal_ifindex_t if_index,
                                  bool *p_ret_v4_pim_status, bool *p_ret_v6_pim_status)
{
    intf_id_cache_key_t key;
    if_str_t _intf_info;

    memset (&_intf_info, 0, sizeof (_intf_info));

    key.vrf_id = vrf_id;
    key.if_index = if_index;

    *p_ret_v4_pim_status = false;
    *p_ret_v6_pim_status = false;
    if (!mcast_intf_cache_get (key, _intf_info))
    {
        NAS_MC_L3_LOG_DEBUG("UTIL",
                          "Interface not found in cache, vrf:%d, if_index:%d",
                          vrf_id, if_index);
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    if (_intf_info.v4_pim_valid)
        *p_ret_v4_pim_status = _intf_info.v4_pim_status;
    if (_intf_info.v6_pim_valid)
        *p_ret_v6_pim_status = _intf_info.v6_pim_status;

    return STD_ERR_OK;
}

mc_route_t::mc_route_t(const route_t& rt_msg) :
        vrf_id(rt_msg.vrf_id), af(rt_msg.af), rtype(rt_msg.rtype),
        grp_ip(rt_msg.group_addr), src_ip(rt_msg.source_addr), iif_id(0),
        copy_to_cpu(rt_msg.data_to_cpu), walker_pending_evt_list_tracker_index(0),
        repl_grp_id(0),status(rt_status_t::PENDING_IN_QUEUE),npu_prg_status(false)
{
    if (rt_msg.op == rt_op::DELETE) {
        return;
    }
    if ((rt_msg.op == rt_op::ADD) || (rt_msg.op == rt_op::UPDATE)) {
        if (!intf_id_from_name(rt_msg.iif_name, iif_id)) {
            throw std::invalid_argument{std::string{"Failed to get ifindex for IIF "} +
                                        rt_msg.iif_name};
        }
    }
    for (auto& oif: rt_msg.oif) {
        hal_ifindex_t oif_id, excl_if_id = 0;
        if (!intf_id_from_name(oif.oif_name, oif_id)) {
            throw std::invalid_argument{std::string{"Failed to get ifindex for OIF "} +
                                        oif.oif_name};
        }
        bool have_excl_if = false;
        if (!oif.exclude_if_name.empty()) {
            if (!intf_id_from_name(oif.exclude_if_name, excl_if_id)) {
                throw std::invalid_argument{
                        std::string{"Failed to get ifindex for EXCLUD IF "} +
                        oif.exclude_if_name};
            }
            have_excl_if = true;
        }
        oif_list.insert(std::make_pair(oif_id, mc_oif_t{oif_id, have_excl_if, excl_if_id}));
    }
}


cps_api_return_code_t _program_route(t_mcast_msg *p_msg, uint32_t nas_num_route_msgs_in_queue)
{
    bool v4_mc_status = false;
    bool v6_mc_status = false;
    bool v4_pim_status = false;
    bool v6_pim_status = false;
    static uint32_t num_rt_msgs_rcvd_b4_walker_trigger = 0;
    static bool     pending_walker_thread_wakeup = false;

    auto rt = dynamic_cast<route_t*>(p_msg);


    num_rt_msgs_rcvd_b4_walker_trigger++;

    /* if there are no more route msgs in queue and there is pending
     * walker wakeup, then resume walker. This trigger is to handle
     * cases where there were lots of invalid msgs after the min threshold
     * was reached, but then didn't had a chance to wake up the walker
     * due to invalid msgs.
     */
    if (pending_walker_thread_wakeup && !nas_num_route_msgs_in_queue) {
        NAS_MC_L3_LOG_DEBUG ("MSG", "Num(%d) msgs processed b4 resuming walker, nas_num_route_msgs_in_queue:%d",
                num_rt_msgs_rcvd_b4_walker_trigger, nas_num_route_msgs_in_queue);
        mcast_resume_rt_walker_thread ();
    }

    if (rt == nullptr) {
        NAS_MC_L3_LOG_ERR("MSG", "Invalid message ");
        return cps_api_ret_code_ERR;
    }

    if (mcast_get_vrf_mcast_status (rt->vrf_name,
            &v4_mc_status, &v6_mc_status) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("MSG", "VRF(%s) not found in cache, "
                "skipping route event:%d ", rt->vrf_name.c_str(), (int)rt->op);
        return cps_api_ret_code_ERR;
    }

    if (((rt->af == AF_INET) && !v4_mc_status) ||
        ((rt->af == AF_INET6) && !v6_mc_status)) {
        NAS_MC_L3_LOG_ERR("MSG", "VRF(%s) MCAST disabled for af:%d, "
                "skipping route event:%d ", rt->vrf_name.c_str(), rt->af, (int)rt->op);
        return cps_api_ret_code_ERR;
    }

    if (!rt->iif_name.empty()) {
        /* if PIM is disabled on IIF,
         * then ignore route event itself.
         */
        mcast_get_pim_status (rt->iif_name,
                &v4_pim_status,
                &v6_pim_status);

        if (((rt->af == AF_INET) && !v4_pim_status) ||
            ((rt->af == AF_INET6) && !v6_pim_status)) {
            NAS_MC_L3_LOG_ERR("MSG", "Intf(%s) PIM disabled on IIF for af:%d, "
                    "skipping route event", rt->iif_name.c_str(), rt->af);
            return cps_api_ret_code_ERR;
        }
    }

    for (auto oif_ix = rt->oif.begin(); oif_ix != rt->oif.end() ;) {

        v4_pim_status = false;
        v6_pim_status = false;

        /* if PIM is disabled on the OIF,
         * then ignore the OIF from route.
         */
        mcast_get_pim_status (oif_ix->oif_name,
                &v4_pim_status,
                &v6_pim_status);

        if (((rt->af == AF_INET) && !v4_pim_status) ||
                ((rt->af == AF_INET6) && !v6_pim_status)) {
            NAS_MC_L3_LOG_DEBUG ("MSG", "Intf(%s) PIM disabled on OIF for af:%d, "
                    "skipping OIF from route ", oif_ix->oif_name.c_str(), rt->af);

            oif_ix = rt->oif.erase(oif_ix);
            rt->upd_mask.set(UPD_OIF_POS);
        }
        else if (!rt->iif_name.empty() && !(oif_ix->oif_name.compare(rt->iif_name))){
            NAS_MC_L3_LOG_DEBUG ("MSG", "OIF (%s) same as IIF (%s) skipping OIF from route ",
                                 oif_ix->oif_name.c_str(), rt->iif_name.c_str());

            oif_ix = rt->oif.erase(oif_ix);
            rt->upd_mask.set(UPD_OIF_POS);
        }
        else {
            oif_ix ++;
        }
    }

    //check if PIM disabled on all OIF's and if so just log it for now.
    //possibly either of OIF or CopyToCpu changed.
    //if its an update to only CopyToCpu then the OIF list would be empty.
    if (rt->oif.size() == 0) {
        NAS_MC_L3_LOG_DEBUG ("MSG", "PIM is disabled on all OIF's ");
    }

    try {
        mc_route_t route_info{*rt};
        switch(rt->op) {
        case rt_op::ADD:
        {
            if (nas_mc_l3_route_db_add(route_info) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR("MSG", "Failed to add route to DB");
                return cps_api_ret_code_ERR;
            }
            auto route_ptr = nas_mc_l3_route_db_get_exact(route_info);
            if (route_ptr == nullptr) {
                NAS_MC_L3_LOG_ERR("MSG", "Failed to get route pointer from DB");
                return cps_api_ret_code_ERR;
            }

            NAS_MC_L3_LOG_INFO ("MSG", "Received Mcast Route Add event "
                    "VRF:%d, AF:%d, Route Type:%d, (%s,%s), IIF:%d",
                    route_info.vrf_id, route_info.af, route_info.rtype,
                    MC_IP_ADDR_TO_STR(&route_info.src_ip),
                    MC_IP_ADDR_TO_STR(&route_info.grp_ip),
                    route_info.iif_id);

            // send route to walker for add processing
            mcast_enqueue_rt_event_to_walker_pending_evt_list(route_ptr);

            break;
        }
        case rt_op::DELETE:
        {
            auto route_ptr = nas_mc_l3_route_db_get_exact(route_info);
            if (route_ptr == nullptr) {
                NAS_MC_L3_LOG_ERR("MSG", "Failed to get route pointer from DB");
                return cps_api_ret_code_ERR;
            }

            if (_program_route_del (route_ptr) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR("MSG", "Failed to delete route");
                return cps_api_ret_code_ERR;
            }
            NAS_MC_L3_LOG_INFO ("MSG", "Mcast Route Delete Success");
            break;
        }
        case rt_op::UPDATE:
        {
            std::vector<rt_upd_type_t> upd_type_list{};
            if (rt->upd_mask.test(UPD_COPY_TO_CPU_POS)) {
                upd_type_list.push_back(rt_upd_type_t::COPY_TO_CPU);
            }
            if (rt->upd_mask.test(UPD_OIF_POS)) {
                upd_type_list.push_back(rt_upd_type_t::OIF);
            }
            if (nas_mc_l3_route_db_update(route_info, upd_type_list) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR("MSG", "Failed to update route to DB");
                return cps_api_ret_code_ERR;
            }
            auto route_ptr = nas_mc_l3_route_db_get_exact(route_info);
            if (route_ptr == nullptr) {
                NAS_MC_L3_LOG_ERR("MSG", "Failed to get route pointer from DB");
                return cps_api_ret_code_ERR;
            }

            NAS_MC_L3_LOG_INFO ("MSG", "Received Mcast Route Update event "
                    "VRF:%d, AF:%d, Route Type:%d, (%s,%s), IIF:%d",
                    route_info.vrf_id, route_info.af, route_info.rtype,
                    MC_IP_ADDR_TO_STR(&route_info.src_ip),
                    MC_IP_ADDR_TO_STR(&route_info.grp_ip),
                    route_info.iif_id);

            // send route to walker for update processing
            mcast_enqueue_rt_event_to_walker_pending_evt_list(route_ptr);

            break;
        }
        default:
            NAS_MC_L3_LOG_ERR("MSG", "Invalid route operation type");
            return cps_api_ret_code_ERR;
        }
    } catch(std::exception& ex) {
        NAS_MC_L3_LOG_ERR("MSG", "Exception: %s", ex.what());
        return cps_api_ret_code_ERR;
    }

    /* Wake-up walker only after processing min. threshold percentage of
     * route messages from the queue.
     */
    if (((nas_num_route_msgs_in_queue * NAS_RT_WALKER_SIG_MIN_THRESHOLD_PERCENT/100)
         < num_rt_msgs_rcvd_b4_walker_trigger)) {
        NAS_MC_L3_LOG_DEBUG ("MSG", "Num(%d) msgs processed b4 resuming walker, nas_num_route_msgs_in_queue:%d",
                num_rt_msgs_rcvd_b4_walker_trigger, nas_num_route_msgs_in_queue);
        mcast_resume_rt_walker_thread();
        num_rt_msgs_rcvd_b4_walker_trigger = 0;
        pending_walker_thread_wakeup = false;
    } else {
        pending_walker_thread_wakeup = true;
    }

    return cps_api_ret_code_OK;
}


/* VLAN member update could be happening in following scenarios:
 * 1) an L2 port is removed from VLAN membership for a specific VLAN,
 *    - in this case, we just need to trigger route updates asynchronously
 *      for all the routes in which this VLAN is either IIF or OIF,
 * 2) an L2 port mode is changed to L3
 *    - in this case, we need to trigger route updates synchronously
 *      for all the routes in which all VLAN's this port was member of.
 *      For this, the RPC handler would have idenfitied all VLAN's this port
 *      was member of and would send interface config event with VLAN mbr update &
 *      is_sync_msg flag set to true.
 *      In the backend we simply would treat is as VLAN member update for
 *      a specific VLAN and handle it either synchronously or asynchronously
 *      based on the is_sync_msg flag.
 */
static t_std_error _vlan_mbr_update (t_mcast_msg *p_msg)
{
    bool v4_mc_status = false;
    bool v6_mc_status = false;
    bool v4_pim_status = false;
    bool v6_pim_status = false;
    hal_ifindex_t if_index;

    auto intf_event = dynamic_cast<intf_event_t*>(p_msg);

    if_str_t intf_tmp;
    memset(&intf_tmp, 0, sizeof(intf_tmp));

    // Check if we have the interface entry in cache
    if (mcast_intf_cache_get(intf_event->intf_name, intf_tmp) != true) {
        // for any interface events, if the interface is not present
        // in local cache, then skip the event.
        NAS_MC_L3_LOG_DEBUG("MSG",
                "Event:%d, interface doesn't exist in local cache, skip event for intf:%s",
                p_msg->type, intf_event->intf_name.c_str());
        return STD_ERR(MCAST_L3, FAIL, 0);
    }
    if_index = intf_tmp.if_index;
    intf_event->vrf_id = intf_tmp.vrf_id;

    /* if Mcast status is disabled on VRF for both v4 & v6,
     * then skip the interface event.
     */
    if (mcast_get_vrf_mcast_status (intf_tmp.vrf_name,
            &v4_mc_status, &v6_mc_status) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("MSG", "Event:%d, VRF(%s) not found in cache, "
                "skipping event.", p_msg->type, intf_tmp.vrf_name.c_str());
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    if (!v4_mc_status && !v6_mc_status) {
        NAS_MC_L3_LOG_ERR("MSG", "Event:%d, VRF(%s) MCAST disabled, "
                "skipping event", p_msg->type, intf_tmp.vrf_name.c_str());
        return STD_ERR_OK;
    }

    /* if it's a PIM enabled interface,
     * then send an event to process route updates.
     */
    mcast_get_pim_status (intf_event->vrf_id, if_index,
            &v4_pim_status, &v6_pim_status);

    if (!v4_pim_status && !v6_pim_status)
    {
        NAS_MC_L3_LOG_DEBUG("MSG", "Event:%d, PIM v4/v6 disabled on Intf:%s, "
                "hence skipping event",
                p_msg->type, intf_event->intf_name.c_str());

        return STD_ERR_OK;
    }

    // for VLAN member update/mode change from L2 to L3 event, set is_iif_oif_remove to false
    if (v4_pim_status) {
        mcast_trigger_route_updates_for_intf (intf_event->vrf_id, AF_INET, if_index, intf_event->is_sync_msg, false);
    }
    if (v6_pim_status) {
        mcast_trigger_route_updates_for_intf (intf_event->vrf_id, AF_INET6, if_index, intf_event->is_sync_msg, false);
    }

    return STD_ERR_OK;
}

static t_std_error _intf_mode_change_to_l2_update (t_mcast_msg *p_msg)
{
    bool cache_update = false;
    bool v4_mc_status = false;
    bool v6_mc_status = false;
    bool v4_pim_status = false;
    bool v6_pim_status = false;
    hal_ifindex_t if_index;

    auto intf_event = dynamic_cast<intf_event_t*>(p_msg);

    if_str_t intf_tmp;
    memset(&intf_tmp, 0, sizeof(intf_tmp));

    // Check if we have the interface entry in cache
    if (mcast_intf_cache_get(intf_event->intf_name, intf_tmp) != true) {
        // for any interface events, if the interface is not present
        // in local cache, then skip the event.
        NAS_MC_L3_LOG_DEBUG("MSG",
                "Event:%d, interface doesn't exist in local cache, skip event for intf:%s",
                p_msg->type, intf_event->intf_name.c_str());
        return STD_ERR(MCAST_L3, FAIL, 0);
    }
    if_index = intf_tmp.if_index;
    intf_event->vrf_id = intf_tmp.vrf_id;

    /* if Mcast status is disabled on VRF for both v4 & v6,
     * then skip the vlan member update event.
     */
    if (mcast_get_vrf_mcast_status (intf_tmp.vrf_name,
            &v4_mc_status, &v6_mc_status) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("MSG", "Event:%d, VRF(%s) not found in cache, "
                "skipping event.", p_msg->type, intf_tmp.vrf_name.c_str());

        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    if (!v4_mc_status && !v6_mc_status) {
        NAS_MC_L3_LOG_ERR("MSG", "Event:%d, VRF(%s) MCAST disabled, "
                "skipping event", p_msg->type, intf_tmp.vrf_name.c_str());
        return STD_ERR_OK;
    }

    /* if it's a PIM enabled VLAN interface,
     * then send an event to process route updates.
     */
    mcast_get_pim_status (intf_event->vrf_id, if_index,
            &v4_pim_status, &v6_pim_status);

    if (!v4_pim_status && !v6_pim_status)
    {
        NAS_MC_L3_LOG_DEBUG("MSG", "Event:%d, PIM v4/v6 disabled on Intf:%s, "
                "hence skipping event",
                p_msg->type, intf_event->intf_name.c_str());

        return STD_ERR_OK;
    }

    // for mode change from L3 to L2, set is_iif_oif_remove to true
    if (v4_pim_status) {
        mcast_trigger_route_updates_for_intf (intf_event->vrf_id, AF_INET, if_index, intf_event->is_sync_msg, true);

        cache_update = true;
        intf_tmp.v4_pim_status = false;
    }
    if (v6_pim_status) {
        mcast_trigger_route_updates_for_intf (intf_event->vrf_id, AF_INET6, if_index, intf_event->is_sync_msg, true);
        cache_update = true;
        intf_tmp.v6_pim_status = false;
    }

    if (cache_update) {
        if (_mcast_rif_delete (intf_tmp.rif_id) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR("MSG",
                    "PIM status disable failed in RIF delete for af:%d, ifname:%s",
                    intf_event->af, intf_event->intf_name.c_str());
            return STD_ERR(MCAST_L3, FAIL, 0);
        }
        intf_tmp.rif_id = INVALID_RIF_ID;

        if (mcast_intf_cache_update(intf_event->intf_name, &intf_tmp) == false) {
            NAS_MC_L3_LOG_ERR("MSG",
                    "PIM status disable failed in intf cache update for ifname:%s",
                    intf_event->intf_name.c_str());
            return STD_ERR(MCAST_L3, FAIL, 0);
        }
    }

    return STD_ERR_OK;
}

cps_api_return_code_t _interface_config_handler(t_mcast_msg *p_msg, uint32_t num_msgs_in_queue)
{
    t_std_error rc = STD_ERR_OK;

    auto intf_event = dynamic_cast<intf_event_t*>(p_msg);

    NAS_MC_L3_LOG_INFO ("MSG", "Event:%d, event_mask:0x%x is_sync_msg:%d",
                        intf_event->type, intf_event->event_mask, intf_event->is_sync_msg);
    if (intf_event == nullptr) {
        NAS_MC_L3_LOG_ERR("MSG", "Event:%d, event_mask:0x%x Invalid message", intf_event->type, intf_event->event_mask);
        return cps_api_ret_code_ERR;
    }
    if (intf_event->event_mask.test(EVT_VLAN_MBR_CHANGE)) {
        rc = _vlan_mbr_update (p_msg);
    }
    else if (intf_event->event_mask.test(EVT_INTF_MODE_CHANGE_TO_L2)) {
        rc = _intf_mode_change_to_l2_update (p_msg);
    } else if (intf_event->event_mask.test(EVT_INTF_DELETE)) {

        //delete the interface from cache
        if (mcast_intf_cache_update(intf_event->intf_name, NULL))
            NAS_MC_L3_LOG_INFO ("MSG", "Deleted interface:%s from cache ",
                    intf_event->intf_name.c_str());

        if (mcast_intf_mlist_map_clear(intf_event->intf_name))
            NAS_MC_L3_LOG_INFO ("MSG", "Deleted VLAN:%s from member port cache ",
                    intf_event->intf_name.c_str());
    }

    if (rc != STD_ERR_OK) return cps_api_ret_code_ERR;

    return cps_api_ret_code_OK;
}


static t_std_error _process_snoop_vlan_update(t_mcast_msg *p_msg)
{
    bool v4_pim_status = false;
    bool v6_pim_status = false;
    hal_ifindex_t if_index;

    auto snoop_event = dynamic_cast<snoop_update_t*>(p_msg);

    if_str_t intf_tmp;
    memset(&intf_tmp, 0, sizeof(intf_tmp));

    // Check if we have the interface entry in cache
    if (mcast_intf_cache_get(snoop_event->vlan_if_name, intf_tmp) != true) {
        // for any interface events, if the interface is not present
        // in local cache, then skip the event.
        NAS_MC_L3_LOG_DEBUG("MSG",
                "Event:%d, interface doesn't exist in local cache, skip Snoop VLAN update event for intf:%s",
                p_msg->type, snoop_event->vlan_if_name.c_str());
        return STD_ERR(MCAST_L3, FAIL, 0);
    }
    if_index = intf_tmp.if_index;
    snoop_event->vrf_id = intf_tmp.vrf_id;

    /* if it's a PIM enabled interface,
     * then send an event to process route updates.
     */
    mcast_get_pim_status (snoop_event->vrf_id, if_index,
            &v4_pim_status, &v6_pim_status);

    if (!v4_pim_status && !v6_pim_status)
    {
        NAS_MC_L3_LOG_DEBUG("MSG", "Event:%d, PIM v4/v6 disabled on Intf:%s, "
                "hence skipping Snoop VLAN update event",
                p_msg->type, snoop_event->vlan_if_name.c_str());

        return STD_ERR_OK;
    }

    // for Snoop VLAN update event, trigger route update and set is_iif_oif_remove to false
    if (v4_pim_status && (snoop_event->af == AF_INET || snoop_event->af == AF_MAX)) {
        mcast_trigger_route_updates_for_intf (snoop_event->vrf_id, AF_INET, if_index, false, false);
    }
    if (v6_pim_status && (snoop_event->af == AF_INET6 || snoop_event->af == AF_MAX)) {
        mcast_trigger_route_updates_for_intf (snoop_event->vrf_id, AF_INET6, if_index, false, false);
    }
    return STD_ERR_OK;
}

static t_std_error _process_snoop_route_update(t_mcast_msg *p_msg)
{
    bool v4_pim_status = false;
    bool v6_pim_status = false;
    hal_ifindex_t if_index;

    auto snoop_event = dynamic_cast<snoop_update_t*>(p_msg);

    if_str_t intf_tmp;
    memset(&intf_tmp, 0, sizeof(intf_tmp));

    // Check if we have the interface entry in cache
    if (mcast_intf_cache_get(snoop_event->vlan_if_name, intf_tmp) != true) {
        // for any interface events, if the interface is not present
        // in local cache, then skip the event.
        NAS_MC_L3_LOG_DEBUG("MSG",
                "Event:%d, interface doesn't exist in local cache, skip Snoop Route update event for intf:%s, af:%d",
                p_msg->type, snoop_event->vlan_if_name.c_str(), snoop_event->af);
        return STD_ERR(MCAST_L3, FAIL, 0);
    }
    if_index = intf_tmp.if_index;
    snoop_event->vrf_id = intf_tmp.vrf_id;

    /* if it's a PIM enabled interface,
     * then send an event to process route updates.
     */
    mcast_get_pim_status (snoop_event->vrf_id, if_index,
            &v4_pim_status, &v6_pim_status);

    if (((snoop_event->af == AF_INET) && (!v4_pim_status)) ||
        ((snoop_event->af == AF_INET6) && (!v6_pim_status))) {
        NAS_MC_L3_LOG_DEBUG("MSG", "Event:%d, PIM v4/v6 disabled on Intf:%s, af:%d "
                "hence skipping Snoop Route update event",
                p_msg->type, snoop_event->vlan_if_name.c_str(), snoop_event->af);

        return STD_ERR_OK;
    }

    // for Snoop Route update trigger route update.
    if ((snoop_event->af == AF_INET) && (v4_pim_status)) {
        mcast_trigger_route_updates_for_snoop_upd (snoop_event->vrf_id, if_index, AF_INET,
                snoop_event->group_addr, snoop_event->star_g, snoop_event->source_addr);

    }
    if ((snoop_event->af == AF_INET6) && (v6_pim_status)) {
        mcast_trigger_route_updates_for_snoop_upd (snoop_event->vrf_id, if_index, AF_INET6,
                snoop_event->group_addr, snoop_event->star_g, snoop_event->source_addr);
    }

    return STD_ERR_OK;
}


cps_api_return_code_t _snoop_update_handler(t_mcast_msg *p_msg, uint32_t num_msgs_in_queue)
{
    t_std_error rc = STD_ERR_OK;

    auto snoop_event = dynamic_cast<snoop_update_t*>(p_msg);

    NAS_MC_L3_LOG_INFO ("MSG", "Event:%d, event_type:%d",
                        snoop_event->type, snoop_event->event_type);
    if (snoop_event == nullptr) {
        NAS_MC_L3_LOG_ERR("MSG", "Event:%d, event_type:%d Invalid message", snoop_event->type, snoop_event->event_type);
        return cps_api_ret_code_ERR;
    }
    if (snoop_event->event_type == SNOOP_VLAN_UPD_EVENT) {
        rc = _process_snoop_vlan_update(p_msg);

        NAS_MC_L3_LOG_DEBUG("MSG", "Snoop VLAN update processing completed for Vlan:%s",
                snoop_event->vlan_if_name.c_str());
    } else if (snoop_event->event_type == SNOOP_ROUTE_UPD_EVENT) {
        rc = _process_snoop_route_update(p_msg);

        NAS_MC_L3_LOG_DEBUG("MSG", "Snoop Route update processing completed for Vlan:%s, af:%d",
                snoop_event->vlan_if_name.c_str(), snoop_event->af);
    }

    if (rc != STD_ERR_OK) return cps_api_ret_code_ERR;

    return cps_api_ret_code_OK;
}


cps_api_return_code_t _sync_msg_notif_handler(t_mcast_msg *p_msg, uint32_t num_msgs_in_queue)
{
    //On receiving sync msg notification event,
    //notify the sender by sending wakeup signal.
    nas_mcast_notify_msg_processing_complete();

    return cps_api_ret_code_OK;
}

bool route_iif_oif_expand (mc_route_t *route, mcast_if_list_t &iiflist, mcast_if_list_t &oif_list)
{
    interface_ctrl_t    intf_ctrl;

    if (route == NULL) {
        NAS_MC_L3_LOG_ERR("NAS-MC-L3-UTILS", "Invalid input param");
        return false;
    }

    NAS_MC_L3_LOG_INFO ("UTILS", "IIF-OIF expansion "
            "VRF:%d, AF:%d, Route Type:%d, (%s,%s), IIF:%d",
            route->vrf_id, route->af, route->rtype,
            MC_IP_ADDR_TO_STR(&route->src_ip),
            MC_IP_ADDR_TO_STR(&route->grp_ip),
            route->iif_id);

    intf_id_cache_key_t if_key;
    if_str_t            intf_info;
    hal_vlan_id_t       intf_vlan_id = 0;
    nas_int_type_t      intf_type = nas_int_type_INVALID;
    std::string         intf_name{};
    bool is_xg = (route->rtype == L3_MCAST_ROUTE_TYPE_XG)
                  ? true : false;

    if_key.vrf_id = route->vrf_id;
    if_key.if_index = route->iif_id;
    if (mcast_intf_cache_get(if_key, intf_info) == true) {
        NAS_MC_L3_LOG_DEBUG("UTILS", "VRF:%d, IIF:%d", if_key.vrf_id, if_key.if_index);
        mcast_if_set_t if_set;
        intf_name = intf_info.if_name;
        intf_type = intf_info.if_type;
        intf_vlan_id = intf_info.vlan_id;

        //if mac-vlan interface, then fetch parent info
        if(intf_info.if_type == nas_int_type_MACVLAN) {
            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

            intf_ctrl.vrf_id = if_key.vrf_id;
            intf_ctrl.if_index = if_key.if_index;
            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;

            if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR("UTILS",
                        "Failed in retrieving intf from cache, "
                        "VRF:%d, IIF:%d", if_key.vrf_id, if_key.if_index);
                return false;
            }
            hal_vrf_id_t parent_vrf_id = intf_ctrl.l3_intf_info.vrf_id;
            hal_ifindex_t parent_if_index = intf_ctrl.l3_intf_info.if_index;

            if (parent_if_index != 0) {
                memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
                intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
                intf_ctrl.vrf_id = parent_vrf_id;
                intf_ctrl.if_index = parent_if_index;

                if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                    NAS_MC_L3_LOG_ERR("UTILS",
                            "Failed in retrieving parent intf from cache, "
                            "VRF:%d, IIF:%d", parent_vrf_id, parent_if_index);
                    return false;
                }

                intf_name.assign(intf_ctrl.if_name);
                intf_type = intf_ctrl.int_type;
                intf_vlan_id = intf_ctrl.vlan_id;
            }
        }
        if (intf_type == nas_int_type_VLAN) {
            std::set<hal_ifindex_t> intf_list;
            if (nas_mc_l2_snooped_port_list_cache_get(0, intf_vlan_id, (BASE_CMN_AF_TYPE_t) route->af, is_xg,
                        route->grp_ip, route->src_ip, intf_list) == STD_ERR_OK) {
                auto it = intf_list.begin();
                for (; it != intf_list.end(); ++it) {
                    if_set.insert(*it);
                }
            } else {
                mcast_intf_mlist_t intf_tg_lst;
                mcast_intf_mlist_t intf_untg_lst;

                if (mcast_intf_mlist_map_mlist_get(intf_name, tagged, intf_tg_lst) == true) {
                    auto it = intf_tg_lst.begin();
                    for (; it != intf_tg_lst.end(); ++it) {
                        if_set.insert(*it);
                    }
                }
                if (mcast_intf_mlist_map_mlist_get(intf_name, untagged, intf_untg_lst) == true) {
                    auto it = intf_untg_lst.begin();
                    for (; it != intf_untg_lst.end(); ++it) {
                        if_set.insert(*it);
                    }
                }
            }
        }
        iiflist.insert(std::make_pair(if_key.if_index, std::move(if_set)));
        NAS_MC_L3_LOG_DEBUG("UTILS", "Inserted IIF to iiflist");
    }

    if (route->oif_list.empty() == false) {
        auto oif_it = route->oif_list.begin();
        for (; oif_it != route->oif_list.end(); ++oif_it) {
            if_key.vrf_id = route->vrf_id;
            if_key.if_index = oif_it->first;
            if (mcast_intf_cache_get(if_key, intf_info) == true) {
                NAS_MC_L3_LOG_DEBUG("UTILS", "VRF:%d, OIF:%d", if_key.vrf_id, if_key.if_index);
                mcast_if_set_t if_set;
                intf_name = intf_info.if_name;
                intf_type = intf_info.if_type;
                intf_vlan_id = intf_info.vlan_id;

                if(intf_info.if_type == nas_int_type_MACVLAN) {
                    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

                    intf_ctrl.vrf_id = if_key.vrf_id;
                    intf_ctrl.if_index = if_key.if_index;
                    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;

                    if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                        NAS_MC_L3_LOG_ERR("UTILS",
                                "Failed in retrieving intf from cache, "
                                "VRF:%d, OIF:%d", if_key.vrf_id, if_key.if_index);
                        return false;
                    }
                    hal_vrf_id_t parent_vrf_id = intf_ctrl.l3_intf_info.vrf_id;
                    hal_ifindex_t parent_if_index = intf_ctrl.l3_intf_info.if_index;

                    if (parent_if_index != 0) {
                        memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
                        intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
                        intf_ctrl.vrf_id = parent_vrf_id;
                        intf_ctrl.if_index = parent_if_index;

                        if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                            NAS_MC_L3_LOG_ERR("UTILS",
                                    "Failed in retrieving parent intf from cache, "
                                    "VRF:%d, OIF:%d", parent_vrf_id, parent_if_index);
                            return false;
                        }

                        intf_name.assign(intf_ctrl.if_name);
                        intf_type = intf_ctrl.int_type;
                        intf_vlan_id = intf_ctrl.vlan_id;
                    }
                }
                if (intf_type == nas_int_type_VLAN) {
                    std::set<hal_ifindex_t> intf_list;
                    if (nas_mc_l2_snooped_port_list_cache_get(0, intf_vlan_id, (BASE_CMN_AF_TYPE_t)route->af, is_xg,
                                route->grp_ip, route->src_ip, intf_list) == STD_ERR_OK) {
                        auto it = intf_list.begin();
                        for (; it != intf_list.end(); ++it) {
                            if ((*it == oif_it->second.exclude_if_id)
                                    && (oif_it->second.has_exclude_if == true)) continue;
                            if_set.insert(*it);
                        }
                    } else {
                        mcast_intf_mlist_t intf_tg_lst;
                        mcast_intf_mlist_t intf_untg_lst;

                        if (mcast_intf_mlist_map_mlist_get(intf_name, tagged, intf_tg_lst) == true) {
                            auto it = intf_tg_lst.begin();
                            for (; it != intf_tg_lst.end(); ++it) {
                                if ((*it == oif_it->second.exclude_if_id)
                                        && (oif_it->second.has_exclude_if == true)) continue;
                                if_set.insert(*it);
                            }
                        }
                        if (mcast_intf_mlist_map_mlist_get(intf_name, untagged, intf_untg_lst) == true) {
                            auto it = intf_untg_lst.begin();
                            for (; it != intf_untg_lst.end(); ++it) {
                                if ((*it == oif_it->second.exclude_if_id)
                                        && (oif_it->second.has_exclude_if == true)) continue;
                                if_set.insert(*it);
                            }
                        }
                    }
                }
                oif_list.insert(std::make_pair(if_key.if_index, std::move(if_set)));
                NAS_MC_L3_LOG_DEBUG("UTILS", "Inserted OIF to oiflist");
            }
        }
    }

    return true;
}

t_std_error mcast_l3_util_clear_routes (l3_mcast_route_cps_key_t &rt_cps_key)
{
    uint32_t     fail_count = 0;
    hal_vrf_id_t vrf_id = 0;
    t_std_error  ret = STD_ERR_OK;

    if (rt_cps_key.vrf_name_valid) {
        if (nas_get_vrf_internal_id_from_vrf_name(rt_cps_key.vrf_name.c_str(), &vrf_id) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR("UTILS", "Route clear failed, not able to get the vrf_id(%s)",
                    rt_cps_key.vrf_name.c_str());
            return STD_ERR(MCAST_L3, FAIL, 0);
        }
    }

    std::vector<mc_route_t*> route_list = nas_mc_l3_route_db_get(((rt_cps_key.vrf_name_valid) ? &vrf_id : NULL),
                                                         ((rt_cps_key.af_valid) ?
                                                                       (const uint32_t*) &rt_cps_key.af : NULL),
                                                         ((rt_cps_key.rt_type_valid) ? &rt_cps_key.rt_type : NULL),
                                                         ((rt_cps_key.grp_ip_valid) ? &rt_cps_key.grp_ip : NULL),
                                                         ((rt_cps_key.src_ip_valid) ? &rt_cps_key.src_ip : NULL),
                                                         NULL);

    auto it = route_list.begin();
    for (; it != route_list.end(); ++it) {
        mc_route_t *rt = *it;
        if (rt != NULL) {
            if (_program_route_del(rt) != STD_ERR_OK) {
                ret = STD_ERR(MCAST_L3, FAIL, 0);
                fail_count++;
            }
        }
    }
    if (fail_count)
        NAS_MC_L3_LOG_ERR("UTILS", "Route clear failed #%d times during route delete", fail_count);

    return ret;
}

static cps_api_return_code_t _route_clear (t_mcast_msg *p_msg, uint32_t nas_num_route_msgs_in_queue)
{
    auto rt = dynamic_cast<route_t*>(p_msg);
    l3_mcast_route_cps_key_t rt_cps_key;
    cps_api_return_code_t ret = cps_api_ret_code_OK;

    memset(&rt_cps_key, 0, sizeof(rt_cps_key));

    rt_cps_key.vrf_name = rt->vrf_name;
    rt_cps_key.vrf_name_valid = true;
    rt_cps_key.af = (BASE_CMN_AF_TYPE_t) rt->af;
    rt_cps_key.af_valid = true;

    switch (rt->op) {
        case rt_op::RT_CLR_SRC_GRP:
            rt_cps_key.src_ip_valid = true;
            rt_cps_key.src_ip = rt->source_addr;
            rt_cps_key.grp_ip_valid = true;
            rt_cps_key.grp_ip = rt->group_addr;
            break;
        case rt_op::RT_CLR_GRP:
            rt_cps_key.grp_ip_valid = true;
            rt_cps_key.grp_ip = rt->group_addr;
            break;
        case rt_op::RT_CLR:
        default:
            break;
    }

    NAS_MC_L3_LOG_DEBUG("UTILS", "Route Clear: vrf(%s),af(%d)", rt->vrf_name.c_str(), rt->af);

    if (mcast_l3_util_clear_routes(rt_cps_key) != STD_ERR_OK) {
        ret = cps_api_ret_code_ERR;
    }

    return ret;
}


void nas_mc_l3_reg_msg_handler()
{
    NAS_MC_L3_LOG_DEBUG("NAS-MC-L3-UTILS", "Registering route message handlers");
    mcast_register_msg_handler(MCAST_STATUS, _set_global_mcast_status);
    mcast_register_msg_handler(PIM_STATUS, _set_pim_status);
    mcast_register_msg_handler(ROUTE_CONFIG, _program_route);
    mcast_register_msg_handler(INTERFACE_CONFIG, _interface_config_handler);
    mcast_register_msg_handler(SNOOP_UPDATE, _snoop_update_handler);
    mcast_register_msg_handler(SYNC_MSG_NOTIF, _sync_msg_notif_handler);
    mcast_register_msg_handler(ROUTE_CLEAR, _route_clear);
    mcast_register_msg_handler(MCAST_MSG_TYPE_MAX, mcast_msg_handler_exit);
}

void mcast_dump_expanded_if_list(mcast_if_list_t &expanded_if_list)
{
    NAS_MC_L3_LOG_DEBUG ("UTILS", "Dump expanded if list");

    auto it1 = expanded_if_list.begin();
    for (; it1 != expanded_if_list.end(); ++it1) {
        NAS_MC_L3_LOG_DEBUG ("UTILS", "IF - %d", it1->first);
        auto it2 = it1->second.begin();
        for (; it2 != it1->second.end(); ++it2) {
            NAS_MC_L3_LOG_DEBUG ("UTILS", "IF Mbr - %d", *(it2));
        }
    }
}

mc_route_t::operator std::string() const
{
    std::ostringstream ss;
    char ip_buffer[HAL_INET6_TEXT_LEN];
    ss << std::endl;
    ss << "-----------------" << std::endl;
    ss << "  IPMC Route" << std::endl;
    ss << "-----------------" << std::endl;
    ss << " VRF      : " << vrf_id << std::endl;
    std_ip_to_string(&grp_ip, ip_buffer, sizeof(ip_buffer));
    ss << " GRP_IP   : " << ip_buffer << std::endl;
    if ((rtype == L3_MCAST_ROUTE_TYPE_SG) || (rtype == L3_MCAST_ROUTE_TYPE_SGRPT)) {
        std_ip_to_string(&src_ip, ip_buffer, sizeof(ip_buffer));
        ss << " SRC_IP   : " << ip_buffer << std::endl;
    } else {
        ss << " SRC_IP   : *" << std::endl;
    }
    ss << " RT_TYPE  : " << rtype << std::endl;
    ss << " IIF      : " << iif_id << std::endl;
    ss << " OIF      : ";
    for (auto& oif: oif_list) {
        ss << "(" << oif.first << ",";
        if (oif.second.has_exclude_if) {
            ss << oif.second.exclude_if_id;
        } else {
            ss << "-";
        }
        ss << "),";
    }
    ss << std::endl;
    ss << " TO_CPU   : " << copy_to_cpu << std::endl;
    ss << " PEND_IDX : " << walker_pending_evt_list_tracker_index << std::endl;
    ss << " REPL_GRP : " << repl_grp_id << std::endl;
    ss << " STATUS   : " << static_cast<int>(status) << std::endl;
    ss << " NPU_PRG  : " << npu_prg_status << std::endl;
    ss << std::endl;
    return ss.str();
}

