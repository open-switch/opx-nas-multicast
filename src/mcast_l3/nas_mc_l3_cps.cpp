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
 * filename: nas_mc_l3_cps.cpp
 */

#include "cps_api_operation.h"
#include "nas_mc_l3_cps.h"
#include "cps_api_errors.h"
#include "cps_class_map.h"
#include "nas_mc_l3_util.h"
#include "nas_mc_l3_cache.h"
#include "nas_mc_l3_walker.h"
#include "l3-multicast.h"
#include "nas_mc_l3_msg.h"
#include "nas_ndi_mcast.h"
#include "cps_api_events.h"
#include "dell-base-if-vlan.h"
#include "dell-base-if.h"
#include "dell-interface.h"
#include "dell-base-interface-common.h"
#include "dell-base-cleanup-events.h"
#include "hal_if_mapping.h"
#include "cps_api_object_key.h"
#include "cps_api_operation.h"
#include "std_utils.h"
#include <list>



#define MCAST_CPS_API_THREAD 1
static cps_api_operation_handle_t mcast_cps_handle;

cps_api_return_code_t _handle_global_mcast_status(cps_api_object_t obj)
{

    cps_api_object_attr_t _vrf_name_attr = cps_api_object_attr_get(obj, L3_MCAST_GLOBAL_VRF_NAME);
    cps_api_object_attr_t _af_attr = cps_api_object_attr_get(obj, L3_MCAST_GLOBAL_AF);
    cps_api_object_attr_t _status_attr = cps_api_object_attr_get(obj, L3_MCAST_GLOBAL_STATUS);
    char vname[NAS_VRF_NAME_SZ] = {'\0'};
    size_t vname_len  = 0;

    if (!_vrf_name_attr || !_af_attr || !_status_attr
            || ((vname_len = cps_api_object_attr_len(_vrf_name_attr)) < 1)) {
        NAS_MC_L3_LOG_ERR("CPS", "Missing attributes in mcast global object");
        return cps_api_ret_code_ERR;
    }

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if ((op != cps_api_oper_DELETE) && !_status_attr) {
        NAS_MC_L3_LOG_ERR("CPS", "Missing status attribute in mcast global object");
        return cps_api_ret_code_ERR;
    }

    t_mcast_msg_uptr pmsg_uptr = mcast_alloc_mem_msg(MCAST_STATUS);
    global_mcast_status_t *pmsg = dynamic_cast<global_mcast_status_t*>(pmsg_uptr.get());
    if (pmsg == NULL) {
        NAS_MC_L3_LOG_ERR("CPS", "MSG allocation failed.");
        return cps_api_ret_code_ERR;
    }

    switch(op) {
        case cps_api_oper_DELETE:
            pmsg->op = rt_op::DELETE;
            break;
        case cps_api_oper_CREATE:
            pmsg->op = rt_op::ADD;
            break;
        case cps_api_oper_SET:
            pmsg->op = rt_op::UPDATE;
            break;
        default:
            NAS_MC_L3_LOG_ERR("CPS", "Invalid op type for mcast status config");
            return cps_api_ret_code_ERR;
    }

    safestrncpy(vname, (const char *)cps_api_object_attr_data_bin(_vrf_name_attr), sizeof(vname));
    if (vname_len < sizeof(vname)) {
        vname[vname_len] = '\0';
    }
    pmsg->vrf_name.assign(vname);


    uint32_t af = cps_api_object_attr_data_u32(_af_attr);
    if(af == BASE_CMN_AF_TYPE_INET) {
        pmsg->af = AF_INET;
    } else if(af == BASE_CMN_AF_TYPE_INET6) {
        pmsg->af = AF_INET6;
    } else {
        NAS_MC_L3_LOG_ERR("CPS", "Unsupported address family");
        return cps_api_ret_code_ERR;
    }
    pmsg->mcast_status = false;
    if (_status_attr)
        pmsg->mcast_status = cps_api_object_attr_data_uint(_status_attr);

    //on vrf instance delete, set status to disable.
    if (pmsg->op == rt_op::DELETE) {
        pmsg->mcast_status = false;
    }

    NAS_MC_L3_LOG_INFO ("CPS", "Received Mcast global status for VRF:%s, AF:%d, status:%d",
            pmsg->vrf_name.c_str(), pmsg->af, pmsg->mcast_status);

    nas_mcast_process_msg(pmsg_uptr.release());
    return cps_api_ret_code_OK;

}

cps_api_return_code_t handle_l3_mcast_route_config (cps_api_operation_types_t op, cps_api_object_it_t it)
{
    bool is_vrf_valid  = false;

    t_mcast_msg_uptr pmsg_uptr = mcast_alloc_mem_msg(ROUTE_CONFIG);
    route_t *pmsg = dynamic_cast<route_t*>(pmsg_uptr.get());
    if (pmsg == NULL) {
        NAS_MC_L3_LOG_ERR("CPS", "MSG allocation failed.");
        return cps_api_ret_code_ERR;
    }

    pmsg->data_to_cpu = false;
    switch(op) {
    case cps_api_oper_DELETE:
        pmsg->op = rt_op::DELETE;
        break;
    case cps_api_oper_CREATE:
        pmsg->op = rt_op::ADD;
        break;
    case cps_api_oper_SET:
        pmsg->op = rt_op::UPDATE;
        break;
    default:
        NAS_MC_L3_LOG_ERR("CPS", "Invalid op type for route config");
        return cps_api_ret_code_ERR;
    }

    pmsg->af = 0;
    while(cps_api_object_it_valid(&it)) {

        cps_api_attr_id_t id = cps_api_object_attr_id(it.attr);
        switch(id) {
            case L3_MCAST_ROUTES_ROUTE_VRF_NAME: {
                char vname[NAS_VRF_NAME_SZ] = {'\0'};
                size_t vname_len  = cps_api_object_attr_len(it.attr);
                if (vname_len < 1) {
                    NAS_MC_L3_LOG_ERR("CPS", "VRF name not present");
                    return cps_api_ret_code_ERR;
                }
                safestrncpy(vname, (const char *)cps_api_object_attr_data_bin(it.attr), sizeof(vname));
                if (vname_len < sizeof(vname)) vname[vname_len] = '\0';
                pmsg->vrf_name.assign(vname);
                is_vrf_valid = true;
                break;
            }
            case L3_MCAST_ROUTES_ROUTE_AF: {
                pmsg->af = cps_api_object_attr_data_u32(it.attr);
                pmsg->group_addr.af_index = pmsg->af;
                pmsg->source_addr.af_index = pmsg->af;
                break;
            }
            case L3_MCAST_ROUTES_ROUTE_GROUP_IP: {
                if (pmsg->af) {
                    pmsg->group_addr.af_index = pmsg->af;
                }
                memcpy(&pmsg->group_addr.u, cps_api_object_attr_data_bin(it.attr),
                           cps_api_object_attr_len(it.attr));
                break;
            }
            case L3_MCAST_ROUTES_ROUTE_SOURCE_IP: {
                if (pmsg->af) {
                    pmsg->source_addr.af_index = pmsg->af;
                }
                memcpy(&pmsg->source_addr.u, cps_api_object_attr_data_bin(it.attr),
                           cps_api_object_attr_len(it.attr));
                break;
            }
            case L3_MCAST_ROUTES_ROUTE_RT_TYPE: {
                auto type_id = cps_api_object_attr_data_u32(it.attr);
                switch(type_id) {
                case L3_MCAST_ROUTE_TYPE_XG:
                case L3_MCAST_ROUTE_TYPE_SG:
                case L3_MCAST_ROUTE_TYPE_SGRPT:
                    pmsg->rtype = static_cast<L3_MCAST_ROUTE_TYPE_t>(type_id);
                    break;
                default:
                    NAS_MC_L3_LOG_ERR("CPS", "Invalid route type value %d from CPS", type_id);
                    return cps_api_ret_code_ERR;
                }
                break;
            }
            case L3_MCAST_ROUTES_ROUTE_IIF_NAME: {
                char int_name[HAL_IF_NAME_SZ] = {'\0'};
                size_t int_name_len = cps_api_object_attr_len(it.attr);
                if (int_name_len < 1) {
                    NAS_MC_L3_LOG_ERR("CPS", "IIF name not present");
                    return cps_api_ret_code_ERR;
                }
                safestrncpy(int_name, (const char *)cps_api_object_attr_data_bin(it.attr), sizeof(int_name));
                if (int_name_len < sizeof(int_name)) int_name[int_name_len] = '\0';
                pmsg->iif_name.assign(int_name);
                break;
            }
            case L3_MCAST_ROUTES_ROUTE_DATA_TO_CPU: {
                pmsg->data_to_cpu = cps_api_object_attr_data_u32(it.attr);
                pmsg->upd_mask.set(UPD_COPY_TO_CPU_POS);
                break;
            }
            case L3_MCAST_ROUTES_ROUTE_OIF: {
                if (cps_api_object_attr_len(it.attr) > 0) {
                    cps_api_object_it_t oif_it = it;

                    for (cps_api_object_it_inside(&oif_it); cps_api_object_it_valid(&oif_it);
                         cps_api_object_it_next(&oif_it)) {

                        oif_t oif{};
                        cps_api_attr_id_t oif_id = cps_api_object_attr_id(oif_it.attr);
                        cps_api_object_it_t in_oif_it = oif_it;
                        NAS_MC_L3_LOG_DEBUG("CPS", "OIF parse OIF Instance: 0x%lx", oif_id);
                        for (cps_api_object_it_inside(&in_oif_it); cps_api_object_it_valid(&in_oif_it);
                             cps_api_object_it_next(&in_oif_it)) {

                            cps_api_attr_id_t in_oif_id = cps_api_object_attr_id(in_oif_it.attr);
                            switch(in_oif_id) {
                                case L3_MCAST_ROUTES_ROUTE_OIF_NAME: {
                                    char oif_name[HAL_IF_NAME_SZ] = {'\0'};
                                    size_t oif_name_len = cps_api_object_attr_len(in_oif_it.attr);
                                    if (oif_name_len > 0) {
                                        safestrncpy(oif_name, (const char *)cps_api_object_attr_data_bin(in_oif_it.attr),
                                                sizeof(oif_name));
                                        if (oif_name_len < sizeof(oif_name)) oif_name[oif_name_len] = '\0';
                                        oif.oif_name.assign(oif_name);
                                        NAS_MC_L3_LOG_DEBUG("CPS", "OIF NAME: %s", oif.oif_name.c_str());
                                    }
                                    break;
                                }
                                case L3_MCAST_ROUTES_ROUTE_OIF_EXCLUDE_INTERFACE: {
                                    char oif_exname[HAL_IF_NAME_SZ] = {'\0'};
                                    size_t oif_exname_len = cps_api_object_attr_len(in_oif_it.attr);
                                    if (oif_exname_len > 0) {
                                        safestrncpy(oif_exname, (const char *)cps_api_object_attr_data_bin(in_oif_it.attr),
                                                sizeof(oif_exname));
                                        if (oif_exname_len < sizeof(oif_exname)) oif_exname[oif_exname_len] = '\0';
                                        oif.exclude_if_name.assign(oif_exname);
                                        NAS_MC_L3_LOG_DEBUG("CPS", "OIF NAME EXCLUDE Intf:%s", oif.exclude_if_name.c_str());
                                    }
                                    break;
                                }
                                default:
                                    NAS_MC_L3_LOG_ERR("CPS", "Invalid OIF object attribute");
                                    break;
                            }
                        }
                        pmsg->oif.push_back(oif);
                    }
                } else {
                    NAS_MC_L3_LOG_DEBUG("CPS", "Remove all OIFs");
                }
                pmsg->upd_mask.set(UPD_OIF_POS);
                break;
            }

            default:
                NAS_MC_L3_LOG_ERR("CPS", "Invalid object attribute");
                break;
        }

        cps_api_object_it_next(&it);
    }

    if (!is_vrf_valid)
    {
        NAS_MC_L3_LOG_ERR("CPS", "Missing key attribute VRF name ");
        return cps_api_ret_code_ERR;
    }

    if (((op == cps_api_oper_CREATE) || (op == cps_api_oper_SET)) && pmsg->iif_name.empty()) {
        NAS_MC_L3_LOG_ERR("CPS", "No IIF given for route operation %d", op);
        return cps_api_ret_code_ERR;
    }

    // Check if we have the vrf entry in cache
    if (nas_get_vrf_internal_id_from_vrf_name(pmsg->vrf_name.c_str(), &pmsg->vrf_id) != STD_ERR_OK)
    {
        NAS_MC_L3_LOG_ERR("MSG", "VRF(%s) info not found in cache, ",
                "skipping route event:%d", pmsg->vrf_name.c_str(), (int)pmsg->op);
        return cps_api_ret_code_ERR;
    }

    NAS_MC_L3_LOG_INFO ("CPS", "Received Mcast Route event "
            "VRF:%s, AF:%d, Route Type:%d, (%s,%s), IIF:%s",
            pmsg->vrf_name.c_str(), pmsg->af, pmsg->rtype,
            MC_IP_ADDR_TO_STR(&pmsg->source_addr),
            MC_IP_ADDR_TO_STR(&pmsg->group_addr),
            pmsg->iif_name.c_str());

    if (!nas_mcast_process_msg(pmsg_uptr.release())) {
        NAS_MC_L3_LOG_ERR("CPS", "Failed to put message in queue");

        return cps_api_ret_code_ERR;
    }

    return cps_api_ret_code_OK;
}

cps_api_return_code_t l3_mcast_write_function(void * context,
                                  cps_api_transaction_params_t * param,
                                  size_t index_of_element_being_updated)
{
    if (param == nullptr) {
        NAS_MC_L3_LOG_ERR("CPS", "Null Param in l3_mcast_write_function");
        return cps_api_ret_code_ERR;
    }
    cps_api_object_t obj = cps_api_object_list_get(param->change_list,index_of_element_being_updated);
    if (obj == NULL) {
        NAS_MC_L3_LOG_ERR("CPS", "L3 Mcast object is not present at index %lu", index_of_element_being_updated);
        return cps_api_ret_code_ERR;
    }

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    cps_api_return_code_t ret = cps_api_ret_code_OK;
    uint32_t sub_cat = cps_api_key_get_subcat(cps_api_object_key(obj));
    switch(sub_cat) {
        case L3_MCAST_GLOBAL_OBJ:
        {
             ret = _handle_global_mcast_status(obj);
             break;
        }
        case L3_MCAST_INTERFACES:
        {
            cps_api_object_it_t it;
            cps_api_object_it_begin(obj, &it);
            ret = handle_l3_mcast_interface_config(op, it);
            break;
        }
        case L3_MCAST_ROUTES:
        {
             cps_api_object_it_t it;
             cps_api_object_it_begin(obj, &it);
             ret = handle_l3_mcast_route_config(op, it);
             break;
        }
        default:
            NAS_MC_L3_LOG_ERR("CPS", "Invalid subcategory in the CPS Object");
            break;
    }

    return ret;
}

cps_api_return_code_t handle_l3_mcast_interface_config (cps_api_operation_types_t op,
                                                        cps_api_object_it_t if_attr_it)
{
    char vrf_name[NAS_VRF_NAME_SZ] = {'\0'};
    char intf_name[HAL_IF_NAME_SZ] = {'\0'};
    uint32_t af = 0;
    bool status = false;
    size_t vrf_name_len, intf_name_len;
    bool vrf_valid, intf_valid, af_valid, status_valid;
    vrf_name_len = intf_name_len = 0;
    vrf_valid = intf_valid = af_valid = status_valid = false;

    for (; cps_api_object_it_valid(&if_attr_it);
            cps_api_object_it_next(&if_attr_it)) {
        cps_api_attr_id_t attr_id =  cps_api_object_attr_id(if_attr_it.attr);
        switch (attr_id) {
            case L3_MCAST_INTERFACES_INTERFACE_VRF_NAME:
            {
                vrf_name_len = cps_api_object_attr_len(if_attr_it.attr);
                safestrncpy(vrf_name, (const char *)cps_api_object_attr_data_bin(if_attr_it.attr),
                        sizeof(vrf_name));
                if (vrf_name_len < sizeof(vrf_name)) vrf_name[vrf_name_len] = '\0';
                vrf_valid = true;
                break;
            }
            case L3_MCAST_INTERFACES_INTERFACE_AF:
            {
                af = cps_api_object_attr_data_u32(if_attr_it.attr);
                af_valid = true;
                break;
            }
            case L3_MCAST_INTERFACES_INTERFACE_NAME:
            {
                intf_name_len = cps_api_object_attr_len(if_attr_it.attr);
                safestrncpy(intf_name, (const char *)cps_api_object_attr_data_bin(if_attr_it.attr),
                        sizeof(intf_name));
                if (intf_name_len < sizeof(intf_name)) intf_name[intf_name_len] = '\0';
                intf_valid = true;
                break;
            }
            case L3_MCAST_INTERFACES_INTERFACE_STATUS:
            {
                status = cps_api_object_attr_data_uint(if_attr_it.attr);
                status_valid = true;
                break;
            }
            default:
            {
                NAS_MC_L3_LOG_ERR("CPS", "Invalid interface attribute");
                break;
            }
        }
    }

    if (!vrf_valid || !af_valid || !intf_valid) {
        NAS_MC_L3_LOG_ERR("CPS", "Missing attributes in mcast interface object");
        return cps_api_ret_code_ERR;
    }

    if ((op != cps_api_oper_DELETE) && !status_valid) {
        NAS_MC_L3_LOG_ERR("CPS", "Missing status attribute in mcast interface object");
        return cps_api_ret_code_ERR;
    }

    t_mcast_msg_uptr pmsg_uptr = mcast_alloc_mem_msg(PIM_STATUS);
    pim_status_t *pmsg = dynamic_cast<pim_status_t*>(pmsg_uptr.get());
    if (pmsg == NULL) {
        NAS_MC_L3_LOG_ERR("CPS", "MSG allocation failed.");
        return cps_api_ret_code_ERR;
    }

    switch (op) {
        case cps_api_oper_DELETE:
            pmsg->op = rt_op::DELETE;
            break;
        case cps_api_oper_CREATE:
            pmsg->op = rt_op::ADD;
            break;
        case cps_api_oper_SET:
            pmsg->op = rt_op::UPDATE;
            break;
        default:
            NAS_MC_L3_LOG_ERR("CPS", "Invalid op type for mcast status config");
            return cps_api_ret_code_ERR;
    }

    pmsg->vrf_name.assign(vrf_name);
    pmsg->intf_name.assign(intf_name);
    if(af == BASE_CMN_AF_TYPE_INET) {
        pmsg->af = AF_INET;
    } else if (af == BASE_CMN_AF_TYPE_INET6) {
        pmsg->af = AF_INET6;
    } else {
        NAS_MC_L3_LOG_ERR("CPS", "Unsupported address family");
        return cps_api_ret_code_ERR;
    }
    if (status_valid) pmsg->pim_status= status;

    NAS_MC_L3_LOG_INFO ("CPS", "Received Mcast interface status for "
            "VRF:%s, AF:%d, interface %s, status:%d",
            pmsg->vrf_name.c_str(), pmsg->af,
            pmsg->intf_name.c_str(), pmsg->pim_status);

    nas_mcast_process_msg(pmsg_uptr.release());
    return cps_api_ret_code_OK;

}

cps_api_return_code_t handle_l3_mcast_interfaces_config (cps_api_transaction_params_t * param,
                                                         cps_api_object_t obj)
{
    cps_api_return_code_t ret = cps_api_ret_code_OK;
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    cps_api_object_it_t it;
    cps_api_object_it_begin(obj, &it);

    while (cps_api_object_it_valid(&it)) {
        if (cps_api_object_attr_len(it.attr) > 0) {
            cps_api_object_it_t if_it = it;
            for (cps_api_object_it_inside(&if_it); cps_api_object_it_valid(&if_it);
                    cps_api_object_it_next(&if_it)) {
                cps_api_object_it_t if_attr_it = if_it;
                cps_api_object_it_inside(&if_attr_it);
                if (handle_l3_mcast_interface_config(op, if_attr_it) != cps_api_ret_code_OK) {
                    ret = cps_api_ret_code_ERR;
                    NAS_MC_L3_LOG_ERR("CPS", "L3 mcast interface config Failed(%d)", ret);
                }
            }
        }
        cps_api_object_it_next(&it);
    }
    return cps_api_ret_code_OK;
}

cps_api_return_code_t handle_l3_mcast_routes_config (cps_api_transaction_params_t * param,
                                                     cps_api_object_t obj)
{
    cps_api_return_code_t ret = cps_api_ret_code_OK;
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    cps_api_object_it_t it;
    cps_api_object_it_begin(obj, &it);

    while (cps_api_object_it_valid(&it)) {
        if (cps_api_object_attr_len(it.attr) > 0) {
            cps_api_object_it_t if_it = it;
            for (cps_api_object_it_inside(&if_it); cps_api_object_it_valid(&if_it);
                    cps_api_object_it_next(&if_it)) {
                cps_api_object_it_t if_attr_it = if_it;
                cps_api_object_it_inside(&if_attr_it);
                if (handle_l3_mcast_route_config(op, if_attr_it) != cps_api_ret_code_OK) {
                    ret = cps_api_ret_code_ERR;
                    NAS_MC_L3_LOG_ERR("CPS", "L3 mcast route config Failed(%d)", ret);
                }
            }
        }
        cps_api_object_it_next(&it);
    }
    return cps_api_ret_code_OK;
}

cps_api_return_code_t l3_mcast_blk_write_function(void * context,
                                                  cps_api_transaction_params_t * param,
                                                  size_t index)
{
    if (param == nullptr) {
        NAS_MC_L3_LOG_ERR("CPS", "Null Param in l3_mcast_blk_write_function");
        return cps_api_ret_code_ERR;
    }
    cps_api_object_t obj = cps_api_object_list_get(param->change_list, index);
    if (obj == NULL) {
        NAS_MC_L3_LOG_ERR("CPS", "L3 Mcast object is not present at index %lu", index);
        return cps_api_ret_code_ERR;
    }

    cps_api_return_code_t ret = cps_api_ret_code_OK;
    uint32_t sub_cat = cps_api_key_get_subcat(cps_api_object_key(obj));
    switch (sub_cat) {
        case L3_MCAST_INTERFACES:
        {
            ret = handle_l3_mcast_interfaces_config(param, obj);
            break;
        }
        case L3_MCAST_ROUTES:
        {
            ret = handle_l3_mcast_routes_config(param, obj);
            break;
        }
        default:
        {
            NAS_MC_L3_LOG_ERR("CPS", "Invalid subcategory (%d)in the CPS Object", sub_cat);
            break;
        }
    }
    return ret;
}

static void _global_mcast_key_get (cps_api_object_t obj, cps_api_qualifier_t &qual, bool &vrf_name_valid,
                            std::string &vrf_name, bool &af_valid, BASE_CMN_AF_TYPE_t &af)
{
    cps_api_key_t         *key = cps_api_object_key(obj);
    cps_api_object_attr_t a;

    vrf_name_valid = af_valid = false;

    qual = cps_api_key_get_qual(key);
    if (cps_api_key_get_len(key) <= CPS_OBJ_KEY_APP_INST_POS) {
        return;
    }

    a = cps_api_get_key_data(obj, L3_MCAST_GLOBAL_VRF_NAME);
    if((vrf_name_valid = (a != NULL))) {
        char vname[NAS_VRF_NAME_SZ] = {'\0'};
        size_t vname_len  = cps_api_object_attr_len(a);
        if (vname_len < 1) {
            vrf_name_valid = false;
        } else {
            safestrncpy(vname, (const char *)cps_api_object_attr_data_bin(a), sizeof(vname));
            if (vname_len < sizeof(vname)) vname[vname_len] = '\0';
            vrf_name.assign(vname);
        }
    }
    a = cps_api_get_key_data(obj, L3_MCAST_GLOBAL_AF);
    if ((af_valid = (a != NULL))) {
        af = (BASE_CMN_AF_TYPE_t)cps_api_object_attr_data_u32(a);
    }

    return;
}

static void _global_mcast_key_set (cps_api_object_t obj, cps_api_qualifier_t qual, bool vrf_name_valid,
                            std::string vrf_name, bool af_valid, BASE_CMN_AF_TYPE_t af)
{
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj), L3_MCAST_GLOBAL_OBJ, qual);

    if (vrf_name_valid) {
        cps_api_set_key_data(obj, L3_MCAST_GLOBAL_VRF_NAME, cps_api_object_ATTR_T_BIN,
                             vrf_name.c_str(), vrf_name.length() + 1);
    }

    if (af_valid) {
        cps_api_set_key_data(obj, L3_MCAST_GLOBAL_AF, cps_api_object_ATTR_T_BIN, &af, sizeof(af));
    }

    return;

}

static cps_api_object_t  _global_mcast_obj_get_by_af(vrf_str_t &vrf_info, cps_api_qualifier_t qual, BASE_CMN_AF_TYPE_t af)
{
    bool             af_status = false;
    switch (af) {
        case BASE_CMN_AF_TYPE_INET:
            if (vrf_info.v4_mcast_valid == false) return NULL;
            af_status = vrf_info.v4_mcast_status;
            break;
        case BASE_CMN_AF_TYPE_INET6:
            if (vrf_info.v6_mcast_valid == false) return NULL;
            af_status = vrf_info.v6_mcast_status;
            break;
        default:
            return NULL;
    }
    cps_api_object_t obj = cps_api_object_create();
    if (obj != NULL) {
        _global_mcast_key_set(obj, qual, true, vrf_info.vrf_name, true, af);
        cps_api_object_attr_add(obj, L3_MCAST_GLOBAL_STATUS, &af_status, sizeof(af_status));
    }
    return obj;
}

void _global_mcast_obj_get_by_vrf_name (vrf_str_t &vrf_info, cps_api_get_params_t *param, cps_api_qualifier_t qual)
{
    cps_api_object_t tmp = NULL;


    if ((tmp = _global_mcast_obj_get_by_af(vrf_info, qual, BASE_CMN_AF_TYPE_INET)) != NULL) {
        cps_api_object_list_append(param->list, tmp);
    }
    if ((tmp = _global_mcast_obj_get_by_af(vrf_info, qual, BASE_CMN_AF_TYPE_INET6)) != NULL) {
        cps_api_object_list_append(param->list, tmp);
    }
}

static cps_api_return_code_t _global_mcast_status_get (cps_api_get_params_t *param, cps_api_object_t req_obj)
{
    cps_api_return_code_t ret = cps_api_ret_code_OK;
    bool                  vrf_name_valid, af_valid;
    cps_api_qualifier_t   qual;
    std::string           vrf_name;
    BASE_CMN_AF_TYPE_t    af = (BASE_CMN_AF_TYPE_t)0;

    vrf_name_valid = af_valid = false;

    if ((param == nullptr) || (req_obj == nullptr)) {
        NAS_MC_L3_LOG_ERR("CPS", "Invalid params (_global_mcast_status_get)");
        return cps_api_ret_code_ERR;
    }

    _global_mcast_key_get(req_obj, qual, vrf_name_valid, vrf_name, af_valid, af);

    nas_mc_l3_lock();

    if (vrf_name_valid) {
        cps_api_object_t tmp = NULL;
        hal_vrf_id_t vrfid = 0;
        if (nas_get_vrf_internal_id_from_vrf_name(vrf_name.c_str(), &vrfid) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR("CPS", "Not able to get the vrf_id(%s)",
                    vrf_name.c_str());

            nas_mc_l3_unlock();
            return cps_api_ret_code_ERR;
        }
        vrf_str_t vrf_info;
        if (mcast_vrf_cache_get(vrfid, vrf_info) != false) {
            if (af_valid) {
                if((tmp = _global_mcast_obj_get_by_af(vrf_info, qual, af)) != NULL) {
                    cps_api_object_list_append(param->list, tmp);
                }
            } else {
                _global_mcast_obj_get_by_vrf_name(vrf_info, param, qual);
            }
        } else {
            NAS_MC_L3_LOG_ERR("CPS", "VRF entry not found in the cache (%s - %u)",
                    vrf_name.c_str(), vrfid);

            nas_mc_l3_unlock();
            return cps_api_ret_code_ERR;
        }
    } else {
        mcast_vrf_cache_for_each_entry_cps_get(param, qual, _global_mcast_obj_get_by_vrf_name);
    }
    nas_mc_l3_unlock();

    return ret;
}

static void _intf_pim_mcast_key_get (cps_api_object_t obj, cps_api_qualifier_t &qual, bool &vrf_name_valid,
                            std::string &vrf_name, bool &af_valid, BASE_CMN_AF_TYPE_t &af,
                            bool &ifname_valid, std::string &ifname)
{
    cps_api_key_t         *key = cps_api_object_key(obj);
    cps_api_object_attr_t a;

    vrf_name_valid = af_valid = ifname_valid = false;

    qual = cps_api_key_get_qual(key);
    if (cps_api_key_get_len(key) <= CPS_OBJ_KEY_APP_INST_POS) {
        return;
    }

    a = cps_api_get_key_data(obj, L3_MCAST_INTERFACES_INTERFACE_VRF_NAME);
    if((vrf_name_valid = (a != NULL))) {
        char vname[NAS_VRF_NAME_SZ] = {'\0'};
        size_t vname_len  = cps_api_object_attr_len(a);
        if (vname_len < 1) {
            vrf_name_valid = false;
        } else {
            safestrncpy(vname, (const char *)cps_api_object_attr_data_bin(a), sizeof(vname));
            if (vname_len < sizeof(vname)) vname[vname_len] = '\0';
            vrf_name.assign(vname);
        }
    }
    a = cps_api_get_key_data(obj, L3_MCAST_INTERFACES_INTERFACE_AF);
    if ((af_valid = (a != NULL))) {
        af = (BASE_CMN_AF_TYPE_t)cps_api_object_attr_data_u32(a);
    }
    a = cps_api_get_key_data(obj, L3_MCAST_INTERFACES_INTERFACE_NAME);
    if ((ifname_valid = (a != NULL))) {
        char if_name[HAL_IF_NAME_SZ] = {'\0'};
        size_t if_name_len  = cps_api_object_attr_len(a);
        if (if_name_len < 1) {
            ifname_valid = false;
        } else {
            safestrncpy(if_name, (const char *)cps_api_object_attr_data_bin(a), sizeof(if_name));
            if (if_name_len < sizeof(if_name)) if_name[if_name_len] = '\0';
            ifname.assign(if_name);
        }
    }

    return;
}

static void _intf_pim_mcast_key_set (cps_api_object_t obj, cps_api_qualifier_t qual, bool vrf_name_valid,
                            std::string vrf_name, bool af_valid, BASE_CMN_AF_TYPE_t af,
                            bool ifname_valid, std::string &ifname)
{
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj), L3_MCAST_INTERFACES_OBJ, qual);

    if (vrf_name_valid) {
        cps_api_set_key_data(obj, L3_MCAST_INTERFACES_INTERFACE_VRF_NAME, cps_api_object_ATTR_T_BIN,
                             vrf_name.c_str(), vrf_name.length() + 1);
    }

    if (af_valid) {
        cps_api_set_key_data(obj, L3_MCAST_INTERFACES_INTERFACE_AF, cps_api_object_ATTR_T_BIN, &af, sizeof(af));
    }

    if (ifname_valid) {
        cps_api_set_key_data(obj, L3_MCAST_INTERFACES_INTERFACE_NAME, cps_api_object_ATTR_T_BIN,
                             ifname.c_str(), ifname.length() + 1);
    }

    return;
}

static cps_api_object_t  _intf_pim_mcast_obj_get_by_af(if_str_t &intf_info, cps_api_qualifier_t qual, BASE_CMN_AF_TYPE_t af)
{
    bool      af_status = false;
    switch (af) {
        case BASE_CMN_AF_TYPE_INET:
            if (intf_info.v4_pim_valid == false) return NULL;
            af_status = intf_info.v4_pim_status;
            break;
        case BASE_CMN_AF_TYPE_INET6:
            if (intf_info.v6_pim_valid == false) return NULL;
            af_status = intf_info.v6_pim_status;
            break;
        default:
            return NULL;
    }
    cps_api_object_t obj = cps_api_object_create();
    if (obj != NULL) {
        _intf_pim_mcast_key_set(obj, qual, true, intf_info.vrf_name, true, af, true, intf_info.if_name);
        cps_api_object_attr_add(obj, L3_MCAST_INTERFACES_INTERFACE_STATUS, &af_status, sizeof(af_status));
    }
    return obj;
}

static void _intf_pim_mcast_obj_get_by_ifname (if_str_t &intf_info, cps_api_get_params_t *param,
                                        cps_api_qualifier_t qual)
{
    cps_api_object_t tmp = NULL;
    if ((tmp = _intf_pim_mcast_obj_get_by_af(intf_info, qual, BASE_CMN_AF_TYPE_INET)) != NULL) {
        cps_api_object_list_append(param->list, tmp);
    }
    if ((tmp = _intf_pim_mcast_obj_get_by_af(intf_info, qual, BASE_CMN_AF_TYPE_INET6)) != NULL) {
        cps_api_object_list_append(param->list, tmp);
    }

}

void _intf_pim_mcast_obj_get_cb (if_str_t &intf_info, cps_api_get_params_t *param, cps_api_qualifier_t qual,
                                 bool af_valid, BASE_CMN_AF_TYPE_t af)
{
    if (af_valid == true) {
        cps_api_object_t tmp = NULL;
        if ((tmp = _intf_pim_mcast_obj_get_by_af(intf_info, qual, af)) != NULL) {
            cps_api_object_list_append(param->list, tmp);
        }
    } else {
        _intf_pim_mcast_obj_get_by_ifname(intf_info, param, qual);
    }
}

cps_api_return_code_t _intf_pim_status_get (cps_api_get_params_t *param, cps_api_object_t req_obj)
{
    cps_api_return_code_t ret = cps_api_ret_code_OK;
    bool                  vrf_name_valid, af_valid, ifname_valid;
    cps_api_qualifier_t   qual;
    std::string           vrf_name, ifname;
    BASE_CMN_AF_TYPE_t    af = (BASE_CMN_AF_TYPE_t)0;
    hal_vrf_id_t          vrfid = 0;

    vrf_name_valid = af_valid = ifname_valid = false;

    if ((param == nullptr) || (req_obj == nullptr)) {
        NAS_MC_L3_LOG_ERR("CPS", "Invalid params (_intf_pim_status_get)");
        return cps_api_ret_code_ERR;
    }

    _intf_pim_mcast_key_get(req_obj, qual, vrf_name_valid, vrf_name, af_valid, af, ifname_valid, ifname);
    if (vrf_name_valid == true) {
        if (nas_get_vrf_internal_id_from_vrf_name(vrf_name.c_str(), &vrfid) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR("CPS", "Not able to get the vrf_id(%s)",
                    vrf_name.c_str());
            return cps_api_ret_code_ERR;
        }
    }

    if (ifname_valid) {
        cps_api_object_t tmp = NULL;
        if_str_t intf_info;
        if (mcast_intf_cache_get(ifname, intf_info) != false) {
            if ((vrf_name_valid != true) || ((vrf_name_valid == true)
                        && (vrfid == intf_info.vrf_id))) {
                if (af_valid) {
                    if((tmp = _intf_pim_mcast_obj_get_by_af(intf_info, qual, af)) != NULL) {
                        cps_api_object_list_append(param->list, tmp);
                    }
                } else {
                    _intf_pim_mcast_obj_get_by_ifname(intf_info, param, qual);
                }
            }
        } else {
            NAS_MC_L3_LOG_ERR("CPS", "Interface entry not found in the cache (%s: %s:%u)",
                    ifname.c_str(), vrf_name.c_str(), vrfid);
            return cps_api_ret_code_ERR;
        }
    } else {
        mcast_intf_cache_for_each_entry_cps_get(param, qual, _intf_pim_mcast_obj_get_cb, vrf_name_valid, vrfid,
                                                af_valid, af);
    }
    return ret;
}


static void _routes_state_mcast_key_get (cps_api_object_t obj, cps_api_qualifier_t &qual, l3_mcast_route_cps_key_t &rt_cps_key)
{
    cps_api_key_t         *key = cps_api_object_key(obj);
    cps_api_object_attr_t a;

    rt_cps_key.vrf_name_valid = rt_cps_key.af_valid = rt_cps_key.src_ip_valid =
        rt_cps_key.grp_ip_valid = rt_cps_key.rt_type_valid = false;

    qual = cps_api_key_get_qual(key);
    if (cps_api_key_get_len(key) <= CPS_OBJ_KEY_APP_INST_POS) {
        return;
    }

    a = cps_api_get_key_data(obj, L3_MCAST_ROUTES_STATE_ROUTE_VRF_NAME);
    if((rt_cps_key.vrf_name_valid = (a != NULL))) {
        char vname[NAS_VRF_NAME_SZ] = {'\0'};
        size_t vname_len  = cps_api_object_attr_len(a);
        if (vname_len < 1) {
            rt_cps_key.vrf_name_valid = false;
        } else {
            safestrncpy(vname, (const char *)cps_api_object_attr_data_bin(a), sizeof(vname));
            if (vname_len < sizeof(vname)) vname[vname_len] = '\0';
            rt_cps_key.vrf_name.assign(vname);
        }
    }
    a = cps_api_get_key_data(obj, L3_MCAST_ROUTES_STATE_ROUTE_AF);
    if ((rt_cps_key.af_valid = (a != NULL))) {
        rt_cps_key.af = (BASE_CMN_AF_TYPE_t)cps_api_object_attr_data_u32(a);
    }
    a = cps_api_get_key_data(obj, L3_MCAST_ROUTES_STATE_ROUTE_RT_TYPE);
    if ((rt_cps_key.rt_type_valid = (a != NULL))) {
        rt_cps_key.rt_type = (L3_MCAST_ROUTE_TYPE_t) cps_api_object_attr_data_u32(a);
    }
    uint8_t len = 0;
    uint32_t   af_index = 0;
    if (rt_cps_key.af == BASE_CMN_AF_TYPE_INET) {
        len = sizeof(rt_cps_key.src_ip.u.v4_addr);
        af_index = HAL_INET4_FAMILY;
    } else if (rt_cps_key.af == BASE_CMN_AF_TYPE_INET6) {
        len = sizeof(rt_cps_key.src_ip.u.v6_addr);
        af_index = HAL_INET6_FAMILY;
    }
    a = cps_api_get_key_data(obj, L3_MCAST_ROUTES_STATE_ROUTE_SOURCE_IP);
    if ((rt_cps_key.src_ip_valid = (a != NULL))) {
        memcpy(&rt_cps_key.src_ip.u.v4_addr, cps_api_object_attr_data_bin(a), len);
        rt_cps_key.src_ip.af_index = af_index;
    }

    a = cps_api_get_key_data(obj, L3_MCAST_ROUTES_STATE_ROUTE_GROUP_IP);
    if ((rt_cps_key.grp_ip_valid = (a != NULL))) {
        memcpy(&rt_cps_key.grp_ip.u.v4_addr, cps_api_object_attr_data_bin(a), len);
        rt_cps_key.grp_ip.af_index = af_index;
    }

    return;
}

static void _routes_state_mcast_key_set (cps_api_object_t obj, cps_api_qualifier_t qual, l3_mcast_route_cps_key_t &rt_cps_key)
{
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj), L3_MCAST_ROUTES_STATE_ROUTE, qual);

    if (rt_cps_key.vrf_name_valid) {
        cps_api_set_key_data(obj, L3_MCAST_ROUTES_STATE_ROUTE_VRF_NAME, cps_api_object_ATTR_T_BIN,
                             rt_cps_key.vrf_name.c_str(), rt_cps_key.vrf_name.length() + 1);
    }

    if (rt_cps_key.af_valid) {
        cps_api_set_key_data(obj, L3_MCAST_ROUTES_STATE_ROUTE_AF, cps_api_object_ATTR_T_BIN,
                &rt_cps_key.af, sizeof(rt_cps_key.af));
    }

    if (rt_cps_key.rt_type_valid) {
        cps_api_set_key_data(obj, L3_MCAST_ROUTES_STATE_ROUTE_RT_TYPE, cps_api_object_ATTR_T_BIN,
                             &rt_cps_key.rt_type, sizeof(rt_cps_key.rt_type));
    }

    if (rt_cps_key.src_ip_valid) {
        uint32_t len = 0;
        if (rt_cps_key.src_ip.af_index == HAL_INET4_FAMILY) {
            len = sizeof(rt_cps_key.src_ip.u.v4_addr);
        } else if (rt_cps_key.src_ip.af_index == HAL_INET6_FAMILY) {
            len = sizeof(rt_cps_key.src_ip.u.v6_addr);
        }
        if (len != 0) {
            cps_api_set_key_data(obj, L3_MCAST_ROUTES_STATE_ROUTE_SOURCE_IP, cps_api_object_ATTR_T_BIN,
                    &rt_cps_key.src_ip.u.v4_addr, len);
        }
    }

    if (rt_cps_key.grp_ip_valid) {
        uint32_t len = 0;
        if (rt_cps_key.grp_ip.af_index == HAL_INET4_FAMILY) {
            len = sizeof(rt_cps_key.grp_ip.u.v4_addr);
        } else if (rt_cps_key.grp_ip.af_index == HAL_INET6_FAMILY) {
            len = sizeof(rt_cps_key.grp_ip.u.v6_addr);
        }
        if (len != 0) {
            cps_api_set_key_data(obj, L3_MCAST_ROUTES_STATE_ROUTE_GROUP_IP, cps_api_object_ATTR_T_BIN,
                    &rt_cps_key.grp_ip.u.v4_addr, len);
        }
    }

    return;

}

static cps_api_object_t _l3_mcast_routes_state_obj_add (cps_api_qualifier_t qual, l3_mcast_route_cps_key_t &rt_key,
                                                 ndi_ipmc_entry_t &ipmc_entry)
{
    cps_api_object_t obj = cps_api_object_create();
    if (obj != NULL) {
        _routes_state_mcast_key_set(obj, qual, rt_key);
        cps_api_object_attr_add(obj, L3_MCAST_ROUTES_STATE_ROUTE_STATUS, &ipmc_entry.route_hit,
                sizeof(ipmc_entry.route_hit));
    }
    return obj;
}

cps_api_return_code_t _l3_mcast_routes_state_get (cps_api_get_params_t *param, cps_api_object_t req_obj)
{
    cps_api_return_code_t      ret = cps_api_ret_code_OK;
    l3_mcast_route_cps_key_t   rt_cps_key;
    cps_api_qualifier_t        qual;

    memset(&rt_cps_key, 0, sizeof(rt_cps_key));
    _routes_state_mcast_key_get(req_obj, qual, rt_cps_key);
    if ((rt_cps_key.vrf_name_valid == false) || (rt_cps_key.af_valid == false)
            || (rt_cps_key.src_ip_valid == false) || (rt_cps_key.grp_ip_valid == false)
            || (rt_cps_key.rt_type_valid == false)) {
        NAS_MC_L3_LOG_ERR("CPS", "Key attributes are missing for routes state object get");
        return cps_api_ret_code_ERR;
    }

    vrf_str_t vrf_info;
    if (rt_cps_key.vrf_name_valid) {
        if (mcast_vrf_cache_get(rt_cps_key.vrf_name.c_str(), vrf_info) == false) {
            NAS_MC_L3_LOG_ERR("CPS", "Not able to get the vrf object (%s) for routes state object get",
                    rt_cps_key.vrf_name.c_str());
            return cps_api_ret_code_ERR;
        }
    }

    hal_vrf_id_t vrf_id = 0;
    if (nas_get_vrf_internal_id_from_vrf_name(rt_cps_key.vrf_name.c_str(), &vrf_id) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "Not able to get the vrf_id(%s) for routes state object get",
                rt_cps_key.vrf_name.c_str());
        return cps_api_ret_code_ERR;
    }
    /* get a copy of exact route from local route DB */
    std::vector<mc_route_t> route_list = nas_mc_l3_route_db_get_copy(&vrf_id, (const uint32_t*) &rt_cps_key.af,
                                               &rt_cps_key.rt_type, &rt_cps_key.grp_ip,
                                               &rt_cps_key.src_ip);
    if (route_list.empty())
    {
        NAS_MC_L3_LOG_ERR("CPS", "Route entry not present in cache for routes state object get");
        return cps_api_ret_code_ERR;
    }
    auto route = route_list.begin();
    /* Get IIF RIF and send it to NDI */
    ndi_rif_id_t iif_rif_id;
    if (!mcast_intf_cache_get_rif_id (route->vrf_id, route->iif_id,
                &iif_rif_id)) {
        NAS_MC_L3_LOG_ERR("CPS", "RIF Id not present in cache for IIF, state object get");
        return cps_api_ret_code_ERR;
    }
    ndi_ipmc_entry_t ipmc_entry;
    memset(&ipmc_entry, 0, sizeof(ipmc_entry));
    ipmc_entry.vrf_id = vrf_info.vrf_obj_id;
    ipmc_entry.iif_rif_id = iif_rif_id;
    ipmc_entry.type = (rt_cps_key.rt_type == L3_MCAST_ROUTE_TYPE_XG)
                       ? NAS_NDI_IPMC_ENTRY_TYPE_XG : NAS_NDI_IPMC_ENTRY_TYPE_SG;
    memcpy(&ipmc_entry.src_ip, &rt_cps_key.src_ip, sizeof(ipmc_entry.src_ip));
    memcpy(&ipmc_entry.dst_ip, &rt_cps_key.grp_ip, sizeof(ipmc_entry.dst_ip));

    t_std_error rc = ndi_ipmc_entry_get(0, &ipmc_entry);
    if (rc != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "IPMC entry get from NDI is falied.");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_t tmp = NULL;
    if ((tmp = _l3_mcast_routes_state_obj_add(qual, rt_cps_key, ipmc_entry)) != NULL) {
        cps_api_object_list_append(param->list, tmp);
    } else {
        NAS_MC_L3_LOG_ERR("CPS", "Adding routes state object failed.");
        return cps_api_ret_code_ERR;
    }
    return ret;
}

static void _routes_mcast_key_get (cps_api_object_t obj, cps_api_qualifier_t &qual, l3_mcast_route_cps_key_t &rt_cps_key)
{
    cps_api_key_t         *key = cps_api_object_key(obj);
    cps_api_object_attr_t a;

    rt_cps_key.vrf_name_valid = rt_cps_key.af_valid = rt_cps_key.src_ip_valid =
        rt_cps_key.grp_ip_valid = rt_cps_key.rt_type_valid = false;

    qual = cps_api_key_get_qual(key);
    if (cps_api_key_get_len(key) <= CPS_OBJ_KEY_APP_INST_POS) {
        return;
    }

    a = cps_api_get_key_data(obj, L3_MCAST_ROUTES_ROUTE_VRF_NAME);
    if((rt_cps_key.vrf_name_valid = (a != NULL))) {
        char vname[NAS_VRF_NAME_SZ] = {'\0'};
        size_t vname_len  = cps_api_object_attr_len(a);
        if (vname_len < 1) {
            rt_cps_key.vrf_name_valid = false;
        } else {
            safestrncpy(vname, (const char *)cps_api_object_attr_data_bin(a), sizeof(vname));
            if (vname_len < sizeof(vname)) vname[vname_len] = '\0';
            rt_cps_key.vrf_name.assign(vname);
        }
    }
    a = cps_api_get_key_data(obj, L3_MCAST_ROUTES_ROUTE_AF);
    if ((rt_cps_key.af_valid = (a != NULL))) {
        rt_cps_key.af = (BASE_CMN_AF_TYPE_t)cps_api_object_attr_data_u32(a);
    }
    a = cps_api_get_key_data(obj, L3_MCAST_ROUTES_ROUTE_RT_TYPE);
    if ((rt_cps_key.rt_type_valid = (a != NULL))) {
        rt_cps_key.rt_type = (L3_MCAST_ROUTE_TYPE_t) cps_api_object_attr_data_u32(a);
    }
    uint8_t len = 0;
    uint32_t af_index = 0;
    if (rt_cps_key.af == BASE_CMN_AF_TYPE_INET) {
        len = sizeof(rt_cps_key.src_ip.u.v4_addr);
        af_index = HAL_INET4_FAMILY;
    } else if (rt_cps_key.af == BASE_CMN_AF_TYPE_INET6) {
        len = sizeof(rt_cps_key.src_ip.u.v6_addr);
        af_index = HAL_INET6_FAMILY;
    }
    if ((!rt_cps_key.rt_type_valid) || (rt_cps_key.rt_type != L3_MCAST_ROUTE_TYPE_XG)) {
        a = cps_api_get_key_data(obj, L3_MCAST_ROUTES_ROUTE_SOURCE_IP);
        if ((rt_cps_key.src_ip_valid = (a != NULL))) {
            memcpy(&rt_cps_key.src_ip.u.v4_addr, cps_api_object_attr_data_bin(a), len);
            rt_cps_key.src_ip.af_index = af_index;
        }
    }

    a = cps_api_get_key_data(obj, L3_MCAST_ROUTES_ROUTE_GROUP_IP);
    if ((rt_cps_key.grp_ip_valid = (a != NULL))) {
        memcpy(&rt_cps_key.grp_ip.u.v4_addr, cps_api_object_attr_data_bin(a), len);
        rt_cps_key.grp_ip.af_index = af_index;
    }

    return;
}

static void _routes_mcast_key_set (cps_api_object_t obj, cps_api_qualifier_t qual, l3_mcast_route_cps_key_t &rt_cps_key)
{
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj), L3_MCAST_ROUTES_ROUTE, qual);

    if (rt_cps_key.vrf_name_valid) {
        cps_api_set_key_data(obj, L3_MCAST_ROUTES_ROUTE_VRF_NAME, cps_api_object_ATTR_T_BIN,
                             rt_cps_key.vrf_name.c_str(), rt_cps_key.vrf_name.length() + 1);
    }

    if (rt_cps_key.af_valid) {
        cps_api_set_key_data(obj, L3_MCAST_ROUTES_ROUTE_AF, cps_api_object_ATTR_T_BIN,
                &rt_cps_key.af, sizeof(rt_cps_key.af));
    }

    if (rt_cps_key.rt_type_valid) {
        cps_api_set_key_data(obj, L3_MCAST_ROUTES_ROUTE_RT_TYPE, cps_api_object_ATTR_T_BIN,
                             &rt_cps_key.rt_type, sizeof(rt_cps_key.rt_type));
    }

    if (rt_cps_key.src_ip_valid) {
        uint32_t len = 0;
        if (rt_cps_key.src_ip.af_index == HAL_INET4_FAMILY) {
            len = sizeof(rt_cps_key.src_ip.u.v4_addr);
        } else if (rt_cps_key.src_ip.af_index == HAL_INET6_FAMILY) {
            len = sizeof(rt_cps_key.src_ip.u.v6_addr);
        }
        if (len != 0) {
            cps_api_set_key_data(obj, L3_MCAST_ROUTES_ROUTE_SOURCE_IP, cps_api_object_ATTR_T_BIN,
                    &rt_cps_key.src_ip.u.v4_addr, len);
        }
    }

    if (rt_cps_key.grp_ip_valid) {
        uint32_t len = 0;
        if (rt_cps_key.grp_ip.af_index == HAL_INET4_FAMILY) {
            len = sizeof(rt_cps_key.grp_ip.u.v4_addr);
        } else if (rt_cps_key.grp_ip.af_index == HAL_INET6_FAMILY) {
            len = sizeof(rt_cps_key.grp_ip.u.v6_addr);
        }
        if (len != 0) {
            cps_api_set_key_data(obj, L3_MCAST_ROUTES_ROUTE_GROUP_IP, cps_api_object_ATTR_T_BIN,
                    &rt_cps_key.grp_ip.u.v4_addr, len);
        }
    }

    return;

}

static cps_api_object_t _l3_mcast_routes_obj_add (cps_api_qualifier_t qual, l3_mcast_route_cps_key_t &rt_key,
                                           mc_route_t *rt)
{
    uint32_t status = 0;
    uint32_t cp_to_cpu = 0;

    cps_api_object_t obj = cps_api_object_create();
    if (obj != NULL) {
        _routes_mcast_key_set(obj, qual, rt_key);
        cp_to_cpu = (uint32_t) rt->copy_to_cpu;
        cps_api_object_attr_add_u32(obj, L3_MCAST_ROUTES_ROUTE_DATA_TO_CPU, cp_to_cpu);
        intf_id_cache_key_t if_key;
        if_key.if_index = rt->iif_id;
        if_key.vrf_id = rt->vrf_id;
        if_str_t intf_info;
        if (mcast_intf_cache_get(if_key, intf_info) != false) {
            cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_IIF_NAME, intf_info.if_name.c_str(),
                    intf_info.if_name.length() + 1);
        }
        if (rt->oif_list.empty() == false) {
            auto it = rt->oif_list.begin();
            for (cps_api_attr_id_t index = 0; it != rt->oif_list.end(); ++it) {
                cps_api_attr_id_t oif_ids[3] = {L3_MCAST_ROUTES_ROUTE_OIF, index, L3_MCAST_ROUTES_ROUTE_OIF_NAME};
                if_key.if_index = it->second.oif_id;
                if_key.vrf_id = rt->vrf_id;
                if (mcast_intf_cache_get(if_key, intf_info) != false) {
                    if (cps_api_object_e_add(obj, oif_ids, sizeof(oif_ids)/sizeof(oif_ids[0]), cps_api_object_ATTR_T_BIN,
                                intf_info.if_name.c_str(), intf_info.if_name.length() + 1)) {
                        ++index;

                        if (it->second.has_exclude_if) {
                            interface_ctrl_t intf_ctrl;
                            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
                            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
                            intf_ctrl.if_index = it->second.exclude_if_id;
                            if (dn_hal_get_interface_info(&intf_ctrl) == STD_ERR_OK) {
                                oif_ids[2] = L3_MCAST_ROUTES_ROUTE_OIF_EXCLUDE_INTERFACE;
                                if (!cps_api_object_e_add(obj, oif_ids, sizeof(oif_ids)/sizeof(oif_ids[0]), cps_api_object_ATTR_T_BIN,
                                            intf_ctrl.if_name, strlen(intf_ctrl.if_name)  + 1)) {
                                    NAS_MC_L3_LOG_ERR("CPS", "Failed adding OIF exclude interface (%s)", intf_info.if_name.c_str());
                                }
                            } else {
                                NAS_MC_L3_LOG_ERR("CPS", "Failed to find OIF exclude interface in cache (%u - %u)",
                                        if_key.if_index, if_key.vrf_id);
                            }
                        }
                    } else {
                        NAS_MC_L3_LOG_ERR("CPS", "Failed adding OIF interface (%s)", intf_info.if_name.c_str());
                    }
                } else {
                    NAS_MC_L3_LOG_ERR("CPS", "Failed to find OIF interface in cache (%u - %u)",
                            if_key.if_index, if_key.vrf_id);
                }
            }
        }
        status = rt->npu_prg_status;
        cps_api_object_attr_add_u32(obj, L3_MCAST_ROUTES_ROUTE_NPU_PRG_DONE, status);
    }
    return obj;
}

cps_api_return_code_t _l3_mcast_routes_get (cps_api_get_params_t *param, cps_api_object_t req_obj)
{
    cps_api_return_code_t ret = cps_api_ret_code_OK;
    l3_mcast_route_cps_key_t   rt_cps_key;
    cps_api_qualifier_t        qual;
    hal_vrf_id_t               vrf_id = 0;

    memset(&rt_cps_key, 0, sizeof(rt_cps_key));
    _routes_mcast_key_get(req_obj, qual, rt_cps_key);

    if (rt_cps_key.vrf_name_valid) {
        if (nas_get_vrf_internal_id_from_vrf_name(rt_cps_key.vrf_name.c_str(), &vrf_id) != STD_ERR_OK) {
            NAS_MC_L3_LOG_ERR("CPS", "Not able to get the vrf_id(%s)",
                    rt_cps_key.vrf_name.c_str());
            return cps_api_ret_code_ERR;
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
            l3_mcast_route_cps_key_t rt_key;
            vrf_str_t  vrf_info;
            memset(&vrf_info, 0, sizeof(vrf_info));
            if (mcast_vrf_cache_get(rt->vrf_id, vrf_info) == false) {
                NAS_MC_L3_LOG_ERR("CPS", "VRF cache lookup failed for vrfid(%u)", rt->vrf_id);
                continue;
            }
            rt_key.vrf_name.assign(vrf_info.vrf_name);
            rt_key.vrf_name_valid = true;
            rt_key.af = (BASE_CMN_AF_TYPE_t) rt->af;
            rt_key.af_valid = true;
            memcpy(&rt_key.src_ip, &rt->src_ip, sizeof(rt_key.src_ip));
            rt_key.src_ip_valid = true;
            memcpy(&rt_key.grp_ip, &rt->grp_ip, sizeof(rt_key.grp_ip));
            rt_key.grp_ip_valid = true;
            rt_key.rt_type = (L3_MCAST_ROUTE_TYPE_t) rt->rtype;
            rt_key.rt_type_valid = true;

            cps_api_object_t tmp = NULL;
            if ((tmp = _l3_mcast_routes_obj_add(qual, rt_key, rt)) != NULL) {
                cps_api_object_list_append(param->list, tmp);
            } else {
                NAS_MC_L3_LOG_ERR("CPS", "Route info add failed: vrf(%s %u) af(%u) rt_type(%u)",
                       rt_key.vrf_name.c_str(), rt->vrf_id, rt_key.af, rt_key.rt_type);
            }
        }
    }
    return ret;
}

cps_api_return_code_t l3_mcast_read_function (void * context, cps_api_get_params_t * param, size_t key_ix)
{
    if (param == nullptr) {
        NAS_MC_L3_LOG_ERR("CPS", "Null Param in l3_mcast_read_function");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_t req_obj = cps_api_object_list_get(param->filters, key_ix);
    if (req_obj == nullptr) {
        NAS_MC_L3_LOG_ERR("CPS", "L3 Mcast read function, object is not present at index %lu", key_ix);
        return cps_api_ret_code_ERR;
    }

    cps_api_return_code_t ret = cps_api_ret_code_OK;

    uint32_t sub_cat = cps_api_key_get_subcat(cps_api_object_key(req_obj));
    switch(sub_cat) {
        case L3_MCAST_GLOBAL_OBJ:
        {
            ret = _global_mcast_status_get(param, req_obj);
            break;
        }
        case L3_MCAST_INTERFACES_OBJ:
        {
            ret = _intf_pim_status_get(param, req_obj);
            break;
        }
        case L3_MCAST_ROUTES_OBJ:
        {
            ret = _l3_mcast_routes_get(param, req_obj);
            break;
        }
        case L3_MCAST_ROUTES_STATE_OBJ:
        {
            ret = _l3_mcast_routes_state_get(param, req_obj);
            break;
        }
        default:
        {
            ret = cps_api_ret_code_ERR;
            break;
        }
    }

    return ret;
}

static cps_api_return_code_t mcast_l3_handle_reg(void) {

    if (cps_api_operation_subsystem_init(&mcast_cps_handle, MCAST_CPS_API_THREAD) != cps_api_ret_code_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "CPS subsystem Init Failure for L3 multicast");
        return cps_api_ret_code_ERR;
    }

    cps_api_registration_functions_t f;
    memset(&f,0,sizeof(f));

    f.handle = mcast_cps_handle;
    f._write_function = l3_mcast_write_function;


    /* Register for l3_mcast global object */
    if (!cps_api_key_from_attr_with_qual(&f.key, L3_MCAST_GLOBAL_OBJ,
                                         cps_api_qualifier_TARGET)) {
        NAS_MC_L3_LOG_ERR("CPS", "Failed to get object key for l3 mcast global object");
        return cps_api_ret_code_ERR;
    }

    if( cps_api_register(&f) != cps_api_ret_code_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "CPS Object ownership Failure for L3 multicast Global object");
        return cps_api_ret_code_ERR;
    }

    /* Register for l3-mcast/interfaces/interface object */
    if (!cps_api_key_from_attr_with_qual(&f.key, L3_MCAST_INTERFACES_INTERFACE,
                                         cps_api_qualifier_TARGET)) {
        NAS_MC_L3_LOG_ERR("CPS", "Failed to get object key for l3 mcast Interface list object");
        return cps_api_ret_code_ERR;
    }

    if( cps_api_register(&f) != cps_api_ret_code_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "CPS Object ownership Failure for L3 multicast Interface list object");
        return cps_api_ret_code_ERR;
    }

    /* Register for l3-mcast/routes/route config object */
    if (!cps_api_key_from_attr_with_qual(&f.key, L3_MCAST_ROUTES_ROUTE,
                                         cps_api_qualifier_TARGET)) {
        NAS_MC_L3_LOG_ERR("CPS", "Failed to get object key for l3 mcast route config object");
        return cps_api_ret_code_ERR;
    }

    if( cps_api_register(&f) != cps_api_ret_code_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "CPS Object ownership Failure for L3 multicast Route config object");
        return cps_api_ret_code_ERR;
    }

    memset(&f,0,sizeof(f));
    f.handle = mcast_cps_handle;
    f._write_function = l3_mcast_blk_write_function;

    if (!cps_api_key_from_attr_with_qual(&f.key, L3_MCAST_INTERFACES, cps_api_qualifier_TARGET)) {
        NAS_MC_L3_LOG_ERR("CPS", "Failed to get object key for l3 mcast Interfaces list object");
        return cps_api_ret_code_ERR;
    }
    if( cps_api_register(&f) != cps_api_ret_code_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "CPS Object ownership Failure for L3 multicast Interfaces list object");
        return cps_api_ret_code_ERR;
    }

    /* Register for l3-mcast/routes config object */
    if (!cps_api_key_from_attr_with_qual(&f.key, L3_MCAST_ROUTES,
                                         cps_api_qualifier_TARGET)) {
        NAS_MC_L3_LOG_ERR("CPS", "Failed to get object key for l3 mcast routes config object");
        return cps_api_ret_code_ERR;
    }

    if( cps_api_register(&f) != cps_api_ret_code_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "CPS Object ownership Failure for L3 multicast Routes config object");
        return cps_api_ret_code_ERR;
    }

    memset(&f,0,sizeof(f));
    f.handle = mcast_cps_handle;
    f._read_function = l3_mcast_read_function;

    /*
     * Register for observed l3_mcast objects
     */

    /* Register for l3_mcast global object */
    if (!cps_api_key_from_attr_with_qual(&f.key, L3_MCAST_GLOBAL_OBJ, cps_api_qualifier_OBSERVED)) {
        NAS_MC_L3_LOG_ERR("CPS", "Failed to get object key for Global object observed qualifier");
        return cps_api_ret_code_ERR;
    }
    if( cps_api_register(&f) != cps_api_ret_code_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "CPS Object ownership Failure for observed Global object");
        return cps_api_ret_code_ERR;
    }

    /* Register for l3_mcast interface object */
    if (!cps_api_key_from_attr_with_qual(&f.key, L3_MCAST_INTERFACES_INTERFACE, cps_api_qualifier_OBSERVED)) {
        NAS_MC_L3_LOG_ERR("CPS", "Failed to get object key for Interface object observed qualifier");
        return cps_api_ret_code_ERR;
    }
    if( cps_api_register(&f) != cps_api_ret_code_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "CPS Object ownership Failure for observed Interface object");
        return cps_api_ret_code_ERR;
    }

    /* Register for l3_mcast routes object */
    if (!cps_api_key_from_attr_with_qual(&f.key, L3_MCAST_ROUTES_ROUTE, cps_api_qualifier_OBSERVED)) {
        NAS_MC_L3_LOG_ERR("CPS", "Failed to get object key for Global object observed qualifier");
        return cps_api_ret_code_ERR;
    }
    if( cps_api_register(&f) != cps_api_ret_code_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "CPS Object ownership Failure for observed Global object");
        return cps_api_ret_code_ERR;
    }

    /* Register for l3_mcast routes state object */
    if (!cps_api_key_from_attr_with_qual(&f.key, L3_MCAST_ROUTES_STATE_ROUTE, cps_api_qualifier_OBSERVED)) {
        NAS_MC_L3_LOG_ERR("CPS", "Failed to get object key for Global object observed qualifier");
        return cps_api_ret_code_ERR;
    }
    if( cps_api_register(&f) != cps_api_ret_code_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "CPS Object ownership Failure for observed Global object");
        return cps_api_ret_code_ERR;
    }

    return cps_api_ret_code_OK;

}

static bool mcast_vlan_member_event_handler(cps_api_object_t obj, void *param)
{
    bool v4_pim_status = false;
    bool v6_pim_status = false;
    cps_api_object_it_t it;
    hal_ifindex_t port_vlan_index = 0;
    hal_ifindex_t port_index = 0;
    const char *name =  NULL;
    interface_ctrl_t intf_ctrl;
    cps_api_object_attr_t ifidx_attr = cps_api_get_key_data(obj,
            DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
    cps_api_object_attr_t ifn_attr = cps_api_object_attr_get(obj, IF_INTERFACES_INTERFACE_NAME);
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    if (op == cps_api_oper_SET) {
        NAS_MC_L3_LOG_ERR("CPS", "VLAN member set operation not supported.");
        return true;
    }
    if ((ifidx_attr == NULL) && (ifn_attr == NULL)) {
        NAS_MC_L3_LOG_ERR("CPS", "Interface name and ifindex not present.");
        return true;
    }

    if (ifidx_attr !=  NULL) {
        port_vlan_index = (uint32_t)cps_api_object_attr_data_u32(ifidx_attr);
        intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
        intf_ctrl.if_index = port_vlan_index;
        intf_ctrl.vrf_id = NAS_DEFAULT_VRF_ID;
    } else if (ifn_attr != NULL) {
        name = (const char*)cps_api_object_attr_data_bin(ifn_attr);
        safestrncpy(intf_ctrl.if_name, name, sizeof(intf_ctrl.if_name));
        intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
    }

    bool add_ports = (op == cps_api_oper_DELETE) ? false : true;

    if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "Vlan interface info not found in NAS common db (ifindex: %u)",
                intf_ctrl.if_index);
        return true;
    }
    if (ifidx_attr == NULL) {
        port_vlan_index = intf_ctrl.if_index;
    }
    std::string st_name = std::string(intf_ctrl.if_name);

    // For VLAN member port change event, accessing VLAN member list map &
    // interface cache is done w/o locking nas_mc_l3_lock().
    // For this specific case, this is fine as we don't have to wait
    // until all pending messages in the msgQ is processed, as VLAN member port
    // information is needed only when PIM is enabled on this VLAN.

    cps_api_object_it_begin(obj,&it);
    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {
        cps_api_attr_id_t attr_id = cps_api_object_attr_id(it.attr);
        switch(attr_id) {
            case DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS:
            case DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS:
                vlan_member_type_t mtype;
                mtype  = (attr_id == DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS)
                                           ? tagged : untagged;
                port_index = (hal_ifindex_t) cps_api_object_attr_data_u32(it.attr);
                mcast_intf_mlist_map_update(st_name, mtype, port_index, add_ports);

                break;
            default:
                break;
        }
    }

    /* if it's a PIM enabled VLAN interface,
     * then send an event to process route updates.
     */
    mcast_get_pim_status (intf_ctrl.vrf_id, port_vlan_index,
            &v4_pim_status, &v6_pim_status);

    if (!v4_pim_status && !v6_pim_status) {
        /* If PIM is disabled, then check for possibility of
         * L3 interface in non-default VRF for this VLAN interface.
         * If one exists, then trigger route update for that VRF interface.
         */
        do {
            hal_vrf_id_t parent_vrf_id = intf_ctrl.l3_intf_info.vrf_id;
            hal_ifindex_t parent_if_index = intf_ctrl.l3_intf_info.if_index;

            if (parent_if_index == 0) {
                NAS_MC_L3_LOG_DEBUG("CPS",
                        "No VRF configured for VLAN(%s) skipping VRF handling "
                        "in VLAN member update event", st_name.c_str());
                break;
            }

            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
            intf_ctrl.vrf_id = parent_vrf_id;
            intf_ctrl.if_index = parent_if_index;

            if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR("CPS", "VLAN member update event "
                        "failed to find VRF interface info "
                        "for VLAN(%s), VRF(%d), if_index(%d)",
                        st_name.c_str(), parent_vrf_id, parent_if_index);
                break;
            }
            if(intf_ctrl.int_type != nas_int_type_MACVLAN) {
                NAS_MC_L3_LOG_DEBUG("CPS", "Not a MAC-VLAN interface, skipping VRF handling"
                        "in VLAN member update event for VLAN(%s), VRF(%d), if_index(%d)",
                        st_name.c_str(), parent_vrf_id, parent_if_index);
                break;
            }

            st_name.assign(intf_ctrl.if_name);

            v4_pim_status = false;
            v6_pim_status = false;

            mcast_get_pim_status (st_name,
                    &v4_pim_status, &v6_pim_status);

        } while (0);
    }

    if (v4_pim_status || v6_pim_status) {
        t_mcast_msg_uptr pmsg_uptr = mcast_alloc_mem_msg(INTERFACE_CONFIG);
        intf_event_t *pmsg = dynamic_cast<intf_event_t*>(pmsg_uptr.get());

        if (pmsg == NULL) {
            NAS_MC_L3_LOG_ERR("CPS", "MSG allocation failed for Type:%d, event_mask:0x%x",
                    INTERFACE_CONFIG, EVT_VLAN_MBR_CHANGE);
        } else {
            pmsg->intf_name.assign((const char *)st_name.c_str());
            pmsg->is_sync_msg = false;
            pmsg->event_mask.set(EVT_VLAN_MBR_CHANGE);

            nas_mcast_process_msg(pmsg_uptr.release());
        }
    }
    return true;
}

// interested only in mode change from L3 to L2,
// other events are skipped for now; caller should ensure
// this is called only in that scenario and there are no
// duplicate mode change events.
static cps_api_return_code_t mcast_interface_mode_change_to_L2 (const char *if_name)
{
    bool is_l3_intf_type = false;
    interface_ctrl_t intf_ctrl;

    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    safestrncpy(intf_ctrl.if_name, if_name, sizeof(intf_ctrl.if_name));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;

    if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "Mode change handler, interface info "
                          "not found in NAS common db (ifname: %s)",
                          if_name);
        return cps_api_ret_code_ERR;
    }

    switch (intf_ctrl.int_type)
    {
        case nas_int_type_PORT: //intentional fall through
        case nas_int_type_LAG:
        case nas_int_type_VLAN:
        case nas_int_type_MACVLAN:
            is_l3_intf_type = true;
            break;
        default:
            break;
    }

    // interested only in mode change events for L3 interfaces whose
    // mode could change to L2 mode.
    if (!is_l3_intf_type)
    {
        NAS_MC_L3_LOG_DEBUG ("CPS", "Ignoring interface mode change to l2 "
                             "for interface:%s", if_name);
        return cps_api_ret_code_OK;
    }

    // On mode change to L2, wait for all pending messages in msgQ
    // before disabling PIM on that interface. If not then any pending
    // PIM enable could end up processed out of order, leaving stale state.
    // So enqueue event to msgQ for it to be processed after all pending msgs.

    NAS_MC_L3_LOG_INFO ("CPS", "Processing Event Type:%d, event_mask:0x%x",
            INTERFACE_CONFIG, EVT_INTF_MODE_CHANGE_TO_L2);

    t_mcast_msg_uptr pmsg_uptr = mcast_alloc_mem_msg(INTERFACE_CONFIG);
    intf_event_t *pmsg = dynamic_cast<intf_event_t*>(pmsg_uptr.get());

    if (pmsg == NULL) {
        NAS_MC_L3_LOG_ERR("CPS", "MSG allocation failed for Type:%d, event_mask:0x%x",
                INTERFACE_CONFIG, EVT_INTF_MODE_CHANGE_TO_L2);
    } else {
        // for interface mode change events set the sync_msg flag to true for it to process in msg thread.
        pmsg->intf_name.assign(if_name);
        pmsg->is_sync_msg = true;
        pmsg->event_mask.set(EVT_INTF_MODE_CHANGE_TO_L2);

        nas_mcast_process_msg(pmsg_uptr.release());
    }

    return cps_api_ret_code_OK;
}


// interested only in mode change from L2 to L3,
// other events are skipped for now; caller should ensure
// this is called only in that scenario and there are no
// duplicate mode change events.
static cps_api_return_code_t mcast_interface_mode_change_to_L3 (const char *if_name)
{
    bool v4_pim_status = false;
    bool v6_pim_status = false;
    bool is_vlan_mbr_type = false;
    interface_ctrl_t intf_ctrl;

    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    safestrncpy(intf_ctrl.if_name, if_name, sizeof(intf_ctrl.if_name));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;

    if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "Mode change handler, interface info "
                          "not found in NAS common db (ifname: %s)",
                          if_name);
        return cps_api_ret_code_ERR;
    }

    switch (intf_ctrl.int_type)
    {
        case nas_int_type_PORT: //intentional fall through
        case nas_int_type_LAG:
            is_vlan_mbr_type = true;
            break;
        default:
            break;
    }

    // interested only in mode change events for VLAN member ports
    // other events are skipped for now.
    if (!is_vlan_mbr_type)
    {
        NAS_MC_L3_LOG_DEBUG ("CPS", "Ignoring interface mode change to l2 "
                             "for interface:%s", if_name);
        return cps_api_ret_code_OK;
    }

    std::list<std::string> vlan_if_name_list;

    // For interface mode change event from L2 to L3, accessing VLAN member list map &
    // interface cache can be done w/o locking nas_mc_l3_lock().
    // For this specific case, this is fine as we don't have to wait
    // until all pending messages in the msgQ is processed, as VLAN member port
    // information is used during route event processing only when PIM is enabled on this VLAN.

    mcast_vlan_member_port_delete (intf_ctrl.if_index, vlan_if_name_list);

    NAS_MC_L3_LOG_INFO("CPS", "Processing Intf:%s, Event Type:%d, event_mask:0x%x sync_msg",
            if_name, INTERFACE_CONFIG, EVT_VLAN_MBR_CHANGE);

    for (auto vlan_it = vlan_if_name_list.begin();
         vlan_it != vlan_if_name_list.end(); ++vlan_it)
    {
        std::string vlan_if_name{*vlan_it};

        NAS_MC_L3_LOG_DEBUG ("CPS",
                "Mode change for VLAN:%s member port:%s",
                vlan_if_name.c_str(), if_name);

        v4_pim_status = false;
        v6_pim_status = false;

        mcast_get_pim_status (vlan_if_name,
                &v4_pim_status, &v6_pim_status);

        if (!v4_pim_status && !v6_pim_status) {
            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

            safestrncpy(intf_ctrl.if_name, vlan_if_name.c_str(), sizeof(intf_ctrl.if_name));
            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;

            if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR("CPS", "Mode change handler failed to find interface info "
                        "for VLAN(%s)", vlan_if_name.c_str());
                continue;
            }
            hal_vrf_id_t parent_vrf_id = intf_ctrl.l3_intf_info.vrf_id;
            hal_ifindex_t parent_if_index = intf_ctrl.l3_intf_info.if_index;

            if (parent_if_index == 0) {
                NAS_MC_L3_LOG_DEBUG("CPS",
                        "No VRF configured for VLAN(%s), skipping VRF handling",
                        vlan_if_name.c_str());
                continue;
            }
            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
            intf_ctrl.vrf_id = parent_vrf_id;
            intf_ctrl.if_index = parent_if_index;

            if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR("CPS", "Mode change handler failed to find VRF interface info "
                        "for VLAN(%s), VRF(%d), if_index(%d)",
                        vlan_if_name.c_str(), parent_vrf_id, parent_if_index);
                continue;
            }

            if(intf_ctrl.int_type != nas_int_type_MACVLAN) {
                NAS_MC_L3_LOG_DEBUG("CPS", "Not a MAC-VLAN interface, skipping VRF handling"
                        "for VLAN(%s), VRF(%d), if_index(%d)",
                        vlan_if_name.c_str(), parent_vrf_id, parent_if_index);
                continue;
            }

            vlan_if_name.assign(intf_ctrl.if_name);

            v4_pim_status = false;
            v6_pim_status = false;

            mcast_get_pim_status (vlan_if_name,
                    &v4_pim_status, &v6_pim_status);

            if (!v4_pim_status && !v6_pim_status) {
                NAS_MC_L3_LOG_DEBUG("CPS", "PIM not enabled on interface, skipping VRF handling"
                        "for VRF(%d), ifname(%s)",
                        parent_vrf_id, vlan_if_name.c_str());
                continue;
            }
        }

        /* only if it's a PIM enabled VLAN interface,
         * then process route updates for
         * VLAN member port mode change synchronously.
         */
        t_mcast_msg_uptr pmsg_uptr = mcast_alloc_mem_msg(INTERFACE_CONFIG);
        intf_event_t *pmsg = dynamic_cast<intf_event_t*>(pmsg_uptr.get());

        if (pmsg == NULL) {
            NAS_MC_L3_LOG_ERR("CPS", "MSG allocation failed for Type:%d, event_mask:0x%x, sync_msg",
                    INTERFACE_CONFIG, EVT_VLAN_MBR_CHANGE);
        } else {
            // for interface mode change events set the sync_msg flag to true for it to process in msg thread.
            pmsg->intf_name.assign(vlan_if_name);
            pmsg->is_sync_msg = true;
            //for interface mode change from l2 to l3, it is same as VLAN member update,
            //but route update has to be processed synchronously in msg thread.
            pmsg->event_mask.set(EVT_VLAN_MBR_CHANGE);

            nas_mcast_process_msg(pmsg_uptr.release());
        }
    }

    return cps_api_ret_code_OK;
}


static cps_api_return_code_t _mcast_interface_mode_change_handler (const char *if_name, uint32_t mode)
{
    cps_api_return_code_t rc = cps_api_ret_code_ERR;

    switch (mode)
    {
        case BASE_IF_MODE_MODE_NONE: //intentional fall through
        case BASE_IF_MODE_MODE_L3:

            NAS_MC_L3_LOG_INFO ("CPS", "interface mode change to l3 "
                    "for interface:%s", if_name);
            rc = mcast_interface_mode_change_to_L3(if_name);
            break;
        case BASE_IF_MODE_MODE_L2: //intentional fall through
        case BASE_IF_MODE_MODE_L2HYBRID:

            NAS_MC_L3_LOG_INFO ("CPS", "interface mode change to l2 "
                    "for interface:%s", if_name);
            rc = mcast_interface_mode_change_to_L2(if_name);
            break;
        default:
            NAS_MC_L3_LOG_INFO ("CPS", "Invalid interface mode change "
                    "for interface:%s", if_name);
            rc = cps_api_ret_code_OK;
            break;
    }

    if (rc == cps_api_ret_code_OK)
    {
        t_mcast_msg_uptr p_syncmsg_uptr = mcast_alloc_mem_msg(SYNC_MSG_NOTIF);
        sync_msg_notif_t *p_syncmsg = dynamic_cast<sync_msg_notif_t*>(p_syncmsg_uptr.get());

        // for interface mode change events send the sync flag and wait for the backend processing to finish.
        if (p_syncmsg != NULL) {
            NAS_MC_L3_LOG_INFO ("CPS", "Waiting on Sync message notification....");
            if (nas_mcast_process_msg(p_syncmsg_uptr.release()))
                nas_mcast_wait_for_msg_processing ();
        } else {
            NAS_MC_L3_LOG_ERR("CPS", "MSG allocation failed for Type:%d", SYNC_MSG_NOTIF);
        }
    }

    return rc;
}


// Interested only in interface delete RPC triggers. This would cleanup all related configurations,
// if port is L2 port, then trigger synchronous VLAN interface event
// (for all VLANs this port is member of) to update all routes this VLAN is IIF/OIF.
static cps_api_return_code_t _mcast_interface_delete (const char *if_name, uint32_t intf_mode)
{
    cps_api_return_code_t rc = cps_api_ret_code_ERR;
    switch (intf_mode)
    {
        case BASE_IF_MODE_MODE_NONE: //intentional fall through
        case BASE_IF_MODE_MODE_L3:

            NAS_MC_L3_LOG_INFO ("CPS", "L3 interface delete for "
                    "ifname:%s", if_name);
            rc = mcast_interface_mode_change_to_L2(if_name);
            break;
        case BASE_IF_MODE_MODE_L2: //intentional fall through
        case BASE_IF_MODE_MODE_L2HYBRID:

            NAS_MC_L3_LOG_INFO ("CPS", "L2 interface delete for "
                    "ifname:%s", if_name);
            rc = mcast_interface_mode_change_to_L3(if_name);
            break;
        default:
            NAS_MC_L3_LOG_INFO ("CPS", "Invalid mode for interface delete, "
                    "ifname:%s", if_name);
            rc = cps_api_ret_code_OK;
            break;
    }

    //send event to delete the interface from cache
    t_mcast_msg_uptr pmsg_uptr = mcast_alloc_mem_msg(INTERFACE_CONFIG);
    intf_event_t *pmsg = dynamic_cast<intf_event_t*>(pmsg_uptr.get());

    if (pmsg == NULL) {
        NAS_MC_L3_LOG_ERR("CPS", "MSG allocation failed for Type:%d, event_mask:0x%x",
                INTERFACE_CONFIG, EVT_INTF_DELETE);
    } else {
        pmsg->intf_name.assign(if_name);
        pmsg->event_mask.set(EVT_INTF_DELETE);

        nas_mcast_process_msg(pmsg_uptr.release());
    }

    if (rc == cps_api_ret_code_OK)
    {
        t_mcast_msg_uptr p_syncmsg_uptr = mcast_alloc_mem_msg(SYNC_MSG_NOTIF);
        sync_msg_notif_t *p_syncmsg = dynamic_cast<sync_msg_notif_t*>(p_syncmsg_uptr.get());

        // for interface mode change events send the sync flag and wait for the backend processing to finish.
        if (p_syncmsg != NULL) {
            NAS_MC_L3_LOG_INFO ("CPS", "Waiting on Sync message notification....");
            if (nas_mcast_process_msg(p_syncmsg_uptr.release()))
                nas_mcast_wait_for_msg_processing ();
        } else {
            NAS_MC_L3_LOG_ERR("CPS", "MSG allocation failed for Type:%d", SYNC_MSG_NOTIF);
        }
    }

    return rc;
}


// Interested only in VRF delete RPC triggers. This would cleanup all related VRF configurations,
// - disables multicast on that VRF
// - disables PIM on all interfaces in that VRF
// - delete all routes in that VRF
static cps_api_return_code_t _mcast_vrf_delete (const char *vrf_name)
{
    global_mcast_status_t *p_status_msg;
    t_mcast_msg_uptr p_status_msg_uptr = mcast_alloc_mem_msg(MCAST_STATUS);
    p_status_msg = dynamic_cast<global_mcast_status_t*>(p_status_msg_uptr.get());
    if (p_status_msg == NULL) {
        NAS_MC_L3_LOG_ERR("CPS", "Failed in VRF(%s) delete RPC, "
                "MSG allocation failure for MCAST disable.", vrf_name);
        return cps_api_ret_code_ERR;
    }

    p_status_msg->vrf_name.assign(vrf_name);
    p_status_msg->af = AF_INET;
    p_status_msg->mcast_status = false;
    p_status_msg->op = rt_op::DELETE;
    nas_mcast_process_msg(p_status_msg_uptr.release());

    t_mcast_msg_uptr msg_uptr = mcast_alloc_mem_msg(MCAST_STATUS);
    p_status_msg = dynamic_cast<global_mcast_status_t*>(msg_uptr.get());
    if (p_status_msg == NULL) {
        NAS_MC_L3_LOG_ERR("CPS", "Failed in VRF(%s) delete RPC, "
                "MSG allocation failure for MCAST disable.", vrf_name);
        return cps_api_ret_code_ERR;
    }

    p_status_msg->vrf_name.assign(vrf_name);
    p_status_msg->af = AF_INET6;
    p_status_msg->mcast_status = false;
    p_status_msg->op = rt_op::DELETE;
    nas_mcast_process_msg(msg_uptr.release());

    t_mcast_msg_uptr p_syncmsg_uptr = mcast_alloc_mem_msg(SYNC_MSG_NOTIF);
    sync_msg_notif_t *p_syncmsg = dynamic_cast<sync_msg_notif_t*>(p_syncmsg_uptr.get());

    // for interface mode change events send the sync flag and wait for the backend processing to finish.
    if (p_syncmsg == NULL) {
        NAS_MC_L3_LOG_ERR("CPS", "Failed in VRF(%s) delete RPC, "
                "MSG allocation failure for SYNC_MSG_NOTIF.", vrf_name);
        return cps_api_ret_code_ERR;
    }
    NAS_MC_L3_LOG_INFO ("CPS", "Waiting on Sync message notification....");
    if (nas_mcast_process_msg(p_syncmsg_uptr.release()))
        nas_mcast_wait_for_msg_processing ();

    return cps_api_ret_code_OK;
}

static t_std_error mcast_event_handle_reg (void)
{
    cps_api_event_reg_t reg;
    const uint_t MEM_NUM_KEYS = 2;
    cps_api_key_t mkeys[MEM_NUM_KEYS];

    memset(&reg, 0, sizeof(reg));
    cps_api_key_from_attr_with_qual(&mkeys[0], DELL_IF_IF_INTERFACES_INTERFACE_UNTAGGED_PORTS,
            cps_api_qualifier_OBSERVED);
    cps_api_key_from_attr_with_qual(&mkeys[1], DELL_IF_IF_INTERFACES_INTERFACE_TAGGED_PORTS,
            cps_api_qualifier_OBSERVED);

    reg.number_of_objects = MEM_NUM_KEYS;
    reg.objects = mkeys;

    if (cps_api_event_thread_reg(&reg, mcast_vlan_member_event_handler, NULL) != cps_api_ret_code_OK) {
        NAS_MC_L3_LOG_ERR("CPS",
                "Failed to register for vlan memeber event handling thread");
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    return STD_ERR_OK;
}

static cps_api_return_code_t mcast_l3_cps_clear_routes (void *context, cps_api_transaction_params_t *param,
                                  size_t ix)
{
    cps_api_return_code_t rc = cps_api_ret_code_OK;

    NAS_MC_L3_LOG_INFO("CPS", "mcast_l3_cps_clear_routes Called.");

    cps_api_object_t obj = cps_api_object_list_get(param->change_list, ix);
    if (obj == CPS_API_OBJECT_NULL) {
        return cps_api_ret_code_PARAM_INVALID;
    }
    cps_api_object_attr_t attr_vrf_name = cps_api_object_attr_get(obj,
            L3_MCAST_CLEAR_L3_MCAST_ROUTES_INPUT_VRF_NAME);
    cps_api_object_attr_t attr_af = cps_api_object_attr_get(obj,
            L3_MCAST_CLEAR_L3_MCAST_ROUTES_INPUT_AF);

    if ((attr_vrf_name == NULL) || (attr_af == NULL)) {
        NAS_MC_L3_LOG_ERR("CPS", "Invalid param, vrf name and AF not specified.");
        return cps_api_ret_code_PARAM_INVALID;
    }

    cps_api_object_attr_t attr_grp_ip = cps_api_object_attr_get(obj,
            L3_MCAST_CLEAR_L3_MCAST_ROUTES_INPUT_GROUP_IP);
    cps_api_object_attr_t attr_src_ip = cps_api_object_attr_get(obj,
            L3_MCAST_CLEAR_L3_MCAST_ROUTES_INPUT_SOURCE_IP);

    if ((attr_src_ip != NULL) && (attr_grp_ip == NULL)) {
        NAS_MC_L3_LOG_ERR("CPS", "Invalid param, Group IP is mandateroy when source is specified.");
        return cps_api_ret_code_PARAM_INVALID;
    }

    t_mcast_msg_uptr pmsg_uptr = mcast_alloc_mem_msg(ROUTE_CONFIG);
    route_t *pmsg = dynamic_cast<route_t*>(pmsg_uptr.get());
    if (pmsg == NULL) {
        NAS_MC_L3_LOG_ERR("CPS-RT-CLR", "MSG allocation failed.");
        return cps_api_ret_code_ERR;
    }
    pmsg->type = ROUTE_CLEAR;
    pmsg->op = rt_op::RT_CLR;

    char vname[NAS_VRF_NAME_SZ] = {'\0'};
    size_t vname_len  = cps_api_object_attr_len(attr_vrf_name);
    if (vname_len > 0) {
        safestrncpy(vname, (const char *)cps_api_object_attr_data_bin(attr_vrf_name),
                sizeof(vname));
        if (vname_len < sizeof(vname)) vname[vname_len] = '\0';
        pmsg->vrf_name.assign(vname);
    }
    pmsg->af = (BASE_CMN_AF_TYPE_t)cps_api_object_attr_data_u32(attr_af);

    uint8_t len = 0;
    uint32_t af_index = 0;
    if (pmsg->af == BASE_CMN_AF_TYPE_INET) {
        len = sizeof(pmsg->group_addr.u.v4_addr);
        af_index = HAL_INET4_FAMILY;
    } else if (pmsg->af == BASE_CMN_AF_TYPE_INET6) {
        len = sizeof(pmsg->group_addr.u.v4_addr);
        af_index = HAL_INET6_FAMILY;
    } else {
         NAS_MC_L3_LOG_ERR("CPS", "Invalid Address family (%d)", pmsg->af);
         return cps_api_ret_code_PARAM_INVALID;
    }
    bool src_ip_valid, grp_ip_valid;
    src_ip_valid = grp_ip_valid = false;
    if ((src_ip_valid = (attr_src_ip != NULL))) {
        memcpy(&pmsg->source_addr.u.v4_addr, cps_api_object_attr_data_bin(attr_src_ip), len);
        pmsg->source_addr.af_index = af_index;
    }
    if ((grp_ip_valid = (attr_grp_ip != NULL))) {
        memcpy(&pmsg->group_addr.u.v4_addr, cps_api_object_attr_data_bin(attr_grp_ip), len);
        pmsg->group_addr.af_index = af_index;
    }

    if (grp_ip_valid && src_ip_valid)
        pmsg->op = rt_op::RT_CLR_SRC_GRP;
    else if (grp_ip_valid && !src_ip_valid)
        pmsg->op = rt_op::RT_CLR_GRP;

    if (!nas_mcast_process_msg(pmsg_uptr.release())) {
        NAS_MC_L3_LOG_ERR("CPS", "Failed to put message in queue");
        return cps_api_ret_code_ERR;
    }
    return rc;
}

static cps_api_return_code_t mcast_cps_process_cleanup_events (void *context,
                                cps_api_transaction_params_t *param,
                                size_t ix)
{
    cps_api_return_code_t rc = cps_api_ret_code_OK;

    cps_api_object_t obj = cps_api_object_list_get(param->change_list, ix);
    if (obj == CPS_API_OBJECT_NULL) {
        return cps_api_ret_code_PARAM_INVALID;
    }

    cps_api_object_attr_t vrf_name_attr = cps_api_object_attr_get(obj,
            BASE_CLEANUP_EVENTS_INPUT_VRF_NAME);
    cps_api_object_attr_t op_type_attr = cps_api_object_attr_get(obj,
            BASE_CLEANUP_EVENTS_INPUT_OP_TYPE);
    cps_api_object_attr_t if_name_attr = cps_api_object_attr_get(obj,
            BASE_CLEANUP_EVENTS_INPUT_IF_NAME);
    cps_api_object_attr_t if_mode_attr = cps_api_object_attr_get(obj,
            BASE_CLEANUP_EVENTS_INPUT_IF_MODE);

    if (op_type_attr == NULL) {
        NAS_MC_L3_LOG_ERR("CPS-ACTION", "Invalid param, operation type not present");
        return cps_api_ret_code_PARAM_INVALID;
    }
    if ((vrf_name_attr == NULL)&& (if_name_attr == NULL)
        && (if_mode_attr == NULL)) {
        NAS_MC_L3_LOG_ERR("CPS-ACTION", "No attribute present");
        return cps_api_ret_code_PARAM_INVALID;
    }

    uint32_t if_mode, op_type;
    const char *if_name, *vrf_name;
    op_type = cps_api_object_attr_data_u32(op_type_attr);

    NAS_MC_L3_LOG_INFO("CPS-ACTION", "mcast_l3_cps_process_cleanup_events, op:%d", op_type);

    switch (op_type) {
         case BASE_CLEANUP_EVENT_TYPE_VRF_DELETE:
            if ((vrf_name_attr == NULL)) {
                NAS_MC_L3_LOG_ERR("CPS-ACTION", "VRF attribute not present");
                return cps_api_ret_code_PARAM_INVALID;
            }
            vrf_name = (const char *)cps_api_object_attr_data_bin(vrf_name_attr);
            NAS_MC_L3_LOG_INFO("CPS-ACTION", "VRF %s deletion event", vrf_name);
            rc = _mcast_vrf_delete (vrf_name);
            break;
         case BASE_CLEANUP_EVENT_TYPE_INTERFACE_DELETE:
            if (if_name_attr == NULL) {
                NAS_MC_L3_LOG_ERR("CPS-ACTION", "Interface delete event, IfName attribute not present");
                return cps_api_ret_code_PARAM_INVALID;
            }
            if_mode = BASE_IF_MODE_MODE_NONE;
            if (if_mode_attr == NULL) {
                NAS_MC_L3_LOG_ERR("CPS-ACTION", "Interface delete event, mode attribute not present");
            } else {
                if_mode = cps_api_object_attr_data_u32(if_mode_attr);
            }

            if_name = (const char *)cps_api_object_attr_data_bin(if_name_attr);
            NAS_MC_L3_LOG_INFO("CPS-ACTION", "Interface %s deletion event", if_name);
            rc = _mcast_interface_delete (if_name, if_mode);

            break;
         case BASE_CLEANUP_EVENT_TYPE_INTERFACE_MODE_CHANGE:
            if (if_name_attr == NULL) {
                NAS_MC_L3_LOG_ERR("CPS-ACTION", "Interface mode change event, IfName attribute not present");
                return cps_api_ret_code_PARAM_INVALID;
            }
            if (if_mode_attr == NULL) {
                NAS_MC_L3_LOG_ERR("CPS-ACTION", "Interface mode change event, mode attribute not present");
                return cps_api_ret_code_PARAM_INVALID;
            }
            if_name = (const char *)cps_api_object_attr_data_bin(if_name_attr);
            if_mode = cps_api_object_attr_data_u32(if_mode_attr);
            NAS_MC_L3_LOG_INFO("CPS-ACTION", "Interface %s mode change event mode: %d", if_name, if_mode);

            if ((if_mode < BASE_IF_MODE_MIN) || (if_mode > BASE_IF_MODE_MAX)) {
                NAS_MC_L3_LOG_DEBUG("CPS-ACTION", "Interface mode change event unsupported mode: %d", if_mode);
                return cps_api_ret_code_PARAM_INVALID;
            }
            rc = _mcast_interface_mode_change_handler (if_name, if_mode);
            break;
         default:
            NAS_MC_L3_LOG_ERR("CPS-ACTION", "operation %d not supported", op_type);
            break;
    }
    return rc;
}


static bool pim_enabled_on_af(uint32_t af, bool v4_pim_status, bool v6_pim_status)
{
    return (af == AF_INET && v4_pim_status) || (af == AF_INET6 && v6_pim_status) ||
           (af == AF_MAX && (v4_pim_status || v6_pim_status));
}

//This API will be used by SNOOPING whenever snooping has to update l3 routes
//whenever snooping is enabled/disabled on a VLAN.
cps_api_return_code_t mcast_snoop_vlan_update_event_handler(const char *vlan_if_name, uint32_t af)
{
    bool v4_pim_status = false;
    bool v6_pim_status = false;
    std::string if_name;
    interface_ctrl_t intf_ctrl;

    if (vlan_if_name == NULL) {
        NAS_MC_L3_LOG_ERR("SNOOP_EVENT", "Invalid vlan interface name for Snoop VLAN update event");
        return cps_api_ret_code_PARAM_INVALID;
    }

    if_name.assign(vlan_if_name);

    mcast_get_pim_status (if_name,
            &v4_pim_status, &v6_pim_status);

    if (!pim_enabled_on_af(af, v4_pim_status, v6_pim_status)) {
        /* If PIM is disabled, then check for possibility of
         * L3 interface in non-default VRF for this VLAN interface.
         * If one exists, then trigger route update for that VRF interface.
         */
        do {
            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
            safestrncpy(intf_ctrl.if_name, vlan_if_name, sizeof(intf_ctrl.if_name));
            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;

            if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR("SNOOP_EVENT", "Snoop VLAN update event failed to find interface info "
                        "for VLAN(%s)", vlan_if_name);
                break;
            }
            hal_vrf_id_t parent_vrf_id = intf_ctrl.l3_intf_info.vrf_id;
            hal_ifindex_t parent_if_index = intf_ctrl.l3_intf_info.if_index;

            if (parent_if_index == 0) {
                NAS_MC_L3_LOG_DEBUG("SNOOP_EVENT",
                        "No VRF configured for VLAN(%s) skipping VRF handling "
                        "in Snoop VLAN update event", vlan_if_name);
                break;
            }

            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
            intf_ctrl.vrf_id = parent_vrf_id;
            intf_ctrl.if_index = parent_if_index;

            if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR("SNOOP_EVENT", "Snoop VLAN update event "
                        "failed to find VRF interface info "
                        "for VLAN(%s), VRF(%d), if_index(%d)",
                        vlan_if_name, parent_vrf_id, parent_if_index);
                break;
            }
            if(intf_ctrl.int_type != nas_int_type_MACVLAN) {
                NAS_MC_L3_LOG_DEBUG("SNOOP_EVENT", "Not a MAC-VLAN interface, skipping VRF handling"
                        "in Snoop VLAN update event for VLAN(%s), VRF(%d), if_index(%d)",
                        vlan_if_name, parent_vrf_id, parent_if_index);
                break;
            }

            if_name.assign(intf_ctrl.if_name);

            v4_pim_status = false;
            v6_pim_status = false;

            mcast_get_pim_status (if_name,
                    &v4_pim_status, &v6_pim_status);

        } while (0);
    }
    /* if PIM is not enabled on this VLAN interface,
     * then we don't need to process this SNOOP update;
     * Even if PIM enable event is pending is message queue,
     * we don't need this SNOOP update, as and when the PIM enable/route config
     * is processed in message thread, during OIF expansion it would fetch the
     * latest VLAN member ports from SNOOP.
     */
    if (pim_enabled_on_af(af, v4_pim_status, v6_pim_status)) {
        t_mcast_msg_uptr pmsg_uptr = mcast_alloc_mem_msg(SNOOP_UPDATE);
        snoop_update_t *pmsg = dynamic_cast<snoop_update_t*>(pmsg_uptr.get());

        if (pmsg == NULL) {
            NAS_MC_L3_LOG_ERR("CPS", "MSG allocation failed for Type:%d, event_type:%d",
                    SNOOP_UPDATE, SNOOP_VLAN_UPD_EVENT);
        } else {
            pmsg->event_type = SNOOP_VLAN_UPD_EVENT;
            pmsg->vlan_if_name.assign(if_name);
            pmsg->af = af;

            nas_mcast_process_msg(pmsg_uptr.release());
        }
    }

    return cps_api_ret_code_OK;
}


//This API will be used by SNOOPING whenever snooping has to update l3 route
//whenever a specific snooping route is updated for L2 ports.
//source_addr will have to passed as NULL for XG route entry.
cps_api_return_code_t mcast_snoop_route_update_event_handler(const char *vlan_if_name, uint32_t af,
                    const hal_ip_addr_t *group_addr, const hal_ip_addr_t *source_addr)
{
    bool v4_pim_status = false;
    bool v6_pim_status = false;
    std::string if_name;
    interface_ctrl_t intf_ctrl;

    if (vlan_if_name == NULL) {
        NAS_MC_L3_LOG_ERR("SNOOP_EVENT", "Invalid vlan interface name for Snoop Route update event");
        return cps_api_ret_code_PARAM_INVALID;
    }

    if_name.assign(vlan_if_name);

    mcast_get_pim_status (if_name,
            &v4_pim_status, &v6_pim_status);

    if (!v4_pim_status && !v6_pim_status) {
        /* If PIM is disabled, then check for possibility of
         * L3 interface in non-default VRF for this VLAN interface.
         * If one exists, then trigger route update for that VRF interface.
         */
        do {
            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
            safestrncpy(intf_ctrl.if_name, vlan_if_name, sizeof(intf_ctrl.if_name));
            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;

            if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR("SNOOP_EVENT", "Snoop Route update event failed to find interface info "
                        "for VLAN(%s), af(%d)", vlan_if_name, af);
                break;
            }
            hal_vrf_id_t parent_vrf_id = intf_ctrl.l3_intf_info.vrf_id;
            hal_ifindex_t parent_if_index = intf_ctrl.l3_intf_info.if_index;

            if (parent_if_index == 0) {
                NAS_MC_L3_LOG_DEBUG("SNOOP_EVENT",
                        "No VRF configured for VLAN(%s), af(%d) skipping VRF handling "
                        "in Snoop Route update event", vlan_if_name, af);
                break;
            }

            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
            intf_ctrl.vrf_id = parent_vrf_id;
            intf_ctrl.if_index = parent_if_index;

            if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                NAS_MC_L3_LOG_ERR("SNOOP_EVENT", "Snoop Route update event "
                        "failed to find VRF interface info "
                        "for VLAN(%s), af(%d), VRF(%d), if_index(%d)",
                        vlan_if_name, af, parent_vrf_id, parent_if_index);
                break;
            }
            if(intf_ctrl.int_type != nas_int_type_MACVLAN) {
                NAS_MC_L3_LOG_DEBUG("SNOOP_EVENT", "Not a MAC-VLAN interface, skipping VRF handling"
                        "in Snoop Route update event for VLAN(%s), af(%d), VRF(%d), if_index(%d)",
                        vlan_if_name, af, parent_vrf_id, parent_if_index);
                break;
            }

            if_name.assign(intf_ctrl.if_name);

            v4_pim_status = false;
            v6_pim_status = false;

            mcast_get_pim_status (if_name,
                    &v4_pim_status, &v6_pim_status);

        } while (0);
    }

    /* if PIM is not enabled on this VLAN interface,
     * then we don't need to process this SNOOP update;
     * Even if PIM enable event is pending is message queue,
     * we don't need this SNOOP update, as and when the PIM enable/route config
     * is processed in message thread, during OIF expansion it would fetch the
     * latest VLAN member ports from SNOOP.
     */
    if (((af == AF_INET) && (v4_pim_status)) ||
        ((af == AF_INET6) && (v6_pim_status))) {
        t_mcast_msg_uptr pmsg_uptr = mcast_alloc_mem_msg(SNOOP_UPDATE);
        snoop_update_t *pmsg = dynamic_cast<snoop_update_t*>(pmsg_uptr.get());

        if (pmsg == NULL) {
            NAS_MC_L3_LOG_ERR("CPS", "MSG allocation failed for Type:%d, event_type:%d, af:%d",
                    SNOOP_UPDATE, SNOOP_ROUTE_UPD_EVENT, af);
        } else {
            pmsg->event_type = SNOOP_ROUTE_UPD_EVENT;
            pmsg->vlan_if_name.assign(if_name);
            pmsg->af = af;
            memcpy (&pmsg->group_addr, group_addr, sizeof (hal_ip_addr_t));
            if (source_addr == nullptr) {
                pmsg->star_g = true;
            } else {
                pmsg->star_g = false;
                memcpy (&pmsg->source_addr, source_addr, sizeof (hal_ip_addr_t));
            }

            nas_mcast_process_msg(pmsg_uptr.release());
        }
    }

    return cps_api_ret_code_OK;
}


static t_std_error mcast_l3_rpc_handle_reg (void)
{
    cps_api_registration_functions_t  api_reg;
    memset(&api_reg, 0, sizeof(api_reg));

    cps_api_key_from_attr_with_qual(&api_reg.key, L3_MCAST_CLEAR_L3_MCAST_ROUTES_OBJ,
                                    cps_api_qualifier_TARGET);

    api_reg.handle = mcast_cps_handle;
    api_reg._write_function = mcast_l3_cps_clear_routes;
    if (cps_api_register(&api_reg) != cps_api_ret_code_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "Failed to register for Route clear RPC.");
        return STD_ERR(MCAST_L3, FAIL, 0);
    }
    memset(&api_reg, 0, sizeof(api_reg));

    cps_api_key_from_attr_with_qual(&api_reg.key, L3_MCAST_BASE_CLEANUP_EVENTS_OBJ,
                                    cps_api_qualifier_TARGET);

    api_reg.handle = mcast_cps_handle;
    api_reg._write_function = mcast_cps_process_cleanup_events;
    if (cps_api_register(&api_reg) != cps_api_ret_code_OK) {
        NAS_MC_L3_LOG_ERR("CPS", "Failed to register for cleanup events RPC.");
        return STD_ERR(MCAST_L3, FAIL, 0);
    }
    return STD_ERR_OK;
}

cps_api_return_code_t mcast_l3_cps_init(void)
{

    // Object ownership
    if (mcast_l3_handle_reg() != cps_api_ret_code_OK) return cps_api_ret_code_ERR;

    if (mcast_event_handle_reg() != STD_ERR_OK) return cps_api_ret_code_ERR;

    if (mcast_l3_rpc_handle_reg() != STD_ERR_OK) return cps_api_ret_code_ERR;


    return cps_api_ret_code_OK;
}


