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
 * filename: nas_mc_l3_util.h
 */

#ifndef __NAS_MC_L3_UTIL_H__
#define __NAS_MC_L3_UTIL_H__


#include "stddef.h"
#include "std_error_codes.h"
#include "event_log.h"
#include "cps_api_errors.h"
#include "nas_mc_l3_msg.h"
#include "nas_mc_l3_cache.h"
#include "nas_mc_l3_cps.h"
#include "nas_mc_repl_grp_db.h"
#include "nas_ndi_ipmc.h"
#include <arpa/inet.h>

#include <unordered_map>
#include <vector>

#define NAS_MC_L3_LOG_ERR(ID, ...)     EV_LOGGING(BASE_MCAST_L3, ERR, ID, __VA_ARGS__)
#define NAS_MC_L3_LOG_INFO(ID, ...)     EV_LOGGING(BASE_MCAST_L3, INFO, ID, __VA_ARGS__)
#define NAS_MC_L3_LOG_DEBUG(ID, ...)   EV_LOGGING(BASE_MCAST_L3, DEBUG, ID, __VA_ARGS__)

#define NAS_MC_INVALID_REPL_GRP_ID          NDI_IPMC_NULL_OBJECT_ID
#define INVALID_RIF_ID                      0

#define MC_IP_MAX_SCRATCH_BUFSZ             256
#define MC_IP_NUM_SCRATCH_BUF               16

#define MC_IP_ADDR_TO_STR(_p_ip_addr)                                       \
        (((_p_ip_addr)->af_index == HAL_INET4_FAMILY) ?                     \
         MC_IPV4_ADDR_TO_STR (&((_p_ip_addr)->u.v4_addr)) :                 \
        (((_p_ip_addr)->af_index == HAL_INET6_FAMILY) ?                     \
         MC_IPV6_ADDR_TO_STR (&((_p_ip_addr)->u.v6_addr)) : ""))

#define MC_IPV4_ADDR_TO_STR(_p_ip_addr)                                     \
        (inet_ntop (AF_INET, (const void *) (_p_ip_addr),                    \
                    (char *) mc_rt_get_scratch_buf (), MC_IP_MAX_SCRATCH_BUFSZ))

#define MC_IPV6_ADDR_TO_STR(_p_ip_addr)                                     \
        (inet_ntop (AF_INET6, (const void *) (_p_ip_addr),                   \
                   (char *) mc_rt_get_scratch_buf (), MC_IP_MAX_SCRATCH_BUFSZ))

enum class rt_upd_type_t
{
    COPY_TO_CPU,
    OIF,
    REPL_GRP_ID,
    STATUS
};

enum class rt_status_t
{
    PENDING_IN_QUEUE,
    PROG_SUCCEED,
    IPMC_PROG_FAIL,
    IPMC_DEL_FAIL,
    REPL_GRP_PROG_FAIL,
    REPL_GRP_DEL_FAIL,
    NOT_PRGM_IN_NPU
};

struct mc_oif_t
{
    hal_ifindex_t oif_id;
    bool has_exclude_if;
    hal_ifindex_t exclude_if_id;
};

struct mc_route_t
{
    uint32_t vrf_id;
    uint32_t af;
    L3_MCAST_ROUTE_TYPE_t rtype;
    hal_ip_addr_t grp_ip;
    hal_ip_addr_t src_ip;

    hal_ifindex_t iif_id;
    std::unordered_map<hal_ifindex_t, mc_oif_t> oif_list;
    bool copy_to_cpu;

    uint32_t walker_pending_evt_list_tracker_index;
    nas_mcast_obj_id_t repl_grp_id;
    rt_status_t status;
    bool        npu_prg_status;

    mc_route_t(const route_t& rt_msg);
    mc_route_t()
    {
        std::tie(vrf_id, af, rtype, iif_id, copy_to_cpu,
                 walker_pending_evt_list_tracker_index, repl_grp_id, status) =
            std::make_tuple(0, AF_INET, L3_MCAST_ROUTE_TYPE_XG, 0, false, 0, 0,
                            rt_status_t::PENDING_IN_QUEUE);
        memset(&grp_ip, 0, sizeof(grp_ip));
        memset(&src_ip, 0, sizeof(src_ip));
    }

    operator std::string() const;
};

void nas_mc_l3_reg_msg_handler();


t_std_error mcast_get_vrf_mcast_status (hal_vrf_id_t vrf_id,
                                        bool *p_ret_v4_mc_status,
                                        bool *p_ret_v6_mc_status);

t_std_error mcast_get_vrf_mcast_status (std::string vrf_name,
                                        bool *p_ret_v4_mc_status,
                                        bool *p_ret_v6_mc_status);

t_std_error mcast_get_pim_status (std::string if_name,
                                  bool *p_ret_v4_pim_status,
                                  bool *p_ret_v6_pim_status);

t_std_error mcast_get_pim_status (hal_vrf_id_t vrf_id, hal_ifindex_t if_index,
                                  bool *p_ret_v4_pim_status, bool *p_ret_v6_pim_status);

t_std_error mcast_get_intf_mode (hal_vrf_id_t vrf_id, hal_ifindex_t if_index,
                                 uint32_t *ret_mode);

t_std_error mcast_get_intf_mode (std::string if_name,
                                 uint32_t *ret_mode);

t_std_error mcast_set_intf_mode (std::string if_name, uint32_t mode);

t_std_error nas_mc_l3_route_db_add(const mc_route_t& rt_info);
t_std_error nas_mc_l3_route_db_delete(const mc_route_t& rt_info);
t_std_error nas_mc_l3_route_db_update(const mc_route_t& rt_info,
                                      const std::vector<rt_upd_type_t>& utype_list);
std::vector<mc_route_t*> nas_mc_l3_route_db_get(const uint32_t* vrf_id, const uint32_t* af,
                                        const L3_MCAST_ROUTE_TYPE_t* rout_type,
                                        const hal_ip_addr_t* grp_ip,
                                        const hal_ip_addr_t* src_ip,
                                        const std::pair<hal_vrf_id_t, hal_ifindex_t>* mbr_rif = nullptr);
std::vector<mc_route_t> nas_mc_l3_route_db_get_copy(const uint32_t* vrf_id, const uint32_t* af,
                                        const L3_MCAST_ROUTE_TYPE_t* rout_type,
                                        const hal_ip_addr_t* grp_ip,
                                        const hal_ip_addr_t* src_ip);
mc_route_t* nas_mc_l3_route_db_get_exact(const mc_route_t& mc_route);

t_std_error _program_route_add_or_update (mc_route_t *mc_rt, bool is_sync);

uint8_t *mc_rt_get_scratch_buf ();

bool route_iif_oif_expand (mc_route_t *route, mcast_if_list_t &iiflist, mcast_if_list_t &oif_list);
void mcast_dump_expanded_if_list(mcast_if_list_t &expanded_iif_list);

t_std_error mcast_l3_util_clear_routes (l3_mcast_route_cps_key_t &rt_cps_key);

#ifdef __cplusplus
extern "C" {
#endif

void nas_mc_l3_lock();
void nas_mc_l3_unlock();

#ifdef __cplusplus
}
#endif

#endif
