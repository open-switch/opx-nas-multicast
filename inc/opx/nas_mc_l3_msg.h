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
 * filename: nas_mc_l3_msg.h
 */

#ifndef __NAS_MC_L3_MSG_H__
#define __NAS_MC_L3_MSG_H__


#include "std_error_codes.h"
#include "cps_api_errors.h"
#include "std_mutex_lock.h"
#include "std_llist.h"
#include "ds_common_types.h"
#include "nas_types.h"
#include "nas_vrf_utils.h"
#include "l3-multicast.h"
#include <unordered_map>
#include <memory>
#include <deque>
#include <utility>
#include <vector>
#include <string>
#include <mutex>
#include <bitset>

/* CONFIG Structures*/

enum class rt_op {
    ADD,
    DELETE,
    UPDATE,
    RT_CLR,
    RT_CLR_GRP,
    RT_CLR_SRC_GRP,
};

typedef struct _oif_s {
    std::string oif_name;
    std::string exclude_if_name;
}oif_t;

typedef enum {
    MCAST_MSG_TYPE_MIN = 0,
    MCAST_STATUS = 1,
    PIM_STATUS = 2,
    ROUTE_CONFIG = 3,
    INTERFACE_CONFIG = 4,
    SNOOP_UPDATE = 5,
    SYNC_MSG_NOTIF = 6,
    ROUTE_CLEAR = 7,
    MCAST_MSG_TYPE_MAX
} t_mcast_msg_type;

constexpr uint32_t INVALID_VRF_ID = static_cast<uint32_t>(-1);

struct t_mcast_msg {
    t_mcast_msg_type type;
    std::string vrf_name;
    uint32_t vrf_id;
    uint32_t af;
    t_mcast_msg(t_mcast_msg_type type) : type(type), vrf_id(INVALID_VRF_ID) {}
    virtual ~t_mcast_msg() = default;
};

struct global_mcast_status_t : public t_mcast_msg {
    bool mcast_status;
    rt_op op;
    global_mcast_status_t() : t_mcast_msg(MCAST_STATUS) {}
    virtual ~global_mcast_status_t() = default;
};

struct pim_status_t : public t_mcast_msg {
    bool pim_status;
    std::string intf_name;
    rt_op op;
    pim_status_t() : t_mcast_msg(PIM_STATUS) {}
    virtual ~pim_status_t() = default;
};

enum {
    UPD_COPY_TO_CPU_POS = 0,
    UPD_OIF_POS
};

struct route_t : public t_mcast_msg {
    uint32_t af;
    hal_ip_addr_t group_addr;
    hal_ip_addr_t source_addr;
    L3_MCAST_ROUTE_TYPE_t rtype;
    std::string iif_name;
    std::vector<oif_t> oif;               // List of outgoing intefaces
    bool data_to_cpu = false;
    rt_op op;
    std::bitset<2> upd_mask;
    route_t() : t_mcast_msg(ROUTE_CONFIG) {}
    virtual ~route_t() = default;
};

enum {
    EVT_VLAN_MBR_CHANGE = 0,
    EVT_INTF_MODE_CHANGE_TO_L2,
    EVT_INTF_DELETE
};

struct intf_event_t : public t_mcast_msg {
    std::string intf_name;
    bool is_sync_msg;
    std::bitset<4> event_mask;
    intf_event_t() : t_mcast_msg(INTERFACE_CONFIG) {}
    virtual ~intf_event_t() = default;
};

typedef enum {
    SNOOP_VLAN_UPD_EVENT = 0,
    SNOOP_ROUTE_UPD_EVENT = 1
} t_mcast_snoop_evt_type;

struct snoop_update_t : public t_mcast_msg {
    t_mcast_snoop_evt_type event_type;
    uint32_t               af;
    std::string            vlan_if_name;
    hal_ip_addr_t          group_addr;
    bool                   star_g;
    hal_ip_addr_t          source_addr;
    snoop_update_t() : t_mcast_msg(SNOOP_UPDATE) {}
    virtual ~snoop_update_t() = default;
};

struct sync_msg_notif_t : public t_mcast_msg {
    sync_msg_notif_t() : t_mcast_msg(SYNC_MSG_NOTIF) {}
    virtual ~sync_msg_notif_t() = default;
};

using msg_handler_func_t = std::function<cps_api_return_code_t(t_mcast_msg*, uint32_t)>;
struct mc_msg_handler_t {
    std::unordered_map<t_mcast_msg_type, msg_handler_func_t>
        func_map;
    std::mutex mutex;
};

using t_mcast_msg_uptr = std::unique_ptr<t_mcast_msg>;

void nas_mcast_wait_for_msg_processing();
void nas_mcast_notify_msg_processing_complete();
bool nas_mcast_process_msg(t_mcast_msg *p_msg);
uint32_t nas_mcast_read_msg_list_stats (t_mcast_msg_type msg_type);
t_mcast_msg_uptr mcast_alloc_mem_msg(t_mcast_msg_type msg_type);
t_mcast_msg *mcast_alloc_route_mem_msg(uint32_t buf_size);
std::string mcast_queue_stats ();
std::string mcast_queue_msg_type_stats ();

void mcast_register_msg_handler(t_mcast_msg_type msg_type, msg_handler_func_t func);
t_std_error mcast_msg_handler_init();
void mcast_msg_handler_deinit();
cps_api_return_code_t mcast_msg_handler_exit(t_mcast_msg *p_msg, uint32_t num_msgs_in_queue);

cps_api_return_code_t _set_global_mcast_status(t_mcast_msg *p_msg, uint32_t num_msgs_in_queue);
cps_api_return_code_t _set_pim_status(t_mcast_msg *p_msg, uint32_t num_msgs_in_queue);
cps_api_return_code_t _program_route(t_mcast_msg *p_msg, uint32_t num_msgs_in_queue);
cps_api_return_code_t _interface_config_handler(t_mcast_msg *p_msg, uint32_t num_msgs_in_queue);
cps_api_return_code_t _snoop_update_handler(t_mcast_msg *p_msg, uint32_t num_msgs_in_queue);
cps_api_return_code_t _sync_msg_notif_handler(t_mcast_msg *p_msg, uint32_t num_msgs_in_queue);


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
