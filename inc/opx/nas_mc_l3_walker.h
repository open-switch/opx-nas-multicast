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
 * filename: nas_mc_l3_walker.h
 */

#ifndef __NAS_MC_L3_WALKER_H__
#define __NAS_MC_L3_WALKER_H__


#include "std_error_codes.h"
#include "cps_api_errors.h"
#include "nas_mc_l3_cache.h"
#include "nas_mc_l3_util.h"


#define MC_RT_WALKER_COUNT            100

t_std_error mcast_walker_handler_init();
void mcast_walker_handler_deinit();
t_std_error mcast_walker_main (void);
t_std_error mcast_resume_rt_walker_thread (void);
t_std_error mcast_enqueue_rt_event_to_walker_pending_evt_list(mc_route_t *mc_rt);
t_std_error mcast_dequeue_rt_event_from_walker_pending_evt_list(mc_route_t **mc_rt);
t_std_error mcast_remove_rt_event_from_walker_pending_evt_list(mc_route_t *mc_rt);
bool mcast_is_walker_pending_evt_list_empty(void);

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
