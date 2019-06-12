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
 * filename: nas_mc_l3_main.cpp
 */
#include "nas_mc_util.h"
#include "nas_mc_l3_main.h"
#include "nas_mc_l3_util.h"
#include "nas_mc_l3_msg.h"
#include "nas_mc_l3_walker.h"
#include "nas_mc_l3_cps.h"
#include "std_thread_tools.h"

static std_mutex_lock_create_static_init_fast(nas_mc_l3_mutex);

t_std_error mcast_task_init(void)
{
    t_std_error     rc = STD_ERR_OK;

    return rc;
}

void mcast_task_exit (void)
{
    return;
}

void mcast_shell_debug_command_init (void)
{
    return;
}

extern "C" t_std_error nas_mc_l3_init(void)
{
    t_std_error     rc = STD_ERR_OK;

    if (nas_mc_init () != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("NAS-MC-L3-MAIN", "Snooping Init failed");
        return STD_ERR(MCAST_L3, FAIL, 0);
    }
    if(mcast_l3_cps_init() != cps_api_ret_code_OK) {
        NAS_MC_L3_LOG_ERR("NAS-MC-L3-MAIN", "CPS Init failure for L3 multicast");
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    rc = mcast_task_init();
    if (rc != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("NAS-MC-L3-MAIN", "MCAST Task init failed.");
        mcast_task_exit();
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    if (mcast_walker_handler_init() != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("NAS-MC-L3-MAIN", "Failed to initiate walker handler");
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    if (mcast_msg_handler_init() != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("NAS-MC-L3-MAIN", "Failed to initiate message handler");
        return STD_ERR(MCAST_L3, FAIL, 0);
    }
    nas_mc_l3_reg_msg_handler();

    mcast_shell_debug_command_init ();
    return STD_ERR_OK;
}

extern "C" void nas_mc_l3_lock()
{
    std_mutex_lock(&nas_mc_l3_mutex);
}

extern "C" void nas_mc_l3_unlock()
{
    std_mutex_unlock(&nas_mc_l3_mutex);
}
