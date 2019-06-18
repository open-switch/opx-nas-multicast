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
 * filename: nas_mc_l3_walker.cpp
 */

#include "nas_mc_l3_util.h"
#include "nas_mc_l3_cache.h"
#include "nas_mc_l3_walker.h"
#include "nas_mc_l3_ndi.h"
#include "std_utils.h"
#include "std_thread_tools.h"
#include <iostream>


static std_thread_create_param_t mcast_walker_thr;
static bool walker_handler_running = true;

pthread_mutex_t mc_rt_mutex;
pthread_cond_t  mc_rt_cond;
static bool     is_mc_pending_for_processing = 0; //initialize the predicate for signal

typedef std::map <uint32_t, mc_route_t *> pending_evt_list;
typedef std::pair <uint32_t, mc_route_t *> pending_evt_list_pair;

// Table to maintain pending route events for walker
static auto mc_walker_pending_evt_list = new pending_evt_list;
static uint32_t walker_pending_evt_list_tracker_index = 0;
//to track the peak value for pending list index
#define         NAS_MC_WALKER_EVT_TRCKR_IDX_MAX_THREASHOLD     50000
static uint32_t walker_evt_trckr_idx_max_threashold_rch_count = 0;
static bool     walker_evt_trckr_idx_reset = true;
static uint32_t walker_pending_evt_peak_index_value = 0;
static uint32_t peak_num_events_pending_in_walker_q = 0;
static uint32_t num_events_pending_in_walker_q = 0;

t_std_error mcast_walker_call_back (mc_route_t *mc_rt);

t_std_error mcast_walker_handler_init()
{
    pthread_mutex_init(&mc_rt_mutex, NULL);
    pthread_cond_init (&mc_rt_cond, NULL);

    std_thread_init_struct(&mcast_walker_thr);
    mcast_walker_thr.name = "mc-walker";
    mcast_walker_thr.thread_function = (std_thread_function_t)mcast_walker_main;
    if (std_thread_create(&mcast_walker_thr)!=STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("MAIN", "Error creating walker thread");
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    return STD_ERR_OK;
}

void mcast_walker_handler_deinit()
{
    walker_handler_running = false;
    //resume walker to exit out of condition wait
    mcast_resume_rt_walker_thread ();

    std_thread_join(&mcast_walker_thr);
    std_thread_destroy_struct(&mcast_walker_thr);
}

t_std_error mcast_resume_rt_walker_thread ()
{
    int retval;

    pthread_mutex_lock(&mc_rt_mutex );
    is_mc_pending_for_processing = 1; //set the predicate for signal
    if((retval = pthread_cond_signal(&mc_rt_cond)) != 0) {
        NAS_MC_L3_LOG_ERR ("MSG", "resume rt walker pthread cond singal failed %d", retval);
    }
    pthread_mutex_unlock(&mc_rt_mutex);

    return STD_ERR_OK;
}

t_std_error mcast_enqueue_rt_event_to_walker_pending_evt_list(mc_route_t *mc_rt)
{
    if (mc_rt-> walker_pending_evt_list_tracker_index != 0)
    {
        /* Route already present in pending event list,
         * so simply return for any further route updates
         * until the event is removed from pending event list or
         * by walker thread processing.
         */
        NAS_MC_L3_LOG_DEBUG ("MSG", "MC Route already pending for walker processing "
                             "vrf:%d, event_list_tracker_index:%d",
                             mc_rt->vrf_id,
                             mc_rt->walker_pending_evt_list_tracker_index);
        return STD_ERR_OK;
    }

    if (!walker_pending_evt_list_tracker_index) walker_evt_trckr_idx_reset = true;

    walker_pending_evt_list_tracker_index++;

    //check for list_tracker index going beyond threshold value to keep track
    //of the number of instances the walker tracker index reaches beyond the threashold.
    if (walker_pending_evt_list_tracker_index == NAS_MC_WALKER_EVT_TRCKR_IDX_MAX_THREASHOLD) {
        if (walker_evt_trckr_idx_reset) {
            walker_evt_trckr_idx_reset = false;
            walker_evt_trckr_idx_max_threashold_rch_count++;

                NAS_MC_L3_LOG_DEBUG ("WALKER-THRESHOLD", "Walker tracker index reaches "
                        "the max threashold(%d), %d times",
                        NAS_MC_WALKER_EVT_TRCKR_IDX_MAX_THREASHOLD,
                        walker_evt_trckr_idx_max_threashold_rch_count);
        }
    }

    mc_rt->walker_pending_evt_list_tracker_index = walker_pending_evt_list_tracker_index;

    mc_walker_pending_evt_list->insert(pending_evt_list_pair(walker_pending_evt_list_tracker_index, mc_rt));

    num_events_pending_in_walker_q++;
    if (peak_num_events_pending_in_walker_q < num_events_pending_in_walker_q)
        peak_num_events_pending_in_walker_q = num_events_pending_in_walker_q;

    // track peak index value
    if (walker_pending_evt_peak_index_value < walker_pending_evt_list_tracker_index)
        walker_pending_evt_peak_index_value = walker_pending_evt_list_tracker_index;

    return STD_ERR_OK;
}

t_std_error mcast_dequeue_rt_event_from_walker_pending_evt_list(mc_route_t **mc_rt, bool *events_pending)
{
    *events_pending = false;
    *mc_rt = NULL;
    if (mc_walker_pending_evt_list->empty())
    {
        // if walker pending event list is empty, then reset to 0 for the tracker index
        walker_pending_evt_list_tracker_index = 0;
        *mc_rt = NULL;
        return STD_ERR_OK;

    }

    auto it = mc_walker_pending_evt_list->begin();
    if (it != mc_walker_pending_evt_list->end())
    {
        *mc_rt = (mc_route_t *) it->second;
        mc_walker_pending_evt_list->erase (it);
        *events_pending = true;

        // invalidate walker pending event list tracker index in route node.
        (*mc_rt)->walker_pending_evt_list_tracker_index = 0;

        num_events_pending_in_walker_q--;
    }

    return STD_ERR_OK;
}

t_std_error mcast_remove_rt_event_from_walker_pending_evt_list(mc_route_t *mc_rt)
{
    t_std_error rc = STD_ERR(MCAST, FAIL, 0);

    if (mc_rt->walker_pending_evt_list_tracker_index == 0)
    {
        /* Route not present in pending event list,
         * so simply return.
         */
        NAS_MC_L3_LOG_DEBUG ("MSG",
                             "MC Route not present in pending event list for walker processing "
                             "vrf:%d, ", mc_rt->vrf_id);
        return STD_ERR_OK;
    }

    if (mc_walker_pending_evt_list->empty())
    {
        // if walker pending event list is empty,
        // but then route is marked for pending event.
        NAS_MC_L3_LOG_ERR ("MSG", "Error! MC Route marked for pending event, "
                           "but walker pending event list is empty "
                           "vrf:%d, event_list_tracker_index:%d",
                           mc_rt->vrf_id,
                           mc_rt->walker_pending_evt_list_tracker_index);
        walker_pending_evt_list_tracker_index = 0;

        return STD_ERR(MCAST, FAIL, 0);
    }

    auto it = mc_walker_pending_evt_list->find(mc_rt->walker_pending_evt_list_tracker_index);
    if (it != mc_walker_pending_evt_list->end())
    {
        mc_walker_pending_evt_list->erase (it);

        // invalidate walker pending event list tracker index in route node.
        mc_rt->walker_pending_evt_list_tracker_index = 0;

        num_events_pending_in_walker_q--;
        rc = STD_ERR_OK;
    }

    return rc;
}

bool mcast_is_walker_pending_evt_list_empty()
{
    if (mc_walker_pending_evt_list->empty())
    {
        return true;
    }
    return false;
}

t_std_error mcast_walker_main (void)
{
    t_std_error     ret = STD_ERR_OK;
    uint32_t        tot_mc_rt_processed = 0;
    bool            events_pending = false;
    mc_route_t     *mc_rt;


    for ( ; walker_handler_running;) {
         pthread_mutex_lock(&mc_rt_mutex);

         while (is_mc_pending_for_processing == 0) {
             pthread_cond_wait(&mc_rt_cond, &mc_rt_mutex);
         }

         is_mc_pending_for_processing = 0;
         pthread_mutex_unlock(&mc_rt_mutex);
         tot_mc_rt_processed = 0;

         nas_mc_l3_lock();
         do {
             mc_rt = NULL;

             ret = mcast_dequeue_rt_event_from_walker_pending_evt_list(&mc_rt, &events_pending);

             if (ret != STD_ERR_OK)
             {
                 NAS_MC_L3_LOG_ERR ("WALKER", "Error in retrieving pending events from walker");
                 break;
             }
             if (events_pending != true)
             {
                 NAS_MC_L3_LOG_DEBUG ("WALKER", "No more events pending in walker");
                 break;
             }

             mcast_walker_call_back (mc_rt);
             tot_mc_rt_processed++;

             if (tot_mc_rt_processed == MC_RT_WALKER_COUNT)
             {
                 NAS_MC_L3_LOG_DEBUG ("WALKER", "Already processed %d walker events, relenquishing control",
                         tot_mc_rt_processed);
                 is_mc_pending_for_processing = 1;
                 break;
             }

         } while (1);
         nas_mc_l3_unlock();
    }
    return ret;
}


t_std_error mcast_walker_call_back (mc_route_t *mc_rt)
{
    t_std_error rc = STD_ERR(MCAST_L3, FAIL, 0);

    rc = _program_route_add_or_update (mc_rt,false);

    if (rc != STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR ("WALKER", "Route Add/Update Failed, "
                "VRF:%d, AF:%d, Type:%d, (%s,%s), IIF:%d, status:%d, "
                "repl_grp_id:0x%lx, npu_prg_done:%d",
                mc_rt->vrf_id, mc_rt->af, mc_rt->rtype,
                MC_IP_ADDR_TO_STR(&mc_rt->src_ip),
                MC_IP_ADDR_TO_STR(&mc_rt->grp_ip),
                mc_rt->iif_id, (int)mc_rt->status,
                mc_rt->repl_grp_id, mc_rt->npu_prg_status);
    }

    return rc;
}

void mcast_reset_walker_processing_debug_data ()
{
    walker_pending_evt_peak_index_value = 0;
    num_events_pending_in_walker_q = 0;
    peak_num_events_pending_in_walker_q = 0;
    walker_evt_trckr_idx_max_threashold_rch_count = 0;
    walker_evt_trckr_idx_reset = 0;
}

void mcast_debug_walker_processing_data ()
{
    // dump debug data from walker processing flow.
    // below data will provide insight into how the walker pending event list
    // is efficiently managed during scaled configurations.
    NAS_MC_L3_LOG_ERR("WALKER-DBG", "walker_pending_evt_list_tracker_index:%d",
                      walker_pending_evt_list_tracker_index);
    NAS_MC_L3_LOG_ERR("WALKER-DBG", "walker_pending_evt_peak_index_value:%d",
                      walker_pending_evt_peak_index_value);
    NAS_MC_L3_LOG_ERR("WALKER-DBG", "num_events_pending_in_walker_q:%d",
                      num_events_pending_in_walker_q);
    NAS_MC_L3_LOG_ERR("WALKER-DBG", "peak_num_events_pending_in_walker_q:%d",
                      peak_num_events_pending_in_walker_q);
    NAS_MC_L3_LOG_ERR("WALKER-DBG", "walker_evt_trckr_idx_max_threashold_rch_count:%d",
                      walker_evt_trckr_idx_max_threashold_rch_count);
    NAS_MC_L3_LOG_ERR("WALKER-DBG", "walker_evt_trckr_idx_reset:%d",
                      walker_evt_trckr_idx_reset);
}
