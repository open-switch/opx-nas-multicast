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
 * filename: nas_mc_l3_msg.cpp
 */

#include "nas_mc_l3_msg.h"
#include "nas_mc_l3_util.h"
#include "std_utils.h"
#include "cps_api_object_category.h"
#include "cps_api_operation.h"
#include "cps_class_map.h"
#include "std_rw_lock.h"
#include "nas_vrf_utils.h"
#include "std_thread_tools.h"

#include <unordered_map>
#include <memory>
#include <deque>
#include <utility>
#include <mutex>
#include <sstream>
#include <condition_variable>
#include <algorithm>

using mcast_msg_uptr_t = std::unique_ptr<t_mcast_msg>;
static auto &mcast_msg_list = *new std::deque<mcast_msg_uptr_t>;

static auto mcast_msg_list_stats = new std::unordered_map<uint32_t,uint32_t> {
    {MCAST_STATUS, 0},
    {PIM_STATUS, 0},
    {ROUTE_CONFIG, 0},
    {INTERFACE_CONFIG, 0},
    {SNOOP_UPDATE, 0},
    {SYNC_MSG_NOTIF, 0},
    {MCAST_MSG_TYPE_MAX, 0},
};

uint_t mcast_msg_peak_cnt = 0;

static std::mutex m_mtx;
static std::condition_variable  m_data;

static std_thread_create_param_t mcast_msg_thr;
static mc_msg_handler_t& mcast_msg_handler = *new mc_msg_handler_t{};

// mutex and conditional variable used when the caller has to wait for
// completion of the msg processing. Msg thread would notify the completion of
// msg processing when there is a thread waiting for processing completion.

std::mutex _mutex;
std::condition_variable  _wait_for_msg_processing_cond;
static bool _sync_msg_processing_complete = false;

void nas_mcast_wait_for_msg_processing()
{
    std::unique_lock<std::mutex> lock{_mutex};

    if (!_sync_msg_processing_complete)
        _wait_for_msg_processing_cond.wait(lock);
    _sync_msg_processing_complete = false;
}

void nas_mcast_notify_msg_processing_complete()
{
    {
        std::unique_lock<std::mutex> lock{_mutex};
        _sync_msg_processing_complete = true;
    }
    _wait_for_msg_processing_cond.notify_one();
}

mcast_msg_uptr_t nas_mcast_read_msg (void)
{
    std::unique_lock<std::mutex> l {m_mtx};
    if (mcast_msg_list.empty()) {
        m_data.wait (l, []{return !mcast_msg_list.empty();});
    }
    auto p_msg = std::move(mcast_msg_list.front());
    mcast_msg_list.pop_front();

    auto it = mcast_msg_list_stats->find(p_msg->type);
    if (it != mcast_msg_list_stats->end())
        it->second--;
    return p_msg;
}

uint32_t nas_mcast_read_msg_list_stats (t_mcast_msg_type msg_type)
{
    std::lock_guard<std::mutex> l {m_mtx};

    auto it = mcast_msg_list_stats->find(msg_type);
    if (it == mcast_msg_list_stats->end())
        return 0;
    return it->second;
}

static bool msg_handler_running = true;
cps_api_return_code_t mcast_msg_handler_exit(t_mcast_msg *p_msg, uint32_t num_msgs_in_queue)
{
    msg_handler_running = false;
    return cps_api_ret_code_OK;
}

static t_std_error mcast_msg_main(void *param)
{
    t_std_error     rc = STD_ERR_OK;
    uint32_t        nas_num_mc_msgs_in_queue = 0;
    /* Process the message from queue */

    auto msg_handler = reinterpret_cast<mc_msg_handler_t*>(param);
    while(msg_handler_running) {
        mcast_msg_uptr_t p_msg_uptr = nas_mcast_read_msg();
        if (!p_msg_uptr)
            continue;
        auto p_msg = p_msg_uptr.get();

        nas_num_mc_msgs_in_queue = nas_mcast_read_msg_list_stats (p_msg->type);

        std::lock_guard<std::mutex> lock(msg_handler->mutex);
        if (msg_handler->func_map.find(p_msg->type) != msg_handler->func_map.end()) {

            nas_mc_l3_lock();
            rc = msg_handler->func_map.at(p_msg->type)(p_msg, nas_num_mc_msgs_in_queue);
            nas_mc_l3_unlock();

            if (rc != STD_ERR_OK) {
                NAS_MC_L3_LOG_INFO("MSG", "Failure for handing message type %d", p_msg->type);
            }
        }
    }
    return STD_ERR_OK;
}

bool nas_mcast_process_msg(t_mcast_msg *p_msg)
{
    bool mcast_msg_thr_wakeup = false;
    if (p_msg) {
        std::lock_guard<std::mutex> l {m_mtx};
        mcast_msg_thr_wakeup = mcast_msg_list.empty();
        mcast_msg_list.emplace_back(p_msg);

        auto it = mcast_msg_list_stats->find(p_msg->type);
        if (it != mcast_msg_list_stats->end())
            it->second++;

        if (mcast_msg_peak_cnt < mcast_msg_list.size())
            mcast_msg_peak_cnt = mcast_msg_list.size();
    }
    if (mcast_msg_thr_wakeup) m_data.notify_one ();
    return true;
}

t_mcast_msg_uptr mcast_alloc_mem_msg(t_mcast_msg_type msg_type)
{
    t_mcast_msg *p_msg = nullptr;
    switch(msg_type) {
    case MCAST_STATUS:
        p_msg = new (std::nothrow) global_mcast_status_t{};
        break;
    case PIM_STATUS:
        p_msg = new (std::nothrow) pim_status_t{};
        break;
    case ROUTE_CONFIG:
        p_msg = new (std::nothrow) route_t{};
        break;
    case INTERFACE_CONFIG:
        p_msg = new (std::nothrow) intf_event_t{};
        break;
    case SYNC_MSG_NOTIF:
        p_msg = new (std::nothrow) sync_msg_notif_t{};
        break;
    case SNOOP_UPDATE:
        p_msg = new (std::nothrow) snoop_update_t{};
        break;
    default:
        break;
    }
    t_mcast_msg_uptr mcast_msg_uptr(p_msg);
    return mcast_msg_uptr;
}


/* allocate memory for the route message for given buffer size.
 * route message buffer size is calculated based on the nh_count
 * in the message.
 */
t_mcast_msg *mcast_alloc_route_mem_msg(uint32_t buf_size)
{
    char *p_msg = new (std::nothrow) char[buf_size];
    return (t_mcast_msg*)p_msg;
}

std::string mcast_queue_stats ()
{
    std::lock_guard<std::mutex> l {m_mtx};
    std::stringstream ss;
    ss << "Current:" << mcast_msg_list.size() << "Peak:" << mcast_msg_peak_cnt;
    return ss.str();
}

std::string mcast_queue_msg_type_stats ()
{
    std::lock_guard<std::mutex> l {m_mtx};
    std::stringstream ss;
    for (auto it = mcast_msg_list_stats->begin(); it != mcast_msg_list_stats->end(); ++it)
        ss << "MsgType:" << it->first << "Msg Count:" << it->second;
    return ss.str();
}

void mcast_sort_array(uint64_t data[], uint32_t count)
{
    std::sort(data,data+count);
}

void mcast_register_msg_handler(t_mcast_msg_type msg_type, msg_handler_func_t func)
{
    std::lock_guard<std::mutex> lock(mcast_msg_handler.mutex);
    mcast_msg_handler.func_map[msg_type] = func;
}

t_std_error mcast_msg_handler_init()
{
    std_thread_init_struct(&mcast_msg_thr);
    mcast_msg_thr.name = "mc-msg";
    mcast_msg_thr.thread_function = (std_thread_function_t)mcast_msg_main;
    mcast_msg_thr.param = &mcast_msg_handler;
    if (std_thread_create(&mcast_msg_thr)!=STD_ERR_OK) {
        NAS_MC_L3_LOG_ERR("NAS-MC-L3-MAIN", "Error creating msg thread");
        return STD_ERR(MCAST_L3, FAIL, 0);
    }

    return STD_ERR_OK;
}

void mcast_msg_handler_deinit()
{
    std_thread_join(&mcast_msg_thr);
    std_thread_destroy_struct(&mcast_msg_thr);
}
