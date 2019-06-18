/*
 * Copyright (c) 2019 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */

/*
 * filename: nas_mc_l3_route_db_ut.cpp
 */

#include <tuple>
#include <set>
#include <algorithm>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <gtest/gtest.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "nas_mc_l3_util.h"
#include "nas_vrf_utils.h"
#include "cps_api_operation.h"
#include "l3-multicast.h"
#include "cps_class_map.h"
#include "std_socket_service.h"
#include "hal_if_mapping.h"
#include "std_utils.h"

#define MC_NSEC_PER_MSEC 1000000

static const uint32_t TEST_VRF_ID = 100;
static const char *TEST_IPV4_GRP_ADDR = "230.1.1.1";
static const char *TEST_IPV4_SRC_ADDR = "202.3.1.1";
static const char *TEST_IPV6_GRP_ADDR = "ff08::1";
static const char *TEST_IPV6_SRC_ADDR = "1234:8888::1";

static const hal_ifindex_t IIF_BASE = 1000;
static const hal_ifindex_t OIF_BASE = 2000;
static const hal_ifindex_t EXCLUDE_IF_BASE = 3000;
static const uint32_t REPL_GRP_ID_BASE = 5000;

static void get_offset_ip(const char *base_addr, uint32_t af, size_t offset,
                          hal_ip_addr_t& ret_ip)
{
    ret_ip.af_index = af;
    if (af == AF_INET) {
        struct in_addr addr;
        ASSERT_EQ(inet_pton(af, base_addr, &addr), 1);
        uint32_t addr_num = ntohl(addr.s_addr);
        ret_ip.u.v4_addr = htonl(addr_num + offset);
    } else if (af == AF_INET6) {
        ASSERT_EQ(inet_pton(af, base_addr, &ret_ip.u.ipv6), 1);
        int idx = 15;
        while(idx > 0 && offset > 0) {
            offset += ret_ip.u.v6_addr[idx];
            ret_ip.u.v6_addr[idx] = (offset & 0xff);
            offset >>= 8;
            idx --;
        }
    } else {
        std::cout << "Unknown IP address family: " << af << std::endl;
        ASSERT_TRUE(false);
    }
}

static std::vector<mc_route_t> generate_routes(size_t count)
{
    std::srand(std::time(nullptr));
    std::vector<mc_route_t> route_list{};
    std::vector<hal_ip_addr_t> grp_ip_list{};
    size_t half_count = count / 2;
    for (size_t idx = 0; idx < count; idx ++) {
        uint32_t af, offset;
        const char *base_ip;
        if (idx < half_count) {
            af = AF_INET;
            offset = idx;
            base_ip = TEST_IPV4_GRP_ADDR;
        } else {
            af = AF_INET6;
            offset = idx - half_count;
            base_ip = TEST_IPV6_GRP_ADDR;
        }
        hal_ip_addr_t grp_ip;
        get_offset_ip(base_ip, af, offset, grp_ip);
        grp_ip_list.push_back(grp_ip);
    }
    for (size_t idx = 0; idx < count; idx ++) {
        if (grp_ip_list.empty()) {
            break;
        }
        mc_route_t route{};
        size_t ip_idx = std::rand() % grp_ip_list.size();
        route.vrf_id = TEST_VRF_ID;
        route.af = grp_ip_list[ip_idx].af_index;
        auto rtype_flag = std::rand() % 3;
        switch (rtype_flag) {
        case 0:
            route.rtype = L3_MCAST_ROUTE_TYPE_XG;
            break;
        case 1:
            route.rtype = L3_MCAST_ROUTE_TYPE_SG;
            break;
        case 2:
            route.rtype = L3_MCAST_ROUTE_TYPE_SGRPT;
            break;
        }
        route.grp_ip = grp_ip_list[ip_idx];
        if (route.rtype == L3_MCAST_ROUTE_TYPE_SG || route.rtype == L3_MCAST_ROUTE_TYPE_SGRPT) {
            const char *base_ip;
            if (route.grp_ip.af_index == AF_INET) {
                base_ip = TEST_IPV4_SRC_ADDR;
            } else {
                base_ip = TEST_IPV6_SRC_ADDR;
            }
            get_offset_ip(base_ip, route.grp_ip.af_index, std::rand() % 100, route.src_ip);
        }
        route.iif_id = std::rand() % 1000 + IIF_BASE;
        if (route.rtype != L3_MCAST_ROUTE_TYPE_SGRPT) {
            size_t oif_cnt = std::rand() % 100 + 10;
            std::set<hal_ifindex_t> oif_set{};
            for (size_t oif_idx = 0; oif_idx < oif_cnt; oif_idx ++) {
                bool has_exclude_if = (std::rand() % 2 == 0);
                hal_ifindex_t oif = std::rand() % 1000 + OIF_BASE;
                if (oif_set.find(oif) != oif_set.end()) {
                    continue;
                }
                oif_set.insert(oif);
                route.oif_list.insert(std::make_pair(oif, mc_oif_t{oif, has_exclude_if,
                                        has_exclude_if ? std::rand() % 1000 + EXCLUDE_IF_BASE : 0}));
            }
        }
        route.copy_to_cpu = std::rand() % 2;
        route.walker_pending_evt_list_tracker_index = 0;
        route.repl_grp_id = std::rand() % 4000 + REPL_GRP_ID_BASE;
        switch(std::rand() % 4) {
        case 0:
        default:
            route.status = rt_status_t::PENDING_IN_QUEUE;
            break;
        case 1:
            route.status = rt_status_t::PROG_SUCCEED;
            break;
        case 2:
            route.status = rt_status_t::IPMC_PROG_FAIL;
            break;
        case 3:
            route.status = rt_status_t::REPL_GRP_PROG_FAIL;
            break;
        }
        route.npu_prg_status = false;

        grp_ip_list.erase(grp_ip_list.begin() + ip_idx);
        route_list.push_back(route);
    }

    return route_list;
}

bool operator==(const mc_oif_t& o1, const mc_oif_t& o2)
{
    return std::tie(o1.oif_id, o1.has_exclude_if, o1.exclude_if_id) ==
           std::tie(o2.oif_id, o2.has_exclude_if, o2.exclude_if_id);
}

bool operator==(const hal_ip_addr_t& a1, const hal_ip_addr_t& a2)
{
    if (a1.af_index != a2.af_index) {
        return false;
    }
    if (a1.af_index == AF_INET) {
        return a1.u.v4_addr == a2.u.v4_addr;
    } else {
        return std::memcmp(a1.u.v6_addr, a2.u.v6_addr, sizeof(a1.u.v6_addr)) == 0;
    }
}

bool operator==(const mc_route_t& r1, const mc_route_t& r2)
{
    if (!(std::tie(r1.vrf_id, r1.af, r1.rtype, r1.grp_ip, r1.src_ip, r1.iif_id, r1.copy_to_cpu,
                   r1.walker_pending_evt_list_tracker_index, r1.repl_grp_id, r1.status, r1.npu_prg_status) ==
          std::tie(r2.vrf_id, r2.af, r2.rtype, r2.grp_ip, r2.src_ip, r2.iif_id, r2.copy_to_cpu,
                   r2.walker_pending_evt_list_tracker_index, r2.repl_grp_id, r2.status, r2.npu_prg_status))) {
        return false;
    }
    std::set<hal_ifindex_t> s1{};
    for (auto& oif: r1.oif_list) {
        s1.insert(oif.first);
    }
    std::set<hal_ifindex_t> s2{};
    for (auto& oif: r2.oif_list) {
        s2.insert(oif.first);
    }
    return s1 == s2;
}

std::ostream& operator<<(std::ostream& os, const mc_route_t& route)
{
    char ip_buf[128];
    os << "[VRF " << route.vrf_id;
    if (route.af == AF_INET) {
        inet_ntop(route.af, &route.grp_ip.u.ipv4, ip_buf, sizeof(ip_buf));
    } else {
        inet_ntop(route.af, &route.grp_ip.u.ipv6, ip_buf, sizeof(ip_buf));
    }
    os << " GRP " << ip_buf;
    if (route.rtype == L3_MCAST_ROUTE_TYPE_SG || route.rtype == L3_MCAST_ROUTE_TYPE_SGRPT) {
        if (route.af == AF_INET) {
            inet_ntop(route.af, &route.src_ip.u.ipv4, ip_buf, sizeof(ip_buf));
        } else {
            inet_ntop(route.af, &route.src_ip.u.ipv6, ip_buf, sizeof(ip_buf));
        }
        os << " SRC " << ip_buf;
        if (route.rtype == L3_MCAST_ROUTE_TYPE_SGRPT) {
            os << " RPT";
        }
    } else {
        os << " SRC *";
    }

    os << " RTTYPE " << route.rtype;
    os << " IIF " << route.iif_id;
    os << " OIF ";
    for (auto& oif: route.oif_list) {
        os << oif.first << ",";
    }
    os << " ]";

    return os;
}

TEST(mcast_l3_route_db, add_route)
{
    auto route_list = generate_routes(1000);
    for (auto& route: route_list) {
        //std::cout << "Add route: " << route << std::endl;
        ASSERT_EQ(nas_mc_l3_route_db_add(route), STD_ERR_OK);
    }
    std::cout << route_list.size() << " routes were successfully added" << std::endl;
    auto rd_route_list = nas_mc_l3_route_db_get(nullptr, nullptr, nullptr, nullptr, nullptr);
    std::cout << rd_route_list.size() << " routes were read from DB" << std::endl;
    ASSERT_EQ(route_list.size(), rd_route_list.size());
    for (auto& route: route_list) {
        std::cout << "Check route: " << route << std::endl;
        auto one_route = nas_mc_l3_route_db_get(&route.vrf_id, &route.af, &route.rtype, &route.grp_ip,
            (route.rtype == L3_MCAST_ROUTE_TYPE_SG || route.rtype == L3_MCAST_ROUTE_TYPE_SGRPT) ? &route.src_ip : nullptr);
        ASSERT_EQ(one_route.size(), 1);
        ASSERT_EQ(route, *one_route[0]);
    }
}

static bool rif_in_route(const mc_route_t& route, hal_vrf_id_t vrf_id, hal_ifindex_t rif_id)
{
    if (route.vrf_id != vrf_id) {
        return false;
    }
    if (route.iif_id == rif_id) {
        return true;
    }
    for (auto& oif: route.oif_list) {
        if (oif.first == rif_id) {
            return true;
        }
    }
    return false;
}

namespace std
{
    template<>
    struct hash<std::pair<hal_vrf_id_t, hal_ifindex_t>>
    {
        size_t operator()(const std::pair<hal_vrf_id_t, hal_ifindex_t>& data) const
        {
            return std::hash<int>()(static_cast<int>(data.first)) ^
                   std::hash<int>()(static_cast<int>(data.second));
        }
    };
}

TEST(mcast_l3_route_db, get_route)
{
    uint32_t vrf = 10;
    uint32_t af = AF_INET;
    auto rd_route_list = nas_mc_l3_route_db_get(&vrf, nullptr, nullptr, nullptr, nullptr);
    ASSERT_TRUE(rd_route_list.empty());
    rd_route_list = nas_mc_l3_route_db_get(nullptr, &af, nullptr, nullptr, nullptr);
    ASSERT_FALSE(rd_route_list.empty());
    for (auto route: rd_route_list) {
        ASSERT_EQ(route->af, af);
    }
    size_t idx = std::rand() % rd_route_list.size();
    auto sub_route_list = nas_mc_l3_route_db_get(nullptr, nullptr, nullptr, &rd_route_list[idx]->grp_ip, nullptr);
    ASSERT_FALSE(sub_route_list.empty());
    for (auto route: sub_route_list) {
        ASSERT_EQ(route->grp_ip, rd_route_list[idx]->grp_ip);
    }

    auto all_routes = nas_mc_l3_route_db_get_copy(nullptr, nullptr, nullptr, nullptr, nullptr);
    ASSERT_TRUE(all_routes.size() > 0);
    std::unordered_set<std::pair<hal_vrf_id_t, hal_ifindex_t>> rif_list{};
    for (auto& route: all_routes) {
        rif_list.insert(std::make_pair(route.vrf_id, route.iif_id));
        for (auto& oif: route.oif_list) {
            rif_list.insert(std::make_pair(route.vrf_id, oif.first));
        }
        if (rif_list.size() > 100) {
            break;
        }
    }
    std::cout << "Test reading route based on " << rif_list.size() << " RIF members" << std::endl;
    for (auto& rif_id: rif_list) {
        auto mbr_routes = nas_mc_l3_route_db_get(nullptr, nullptr, nullptr, nullptr, nullptr, &rif_id);
        ASSERT_TRUE(mbr_routes.size() > 0);
        for (auto route: mbr_routes) {
            ASSERT_TRUE(rif_in_route(*route, rif_id.first, rif_id.second));
        }
    }
}

TEST(mcast_l3_route_db, update_route)
{
    auto rd_route_list = nas_mc_l3_route_db_get_copy(nullptr, nullptr, nullptr, nullptr, nullptr);
    ASSERT_FALSE(rd_route_list.empty());
    for (auto& route: rd_route_list) {
        int rand_num = std::rand();
        if (rand_num % 10 == 0) {
            route.copy_to_cpu = !route.copy_to_cpu;
            ASSERT_EQ(nas_mc_l3_route_db_update(route, {rt_upd_type_t::COPY_TO_CPU}), STD_ERR_OK);
        }
        if (rand_num % 10 == 1) {
            auto itor = route.oif_list.begin();
            while (itor != route.oif_list.end()) {
                if (std::rand() % 2 == 0) {
                    itor = route.oif_list.erase(itor);
                } else {
                    if (itor->second.has_exclude_if) {
                        itor->second.exclude_if_id += 300;
                    }
                    itor ++;
                }
            }
            size_t add_cnt = std::rand() % 5 + 1;
            for (size_t idx = 0; idx < add_cnt; idx ++) {
                hal_ifindex_t oif_id = OIF_BASE + 1000 + idx;
                route.oif_list.insert(std::make_pair(oif_id, mc_oif_t{oif_id, false, 0}));
            }
            ASSERT_EQ(nas_mc_l3_route_db_update(route, {rt_upd_type_t::OIF}), STD_ERR_OK);
        }
        if (rand_num % 10 == 2) {
            route.repl_grp_id += 30;
            ASSERT_EQ(nas_mc_l3_route_db_update(route, {rt_upd_type_t::REPL_GRP_ID}), STD_ERR_OK);
        }
        if (rand_num % 10 == 3) {
            int status_type = std::rand() % 3;
            switch(status_type) {
            case 0:
                route.status = rt_status_t::PROG_SUCCEED;
                break;
            case 1:
                route.status = rt_status_t::IPMC_PROG_FAIL;
                break;
            case 2:
                route.status = rt_status_t::REPL_GRP_PROG_FAIL;
                break;
            }
            ASSERT_EQ(nas_mc_l3_route_db_update(route, {rt_upd_type_t::STATUS}), STD_ERR_OK);
        }
    }
    for (auto route: rd_route_list) {
        //std::cout << "Check route: " << route << std::endl;
        auto one_route = nas_mc_l3_route_db_get(&route.vrf_id, &route.af, &route.rtype, &route.grp_ip,
            (route.rtype == L3_MCAST_ROUTE_TYPE_SG || route.rtype == L3_MCAST_ROUTE_TYPE_SGRPT) ? &route.src_ip : nullptr);
        ASSERT_EQ(one_route.size(), 1);
        ASSERT_EQ(route, *one_route[0]);
    }
}

TEST(mcast_l3_route_db, delete_route)
{
    auto rd_route_list = nas_mc_l3_route_db_get_copy(nullptr, nullptr, nullptr, nullptr, nullptr);
    ASSERT_FALSE(rd_route_list.empty());
    for (auto& route: rd_route_list) {
        ASSERT_EQ(nas_mc_l3_route_db_delete(route), STD_ERR_OK);
    }
    auto route_list = nas_mc_l3_route_db_get(nullptr, nullptr, nullptr, nullptr, nullptr);
    ASSERT_TRUE(route_list.empty());
}

static cps_api_return_code_t handle_global_status(t_mcast_msg* p_msg, uint32_t num_msgs_in_queue)
{
    auto st = dynamic_cast<global_mcast_status_t*>(p_msg);
    if (st == nullptr) {
        std::cout << "Not global status message" << std::endl;
        return cps_api_ret_code_ERR;
    }
    std::cout << "Entering global status message handler" << std::endl;
    std::cout << "Global status: " << st->mcast_status << std::endl;
    vrf_str_t vrf_cfg;
    vrf_cfg.vrf_name = st->vrf_name;
    vrf_cfg.vrf_obj_id = st->vrf_id;
    vrf_cfg.v4_mcast_valid = true;
    vrf_cfg.v4_mcast_status = st->mcast_status;
    vrf_cfg.v6_mcast_valid = true;
    vrf_cfg.v6_mcast_status = st->mcast_status;
    if (!mcast_vrf_cache_update(st->vrf_id, &vrf_cfg)) {
        std::cout << "Failed to update VRF cache" << std::endl;
        return cps_api_ret_code_ERR;
    }
    return cps_api_ret_code_OK;
}

static bool if_name_to_index(const std::string& if_name, hal_ifindex_t& if_index)
{
    interface_ctrl_t intf_ctrl;

    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
    safestrncpy(intf_ctrl.if_name, if_name.c_str(),
                sizeof(intf_ctrl.if_name));

    if(dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
        return false;
    }

    if_index = intf_ctrl.if_index;
    return true;
}

static cps_api_return_code_t handle_pim_status(t_mcast_msg* p_msg, uint32_t num_msgs_in_queue)
{
    auto st = dynamic_cast<pim_status_t*>(p_msg);
    if (st == nullptr) {
        std::cout << "Not PIM status message" << std::endl;
        return cps_api_ret_code_ERR;
    }
    std::cout << "Entering interface PIM status message handler" << std::endl;
    std::cout << "PIM status for interface " << st->intf_name
              << " : " << st->pim_status << std::endl;
    if_str_t intf_cfg;
    intf_cfg.if_name = st->intf_name;
    if (!if_name_to_index(st->intf_name, intf_cfg.if_index)) {
        std::cout << "Failed to get ifindex from name" << std::endl;
        return cps_api_ret_code_ERR;
    }
    intf_cfg.vrf_name = st->vrf_name;
    intf_cfg.vrf_id = st->vrf_id;
    intf_cfg.if_type = nas_int_type_PORT;
    intf_cfg.vlan_id = 100;
    intf_cfg.rif_id = 10;
    intf_cfg.v4_pim_valid = true;
    intf_cfg.v4_pim_status = st->pim_status;
    intf_cfg.v6_pim_valid = true;
    intf_cfg.v6_pim_status = st->pim_status;
    if (!mcast_intf_cache_update(st->intf_name, &intf_cfg)) {
        std::cout << "Failed to update interface cache" << std::endl;
        return cps_api_ret_code_ERR;
    }
    return cps_api_ret_code_OK;
}

static cps_api_return_code_t handle_route(t_mcast_msg* p_msg, uint32_t num_msgs_in_queue)
{
    auto rt = dynamic_cast<route_t*>(p_msg);
    if (rt == nullptr) {
        std::cout << "Not route message" << std::endl;
        return cps_api_ret_code_ERR;
    }
    std::cout << "Entering route message handler" << std::endl;
    mc_route_t route_info{*rt};
    std::vector<rt_upd_type_t> upd_type_list{};
    if (rt->upd_mask.test(UPD_COPY_TO_CPU_POS)) {
        upd_type_list.push_back(rt_upd_type_t::COPY_TO_CPU);
    }
    if (rt->upd_mask.test(UPD_OIF_POS)) {
        upd_type_list.push_back(rt_upd_type_t::OIF);
    }

    std::cout << std::string(route_info);
    switch(rt->op) {
    case rt_op::ADD:
        std::cout << "Operation: add route" << std::endl;
        if (nas_mc_l3_route_db_add(route_info) != STD_ERR_OK) {
            std::cout << "Failed" << std::endl;
            return cps_api_ret_code_ERR;
        }
        break;
    case rt_op::DELETE:
        std::cout << "Operation: delete route" << std::endl;
        if (nas_mc_l3_route_db_delete(route_info) != STD_ERR_OK) {
            std::cout << "Failed" << std::endl;
            return cps_api_ret_code_ERR;
        }
        break;
    case rt_op::UPDATE:
        std::cout << "Operation: update route" << std::endl;
        if (nas_mc_l3_route_db_update(route_info, upd_type_list) != STD_ERR_OK) {
            std::cout << "Failed" << std::endl;
            return cps_api_ret_code_ERR;
        }
        break;
    default:
        std::cout << "Invalid message op type" << std::endl;
        return cps_api_ret_code_ERR;
    }
    std::cout << "Leaving route message handler" << std::endl;
    return cps_api_ret_code_OK;
}

static const char *TEST_VRF_NAME = "test_vrf";

static void mc_msec_sleep (uint32_t msec_sleep_time)
{
    struct timespec timeOut,remains;
    uint32_t sane_sleep_time;

    if (msec_sleep_time > 1000) {
        sane_sleep_time = 999;
    } else {
        sane_sleep_time = msec_sleep_time;
    }
    timeOut.tv_sec = 0;
    timeOut.tv_nsec = sane_sleep_time * MC_NSEC_PER_MSEC;
    nanosleep(&timeOut, &remains);
}

static bool send_pim_enable_config()
{
    t_mcast_msg_uptr pmsg_uptr = mcast_alloc_mem_msg(MCAST_STATUS);
    global_mcast_status_t *pmsg = dynamic_cast<global_mcast_status_t*>(pmsg_uptr.get());
    if (pmsg == nullptr) {
        return false;
    }
    pmsg->vrf_name = TEST_VRF_NAME;
    pmsg->af = AF_INET;
    pmsg->mcast_status = true;
    pmsg->op = rt_op::ADD;

    if (!nas_mcast_process_msg(pmsg_uptr.release())) {
        std::cout << "Failure sending global status message" << std::endl;
        return false;
    }

    char name_buf[32];
    for (int idx = 1; idx <= 64; idx ++) {
        snprintf(name_buf, sizeof(name_buf), "e101-%03d-0", idx);
        t_mcast_msg_uptr p_if_msg_uptr = mcast_alloc_mem_msg(PIM_STATUS);
        pim_status_t* p_if_msg = dynamic_cast<pim_status_t*>(p_if_msg_uptr.get());
        if (p_if_msg == nullptr) {
            return false;
        }
        p_if_msg->vrf_name = TEST_VRF_NAME;
        p_if_msg->af = AF_INET;
        p_if_msg->pim_status = true;
        p_if_msg->op = rt_op::ADD;
        p_if_msg->intf_name = name_buf;

        if (!nas_mcast_process_msg(p_if_msg_uptr.release())) {
            std::cout << "Failure sending PIM status message for interface " << name_buf << std::endl;
            return false;
        }
        mc_msec_sleep(5);
    }

    return true;
}

static bool send_add_route_msg(uint32_t af, const char* grp_ip, const char* src_ip,
                               const std::string& iif,
                               const std::vector<std::pair<std::string, std::string>>& oif_list,
                               bool to_cpu)
{
    t_mcast_msg_uptr pmsg_uptr = mcast_alloc_mem_msg(ROUTE_CONFIG);
    route_t *pmsg = dynamic_cast<route_t*>(pmsg_uptr.get());
    if (pmsg == nullptr) {
        return false;
    }
    pmsg->vrf_name = TEST_VRF_NAME;

    // get vrf-id from name
    if (nas_get_vrf_internal_id_from_vrf_name(pmsg->vrf_name.c_str(), &pmsg->vrf_id) != STD_ERR_OK)
    {
        std::cout << "VRF info not found in cache" << std::endl;
        return false;
    }
    pmsg->af = af;
    get_offset_ip(grp_ip, af, 0, pmsg->group_addr);
    if (src_ip != nullptr) {
        pmsg->rtype = L3_MCAST_ROUTE_TYPE_SG;
        get_offset_ip(src_ip, af, 0, pmsg->source_addr);
    } else {
        pmsg->rtype = L3_MCAST_ROUTE_TYPE_XG;
    }
    pmsg->iif_name = iif;
    for (auto& oif: oif_list) {
        pmsg->oif.push_back(oif_t{oif.first, oif.second});
    }
    pmsg->data_to_cpu = to_cpu;
    pmsg->op = rt_op::ADD;

    if (!nas_mcast_process_msg(pmsg_uptr.release())) {
        std::cout << "Failure sending route message" << std::endl;
        return false;
    }
    return true;
}

static bool send_delete_route_msg(uint32_t af, const char* grp_ip, const char* src_ip,
                                  const std::string& iif,
                                  const std::vector<std::string>& oif_list)
{
    t_mcast_msg_uptr pmsg_uptr = mcast_alloc_mem_msg(ROUTE_CONFIG);
    route_t *pmsg = dynamic_cast<route_t*>(pmsg_uptr.get());
    if (pmsg == nullptr) {
        return false;
    }
    pmsg->vrf_name = TEST_VRF_NAME;

    // get vrf-id from name
    if (nas_get_vrf_internal_id_from_vrf_name(pmsg->vrf_name.c_str(), &pmsg->vrf_id) != STD_ERR_OK)
    {
        std::cout << "VRF info not found in cache" << std::endl;
        return false;
    }
    pmsg->af = af;
    get_offset_ip(grp_ip, af, 0, pmsg->group_addr);
    if (src_ip != nullptr) {
        pmsg->rtype = L3_MCAST_ROUTE_TYPE_SG;
        get_offset_ip(src_ip, af, 0, pmsg->source_addr);
    } else {
        pmsg->rtype = L3_MCAST_ROUTE_TYPE_XG;
    }
    pmsg->op = rt_op::DELETE;
    pmsg->iif_name = iif;
    for (auto& oif: oif_list) {
        pmsg->oif.push_back(oif_t{oif, ""});
    }

    if (!nas_mcast_process_msg(pmsg_uptr.release())) {
        std::cout << "Failure sending route message" << std::endl;
        return false;
    }
    return true;
}

static bool send_exit_msg()
{
    t_mcast_msg* pmsg = new t_mcast_msg{MCAST_MSG_TYPE_MAX};
    if (!nas_mcast_process_msg(pmsg)) {
        std::cout << "Failure sending exit message" << std::endl;
        return false;
    }

    return true;
}

static void register_ifindex_map()
{
    char name_buf[32];
    interface_ctrl_t if_info;
    for (int idx = 1; idx <= 64; idx ++) {
        snprintf(name_buf, sizeof(name_buf), "e101-%03d-0", idx);
        memset(&if_info, 0, sizeof(if_info));
        if_info.port_mapped = true;
        if_info.npu_id = 1;
        if_info.port_id = idx;
        if_info.tap_id = idx;
        if_info.if_index = idx + 10;
        if_info.vrf_id = 100;
        safestrncpy(if_info.vrf_name, TEST_VRF_NAME,
                    sizeof(if_info.vrf_name));
        safestrncpy(if_info.if_name, name_buf, sizeof(if_info.if_name));
        if_info.int_type = nas_int_type_PORT;
        ASSERT_EQ(dn_hal_if_register(HAL_INTF_OP_REG, &if_info), STD_ERR_OK);
    }
}

TEST(mcast_l3_route_msg, init_msg_handle)
{
    nas_vrf_ctrl_t vrf_info;
    memset(&vrf_info, 0, sizeof(vrf_info));
    safestrncpy(vrf_info.vrf_name, TEST_VRF_NAME, sizeof(vrf_info.vrf_name));
    vrf_info.vrf_int_id = 50;
    vrf_info.vrf_id = TEST_VRF_ID;
    ASSERT_EQ(nas_update_vrf_info(NAS_VRF_OP_ADD, &vrf_info), STD_ERR_OK);
    register_ifindex_map();
    ASSERT_EQ(mcast_msg_handler_init(), STD_ERR_OK);
    mcast_register_msg_handler(MCAST_STATUS, handle_global_status);
    mcast_register_msg_handler(PIM_STATUS, handle_pim_status);
    mcast_register_msg_handler(ROUTE_CONFIG, handle_route);
    mcast_register_msg_handler(MCAST_MSG_TYPE_MAX, mcast_msg_handler_exit);

    std::cout << "Send global and interface PIM enable message to queue" << std::endl;
    ASSERT_TRUE(send_pim_enable_config());
}

using rt_member_t = std::tuple<uint32_t, std::string, std::string, std::string, std::vector<std::pair<std::string, std::string>>, bool>;

// af, grp_ip, src_ip, iif, oif_list, to_cpu
std::vector<rt_member_t> ut_member_list {{AF_INET, "230.5.5.5", "", "e101-001-0", {{"e101-010-0", ""}, {"e101-011-0", "e101-012-0"}}, false},
                                         {AF_INET, "231.5.5.6", "1.2.3.4", "e101-002-0", {{"e101-010-0", ""}, {"e101-011-0", "e101-012-0"}}, true},
                                         {AF_INET6, "ff08:1::1", "1234:1111::2", "e101-003-0", {{"e101-013-0", "e101-014-0"}}, true},
                                         {AF_INET6, "ff09:1::2", "", "e101-004-0", {{"e101-013-0", "e101-014-0"}}, false}};

TEST(mcast_l3_route_msg, add_route)
{
    std::cout << "Send route add message to queue" << std::endl;
    for (auto& member: ut_member_list) {
        auto src_ip = std::get<2>(member);
        ASSERT_TRUE(send_add_route_msg(std::get<0>(member),
                                       std::get<1>(member).c_str(), src_ip.empty() ? nullptr : src_ip.c_str(),
                                       std::get<3>(member),
                                       std::get<4>(member), std::get<5>(member)));
    }
}

TEST(mcast_l3_route_msg, check_route)
{
    sleep(1);
    auto rd_route_list = nas_mc_l3_route_db_get(nullptr, nullptr, nullptr, nullptr, nullptr);
    ASSERT_EQ(rd_route_list.size(), 4);
    std::cout << "Route from DB:" << std::endl;
    for (auto route: rd_route_list) {
        std::cout << *route << std::endl;
    }
}

TEST(mcast_l3_route_msg, delete_route)
{
    std::cout << "Send route delete message to queue" << std::endl;
    for (auto& member: ut_member_list) {
        auto src_ip = std::get<2>(member);
        std::vector<std::string> oif_list{};
        std::transform(std::get<4>(member).begin(), std::get<4>(member).end(), std::back_inserter(oif_list),
                       [](std::pair<std::string, std::string>& pr)->std::string{return pr.first;});
        ASSERT_TRUE(send_delete_route_msg(std::get<0>(member),
                                          std::get<1>(member).c_str(), src_ip.empty() ? nullptr : src_ip.c_str(),
                                          std::get<3>(member), oif_list));
    }
    sleep(1);
    auto rd_route_list = nas_mc_l3_route_db_get(nullptr, nullptr, nullptr, nullptr, nullptr);
    for (auto route: rd_route_list) {
        std::cout << *route << std::endl;
    }
    ASSERT_TRUE(rd_route_list.empty());
}

static cps_api_operation_handle_t cps_handle;
extern cps_api_return_code_t l3_mcast_write_function(void * context, cps_api_transaction_params_t * param, size_t index);

cps_api_return_code_t ut_write_function(void * context, cps_api_transaction_params_t * param, size_t index)
{
    std::cout << "Entering CPS serivce write handler" << std::endl;
    return l3_mcast_write_function(context, param, index);
}

TEST(mcast_l3_route_msg, init_cps_subsystem)
{
    ASSERT_EQ(cps_api_operation_subsystem_init(&cps_handle, 1), cps_api_ret_code_OK);
    cps_api_registration_functions_t f;
    memset(&f,0,sizeof(f));

    f.handle = cps_handle;
    f._write_function = ut_write_function;

    ASSERT_TRUE(cps_api_key_from_attr_with_qual(&f.key, L3_MCAST_ROUTES_ROUTE, cps_api_qualifier_RESERVED1));

    char buf[256];
    std::cout << "Server KEY: ";
    std::cout << cps_api_key_print(&f.key, buf, sizeof(buf)) << " (";
    std::cout << cps_api_key_name_print(&f.key, buf, sizeof(buf)) << ")" << std::endl;

    ASSERT_EQ(cps_api_register(&f), cps_api_ret_code_OK);
}

static bool send_config_route_req(uint32_t af, const char* grp_ip, const char* src_ip,
                                  const std::string& iif,
                                  const std::vector<std::pair<std::string, std::string>>& oif_list,
                                  bool to_cpu, rt_op op, bool upd_to_cpu = false, bool upd_oif = false)
{
    cps_api_transaction_params_t trans;
    if (cps_api_transaction_init(&trans) != cps_api_ret_code_OK) {
        return false;
    }
    cps_api_object_t obj = cps_api_object_create();
    if (obj == nullptr) {
        return false;
    }
    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                         L3_MCAST_ROUTES_ROUTE, cps_api_qualifier_RESERVED1)) {
        return false;
    }

    char buf[256];
    std::cout << "Req KEY: ";
    std::cout << cps_api_key_print(cps_api_object_key(obj), buf, sizeof(buf)) << " (";
    std::cout << cps_api_key_name_print(cps_api_object_key(obj), buf, sizeof(buf)) << ")" << std::endl;

    cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_VRF_NAME, TEST_VRF_NAME, strlen(TEST_VRF_NAME) + 1);
    cps_api_object_attr_add_u32(obj, L3_MCAST_ROUTES_ROUTE_AF, af);
    if (af == AF_INET) {
        struct in_addr addr;
        inet_pton(af, grp_ip, &addr);
        cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_GROUP_IP, &addr.s_addr, sizeof(addr.s_addr));
        if (src_ip != nullptr) {
            inet_pton(af, src_ip, &addr);
            cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_SOURCE_IP, &addr.s_addr, sizeof(addr.s_addr));
        }
    } else {
        struct in6_addr addr;
        inet_pton(af, grp_ip, &addr);
        cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_GROUP_IP, &addr.s6_addr, sizeof(addr.s6_addr));
        if (src_ip != nullptr) {
            inet_pton(af, src_ip, &addr);
            cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_SOURCE_IP, &addr.s6_addr, sizeof(addr.s6_addr));
        }
    }
    if (src_ip == nullptr) {
        cps_api_object_attr_add_u32(obj, L3_MCAST_ROUTES_ROUTE_RT_TYPE, L3_MCAST_ROUTE_TYPE_XG);
    } else {
        cps_api_object_attr_add_u32(obj, L3_MCAST_ROUTES_ROUTE_RT_TYPE, L3_MCAST_ROUTE_TYPE_SG);
    }
    if (op != rt_op::DELETE) {
        if ((op == rt_op::ADD) || (op == rt_op::UPDATE)) {
            cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_IIF_NAME, iif.c_str(), iif.length() + 1);
        }
        if (op == rt_op::ADD || upd_to_cpu) {
            cps_api_object_attr_add_u32(obj, L3_MCAST_ROUTES_ROUTE_DATA_TO_CPU, to_cpu);
        }
        if (op == rt_op::ADD || upd_oif) {
            if (!oif_list.empty()) {
                size_t idx = 0;
                cps_api_attr_id_t ids[3] = {L3_MCAST_ROUTES_ROUTE_OIF, 0, 0};
                for (auto& oif: oif_list) {
                    ids[1] = idx;
                    ids[2] = L3_MCAST_ROUTES_ROUTE_OIF_NAME;
                    cps_api_object_e_add(obj, ids, 3, cps_api_object_ATTR_T_BIN, oif.first.c_str(), oif.first.length() + 1);
                    ids[2] = L3_MCAST_ROUTES_ROUTE_OIF_EXCLUDE_INTERFACE;
                    cps_api_object_e_add(obj, ids, 3, cps_api_object_ATTR_T_BIN, oif.second.c_str(), oif.second.length() + 1);
                    idx ++;
                }
            } else {
                // Add "NULL" attribute to remove all OIF
                cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_OIF, nullptr, 0);
            }
        }
    }

    cps_api_return_code_t rc;
    switch(op) {
    case rt_op::ADD:
        rc = cps_api_create(&trans, obj);
        break;
    case rt_op::UPDATE:
        rc = cps_api_set(&trans, obj);
        break;
    case rt_op::DELETE:
        rc = cps_api_delete(&trans, obj);
        break;
    default:
        return false;
    }

    if (rc != cps_api_ret_code_OK) {
        std::cout << "Failed to add object to transaction for creation" << std::endl;
        return false;
    }

    if (cps_api_commit(&trans) != cps_api_ret_code_OK) {
        std::cout << "Failed to commit" << std::endl;
        cps_api_transaction_close(&trans);
        return false;
    }

    cps_api_transaction_close(&trans);
    return true;
}

TEST(mcast_l3_route_msg, cps_add_route)
{
    std::cout << "Send cps route add request" << std::endl;
    for (auto& member: ut_member_list) {
        auto src_ip = std::get<2>(member);
        ASSERT_TRUE(send_config_route_req(std::get<0>(member),
                                          std::get<1>(member).c_str(), src_ip.empty() ? nullptr : src_ip.c_str(),
                                          std::get<3>(member),
                                          std::get<4>(member), std::get<5>(member), rt_op::ADD));
    }
}

TEST(mcast_l3_route_msg, cps_check_route)
{
    sleep(1);
    auto rd_route_list = nas_mc_l3_route_db_get(nullptr, nullptr, nullptr, nullptr, nullptr);
    ASSERT_EQ(rd_route_list.size(), 4);
    std::cout << "Route from DB:" << std::endl;
    for (auto route: rd_route_list) {
        std::cout << *route << std::endl;
    }
}

TEST(mcast_l3_route_msg, cps_update_route)
{
    std::cout << "Send cps route update request" << std::endl;
    size_t idx = 0;
    bool upd_to_cpu = false, upd_oif = false;
    for (auto& member: ut_member_list) {
        auto& src_ip = std::get<2>(member);
        auto& oif_list = std::get<4>(member);
        auto copy_to_cpu = std::get<5>(member);
        if (idx <= 2) {
            upd_oif = true;
            upd_to_cpu = false;
        } else {
            upd_oif = false;
            upd_to_cpu = true;
        }
        switch(idx) {
        case 0:
            oif_list.clear();
            break;
        case 1:
            oif_list.push_back(std::make_pair("e101-020-0", ""));
            oif_list.push_back(std::make_pair("e101-021-0", "e101-030-0"));
            break;
        case 2:
            oif_list.pop_back();
            break;
        case 3:
            copy_to_cpu = !copy_to_cpu;
            break;
        default:
            break;
        }
        ASSERT_TRUE(send_config_route_req(std::get<0>(member),
                                          std::get<1>(member).c_str(), src_ip.empty() ? nullptr : src_ip.c_str(),
                                          std::get<3>(member),
                                          oif_list, copy_to_cpu, rt_op::UPDATE, upd_to_cpu, upd_oif));
        idx ++;
    }
}

TEST(mcast_l3_route_msg, cps_check_route_1)
{
    sleep(1);
    auto rd_route_list = nas_mc_l3_route_db_get(nullptr, nullptr, nullptr, nullptr, nullptr);
    ASSERT_EQ(rd_route_list.size(), 4);
    std::cout << "After update, Route from DB:" << std::endl;
    for (auto route: rd_route_list) {
        std::cout << *route << std::endl;
    }
}

TEST(mcast_l3_route_msg, cps_delete_route)
{
    std::cout << "Send cps route delete request" << std::endl;
    for (auto& member: ut_member_list) {
        auto src_ip = std::get<2>(member);
        ASSERT_TRUE(send_config_route_req(std::get<0>(member),
                                          std::get<1>(member).c_str(), src_ip.empty() ? nullptr : src_ip.c_str(),
                                          std::get<3>(member),
                                          std::get<4>(member), std::get<5>(member), rt_op::DELETE));
    }
    sleep(1);
    auto rd_route_list = nas_mc_l3_route_db_get(nullptr, nullptr, nullptr, nullptr, nullptr);
    for (auto route: rd_route_list) {
        std::cout << *route << std::endl;
    }
    ASSERT_TRUE(rd_route_list.empty());
}

TEST(mcast_l3_route_msg, exit_msg_handle)
{
    ASSERT_TRUE(send_exit_msg());
    mcast_msg_handler_deinit();
}

struct std_socket_service_data_t
{
    std_socket_server_handle_t *thread_pool;
};

TEST(mcast_l3_route_msg, exit_cps_subsystem)
{
    sleep(1);
    auto sock_handle = static_cast<std_socket_service_data_t*>(cps_handle);
    ASSERT_EQ(std_socket_service_destroy(sock_handle->thread_pool), STD_ERR_OK);
}

int main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
