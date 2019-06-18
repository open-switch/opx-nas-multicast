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
 * filename: nas_mc_l3_walker_ut.cpp
 */

#include "nas_mc_l3_main.h"
#include "nas_mc_l3_cache.h"
#include "nas_mc_l3_msg.h"
#include "nas_mc_l3_util.h"
#include "nas_vrf_utils.h"
#include "hal_if_mapping.h"
#include "nas_mc_l3_walker.h"
#include "std_utils.h"
#include "std_thread_tools.h"

#include <tuple>
#include <set>
#include <algorithm>
#include <iostream>
#include <thread>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <thread>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>


const uint32_t TEST_VRF_ID = 100;
const char *TEST_IPV4_GRP_ADDR = "230.1.1.1";
const char *TEST_IPV4_SRC_ADDR = "202.3.1.1";
const char *TEST_IPV6_GRP_ADDR = "ff08::1";
const char *TEST_IPV6_SRC_ADDR = "1234:8888::1";

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
    if (route.rtype == L3_MCAST_ROUTE_TYPE_SG) {
        if (route.af == AF_INET) {
            inet_ntop(route.af, &route.src_ip.u.ipv4, ip_buf, sizeof(ip_buf));
        } else {
            inet_ntop(route.af, &route.src_ip.u.ipv6, ip_buf, sizeof(ip_buf));
        }
        os << " SRC " << ip_buf;
    } else {
        os << " SRC *";
    }

    os << " IIF " << route.iif_id;
    os << " OIF ";
    for (auto& oif: route.oif_list) {
        os << oif.first << ",";
    }
    os << " ]";

    return os;
}

const char *TEST_VRF_NAME = "test_vrf";

static bool send_mcast_enable_config(const char *vrf_name)
{
    t_mcast_msg_uptr pmsg_uptr = mcast_alloc_mem_msg(MCAST_STATUS);
    global_mcast_status_t *pmsg = dynamic_cast<global_mcast_status_t*>(pmsg_uptr.get());
    if (pmsg == nullptr) {
        return false;
    }
    pmsg->vrf_name.assign(vrf_name);
    pmsg->af = AF_INET;
    pmsg->mcast_status = true;
    pmsg->op = rt_op::ADD;

    if (!nas_mcast_process_msg(pmsg_uptr.release())) {
        std::cout << "Failure sending global status message" << std::endl;
        return false;
    }
    std::cout << "Success sending Mcast enable message for VRF " << vrf_name <<std::endl;

    return true;
}

static bool send_pim_enable_config(const char *vrf_name, const char *if_name)
{
    t_mcast_msg_uptr p_if_msg_uptr = mcast_alloc_mem_msg(PIM_STATUS);
    pim_status_t* p_if_msg = dynamic_cast<pim_status_t*>(p_if_msg_uptr.get());
    if (p_if_msg == nullptr) {
        return false;
    }
    p_if_msg->af = AF_INET;
    p_if_msg->pim_status = true;
    p_if_msg->intf_name.assign(if_name);
    p_if_msg->vrf_name.assign(vrf_name);
    p_if_msg->op = rt_op::ADD;

    if (!nas_mcast_process_msg(p_if_msg_uptr.release())) {
        std::cout << "Failure sending PIM status message for interface " << if_name << std::endl;
        return false;
    }
    std::cout << "Success sending PIM enable message for interface " << if_name <<std::endl;

    return true;
}
static void create_test_interfaces (const char *if_name)
{
    static int if_index = 101; //starting ifindex for test
    interface_ctrl_t r;
    memset(&r,0,sizeof(r));
    r.if_index = if_index++;
    safestrncpy (r.vrf_name, TEST_VRF_NAME, sizeof (r.vrf_name));
    safestrncpy (r.if_name, if_name, sizeof (r.if_name));

    ASSERT_TRUE(dn_hal_if_register(HAL_INTF_OP_REG,&r)==STD_ERR_OK);
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

TEST(mcast_l3_walker_test, init_handle)
{
    nas_vrf_ctrl_t vrf_info;
    memset(&vrf_info, 0, sizeof(vrf_info));
    safestrncpy(vrf_info.vrf_name, TEST_VRF_NAME, sizeof(vrf_info.vrf_name));
    vrf_info.vrf_int_id = 50;
    vrf_info.vrf_id = 2000;
    ASSERT_EQ(nas_update_vrf_info(NAS_VRF_OP_ADD, &vrf_info), STD_ERR_OK);

    std::vector<std::string> intf_list {{"e101-001-0"},
        {"e101-002-0"},
        {"e101-003-0"},
        {"e101-004-0"},
        {"e101-010-0"},
        {"e101-011-0"},
        {"e101-012-0"},
        {"e101-013-0"},
        {"e101-014-0"}};

    std::cout << "Adding test interfaces " << std::endl;
    for (auto& member: intf_list) {
        create_test_interfaces (member.c_str());
    }

    ASSERT_EQ(mcast_walker_handler_init(), STD_ERR_OK);
    ASSERT_EQ(mcast_msg_handler_init(), STD_ERR_OK);
    mcast_register_msg_handler(MCAST_STATUS, _set_global_mcast_status);
    mcast_register_msg_handler(PIM_STATUS, _set_pim_status);
    mcast_register_msg_handler(ROUTE_CONFIG, _program_route);
    mcast_register_msg_handler(MCAST_MSG_TYPE_MAX, mcast_msg_handler_exit);

    ASSERT_TRUE(send_mcast_enable_config(TEST_VRF_NAME));

    for (auto& member: intf_list) {
        ASSERT_TRUE(send_pim_enable_config(TEST_VRF_NAME, (const char*) member.c_str()));
    }
}


using rt_member_t = std::tuple<uint32_t, std::string, std::string, std::string, std::vector<std::pair<std::string, std::string>>, bool>;

// af, grp_ip, src_ip, iif, oif_list, to_cpu
std::vector<rt_member_t> ut_member_list {{AF_INET, "230.5.5.5", "", "e101-001-0", {{"e101-010-0", ""}, {"e101-011-0", "e101-012-0"}}, false},
                                         {AF_INET, "231.5.5.6", "1.2.3.4", "e101-002-0", {{"e101-010-0", ""}, {"e101-011-0", "e101-012-0"}}, true},
                                         {AF_INET6, "ff08:1::1", "1234:1111::2", "e101-003-0", {{"e101-013-0", "e101-014-0"}}, true},
                                         {AF_INET6, "ff09:1::2", "", "e101-004-0", {{"e101-013-0", "e101-014-0"}}, false}};


TEST(mcast_l3_walker_test, add_route)
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

TEST(mcast_l3_walker_test, check_route)
{
    sleep(1);
    auto rd_route_list = nas_mc_l3_route_db_get(nullptr, nullptr, nullptr, nullptr, nullptr);
    ASSERT_EQ(rd_route_list.size(), 4);
    std::cout << "Route from DB:" << std::endl;
    for (auto route: rd_route_list) {
        std::cout << *route << std::endl;
    }
}

TEST(mcast_l3_walker_test, delete_route)
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

TEST(mcast_l3_walker_test, exit_handle)
{
    bool ret = false;
    while (1)
    {
        nas_mc_l3_lock();
        ret = mcast_is_walker_pending_evt_list_empty();
        nas_mc_l3_unlock();
        if (ret == true)
            break;
        sleep (5);
    }
    ASSERT_TRUE(send_exit_msg());
    mcast_msg_handler_deinit();
    mcast_walker_handler_deinit();
}

int main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
