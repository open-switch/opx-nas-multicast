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
 * filename: nas_mc_l3_cps_ut.cpp
 */

#include "gtest/gtest.h"

#include "cps_api_operation.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "cps_api_events.h"
#include "nas_types.h"
#include "nas_vrf_utils.h"
#include "dell-base-acl.h"
#include "dell-base-if.h"
#include "dell-base-if-vlan.h"
#include "dell-interface.h"
#include "l3-multicast.h"
#include "std_ip_utils.h"
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <unordered_map>
#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>

using namespace std;

typedef struct oif_data_s {
    string   oif_name;
    bool     exclude_present;
    string   exclude_if_name;
} oif_data_t;

typedef struct mroute_info_t_ {
    const string vrf_name;
    const string iif_name;
    vector<string> group_ip;
    vector<string> src_ip;
    uint32_t af;
    uint32_t rt_type;
    vector<oif_data_t> oifs_name;
} mroute_info_t;


#define MAX_TEST_GROUPS 500
#define MAX_TEST_SOURCES 500

#define MAX_TEST_VRFS 1023

static bool is_non_default_vrf_test = false;
static uint32_t test_addr_family = AF_INET;
static uint32_t skip_obj_print_during_test = false;
static uint32_t source_count = 5;
static uint32_t group_count = 5;
static bool bulk_container = true;
static uint32_t vrf_count = 32;

static const string test_cmd_file = "/tmp/test_mcast_cfg";

static string TEST_VRF_NAME{"default"};
static string ROUTE_IF_NAME_1{"e101-001-0"};
static string ROUTE_OIF_NAME_1{"e101-002-0"};
static string ROUTE_OIF_NAME_2{"e101-003-0"};
static string ROUTE_IF_NAME_2{"e101-004-0"};
static const string INVALID_ROUTE_OIF_NAME_1{"e111-222-0"};
static const string NULL_STRING{""};
static vector<oif_data_t> ROUTE_OIF_LIST_1 = {{ROUTE_OIF_NAME_1, false, NULL_STRING}};
static vector<oif_data_t> ROUTE_OIF_LIST_2 = {{ROUTE_OIF_NAME_1, false, NULL_STRING}, {ROUTE_OIF_NAME_2, false, NULL_STRING}};
static vector<oif_data_t> ROUTE_OIF_LIST_3 = {{ROUTE_OIF_NAME_2, false, NULL_STRING}};
static vector<oif_data_t> INVALID_ROUTE_OIF_LIST_1 = {{INVALID_ROUTE_OIF_NAME_1, false, NULL_STRING}};

static string ROUTE_LAG_IF_NAME{"bo15"};
static string ROUTE_LAG_OIF_NAME{"bo16"};
static string ROUTE_LAG_VLAN_MBR_NAME{"bo17"};
static string ROUTE_LAG_VLAN_OIF_NAME{"br201"};
static vector<oif_data_t> ROUTE_LAG_OIF_LIST_1 = {{ROUTE_LAG_OIF_NAME, false, NULL_STRING}};
static vector<oif_data_t> ROUTE_LAG_OIF_LIST_2 = {{ROUTE_LAG_OIF_NAME, false, NULL_STRING}, {ROUTE_LAG_VLAN_OIF_NAME, false, NULL_STRING}};
static string LAG_IF_NAME_1{"e101-013-0"};
static string LAG_IF_NAME_2{"e101-014-0"};
static string LAG_IF_NAME_3{"e101-015-0"};
static string LAG_IF_NAME_4{"e101-016-0"};
static string LAG_IF_NAME_5{"e101-017-0"};
static string LAG_IF_NAME_6{"e101-018-0"};

static vector<string> TEST_NULL_LIST = {};
static vector<oif_data_t> TEST_OIF_NULL_LIST = {};
static vector<string> TEST_GRP_IP_ADDR = {"225.1.1.1"};
static vector<string> TEST_SRC_IP_ADDR = {"8.8.8.8"};
static vector<string> TEST_GRP_IPV4 = {"225.1.1.1"};
static vector<string> TEST_SRC_IPV4 = {"8.8.8.8"};
static vector<string> TEST_GRP_IPV6 = {"ff0e::8888"};
static vector<string> TEST_SRC_IPV6 = {"8888::8888"};
static vector<string> TEST_GRP_RANGE_IP_ADDR = {"226.0.0.0"};
static vector<string> TEST_SRC_RANGE_IP_ADDR = {"9.0.0.1"};
static vector<string> TEST_GRP_RANGE_IPV4 = {"226.0.0.0"};
static vector<string> TEST_SRC_RANGE_IPV4 = {"9.0.0.1"};
static vector<string> TEST_GRP_RANGE_IPV6 = {"ff0e::1:1"};
static vector<string> TEST_SRC_RANGE_IPV6 = {"8888::1:1"};
static vector<string> TEST_GRP_IPV4_LIST = {"225.0.0.5", "225.0.0.6", "225.0.0.7"};
static vector<string> TEST_SRC_IPV4_LIST = {"5.5.5.5", "6.6.6.6", "7.7.7.7"};
static vector<string> TEST_GRP_IPV6_LIST = {"ff0e::5", "ff0e::6", "ff0e::7"};
static vector<string> TEST_SRC_IPV6_LIST = {"5555::5555", "6666::6666", "7777::7777"};
static const uint_t IGMP_PROTO_ID = 2;
static const string L2VLAN_TYPE{"ianaift:l2vlan"};
static const string LAG_TYPE{"ianaift:ieee8023adLag"};


static string ROUTE_VLAN_IF_NAME_1{"br201"};
static string ROUTE_VLAN_OIF_NAME_1{"br202"};
static string ROUTE_VLAN_OIF_NAME_2{"br203"};
static vector<oif_data_t> ROUTE_VLAN_OIF_LIST_1 = {{ROUTE_VLAN_OIF_NAME_1, false, NULL_STRING}};
static vector<oif_data_t> ROUTE_VLAN_OIF_LIST_2 = {{ROUTE_VLAN_OIF_NAME_1, false, NULL_STRING}, {ROUTE_VLAN_OIF_NAME_2, false, NULL_STRING}};
static vector<oif_data_t> ROUTE_VLAN_OIF_LIST_3 = {{ROUTE_VLAN_OIF_NAME_2, false, NULL_STRING}};
static const string INVALID_ROUTE_VLAN_OIF_NAME_1{"br3999"};
static vector<oif_data_t> INVALID_ROUTE_VLAN_OIF_LIST_1 = {{INVALID_ROUTE_VLAN_OIF_NAME_1, false, NULL_STRING}};

static const string TEST_VLAN_4 {"br401"};
static const string TEST_VLAN_5 {"br501"};

static vector<string> TEST_VRF_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "ip vrf test_vrf_1",
                   "exit",
               };

static vector<string> TEST_VRF_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "no ip vrf test_vrf_1",
                   "exit",
               };

static vector<string> TEST_VRF_ROUTE_IF_NAME_1_L3_MODE_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/1",
                   "no switchport",
                   "ip vrf forwarding test_vrf_1",
                   "end",
               };

static vector<string> TEST_VRF_ROUTE_IF_NAME_1_L3_MODE_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/1",
                   "no ip vrf forwarding",
                   "switchport mode access",
                   "end",
               };

static vector<string> TEST_VRF_ROUTE_IF_NAME_2_L3_MODE_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/4",
                   "no switchport",
                   "ip vrf forwarding test_vrf_1",
                   "end",
               };

static vector<string> TEST_VRF_ROUTE_IF_NAME_2_L3_MODE_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/4",
                   "no ip vrf forwarding",
                   "switchport mode access",
                   "end",
               };

static vector<string> TEST_VRF_ROUTE_OIF_NAME_1_L3_MODE_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/2",
                   "no switchport",
                   "ip vrf forwarding test_vrf_1",
                   "end",
               };

static vector<string> TEST_VRF_ROUTE_OIF_NAME_1_L3_MODE_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/2",
                   "no ip vrf forwarding",
                   "switchport mode access",
                   "end",
               };

static vector<string> TEST_VRF_ROUTE_OIF_NAME_2_L3_MODE_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/3",
                   "no switchport",
                   "ip vrf forwarding test_vrf_1",
                   "end",
               };

static vector<string> TEST_VRF_ROUTE_OIF_NAME_2_L3_MODE_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/3",
                   "no ip vrf forwarding",
                   "switchport mode access",
                   "end",
               };

static vector<string> TEST_INTF_VLAN_1_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 201",
                   "no ip address",
                   "no ipv6 address",
                   "end",
               };

static vector<string> TEST_INTF_VLAN_2_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 202",
                   "no ip address",
                   "no ipv6 address",
                   "end",
               };

static vector<string> TEST_INTF_VLAN_3_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 203",
                   "no ip address",
                   "no ipv6 address",
                   "end",
               };

static vector<string> TEST_INTF_VLAN_1_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "no interface vlan 201",
                   "end",
               };

static vector<string> TEST_INTF_VLAN_2_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "no interface vlan 202",
                   "end",
               };

static vector<string> TEST_INTF_VLAN_3_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "no interface vlan 203",
                   "end",
               };


static vector<string> TEST_VRF_ROUTE_VLAN_IF_NAME_1_L3_MODE_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 201",
                   "ip vrf forwarding test_vrf_1",
                   "end",
               };

static vector<string> TEST_VRF_ROUTE_VLAN_IF_NAME_1_L3_MODE_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 201",
                   "no ip address",
                   "no ipv6 address",
                   "no ip vrf forwarding",
                   "end",
               };

static vector<string> TEST_VRF_ROUTE_VLAN_OIF_NAME_1_L3_MODE_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 202",
                   "ip vrf forwarding test_vrf_1",
                   "end",
               };

static vector<string> TEST_VRF_ROUTE_VLAN_OIF_NAME_1_L3_MODE_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 202",
                   "no ip address",
                   "no ipv6 address",
                   "no ip vrf forwarding",
                   "end",
               };

static vector<string> TEST_VRF_ROUTE_VLAN_OIF_NAME_2_L3_MODE_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 203",
                   "ip vrf forwarding test_vrf_1",
                   "end",
               };

static vector<string> TEST_VRF_ROUTE_VLAN_OIF_NAME_2_L3_MODE_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 203",
                   "no ip address",
                   "no ipv6 address",
                   "no ip vrf forwarding",
                   "end",
               };

static vector<string> TEST_VLAN_MBR_1_MODE_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/11",
                   "switchport mode trunk",
                   "exit",
               };
static vector<string> TEST_VLAN_MBR_2_MODE_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/12",
                   "switchport mode trunk",
                   "exit",
               };

static vector<string> TEST_VLAN_MBR_1_MODE_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/11",
                   "no switchport",
                   "exit",
               };
static vector<string> TEST_VLAN_MBR_2_MODE_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/12",
                   "no switchport",
                   "exit",
               };

static vector<string> TEST_VLAN_1_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 201",
                   "ip address 201.201.201.1/24",
                   "ipv6 address 201:201:201::1/64",
                   "exit",
                   "interface ethernet 1/1/11",
                   "switchport mode trunk",
                   "switchport trunk allowed vlan 201",
                   "exit",
                   "interface ethernet 1/1/12",
                   "switchport mode trunk",
                   "switchport trunk allowed vlan 201",
                   "exit",
               };

static vector<string> TEST_VLAN_2_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 202",
                   "ip address 202.202.202.1/24",
                   "ipv6 address 202:202:202::1/64",
                   "exit",
                   "interface ethernet 1/1/11",
                   "switchport mode trunk",
                   "switchport trunk allowed vlan 202",
                   "exit",
                   "interface ethernet 1/1/12",
                   "switchport mode trunk",
                   "switchport trunk allowed vlan 202",
                   "exit",
               };

static vector<string> TEST_VLAN_3_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 203",
                   "ip address 203.203.203.1/24",
                   "ipv6 address 203:203:203::1/64",
                   "exit",
                   "interface ethernet 1/1/11",
                   "switchport mode trunk",
                   "switchport trunk allowed vlan 203",
                   "exit",
                   "interface ethernet 1/1/12",
                   "switchport mode trunk",
                   "switchport trunk allowed vlan 203",
                   "exit",
               };

static vector<string> TEST_VLAN_4_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 401",
                   "ip address 41.41.41.1/24",
                   "ipv6 address 41:41:41::1/64",
                   "exit",
                   "interface ethernet 1/1/11",
                   "switchport mode trunk",
                   "switchport trunk allowed vlan 401",
                   "exit",
                   "interface ethernet 1/1/12",
                   "switchport mode trunk",
                   "switchport trunk allowed vlan 401",
                   "exit",
               };

static vector<string> TEST_VLAN_4_CLI_NO_SHUT_IP_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 401",
                   "no shutdown",
                   "ip address 41.41.41.1/24",
                   "ipv6 address 41:41:41::1/64",
                   "exit",
               };



static vector<string> TEST_VLAN_1_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/11",
                   "no switchport trunk allowed vlan 201",
                   "exit",
                   "interface ethernet 1/1/12",
                   "no switchport trunk allowed vlan 201",
                   "exit",
                   "interface vlan 201",
                   "no ip address",
                   "no ipv6 address",
                   "exit",
               };

static vector<string> TEST_VLAN_2_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/11",
                   "no switchport trunk allowed vlan 202",
                   "exit",
                   "interface ethernet 1/1/12",
                   "no switchport trunk allowed vlan 202",
                   "exit",
                   "interface vlan 202",
                   "no ip address",
                   "no ipv6 address",
                   "exit",
               };

static vector<string> TEST_VLAN_3_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/11",
                   "no switchport trunk allowed vlan 203",
                   "exit",
                   "interface ethernet 1/1/12",
                   "no switchport trunk allowed vlan 203",
                   "exit",
                   "interface vlan 203",
                   "no ip address",
                   "no ipv6 address",
                   "exit",
               };

static vector<string> TEST_VLAN_4_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/11",
                   "no switchport trunk allowed vlan 401",
                   "exit",
                   "interface ethernet 1/1/12",
                   "no switchport trunk allowed vlan 401",
                   "exit",
                   "interface vlan 401",
                   "no ip address",
                   "no ipv6 address",
                   "exit",
                   "no interface vlan 401",
                   "exit",
               };

static vector<string> TEST_VLAN_4_CLI_SHUT_NO_IP_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 401",
                   "no ip address",
                   "no ipv6 address",
                   "shutdown",
                   "exit",
               };

static vector<string> TEST_ROUTE_IF_NAME_1_L3_MODE_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/1",
                   "no switchport",
                   "exit",
               };

static vector<string> TEST_ROUTE_IF_NAME_1_L2_MODE_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/1",
                   "switchport mode access",
                   "exit",
               };

static vector<string> TEST_ROUTE_IF_NAME_2_L3_MODE_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/4",
                   "no switchport",
                   "exit",
               };

static vector<string> TEST_ROUTE_IF_NAME_2_L2_MODE_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/4",
                   "switchport mode access",
                   "exit",
               };

static vector<string> TEST_ROUTE_OIF_NAME_1_L3_MODE_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/2",
                   "no switchport",
                   "exit",
               };

static vector<string> TEST_ROUTE_OIF_NAME_1_L2_MODE_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/2",
                   "switchport mode access",
                   "exit",
               };

static vector<string> TEST_ROUTE_OIF_NAME_2_L3_MODE_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/3",
                   "no switchport",
                   "exit",
               };

static vector<string> TEST_ROUTE_OIF_NAME_2_L2_MODE_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/3",
                   "switchport mode access",
                   "exit",
               };

static vector<string> TEST_ROUTE_EXL_1_IIF_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 901",
                   "exit",
                   "interface ethernet 1/1/10",
                   "switchport mode trunk",
                   "switchport trunk allowed vlan 901",
                   "exit",
                   "interface ethernet 1/1/11",
                   "switchport mode trunk",
                   "switchport trunk allowed vlan 901",
                   "exit",
                   "interface ethernet 1/1/12",
                   "switchport mode trunk",
                   "switchport trunk allowed vlan 901",
                   "exit",
};
static vector<string> TEST_ROUTE_EXL_1_IIF_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/10",
                   "no switchport trunk allowed vlan 901",
                   "exit",
                   "interface ethernet 1/1/11",
                   "no switchport trunk allowed vlan 901",
                   "exit",
                   "interface ethernet 1/1/12",
                   "no switchport trunk allowed vlan 901",
                   "exit",
                   "no interface vlan 901",
                   "exit",
};


static vector<string> TEST_ROUTE_EXL_1_OIF_1_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 905",
                   "exit",
                   "interface ethernet 1/1/15",
                   "switchport mode trunk",
                   "switchport trunk allowed vlan 905",
                   "exit",
                   "interface ethernet 1/1/16",
                   "switchport mode trunk",
                   "switchport trunk allowed vlan 905",
                   "exit",
                   "interface ethernet 1/1/17",
                   "switchport mode trunk",
                   "switchport trunk allowed vlan 905",
                   "exit",
};
static vector<string> TEST_ROUTE_EXL_1_OIF_1_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/15",
                   "no switchport trunk allowed vlan 905",
                   "exit",
                   "interface ethernet 1/1/16",
                   "no switchport trunk allowed vlan 905",
                   "exit",
                   "interface ethernet 1/1/17",
                   "no switchport trunk allowed vlan 905",
                   "exit",
                   "no interface vlan 905",
                   "exit",
};

static vector<string> TEST_ROUTE_EXL_1_OIF_2_CFG = {
                   "end",
                   "configure terminal",
                   "interface vlan 910",
                   "exit",
                   "interface ethernet 1/1/20",
                   "switchport mode trunk",
                   "switchport trunk allowed vlan 910",
                   "exit",
                   "interface ethernet 1/1/21",
                   "switchport mode trunk",
                   "switchport trunk allowed vlan 910",
                   "exit",
                   "interface ethernet 1/1/22",
                   "switchport mode trunk",
                   "switchport trunk allowed vlan 910",
                   "exit",
};

static vector<string> TEST_ROUTE_EXL_1_OIF_2_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/20",
                   "no switchport trunk allowed vlan 910",
                   "exit",
                   "interface ethernet 1/1/21",
                   "no switchport trunk allowed vlan 910",
                   "exit",
                   "interface ethernet 1/1/22",
                   "no switchport trunk allowed vlan 910",
                   "exit",
                   "no interface vlan 910",
                   "exit",
};

static vector<string> TEST_LAG_L3_1_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface port-channel15",
                   "exit",
               };

static vector<string> TEST_LAG_L3_2_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface port-channel16",
                   "exit",
               };

static vector<string> TEST_LAG_L2_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface port-channel17",
                   "exit",
               };

static vector<string> TEST_LAG_L3_1_CLI_DYN_CFG = {
                   "end",
                   "configure terminal",
                   "interface port-channel15",
                   "no switchport",
                   "ip address 204.204.204.1/24",
                   "ipv6 address 204:204:204::1/64",
                   "exit",
                   "interface ethernet 1/1/13",
                   "no switchport",
                   "channel-group 15 mode on",
                   "exit",
                   "interface ethernet 1/1/14",
                   "no switchport",
                   "channel-group 15 mode on",
                   "exit",
               };

static vector<string> TEST_LAG_L3_2_CLI_DYN_CFG = {
                   "end",
                   "configure terminal",
                   "interface port-channel16",
                   "no switchport",
                   "ip address 205.205.205.1/24",
                   "ipv6 address 205:205:205::1/64",
                   "exit",
                   "interface ethernet 1/1/15",
                   "no switchport",
                   "channel-group 16 mode on",
                   "exit",
                   "interface ethernet 1/1/16",
                   "no switchport",
                   "channel-group 16 mode on",
                   "exit",
               };

static vector<string> TEST_LAG_L2_CLI_DYN_CFG = {
                   "end",
                   "configure terminal",
                   "interface port-channel17",
                   "switchport mode access",
                   "switchport access vlan 201",
                   "exit",
                   "interface ethernet 1/1/17",
                   "no switchport",
                   "channel-group 17 mode on",
                   "exit",
                   "interface ethernet 1/1/18",
                   "no switchport",
                   "channel-group 17 mode on",
                   "exit",
               };

static vector<string> TEST_LAG_L3_1_VRF_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface port-channel15",
                   "no switchport",
                   "ip vrf forwarding test_vrf_1",
                   "exit",
               };

static vector<string> TEST_LAG_L3_2_VRF_CLI_CFG = {
                   "end",
                   "configure terminal",
                   "interface port-channel16",
                   "no switchport",
                   "ip vrf forwarding test_vrf_1",
                   "exit",
               };

static vector<string> TEST_LAG_L3_1_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "no interface port-channel15",
               };

static vector<string> TEST_LAG_L3_2_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "no interface port-channel16",
               };

static vector<string> TEST_LAG_L2_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "no interface port-channel17",
               };

static vector<string> TEST_LAG_L3_1_CLI_NO_DYN_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/13",
                   "no channel-group",
                   "exit",
                   "interface ethernet 1/1/14",
                   "no channel-group",
                   "exit",
                   "interface port-channel15",
                   "no ip address",
                   "no ipv6 address",
                   "exit",
               };

static vector<string> TEST_LAG_L3_2_CLI_NO_DYN_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/15",
                   "no channel-group",
                   "exit",
                   "interface ethernet 1/1/16",
                   "no channel-group",
                   "exit",
                   "interface port-channel16",
                   "no ip address",
                   "no ipv6 address",
                   "exit",
               };

static vector<string> TEST_LAG_L2_CLI_NO_DYN_CFG = {
                   "end",
                   "configure terminal",
                   "interface ethernet 1/1/17",
                   "no channel-group",
                   "exit",
                   "interface ethernet 1/1/18",
                   "no channel-group",
                   "exit",
                   "interface port-channel17",
                   "no switchport access vlan",
                   "exit",
               };

static vector<string> TEST_LAG_L3_1_VRF_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface port-channel15",
                   "no ip vrf forwarding",
                   "exit",
                   "no interface port-channel15",
               };

static vector<string> TEST_LAG_L3_2_VRF_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "interface port-channel16",
                   "no ip vrf forwarding",
                   "exit",
                   "no interface port-channel16",
               };

static vector<string> TEST_LAG_L2_VRF_CLI_NO_CFG = {
                   "end",
                   "configure terminal",
                   "no interface port-channel17",
               };

static bool string_equal (const string &string1, const string &string2)
{
    bool   compare_result;

    compare_result = (string1.compare(string2));
    return (!compare_result);
}

static bool find_string_in_vector (const string &target, vector<string>  &in_vector)
{
    for (std::vector<string>::iterator it = in_vector.begin();
         it != in_vector.end(); ++it) {
        if (string_equal(target, *it)) {
            return (true);
        }
    }
    return false;
}

bool string_vector_equivalent (vector<string> &vector1, vector<string> &vector2)
{

    // Determine if the the two vectors are the same size and if every string
    // in the first vector is contained in the second vector.

    if (vector1.size() != vector2.size()) {
        return false;
    }

    for (std::vector<string>::iterator it = vector1.begin() ;
         it != vector1.end(); ++it) {
        if (!find_string_in_vector(*it, vector2)) {
            return false;
        }
    }

    return true;
}

static bool find_oif_in_vector (oif_data_t &target, vector<oif_data_t> &in_vector)
{
    for (std::vector<oif_data_t>::iterator it = in_vector.begin();
         it != in_vector.end(); ++it) {
        if ((string_equal(target.oif_name, it->oif_name))
                && (target.exclude_present == it->exclude_present)) {
            bool ret = true;
            if ((target.exclude_present) &&
                !string_equal(target.exclude_if_name, it->exclude_if_name)) {
                ret = false;
            }
            return ret;
        }
    }
    return false;
}

static bool oif_list_vector_equivalent (vector <oif_data_t> &v1,
                                        vector<oif_data_t> &v2)
{
    if (v1.size() != v2.size()) return false;

    for (std::vector<oif_data_t>::iterator it = v1.begin() ; it != v1.end();
         ++it) {
        if (!find_oif_in_vector(*it, v2)) {
            return false;
        }
    }

    return true;
}

static void send_cfg_to_switch (vector<string> &cmd_vect)
{
    ofstream myfile;
    myfile.open (test_cmd_file.c_str());

    for (size_t i = 0; i < cmd_vect.size(); i++)
    {
        myfile << cmd_vect[i].c_str() << "\n";
        std::cout << cmd_vect[i].c_str() << "\n";
    }
    myfile << "\n";
    myfile.close();
    system("sudo -u admin clish --b /tmp/test_mcast_cfg");
    sleep (1);
}

static void mcast_vrf_dump_object_content (cps_api_object_t obj)
{
    cps_api_object_attr_t vrf_attr;
    cps_api_object_attr_t af_attr;

    vrf_attr = cps_api_get_key_data(obj, L3_MCAST_GLOBAL_VRF_NAME);
    af_attr = cps_api_get_key_data(obj, L3_MCAST_GLOBAL_AF);

    if (vrf_attr != NULL) {
        char vrf_name[256];
        memset(vrf_name,'\0',sizeof(vrf_name));
        memcpy(vrf_name, cps_api_object_attr_data_bin(vrf_attr), cps_api_object_attr_len(vrf_attr));
        std::cout<<"    VRF-name: "<<vrf_name<<std::endl;
    }
    if (af_attr != NULL) {
        uint32_t af = 0;
        af = cps_api_object_attr_data_u32(af_attr);
        std::cout<<"    AF: "<<af<<std::endl;
    }

    cps_api_object_attr_t status_attr;
    status_attr = cps_api_object_attr_get(obj, L3_MCAST_GLOBAL_STATUS);
    if (status_attr != NULL) {
        bool val = cps_api_object_attr_data_uint(status_attr);
        std::cout<<"    Status: "<< val <<std::endl;
    }
}

static void mcast_intf_dump_object_content (cps_api_object_t obj)
{
    cps_api_object_attr_t vrf_attr;
    cps_api_object_attr_t intf_attr;
    cps_api_object_attr_t af_attr;

    vrf_attr = cps_api_get_key_data(obj,
                                    L3_MCAST_INTERFACES_INTERFACE_VRF_NAME);
    intf_attr = cps_api_get_key_data(obj, L3_MCAST_INTERFACES_INTERFACE_NAME);
    af_attr = cps_api_get_key_data(obj, L3_MCAST_INTERFACES_INTERFACE_AF);

    if (vrf_attr != NULL) {
        char vrf_name[256];
        memset(vrf_name,'\0',sizeof(vrf_name));
        memcpy(vrf_name, cps_api_object_attr_data_bin(vrf_attr), cps_api_object_attr_len(vrf_attr));
        std::cout<<"    VRF-name: "<<vrf_name<<std::endl;
    }
    if (af_attr != NULL) {
        uint32_t af = 0;
        af = cps_api_object_attr_data_u32(af_attr);
        std::cout<<"    AF: "<<af<<std::endl;
    }
    if (intf_attr != NULL) {
        char intf_name[256];
        memset(intf_name,'\0',sizeof(intf_name));
        memcpy(intf_name, cps_api_object_attr_data_bin(intf_attr), cps_api_object_attr_len(intf_attr));
        std::cout<<"    Intf-name: "<< intf_name <<std::endl;
    }
    cps_api_object_attr_t status_attr;
    status_attr = cps_api_object_attr_get(obj,
                                          L3_MCAST_INTERFACES_INTERFACE_STATUS);
    if (status_attr != NULL) {
        bool val = cps_api_object_attr_data_uint(status_attr);
        std::cout<<"    Status: "<< val <<std::endl;
    }
}


static void mcast_route_dump_object_content (cps_api_object_t obj)
{

    void *p_ip_addr = NULL;
    uint32_t af = 0;
    int addr_len;
    char str[INET6_ADDRSTRLEN];

    cps_api_object_it_t it;
    cps_api_object_it_begin(obj,&it);

    cps_api_object_attr_t vrf_attr;
    cps_api_object_attr_t af_attr;
    cps_api_object_attr_t grp_attr;
    cps_api_object_attr_t src_attr;
    cps_api_object_attr_t rt_type_attr;

    vrf_attr = cps_api_get_key_data(obj, L3_MCAST_ROUTES_ROUTE_VRF_NAME);
    af_attr = cps_api_get_key_data(obj, L3_MCAST_ROUTES_ROUTE_AF);
    src_attr = cps_api_get_key_data(obj, L3_MCAST_ROUTES_ROUTE_SOURCE_IP);
    grp_attr = cps_api_get_key_data(obj, L3_MCAST_ROUTES_ROUTE_GROUP_IP);
    rt_type_attr = cps_api_get_key_data(obj, L3_MCAST_ROUTES_ROUTE_RT_TYPE);

    if (vrf_attr != NULL) {
        char vrf_name[256];
        memset(vrf_name,'\0',sizeof(vrf_name));
        memcpy(vrf_name, cps_api_object_attr_data_bin(vrf_attr), cps_api_object_attr_len(vrf_attr));
        std::cout<<"    VRF-name: "<<vrf_name<<std::endl;
    }
    if (af_attr != NULL) {
        af = cps_api_object_attr_data_u32(af_attr);
        std::cout<<"    AF: "<<af<<std::endl;
    }
    if (src_attr != NULL) {
        p_ip_addr = cps_api_object_attr_data_bin(src_attr);

        if (af == AF_INET || af == AF_INET6) {
            addr_len = ((af == AF_INET6)?INET6_ADDRSTRLEN:INET_ADDRSTRLEN);
            std::cout << "    Source Address: " <<
                inet_ntop(af,p_ip_addr,str, addr_len)<<std::endl;
        }
    }
    if (grp_attr != NULL) {
        p_ip_addr = cps_api_object_attr_data_bin(grp_attr);

        if (af == AF_INET || af == AF_INET6) {
            addr_len = ((af == AF_INET6)?INET6_ADDRSTRLEN:INET_ADDRSTRLEN);
            std::cout << "    Group Address: "<<inet_ntop(af, p_ip_addr, str,
                    addr_len)<<std::endl;
        }
    }
    if (rt_type_attr != NULL) {
        uint32_t rt_type = cps_api_object_attr_data_u32(rt_type_attr);
        std::cout<<"    RT Type: "<<rt_type<<std::endl;
    }

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it)) {
       switch (cps_api_object_attr_id(it.attr)) {

            case L3_MCAST_ROUTES_ROUTE_IIF_NAME:
                char if_name[256];
                memset(if_name,'\0',sizeof(if_name));
                memcpy(if_name, cps_api_object_attr_data_bin(it.attr), cps_api_object_attr_len(it.attr));
                std::cout<<"    IIF-name: "<<if_name<<std::endl;
                break;

            case L3_MCAST_ROUTES_ROUTE_DATA_TO_CPU:
                uint32_t cp_to_cpu;
                cp_to_cpu = cps_api_object_attr_data_u32(it.attr);
                std::cout<<"    CopyToCPU: "<<cp_to_cpu<<std::endl;
                break;

            case L3_MCAST_ROUTES_ROUTE_NPU_PRG_DONE:
                uint32_t npu_prg_done;
                npu_prg_done = cps_api_object_attr_data_u32(it.attr);
                std::cout<<"    NPU Program Status: "<<npu_prg_done<<std::endl;
                break;

            case L3_MCAST_ROUTES_ROUTE_OIF:
                {
                    if (cps_api_object_attr_len(it.attr) > 0)
                    {
                        cps_api_object_it_t oif_it = it;

                        for (cps_api_object_it_inside(&oif_it);
                             cps_api_object_it_valid(&oif_it);
                             cps_api_object_it_next(&oif_it))
                        {
                            cps_api_object_it_t in_oif_it = oif_it;

                            for (cps_api_object_it_inside(&in_oif_it);
                                 cps_api_object_it_valid(&in_oif_it);
                                 cps_api_object_it_next(&in_oif_it))
                            {
                                cps_api_attr_id_t in_oif_id =
                                    cps_api_object_attr_id(in_oif_it.attr);
                                switch(in_oif_id)
                                {
                                    case L3_MCAST_ROUTES_ROUTE_OIF_NAME:
                                        {
                                            const char *oif =
                                                ((const char *)
                                                 cps_api_object_attr_data_bin(
                                                     in_oif_it.attr));
                                            std::cout << "    OIF-name: " <<
                                                oif<<std::endl;
                                        }
                                        break;
                                    case L3_MCAST_ROUTES_ROUTE_OIF_EXCLUDE_INTERFACE:
                                        {
                                            const char *oif_excl_if =
                                                ((const char *)
                                                 cps_api_object_attr_data_bin(
                                                     in_oif_it.attr));
                                            std::cout << "        Exclude "
                                                         "Intf-name: " <<
                                                         oif_excl_if<<std::endl;
                                        }
                                        break;
                                    default:
                                        break;
                                }
                            }
                        }
                    }
                }
                break;

            default:
                break;
       }
    }
}

static void add_offset_to_char_array (unsigned char *array, uint32_t offset,
                                      uint32_t size)
{
    int addr_offset;
    uint32_t sum;
    uint32_t carry;

    for (addr_offset = size - 1; addr_offset >= 0; addr_offset--) {
        sum = (uint32_t)(array[addr_offset]) + offset;
        array[addr_offset] = (sum & 0xff);
        carry = sum >> 8;
        if (!carry) {
            break;
        }
        offset = carry;
    }

    if (carry) {
        cout << "IP address overflow in adding " << offset <<
             "to the input address." << endl;
    }
}

static void ipv4_address_add (struct in_addr *buf, uint32_t offset)
{
    unsigned char ip_bytes[4];
    int byte_index;
    unsigned char *buf_ptr;
 
    //Store network ordered bytes in a character array for endian independent
    //adding
    for (byte_index = 0; byte_index < 4; byte_index++) {
        ip_bytes[byte_index] = ((unsigned char *)(&buf->s_addr))[byte_index];
    }

    //Do the endian independent adding to the netowrk ordered IP address.
    add_offset_to_char_array(ip_bytes, offset, 4);

    //Store the result in network order.
    buf_ptr = (unsigned char *)(&buf->s_addr);
    for (byte_index = 0; byte_index < 4; byte_index++) {
        buf_ptr[byte_index] = ip_bytes[byte_index];
    }

//  buf->s_addr += offset;
}

static void ipv6_address_add (struct in6_addr *buf, uint32_t offset)
{
    add_offset_to_char_array(buf->s6_addr, offset, sizeof(buf->s6_addr));
}

// Calculate the value of the IP address string equal to the input base IP
// string offset by the specified amount. 
static vector <string>  string_ip_addr_add (uint32_t af,
                                            vector <string> in_string_ip,
                                            uint32_t offset)
{
    char str[INET6_ADDRSTRLEN];
    unsigned char buf[sizeof(struct in6_addr)];
    vector <string> null_result = {};
    vector <string> out_string = {""};
    int s;


    // Convert the input IP address string to a (numerical) struct of the
    // appropriate type for the specified AF.
    s = inet_pton(af, in_string_ip[0].c_str(), buf);
    if (s != 1) {
        if (s == 0) {
            cout << "Invalid input IP address string for IP address string add."
                 << endl;
        } else {
            cout << "Invalid input AF " << af << " for IP address string add."
                 << endl;
        }
        return null_result;
    }

    // Add the specified offset to the integer value of the IP address struct.
    if (af == AF_INET) {
        ipv4_address_add(((struct in_addr *)buf), offset);
    } else {
        ipv6_address_add(((struct in6_addr *)buf), offset);
    }

    // Convert the result back to string format.
    if (inet_ntop(af, buf, str, INET6_ADDRSTRLEN) == NULL) {
        cout << "Invalid result for converted IP address address sum." << endl;
        return null_result;
    }

    out_string[0].assign((const char *)str);
    return out_string;
}
                
static void mc_print_time (const char *event)
{
    time_t rawtime;
    char print_buff[200];

    time (&rawtime);
    snprintf(print_buff, 199, "%s", ctime(&rawtime));
    cout << event << ": " << print_buff << endl;
}

static bool vrf_get_mcast_status (const string &vrf_name,
        uint32_t af, bool validate_status, bool status)
{
    bool ret = false;
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);
    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj), L3_MCAST_GLOBAL_OBJ,
            cps_api_qualifier_OBSERVED);

    cps_api_set_key_data (obj, L3_MCAST_GLOBAL_VRF_NAME,
            cps_api_object_ATTR_T_BIN,vrf_name.c_str(), vrf_name.size() + 1);

    if (af == AF_INET) {
        af = BASE_CMN_AF_TYPE_INET;
    } else {
        af = BASE_CMN_AF_TYPE_INET6;
    }
    cps_api_set_key_data (obj, L3_MCAST_GLOBAL_AF,
            cps_api_object_ATTR_T_U32, &af, sizeof (af));


    if (skip_obj_print_during_test != true) {
        std::cout<<"VRF object content sent for GET: " <<std::endl;
        mcast_vrf_dump_object_content (obj);
        std::cout<<"--------------------------------"<<std::endl;
    }

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);

        for ( size_t ix = 0 ; ix < mx ; ++ix ) {
            obj = cps_api_object_list_get(gp.list,ix);

            if (skip_obj_print_during_test != true) {
                std::cout<<"VRF object content received from GET: " <<std::endl;
                mcast_vrf_dump_object_content (obj);
                std::cout<<"-------------------------------------"<<std::endl;
            }
            cps_api_object_attr_t status_attr = cps_api_object_attr_get(obj, L3_MCAST_GLOBAL_STATUS);

            if (!validate_status) {
                ret = true;
            } else if (status_attr != NULL) {
                bool val = cps_api_object_attr_data_uint(status_attr);
                if (val == status)
                    ret = true;
            }
        }
    }

    if (status && !ret) {
        cout << "VRF Mcast status get failed." << endl;
    }

    cps_api_get_request_close(&gp);
    return ret;
}


static bool vrf_mcast_status (const string &vrf_name,
                              uint32_t af, bool status)
{
    cps_api_object_t             obj;
    bool ret = false;

    obj = cps_api_object_create();
    if (obj == NULL ) return 0;
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    L3_MCAST_GLOBAL_OBJ,
                                    cps_api_qualifier_TARGET);
    if (af == AF_INET) {
        af = BASE_CMN_AF_TYPE_INET;
    }
    else {
        af = BASE_CMN_AF_TYPE_INET6;
    }
    cps_api_object_attr_add(obj, L3_MCAST_GLOBAL_VRF_NAME, vrf_name.c_str(),
                            vrf_name.size() + 1);
    cps_api_object_attr_add_u32(obj, L3_MCAST_GLOBAL_AF, af);
    cps_api_object_attr_add(obj, L3_MCAST_GLOBAL_STATUS, &status, sizeof(status));

    cps_api_transaction_params_t tr;
    if(cps_api_transaction_init(&tr)!=cps_api_ret_code_OK) {
      cps_api_object_delete(obj);
      return false;
    }

   if(status)
      cps_api_create(&tr,obj);
    else
      cps_api_delete(&tr,obj);

    if (skip_obj_print_during_test != true) {
        cout << "Input object for COMMIT: " << endl;
        cps_api_object_print(obj);
    }
    if (cps_api_commit(&tr) == cps_api_ret_code_OK) ret = true;

    cps_api_transaction_close(&tr);

    sleep (2);
    return ret;
}

static bool intf_get_pim_status (const string &vrf_name, const string &if_name,
        uint32_t af, bool validate_status, bool status)
{
    bool ret = false;
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);
    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj), L3_MCAST_INTERFACES_INTERFACE,
            cps_api_qualifier_OBSERVED);

    cps_api_set_key_data (obj, L3_MCAST_INTERFACES_INTERFACE_VRF_NAME,
            cps_api_object_ATTR_T_BIN,vrf_name.c_str(), vrf_name.size() + 1);
    cps_api_set_key_data (obj, L3_MCAST_INTERFACES_INTERFACE_NAME,
            cps_api_object_ATTR_T_BIN,if_name.c_str(), if_name.size() + 1);

    if (af == AF_INET) {
        af = BASE_CMN_AF_TYPE_INET;
    } else {
        af = BASE_CMN_AF_TYPE_INET6;
    }
    cps_api_set_key_data (obj, L3_MCAST_INTERFACES_INTERFACE_AF,
            cps_api_object_ATTR_T_U32, &af, sizeof (af));


    //std::cout<<"Intf object content sent for GET: " <<std::endl;
    //mcast_intf_dump_object_content (obj);
    //std::cout<<"-----------------------------"<<std::endl;

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);

        for ( size_t ix = 0 ; ix < mx ; ++ix ) {
            obj = cps_api_object_list_get(gp.list,ix);

            if (skip_obj_print_during_test != true) {
                std::cout<<"Intf object content received from GET: " <<
                    std::endl;
                mcast_intf_dump_object_content (obj);
                std::cout<<"-----------------------------"<<std::endl;
            }
            cps_api_object_attr_t status_attr = cps_api_object_attr_get(obj,
                    L3_MCAST_INTERFACES_INTERFACE_STATUS);

            if (!validate_status) {
                ret = true;
            } else if (status_attr != NULL) {
                bool val = cps_api_object_attr_data_uint(status_attr);
                if (val == status)
                    ret = true;
            }
        }
    }

    if (!ret)
        std::cout<<"Interface PIM status get failed."<<std::endl;

    cps_api_get_request_close(&gp);
    return ret;
}



static bool intf_pim_status (const string &vrf_name, const string &if_name,
                             uint32_t af, bool status)
{
    cps_api_object_t             obj;
    bool ret = false;

    obj = cps_api_object_create();
    if (obj == NULL ) return 0;
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj), L3_MCAST_INTERFACES_INTERFACE,
                                    cps_api_qualifier_TARGET);
    if (af == AF_INET) {
        af = BASE_CMN_AF_TYPE_INET;
    }
    else {
        af = BASE_CMN_AF_TYPE_INET6;
    }
    cps_api_object_attr_add(obj, L3_MCAST_INTERFACES_INTERFACE_VRF_NAME,
                            vrf_name.c_str(), vrf_name.size() + 1);
    cps_api_object_attr_add(obj, L3_MCAST_INTERFACES_INTERFACE_NAME,
                            if_name.c_str(), if_name.size() + 1);
    cps_api_object_attr_add_u32(obj, L3_MCAST_INTERFACES_INTERFACE_AF, af);
    cps_api_object_attr_add(obj, L3_MCAST_INTERFACES_INTERFACE_STATUS,
                            &status, sizeof(status));

    cps_api_transaction_params_t tr;
    if(cps_api_transaction_init(&tr)!=cps_api_ret_code_OK) {
      cps_api_object_delete(obj);
      return false;
    }

   if(status)
      cps_api_create(&tr,obj);
    else
      cps_api_delete(&tr,obj);

    if (skip_obj_print_during_test != true) {
        cout << "Input object for COMMIT: " << endl;
        cps_api_object_print(obj);
    }
    if (cps_api_commit(&tr) == cps_api_ret_code_OK) ret = true;

    cps_api_transaction_close(&tr);

    sleep (2);
    return ret;
}

static bool send_l3_mc_cleanup_rpc (BASE_CLEANUP_EVENT_TYPE_t op_type,
        const string &vrf_name, const string &if_name,
        BASE_IF_MODE_t if_mode)
{
    cps_api_object_t             obj;
    bool ret = false;

    obj = cps_api_object_create();
    if (obj == NULL ) return 0;
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    L3_MCAST_BASE_CLEANUP_EVENTS_OBJ,
                                    cps_api_qualifier_TARGET);

    cps_api_object_attr_add_u32(obj, BASE_CLEANUP_EVENTS_INPUT_OP_TYPE,
                                op_type);
    switch (op_type)
    {
        case BASE_CLEANUP_EVENT_TYPE_INTERFACE_DELETE:
            cps_api_object_attr_add(obj, BASE_CLEANUP_EVENTS_INPUT_IF_NAME,
                                    if_name.c_str(), if_name.size() + 1);
            cps_api_object_attr_add_u32(obj, BASE_CLEANUP_EVENTS_INPUT_IF_MODE,
                                        if_mode);
            break;
        case BASE_CLEANUP_EVENT_TYPE_INTERFACE_MODE_CHANGE:
            cps_api_object_attr_add(obj, BASE_CLEANUP_EVENTS_INPUT_IF_NAME,
                                    if_name.c_str(), if_name.size() + 1);
            cps_api_object_attr_add_u32(obj, BASE_CLEANUP_EVENTS_INPUT_IF_MODE,
                                        if_mode);
            break;
        case BASE_CLEANUP_EVENT_TYPE_VRF_DELETE:
            cps_api_object_attr_add(obj, BASE_CLEANUP_EVENTS_INPUT_VRF_NAME,
                                    vrf_name.c_str(), vrf_name.size() + 1);
            break;
        default:
            std::cout << "Unsupport cleanup RPC" << std::endl;
            cps_api_object_delete(obj);
            return false;
    }

    cps_api_transaction_params_t tr;
    if(cps_api_transaction_init(&tr)!=cps_api_ret_code_OK) {
      cps_api_object_delete(obj);
      return false;
    }

    cps_api_action(&tr,obj);

    if (skip_obj_print_during_test != true) {
        cout << "Input object for RPC: " << endl;
        cps_api_object_print(obj);
    }
    if (cps_api_commit(&tr) == cps_api_ret_code_OK) ret = true;

    cps_api_transaction_close(&tr);

    return ret;
}

static bool mc_obj_pack_one_l3_mc_update_route(cps_api_object_t &obj,
                                 mroute_info_t &mroute_info,
                                 cps_api_operation_types_t op,
                                 bool include_copy_to_cpu = false,
                                 bool copy_to_cpu = false)
{
    uint32_t base_af;

    obj = cps_api_object_create();
    if (!obj) return false;
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    L3_MCAST_ROUTES_ROUTE,
                                    cps_api_qualifier_TARGET);

    if (mroute_info.af == AF_INET) {
        base_af = BASE_CMN_AF_TYPE_INET;
        struct in_addr ipv4_addr = {0};
        struct in_addr src_ipv4_addr = {0};
        inet_pton(AF_INET, mroute_info.group_ip[0].c_str(), &ipv4_addr);
        cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_GROUP_IP,
                                &ipv4_addr, sizeof(ipv4_addr));
        if (mroute_info.src_ip.size() > 0)
            inet_pton(AF_INET, mroute_info.src_ip[0].c_str(), &src_ipv4_addr);

        cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_SOURCE_IP,
                                &src_ipv4_addr, sizeof(src_ipv4_addr));

    } else {
        base_af = BASE_CMN_AF_TYPE_INET6;
        struct in6_addr ipv6_addr = {0};
        struct in6_addr src_ipv6_addr = {0};
        inet_pton(AF_INET6, mroute_info.group_ip[0].c_str(), &ipv6_addr);
        cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_GROUP_IP,
                                &ipv6_addr, sizeof(ipv6_addr));
        if (mroute_info.src_ip.size() > 0)
            inet_pton(AF_INET6, mroute_info.src_ip[0].c_str(), &src_ipv6_addr);

        cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_SOURCE_IP,
                                &src_ipv6_addr, sizeof(src_ipv6_addr));

    }

    cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_VRF_NAME,
                            mroute_info.vrf_name.c_str(),
                            mroute_info.vrf_name.size() + 1);
    cps_api_object_attr_add_u32(obj, L3_MCAST_ROUTES_ROUTE_AF, base_af);
    cps_api_object_attr_add_u32(obj, L3_MCAST_ROUTES_ROUTE_RT_TYPE,
                                mroute_info.rt_type);
    cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_IIF_NAME,
                            mroute_info.iif_name.c_str(),
                            mroute_info.iif_name.size() + 1);

    if (mroute_info.oifs_name.size()) {
        for (size_t i = 0; i < mroute_info.oifs_name.size();i++) {
            cps_api_attr_id_t oif_ids[3] = {L3_MCAST_ROUTES_ROUTE_OIF, i,
                                            L3_MCAST_ROUTES_ROUTE_OIF_NAME};
            if (!cps_api_object_e_add(obj, oif_ids, 3,
                        cps_api_object_ATTR_T_BIN,
                        mroute_info.oifs_name[i].oif_name.c_str(),
                        mroute_info.oifs_name[i].oif_name.size() + 1)) {
                cout << "Failed to set mc entry OIF # " << i << endl;
                return false;
            }
            if (mroute_info.oifs_name[i].exclude_present) {
                oif_ids[2] = L3_MCAST_ROUTES_ROUTE_OIF_EXCLUDE_INTERFACE;
                if (!cps_api_object_e_add(obj, oif_ids, 3,
                        cps_api_object_ATTR_T_BIN,
                        mroute_info.oifs_name[i].exclude_if_name.c_str(),
                        mroute_info.oifs_name[i].exclude_if_name.size() + 1)) {
                    cout << "Failed to set mc entry OIF # " << i <<
                        "exclude ifname" << endl;
                    return false;
                }
            }
        }
    } else if (op == cps_api_oper_SET) {
        if (!cps_api_object_attr_add(obj, L3_MCAST_ROUTES_ROUTE_OIF, "", 0)) {
            cout << "Failed to delete mc entry OIF list" << endl;
            return false;
        }
    }

    if (include_copy_to_cpu) {
        uint32_t val = copy_to_cpu;
        cps_api_object_attr_add_u32(obj, L3_MCAST_ROUTES_ROUTE_DATA_TO_CPU,
                                    val);
    }
    return true;
}

static bool trans_add_one_l3_mc_update_event(cps_api_transaction_params_t *tr,
                                 mroute_info_t &mroute_info,
                                 cps_api_operation_types_t op,
                                 bool include_copy_to_cpu = false,
                                 bool copy_to_cpu = false)
{
    cps_api_object_t obj;

    if (!tr) {
        return false;
    }

    if (!mc_obj_pack_one_l3_mc_update_route(obj, mroute_info,
                                            op, include_copy_to_cpu,
                                            copy_to_cpu)) {
        return false;
    }


    if (op == cps_api_oper_CREATE)
        cps_api_create(tr,obj);
    else if(op == cps_api_oper_SET)
        cps_api_set(tr,obj);
    else
        cps_api_delete(tr,obj);

    if (skip_obj_print_during_test != true) {
        cout << "Input object for COMMIT: " << endl;
        cps_api_object_print(obj);
    }
    return true;
}

static bool add_mroute_to_container_object (cps_api_object_t container_obj,
                                            cps_api_attr_id_t route_index,
                                            mroute_info_t &mroute_info,
                                            cps_api_operation_types_t op,
                                            bool include_copy_to_cpu = false,
                                            bool copy_to_cpu = false)
{
    uint32_t base_af;

    cps_api_attr_id_t group_id[3] = {L3_MCAST_ROUTES_ROUTE, route_index,
                                     L3_MCAST_ROUTES_ROUTE_GROUP_IP};
    cps_api_attr_id_t source_id[3] = {L3_MCAST_ROUTES_ROUTE, route_index,
                                      L3_MCAST_ROUTES_ROUTE_SOURCE_IP};
    cps_api_attr_id_t vrf_id[3] = {L3_MCAST_ROUTES_ROUTE, route_index,
                                   L3_MCAST_ROUTES_ROUTE_VRF_NAME};
    cps_api_attr_id_t af_id[3] = {L3_MCAST_ROUTES_ROUTE, route_index,
                                  L3_MCAST_ROUTES_ROUTE_AF};
    cps_api_attr_id_t rt_type_id[3] = {L3_MCAST_ROUTES_ROUTE, route_index,
                                       L3_MCAST_ROUTES_ROUTE_RT_TYPE};
    cps_api_attr_id_t iif_id[3] = {L3_MCAST_ROUTES_ROUTE, route_index,
                                   L3_MCAST_ROUTES_ROUTE_IIF_NAME};
    if (!container_obj) {
        cout << "NULL input container_obj for " << __FUNCTION__ << endl;
        return false;
    }

    if (mroute_info.af == AF_INET) {
        base_af = BASE_CMN_AF_TYPE_INET;
        struct in_addr ipv4_addr = {0};
        struct in_addr src_ipv4_addr = {0};
        inet_pton(AF_INET, mroute_info.group_ip[0].c_str(), &ipv4_addr);

        if (!cps_api_object_e_add(container_obj, group_id, 3,
                                  cps_api_object_ATTR_T_BIN,
                                  &ipv4_addr, sizeof(ipv4_addr))) {
            cout << __FUNCTION__ << " failed to e_add group ipv4 address" <<
                endl;
            return false;
        }
        if (mroute_info.src_ip.size() > 0)
            inet_pton(AF_INET, mroute_info.src_ip[0].c_str(), &src_ipv4_addr);

        if (!cps_api_object_e_add(container_obj, source_id, 3,
                                  cps_api_object_ATTR_T_BIN,
                                  &src_ipv4_addr, sizeof(src_ipv4_addr))) {
            cout << __FUNCTION__ << " failed to e_add source ipv4 address" <<
                endl;
            return false;
        }
    } else {
        base_af = BASE_CMN_AF_TYPE_INET6;
        struct in6_addr ipv6_addr = {0};
        struct in6_addr src_ipv6_addr = {0};
        inet_pton(AF_INET6, mroute_info.group_ip[0].c_str(), &ipv6_addr);
        if (!cps_api_object_e_add(container_obj, group_id, 3,
                                  cps_api_object_ATTR_T_BIN,
                                 &ipv6_addr, sizeof(ipv6_addr))) {
            cout << __FUNCTION__ << " failed to e_add group ipv6 address" <<
                endl;
            return false;
        }
        if (mroute_info.src_ip.size() > 0)
            inet_pton(AF_INET6, mroute_info.src_ip[0].c_str(), &src_ipv6_addr);

        if (!cps_api_object_e_add(container_obj, source_id, 3,
                                  cps_api_object_ATTR_T_BIN,
                                 &src_ipv6_addr, sizeof(src_ipv6_addr))) {
            cout << __FUNCTION__ << " failed to e_add source ipv6 address" <<
                endl;
            return false;
        }
    }

    if (!cps_api_object_e_add(container_obj, vrf_id, 3,
                              cps_api_object_ATTR_T_BIN,
                              mroute_info.vrf_name.c_str(),
                              mroute_info.vrf_name.size() + 1)) {
        cout << __FUNCTION__ << " failed to e_add vrf name" << endl;
        return false;
    }
    if (!cps_api_object_e_add(container_obj, af_id, 3,
                              cps_api_object_ATTR_T_U32,
                              &base_af, sizeof(base_af))) {
        cout << __FUNCTION__ << " failed to e_add AF" << endl;
        return false;
    }
    if (!cps_api_object_e_add(container_obj, rt_type_id, 3,
                              cps_api_object_ATTR_T_U32,
                              &mroute_info.rt_type,
                              sizeof(mroute_info.rt_type))) {
        cout << __FUNCTION__ << " failed to e_add rt_type" << endl;
        return false;
    }
    if (!cps_api_object_e_add(container_obj, iif_id, 3,
                              cps_api_object_ATTR_T_BIN,
                              mroute_info.iif_name.c_str(),
                              mroute_info.iif_name.size() + 1)) {
        cout << __FUNCTION__ << " failed to e_add iif name" << endl;
        return false;
    }


    if (mroute_info.oifs_name.size()) {
        for (size_t i = 0; i < mroute_info.oifs_name.size();i++) {
            cps_api_attr_id_t oif_ids[5] = {L3_MCAST_ROUTES_ROUTE, route_index,
                                            L3_MCAST_ROUTES_ROUTE_OIF, i,
                                            L3_MCAST_ROUTES_ROUTE_OIF_NAME};
            if (!cps_api_object_e_add(container_obj, oif_ids, 5,
                        cps_api_object_ATTR_T_BIN,
                        mroute_info.oifs_name[i].oif_name.c_str(),
                        mroute_info.oifs_name[i].oif_name.size() + 1)) {
                cout << __FUNCTION__ << ": Failed to set mc entry OIF" << endl;
                return false;
            }
            if (mroute_info.oifs_name[i].exclude_present) {
                oif_ids[4] = L3_MCAST_ROUTES_ROUTE_OIF_EXCLUDE_INTERFACE;
                if (!cps_api_object_e_add(container_obj, oif_ids, 5,
                        cps_api_object_ATTR_T_BIN,
                        mroute_info.oifs_name[i].exclude_if_name.c_str(),
                        mroute_info.oifs_name[i].exclude_if_name.size() + 1)) {
                    cout << __FUNCTION__ <<
                        " Failed to set mc entry OIF exclude ifname" << endl;
                    return false;
                }
            }
        }
    } else if (op == cps_api_oper_SET) {
        cps_api_attr_id_t oif_id[3] = {L3_MCAST_ROUTES_ROUTE, route_index,
                                        L3_MCAST_ROUTES_ROUTE_OIF};
        if (!cps_api_object_e_add(container_obj, oif_id, 3,
                                  cps_api_object_ATTR_T_BIN, "", 0)) {
            cout << __FUNCTION__ <<
                " Failed e_add for deletion of mc entry OIF list" << endl;
            return false;
        }
    }

    if (include_copy_to_cpu) {
        uint32_t val = copy_to_cpu;
        cps_api_attr_id_t copy_to_cpu_id[3] =
            {L3_MCAST_ROUTES_ROUTE, route_index,
             L3_MCAST_ROUTES_ROUTE_DATA_TO_CPU};
        if (!cps_api_object_e_add(container_obj, copy_to_cpu_id, 3,
                                  cps_api_object_ATTR_T_U32, &val,
                                  sizeof(val))) {
            cout << __FUNCTION__ <<
                " Failed to e_add copy to CPU attribute" << endl;
            return false;
        }
    }
    /*
     * End of embedded add
    */

    return true;
}

static bool send_l3_mc_update_event(const string &vrf_name,
                                 const string &iif_name,
                                 vector<string> &group_ip,
                                 vector<string> &src_ip,
                                 uint32_t af, uint32_t rt_type,
                                 vector<oif_data_t> &oifs_name,
                                 cps_api_operation_types_t op,
                                 bool include_copy_to_cpu = false,
                                 bool copy_to_cpu = false)
{
    bool ret = false;
    cps_api_transaction_params_t tr;
    mroute_info_t mroute_info = {vrf_name, iif_name, group_ip, src_ip, af,
                                 rt_type, oifs_name};

    if (cps_api_transaction_init(&tr)!= cps_api_ret_code_OK) {
        cout << "Failed to initialize transaction in " << __FUNCTION__ <<
            endl;
        return false;
    }

    ret = trans_add_one_l3_mc_update_event(&tr, mroute_info, op,
                                           include_copy_to_cpu, copy_to_cpu);

    if (!ret) {
        cps_api_transaction_close(&tr);
        return false;
    }

    if (cps_api_commit(&tr) == cps_api_ret_code_OK) ret = true;

    cps_api_transaction_close(&tr);
    return ret;
}

static void mc_parse_cps_oif_list (cps_api_object_it_t &it,
                                   vector<oif_data_t> &route_oif_list)
{
    cps_api_object_it_t oif_it = it;

    for (cps_api_object_it_inside(&oif_it); cps_api_object_it_valid(&oif_it);
            cps_api_object_it_next(&oif_it))
    {
        oif_data_t oif_data;
        oif_data.exclude_present = false;
        oif_data.oif_name.erase();
        oif_data.exclude_if_name.erase();
        cps_api_object_it_t in_oif_it = oif_it;
        for (cps_api_object_it_inside(&in_oif_it);
                cps_api_object_it_valid(&in_oif_it);
                cps_api_object_it_next(&in_oif_it))
        {
            cps_api_attr_id_t in_oif_id =
                cps_api_object_attr_id(in_oif_it.attr);
            switch(in_oif_id)
            {
                case L3_MCAST_ROUTES_ROUTE_OIF_NAME:
                    {
                        oif_data.oif_name.assign(
                                (const char *)
                                    cps_api_object_attr_data_bin(
                                        in_oif_it.attr));
                    }
                    break;
                case L3_MCAST_ROUTES_ROUTE_OIF_EXCLUDE_INTERFACE:
                    {
                        oif_data.exclude_if_name.assign(
                                (const char *)
                                    cps_api_object_attr_data_bin(
                                        in_oif_it.attr));
                        oif_data.exclude_present = true;
                    }
                    break;
                default:
                    break;
            }
        }
        std::cout << "Route get output:++++++++++++++++++++++++++++++++++"
                     "+++++++++" << std::endl;
        std::cout << "oif_name: " << oif_data.oif_name << std::endl;
        std::cout << "exclude_if_name: " << oif_data.exclude_if_name <<
            std::endl;
        std::cout << "exclude_present: " << ((oif_data.exclude_present) ?
                "true" : "false") << std::endl;
        std::cout << "End ++++++++++++++++++++++++++++++++++++++++++++++"
                     "++++++++" << std::endl;
        route_oif_list.push_back(oif_data);
    }
}

static bool send_l3_mc_get (const string &vrf_name, const string &iif_name,
                                 vector<string> &group_ip,
                                 vector<string> &src_ip,
                                 uint32_t af, uint32_t rt_type,
                                 vector<oif_data_t> &oifs_name,
                                 bool should_exist_in_npu = false,
                                 bool check_copy_to_cpu_val = false,
                                 bool copy_to_cpu_val = false,
                                 bool skip_oif_check = false,
                                 bool bulk_get = false,
                                 uint32_t bulk_count = 0)
{
    uint32_t base_af;
    bool ret = false;

    cps_api_get_params_t gp;


    if (af == AF_INET) {
        base_af = BASE_CMN_AF_TYPE_INET;
    } else {
        base_af = BASE_CMN_AF_TYPE_INET6;
    }

    cps_api_get_request_init(&gp);
    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    L3_MCAST_ROUTES_ROUTE,
                                    cps_api_qualifier_OBSERVED);
    cps_api_set_key_data (obj, L3_MCAST_ROUTES_ROUTE_VRF_NAME,
                          cps_api_object_ATTR_T_BIN,vrf_name.c_str(),
                          vrf_name.size() + 1);
    cps_api_set_key_data (obj, L3_MCAST_ROUTES_ROUTE_AF,
                          cps_api_object_ATTR_T_U32, &base_af,
                          sizeof (base_af));

    if (!bulk_get) {
        cps_api_set_key_data (obj, L3_MCAST_ROUTES_ROUTE_RT_TYPE,
                              cps_api_object_ATTR_T_U32, &rt_type,
                              sizeof (rt_type));
        if (af == AF_INET) {
            base_af = BASE_CMN_AF_TYPE_INET;
            struct in_addr ipv4_addr = {0};
            struct in_addr src_ipv4_addr = {0};
            inet_pton(AF_INET, group_ip[0].c_str(), &ipv4_addr);
            cps_api_set_key_data (obj, L3_MCAST_ROUTES_ROUTE_GROUP_IP,
                                  cps_api_object_ATTR_T_BIN, &ipv4_addr,
                                  sizeof(ipv4_addr));

            if (src_ip.size() > 0) {
                inet_pton(AF_INET, src_ip[0].c_str(), &src_ipv4_addr);
            }
            cps_api_set_key_data (obj, L3_MCAST_ROUTES_ROUTE_SOURCE_IP,
                                  cps_api_object_ATTR_T_BIN, &src_ipv4_addr,
                                  sizeof(src_ipv4_addr));

        } else {
            base_af = BASE_CMN_AF_TYPE_INET6;
            struct in6_addr ipv6_addr = {0};
            struct in6_addr src_ipv6_addr = {0};
            inet_pton(AF_INET6, group_ip[0].c_str(), &ipv6_addr);
            cps_api_set_key_data(obj, L3_MCAST_ROUTES_ROUTE_GROUP_IP,
                                 cps_api_object_ATTR_T_BIN, &ipv6_addr,
                                 sizeof(ipv6_addr));

            if (src_ip.size() > 0) {
                inet_pton(AF_INET6, src_ip[0].c_str(), &src_ipv6_addr);
            }
            cps_api_set_key_data(obj, L3_MCAST_ROUTES_ROUTE_SOURCE_IP,
                                 cps_api_object_ATTR_T_BIN, &src_ipv6_addr,
                                 sizeof(src_ipv6_addr));
        }
    }


    //std::cout<<"Route object content sent for GET: " <<std::endl;
    //mcast_route_dump_object_content(obj);
    //std::cout<<"-----------------------------"<<std::endl;

    if (cps_api_get(&gp)!=cps_api_ret_code_OK) {
        cps_api_get_request_close(&gp);
        return ret;
    }
    size_t mx = cps_api_object_list_size(gp.list);

    std::cout<<"Num routes returned: "<<mx <<std::endl;
    std::cout<<"====================="<<std::endl;

    if (bulk_get && (mx != bulk_count)) {
        cout << "Bulk route count mismatch: Expected number of routes: "
             << bulk_count << endl;
        cps_api_get_request_close(&gp);
        return false;
    }

    if (!mx) {
        std::cout<<"  Route Not programmed in NPU"<<std::endl;
        std::cout<<"-----------------------------"<<std::endl;
        cps_api_get_request_close(&gp);
        return ret;
    }

    ret = true;
    for ( size_t ix = 0 ; ix < mx ; ++ix ) {
        obj = cps_api_object_list_get(gp.list,ix);

        bool oif_attr_present = false;
        std::vector<oif_data_t> route_oif_list{};

        cps_api_object_it_t it;
        cps_api_object_it_begin(obj, &it);

        for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) )
        {
            int id = (int) cps_api_object_attr_id(it.attr);
            switch (id)
            {
                case L3_MCAST_ROUTES_ROUTE_OIF:
                    {
                        if (cps_api_object_attr_len(it.attr) > 0) {
                            oif_attr_present = true;
                            mc_parse_cps_oif_list(it, route_oif_list);
                        }
                        if (!skip_oif_check) {
                            ret = oif_list_vector_equivalent(oifs_name,
                                    route_oif_list);
                        }
                        if (!ret)
                        {
                            std::cout << "  Route OIF doesn't match, ret : " <<
                                ret << std::endl;
                            std::cout << "  incoming OIF sz  : " <<
                                oifs_name.size() << std::endl;
                            std::cout << "  route OIF sz     : " <<
                                route_oif_list.size() << std::endl;
                            std::cout << "-------------------------" <<
                                std::endl;
                            ret = false;
                        } else {
                            cout << "Route OIF match success " << endl;
                        }
                    }
                    break;
                case L3_MCAST_ROUTES_ROUTE_DATA_TO_CPU:
                    {
                        if (check_copy_to_cpu_val) {
                            bool cp_to_cpu = (bool)(uint32_t)
                                cps_api_object_attr_data_u32(it.attr);
                            if (copy_to_cpu_val != cp_to_cpu) {
                                std::cout << "Route Copy To Cpu flag doesn't "
                                             "match, val to check: " <<
                                             copy_to_cpu_val << std::endl;
                                ret = false;
                            }
                        }
                    }
                    break;
                default:
                    break;

            }
        }

        if ((oifs_name.size() > 0) && (!oif_attr_present)) {
            ret = false;
            cout << "Route OIF mismatch: No OIFs found for OIF list "
                    "size " << oifs_name.size() << endl;
        } else if (!oifs_name.size() && (!oif_attr_present)) {
            cout << "Route NULL OIF match success " << endl;
        }

        mcast_route_dump_object_content(obj);
        std::cout<<"-----------------------------"<<std::endl;
        cps_api_object_attr_t prg_done_attr = cps_api_object_attr_get(obj,
                L3_MCAST_ROUTES_ROUTE_NPU_PRG_DONE);
        if (should_exist_in_npu &&
                ((prg_done_attr == nullptr) ||
                 (cps_api_object_attr_data_u32(prg_done_attr) == false))) {
            std::cout<<"  Route Not programmed in NPU"<<std::endl;
            std::cout<<"-----------------------------"<<std::endl;
            ret = false;
            break;
        }
    }

    cps_api_get_request_close(&gp);

    return ret;
}

TEST(nas_l3_mcast, vrf_validate_mcast_v4_v6_instance_add_del)
{
/*    if (vrf_get_mcast_status (TEST_VRF_NAME, AF_INET, false, false)) {
        cout << __FUNCTION__ << ": Unexpected mcast instance before instance "
                                "creation. Deleting ..." << endl;
        ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, AF_INET, false));
    }
    */
    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, AF_INET, true));

    if (!vrf_get_mcast_status (TEST_VRF_NAME, AF_INET, true, true)) {
        cout << __FUNCTION__ << ": Incorrect mcast status on first GET. "
            "Retrying" << endl;
    }


    ASSERT_TRUE(vrf_get_mcast_status (TEST_VRF_NAME, AF_INET, true, true));

    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, AF_INET6, true));
    ASSERT_TRUE(vrf_get_mcast_status (TEST_VRF_NAME, AF_INET6, true, true));

    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, AF_INET, false));
    ASSERT_TRUE(!vrf_get_mcast_status (TEST_VRF_NAME, AF_INET, false, false));

    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, AF_INET6, false));
    ASSERT_TRUE(!vrf_get_mcast_status (TEST_VRF_NAME, AF_INET6, false, false));
}

TEST(nas_l3_mcast, intf_validate_pim_v4_v6_instance_add_del)
{
    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, AF_INET, true));
    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, AF_INET6, true));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, AF_INET, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, AF_INET, true, true));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, AF_INET6, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, AF_INET6, true, true));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, AF_INET, false));
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, AF_INET, false, false));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, AF_INET6, false));
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, AF_INET6, false, false));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_2, AF_INET, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_2, AF_INET, true, true));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_2, AF_INET6, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_2, AF_INET6, true, true));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_2, AF_INET, false));
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_2, AF_INET, false, false));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_2, AF_INET6, false));
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_2, AF_INET6, false, false));

    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, AF_INET, false));
    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, AF_INET6, false));
}

TEST(nas_l3_mcast, vrf_mcast_enable)
{
    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, test_addr_family, true));
    ASSERT_TRUE(vrf_get_mcast_status (TEST_VRF_NAME, test_addr_family, true, true));
}

TEST(nas_l3_mcast, intf_pim_enable)
{
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, test_addr_family, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, test_addr_family, true, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_1, test_addr_family, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_1, test_addr_family, true, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_2, test_addr_family, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_2, test_addr_family, true, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_2, test_addr_family, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_2, test_addr_family, true, true));
}

TEST(nas_l3_mcast, send_ipv4_StarG_route_add_event)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, TEST_OIF_NULL_LIST, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, TEST_OIF_NULL_LIST, 1));
}

TEST(nas_l3_mcast, get_ipv4_StarG_route)
{
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, TEST_OIF_NULL_LIST, 1));
}

TEST(nas_l3_mcast, send_ipv4_StarG_route_del_event)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, TEST_OIF_NULL_LIST, cps_api_oper_DELETE));

    sleep (2);
    //validate route is NOT present in cache
    ASSERT_TRUE((!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, TEST_OIF_NULL_LIST, 0)));
}

TEST(nas_l3_mcast, send_ipv4_SG_route_add_event)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, TEST_OIF_NULL_LIST, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, TEST_OIF_NULL_LIST, 1));
}

TEST(nas_l3_mcast, send_ipv4_SG_route_del_event)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, TEST_OIF_NULL_LIST, cps_api_oper_DELETE));
    sleep (2);
    //validate route is NOT present in NPU
    ASSERT_TRUE((!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, TEST_OIF_NULL_LIST, 0)));
}

TEST(nas_l3_mcast, send_ipv4_SGRPT_route_add_event)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 3, TEST_OIF_NULL_LIST, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 3, TEST_OIF_NULL_LIST, 1));
}

TEST(nas_l3_mcast, send_ipv4_SGRPT_route_del_event)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 3, TEST_OIF_NULL_LIST, cps_api_oper_DELETE));
    sleep (2);
    //validate route is NOT present in NPU
    ASSERT_TRUE((!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 3, TEST_OIF_NULL_LIST, 0)));
}

TEST(nas_l3_mcast, send_ipv4_SGRPTWithSG_route_add_event)
{
    //This test will check both SG and SGRPT present together case
    //Have SG route and then SGRPT entry with different IIF
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, TEST_OIF_NULL_LIST, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, TEST_OIF_NULL_LIST, 1));

    //Add SGRPT with different IIF
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_2,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 3, TEST_OIF_NULL_LIST, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_2,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 3, TEST_OIF_NULL_LIST, 1));
}

TEST(nas_l3_mcast, send_ipv4_SGRPTWithSG_route_del_event)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, TEST_OIF_NULL_LIST, cps_api_oper_DELETE));
    sleep (2);
    //validate route is NOT present in NPU
    ASSERT_TRUE((!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, TEST_OIF_NULL_LIST, 0)));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_2,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 3, TEST_OIF_NULL_LIST, cps_api_oper_DELETE));
    sleep (2);
    //validate route is NOT present in NPU
    ASSERT_TRUE((!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_2,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 3, TEST_OIF_NULL_LIST, 0)));
}

TEST(nas_l3_mcast, send_ipv4_StarG_route_add_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_OIF_LIST_1, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_OIF_LIST_1, 1));

    //negative check - validate with invalid route OIF
    std::cout << "Negative check" <<std::endl;
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, INVALID_ROUTE_OIF_LIST_1, 0));
}

TEST(nas_l3_mcast, send_ipv4_StarG_route_del_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_OIF_LIST_1, cps_api_oper_DELETE));
    sleep (2);
    //validate route is NOT present in cache
    ASSERT_TRUE((!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_OIF_LIST_1, 0)));
}

TEST(nas_l3_mcast, send_ipv4_StarG_route_update_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_OIF_LIST_1, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_OIF_LIST_1, 1));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_OIF_LIST_2, cps_api_oper_SET));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_OIF_LIST_2, 1));


    //negative check - validate with invalid route OIF
    std::cout << "Negative check" <<std::endl;
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, INVALID_ROUTE_OIF_LIST_1, 0));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_OIF_LIST_2, cps_api_oper_DELETE));
    sleep (2);

    //validate route is not present in cache
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_OIF_LIST_2, 0));
}



TEST(nas_l3_mcast, send_ipv4_SG_route_add_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_OIF_LIST_1, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_1, 1));

    //negative check - validate with invalid route oif
    std::cout << "Negative check" <<std::endl;
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, INVALID_ROUTE_OIF_LIST_1, 0));
}

TEST(nas_l3_mcast, send_ipv4_SG_route_del_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_OIF_LIST_1, cps_api_oper_DELETE));

    sleep (2);
    //validate route is NOT present in cache
    ASSERT_TRUE((!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_1, 0)));
}

TEST(nas_l3_mcast, send_ipv4_SG_route_update_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_OIF_LIST_1, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_1, 1));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_OIF_LIST_2, cps_api_oper_SET));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_2, 1));


    //negative check - validate with invalid route OIF
    std::cout << "Negative check" <<std::endl;
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, INVALID_ROUTE_OIF_LIST_1, 0));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_OIF_LIST_2, cps_api_oper_DELETE));
    sleep (2);

    //validate route is not present in cache
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_2, 0));
}

TEST(nas_l3_mcast, send_ipv4_SG_route_with_oif_add)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_OIF_LIST_2, cps_api_oper_CREATE));
    sleep (2);

    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_2, 1));

}

TEST(nas_l3_mcast, send_ipv4_SG_route_with_oif_del)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_OIF_LIST_2, cps_api_oper_DELETE));
    sleep (2);

    //validate route is not present in cache
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_2, 0));
}

TEST(nas_l3_mcast, send_ipv4_SG_route_oif_state_transition)
{
    //Create an SG route with a NULL OIF list and verify, then
    //change the OIF list to non-NULL with muliple OIFs and verify.
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, TEST_OIF_NULL_LIST, cps_api_oper_CREATE));
    sleep (2);
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, TEST_OIF_NULL_LIST, 1));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_OIF_LIST_2, cps_api_oper_SET));
    sleep (2);
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_2, 1));

    //Decrease the OIF list size and verify.
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_OIF_LIST_1, cps_api_oper_SET));
    sleep (2);
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_1, 1));

    //Simultaneously remove an OIF and add a different OIF, then verify the result.
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_OIF_LIST_3, cps_api_oper_SET));
    sleep (2);
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_3, 1));

    
    //Change the OIF list to an empty list and verify.
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, TEST_OIF_NULL_LIST, cps_api_oper_SET));
    sleep (2);
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, TEST_OIF_NULL_LIST, 1));

    //Change back to a multiple OIF list and verify, then verify a
    //transition from the multiple OIF list to a NULL OIF list.
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_OIF_LIST_2, cps_api_oper_SET));
    sleep (2);
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_2, 1));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, TEST_OIF_NULL_LIST, cps_api_oper_SET));
    sleep (2);
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, TEST_OIF_NULL_LIST, 1));

    // Delete the mroute and verify that it has been removed.
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, TEST_OIF_NULL_LIST, cps_api_oper_DELETE));
    sleep (2);

    //validate route is not present in cache
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, TEST_OIF_NULL_LIST));
}

TEST(nas_l3_mcast, send_ipv4_SG_route_update_event_with_copy_to_cpu)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_OIF_LIST_1, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_1, 1, 1, 0));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_OIF_LIST_2, cps_api_oper_SET));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_2, 1, 1, 0));

    //update copy to cpu flag.
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_OIF_LIST_2, cps_api_oper_SET, 1, 1));
    sleep (2);
    //validate route is present with correct copy_to_cpu flag.
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_2, 1, 1, 1));


    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_OIF_LIST_2, cps_api_oper_DELETE));
    sleep (2);

    //validate route is not present in cache
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_2, 0, 0, 0));
}

// Create and verify (group_count X source_count) mroutes.
TEST(nas_l3_mcast, create_and_update_multiple_SG_routes)
{
    vector <string> current_group;
    vector <string> current_source;
    uint32_t group_index, source_index;
    uint32_t total_count = group_count * source_count;
    uint32_t sleep_time = 5 + total_count/80;
    bool ret = false;
    cps_api_transaction_params_t tr;
    cps_api_object_t obj;
    cps_api_attr_id_t route_index = 0;
    mroute_info_t mroute_info = {TEST_VRF_NAME, ROUTE_IF_NAME_1, {}, {},
                                 test_addr_family, 2, ROUTE_OIF_LIST_1};

    cout << "Scaled mroute test: creating " << total_count << " mroutes" << endl;
    // Create (group_count X source_count) mroutes.
    if (bulk_container) {

        // Create an object for the container to hold the routes.
        //
        ASSERT_TRUE(cps_api_transaction_init(&tr) == cps_api_ret_code_OK);
        obj = cps_api_object_create();
        ASSERT_TRUE(obj != NULL );
        cps_api_key_from_attr_with_qual(cps_api_object_key(obj), L3_MCAST_ROUTES,
                                        cps_api_qualifier_TARGET);
    }

    for (group_index = 0; group_index < group_count; group_index++) {
        current_group = string_ip_addr_add(test_addr_family,
                                           TEST_GRP_RANGE_IP_ADDR,
                                           group_index);
        for (source_index = 0; source_index < source_count; source_index++) {
            current_source = string_ip_addr_add(test_addr_family,
                                                TEST_SRC_RANGE_IP_ADDR,
                                                source_index);

            if (bulk_container) {
                mroute_info.group_ip = current_group;
                mroute_info.src_ip = current_source;
                mroute_info.oifs_name = ROUTE_OIF_LIST_1;

                ret = add_mroute_to_container_object(obj, route_index++,
                                                     mroute_info,
                                                     cps_api_oper_CREATE);
                if (!ret) {
                    cps_api_object_delete(obj);
                    cps_api_transaction_close(&tr);
                    ASSERT_TRUE(ret);
                }
            } else {
                ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME,
                                ROUTE_IF_NAME_1, current_group, current_source,
                                test_addr_family, 2, ROUTE_OIF_LIST_1,
                                cps_api_oper_CREATE));
            }
        }
    }

    if (bulk_container) {
        cps_api_create(&tr,obj);
        ret = (cps_api_commit(&tr) == cps_api_ret_code_OK);
        cps_api_transaction_close(&tr);
        if (!ret) {
            ASSERT_TRUE(ret);
        }
    }

    sleep(sleep_time);

    // Verify that each of the created routes can be found and that each
    // of the routes has the correct values for the OIF list and other
    // attributes.
    //
    cout << "Scaled mroute test: verifying " << total_count << " mroutes" << endl;
    if (bulk_container) {
        ASSERT_TRUE(send_l3_mc_get(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                   TEST_GRP_RANGE_IP_ADDR, TEST_SRC_RANGE_IP_ADDR,
                                   test_addr_family, 2, ROUTE_OIF_LIST_1, 1,
                                   false, false, false, true, total_count));
    } else {
        for (group_index = 0; group_index < group_count; group_index++) {
            current_group = string_ip_addr_add(test_addr_family,
                                               TEST_GRP_RANGE_IP_ADDR,
                                               group_index);
            for (source_index = 0; source_index < source_count;
                 source_index++) {
                current_source = string_ip_addr_add(test_addr_family,
                                                    TEST_SRC_RANGE_IP_ADDR,
                                                    source_index);
                ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                            current_group,
                                            current_source,
                                            test_addr_family, 2,
                                            ROUTE_OIF_LIST_1, 1));
            }
        }
    }

    // Modify the OIF list for (group_count X source_count) mroutes.
    cout << "Scaled mroute test: modifying " << total_count << " mroutes" << endl;
    if (bulk_container) {
        ASSERT_TRUE(cps_api_transaction_init(&tr) == cps_api_ret_code_OK);
        obj = cps_api_object_create();
        ASSERT_TRUE(obj != NULL );
        cps_api_key_from_attr_with_qual(cps_api_object_key(obj), L3_MCAST_ROUTES,
                                        cps_api_qualifier_TARGET);
        route_index = 0;
    }

    for (group_index = 0; group_index < group_count; group_index++) {
        current_group = string_ip_addr_add(test_addr_family,
                                           TEST_GRP_RANGE_IP_ADDR,
                                           group_index);
        for (source_index = 0; source_index < source_count; source_index++) {
            current_source = string_ip_addr_add(test_addr_family,
                                                TEST_SRC_RANGE_IP_ADDR,
                                                source_index);

            if (bulk_container) {
                mroute_info.group_ip = current_group;
                mroute_info.src_ip = current_source;
                mroute_info.oifs_name = ROUTE_OIF_LIST_2;
                ret = add_mroute_to_container_object(obj, route_index++,
                                                     mroute_info,
                                                     cps_api_oper_SET);
                if (!ret) {
                    cps_api_object_delete(obj);
                    cps_api_transaction_close(&tr);
                    ASSERT_TRUE(ret);
                }
            } else {
                ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME,
                                ROUTE_IF_NAME_1, current_group, current_source,
                                test_addr_family, 2, ROUTE_OIF_LIST_2,
                                cps_api_oper_SET));
            }
        }
    }

    if (bulk_container) {
        cps_api_set(&tr, obj);
        ret = (cps_api_commit(&tr) == cps_api_ret_code_OK);
        cps_api_transaction_close(&tr);
        if (!ret) {
            ASSERT_TRUE(ret);
        }
    }

    sleep(sleep_time);

    // Verify that each of the modified routes can be found and that each
    // of the routes has the correct values for the OIF list and other
    // attributes.
    cout << "Scaled mroute test: verifying " << total_count << " mroutes" << endl;
    if (bulk_container) {
        ASSERT_TRUE(send_l3_mc_get(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                   TEST_GRP_RANGE_IP_ADDR,
                                   TEST_SRC_RANGE_IP_ADDR,
                                   test_addr_family, 2, ROUTE_OIF_LIST_2, 1,
                                   false, false, false, true, total_count));
    } else {
        for (group_index = 0; group_index < group_count; group_index++) {
            current_group = string_ip_addr_add(test_addr_family,
                                               TEST_GRP_RANGE_IP_ADDR,
                                               group_index);
            for (source_index = 0; source_index < source_count;
                 source_index++) {
                current_source = string_ip_addr_add(test_addr_family,
                                                    TEST_SRC_RANGE_IP_ADDR,
                                                    source_index);
                ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                            current_group,
                                            current_source,
                                            test_addr_family, 2,
                                            ROUTE_OIF_LIST_2, 1));
            }
        }
    }
}

// Delete and verify deletion of (group_count X source_count) mroutes.
TEST(nas_l3_mcast, delete_multiple_SG_routes)
{
    vector <string> current_group;
    vector <string> current_source;
    uint32_t group_index, source_index;
    uint32_t total_count = group_count * source_count;
    uint32_t sleep_time = 5 + total_count/80;
    bool ret = false;
    cps_api_transaction_params_t tr;
    cps_api_object_t obj;
    cps_api_attr_id_t route_index = 0;
    mroute_info_t mroute_info = {TEST_VRF_NAME, ROUTE_IF_NAME_1, {}, {},
                                 test_addr_family, 2, ROUTE_OIF_LIST_1};

    if (bulk_container) {
        ASSERT_TRUE(cps_api_transaction_init(&tr) == cps_api_ret_code_OK);
        obj = cps_api_object_create();
        ASSERT_TRUE(obj != NULL );
        cps_api_key_from_attr_with_qual(cps_api_object_key(obj), L3_MCAST_ROUTES,
                                        cps_api_qualifier_TARGET);
    }

    // Delete each of the created routes (verifying successful search and
    // deletion).
    cout << "Scaled mroute test: deleting " << total_count << " mroutes" << endl;
    for (group_index = 0; group_index < group_count; group_index++) {
        current_group = string_ip_addr_add(test_addr_family,
                                           TEST_GRP_RANGE_IP_ADDR,
                                           group_index);
        for (source_index = 0; source_index < source_count; source_index++) {
            current_source = string_ip_addr_add(test_addr_family,
                                                TEST_SRC_RANGE_IP_ADDR,
                                                source_index);

            if (bulk_container) {
                mroute_info.group_ip = current_group;
                mroute_info.src_ip = current_source;
                mroute_info.oifs_name = ROUTE_OIF_LIST_2;
                ret = add_mroute_to_container_object(obj, route_index++,
                                                     mroute_info,
                                                     cps_api_oper_DELETE);
                if (!ret) {
                    cps_api_object_delete(obj);
                    cps_api_transaction_close(&tr);
                    ASSERT_TRUE(ret);
                }
            } else {
                ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME,
                                ROUTE_IF_NAME_1, current_group, current_source,
                                test_addr_family, 2, ROUTE_OIF_LIST_2,
                                cps_api_oper_DELETE));
            }
        }
    }

    if (bulk_container) {
        cps_api_delete(&tr,obj);
        ret = (cps_api_commit(&tr) == cps_api_ret_code_OK);
        cps_api_transaction_close(&tr);
        if (!ret) {
            ASSERT_TRUE(ret);
        }
    }

    sleep(sleep_time);

    // Verify that each of the deleted routes has actually been removed.
    cout << "Scaled mroute test: Verifying deletion of  "
        << total_count << " mroutes" << endl;
    if (bulk_container) {
        ASSERT_FALSE(send_l3_mc_get(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                    TEST_GRP_RANGE_IP_ADDR,
                                    TEST_SRC_RANGE_IP_ADDR,
                                    test_addr_family, 2, ROUTE_OIF_LIST_2, 1,
                                    false, false, false, true, 0));
        return;
    }

    for (group_index = 0; group_index < group_count; group_index++) {
        current_group = string_ip_addr_add(test_addr_family,
                                           TEST_GRP_RANGE_IP_ADDR,
                                           group_index);
        for (source_index = 0; source_index < source_count; source_index++) {
            current_source = string_ip_addr_add(test_addr_family,
                                                TEST_SRC_RANGE_IP_ADDR,
                                                source_index);
            ASSERT_FALSE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                         current_group, current_source,
                                         test_addr_family, 2,
                                         ROUTE_OIF_LIST_2, 1));
        }
    }
}
        
static bool configure_test_vrfs (bool add)
{
    cps_api_object_t vrf_obj;
    cps_api_transaction_params_t vrf_tr;
    cps_api_return_code_t cps_api_ret;
    const char *vrf_cfg_base_str = "test_vrf_";
    string vrf_string;
    string op_string = add ? "add" : "delete";
    uint32_t vrf_idx;

    for (vrf_idx = 0; vrf_idx < vrf_count; vrf_idx++) {
        if (vrf_idx && !(vrf_idx % 100)) {
            cout << "Pausing config after " << vrf_idx << " VRFs" << endl;
            mc_print_time("VRF config pause");
            sleep(2);
        }
        vrf_string = vrf_cfg_base_str + to_string(vrf_idx);
        cps_api_ret = cps_api_transaction_init(&vrf_tr);
        if (cps_api_ret != cps_api_ret_code_OK) {
            cout << __FUNCTION__ <<
                " failed to initialize a CPS transaction. RC = " <<
                cps_api_ret << endl;
            return false;
        }
        
        vrf_obj = cps_api_object_create();
        if (!vrf_obj) {
            cout << __FUNCTION__ <<
                " failed to create a CPS object for a transaction" << endl;
            cps_api_transaction_close(&vrf_tr);
            return false;
        }
        cps_api_key_from_attr_with_qual(cps_api_object_key(vrf_obj),
                                        NI_NETWORK_INSTANCES_OBJ,
                                        cps_api_qualifier_TARGET);
        if (!cps_api_object_attr_add(
                    vrf_obj, NI_NETWORK_INSTANCES_NETWORK_INSTANCE_NAME,
                    vrf_string.c_str(), vrf_string.size() + 1)) {
            cout << __FUNCTION__ << "failed to add name of vrf " << vrf_idx <<
                " to the transaction object" << endl;
            cps_api_object_delete(vrf_obj);
            cps_api_transaction_close(&vrf_tr);
            return false;
        }
        if (add) {
            cps_api_create(&vrf_tr, vrf_obj);
        } else {
            cps_api_delete(&vrf_tr, vrf_obj);
        }
        cps_api_ret = cps_api_commit(&vrf_tr);
        if (cps_api_ret != cps_api_ret_code_OK) {
            cout << __FUNCTION__ << " failed to commit CPS VRF " <<
                op_string << " transaction for " << vrf_string.c_str() <<
                ". RC = " <<
                cps_api_ret << endl;
            cps_api_transaction_close(&vrf_tr);
            return false;
        }
        cps_api_transaction_close(&vrf_tr);
    }

    return true;
}

// Create/configure multiple ("vrf_count") VRFs. Enable multicast in even
// numbered VRFs and disable it in odd numbered VRFs. Verify that the
// correct multicast state is programmed for each of the VRFs. After that,
// toggle the multicast state in all of the VRFs and re-verify the result.
//
TEST(nas_l3_mcast, multiple_vrf_mcast_enable)
{
    uint32_t vrf_num;
    bool mcast_status;
    bool ret = true;
    string curr_vrf_name;
    uint32_t save_skip_print;

    // Save the current state of the "skip object print" flag and set the flag.
    // Restore it on exit.
    save_skip_print = skip_obj_print_during_test;
    skip_obj_print_during_test = true;

    // Configure the VRFs.
    cout << "Configuring " << vrf_count << " VRFs." << endl;
    mc_print_time("VRF config start");
    ret = configure_test_vrfs(true);
    if (!ret) {
        skip_obj_print_during_test = save_skip_print;
        ASSERT_TRUE(ret);
    }
    mc_print_time("VRF config end");
    sleep(10);

    // Enable mcast on odd VRFs and disable it on even VRFs.
    cout << "Enabling and verifying mcast in odd VRFs." << endl;
    mc_print_time("Odd VRF mcast enable start");
    for (vrf_num = 0; vrf_num < vrf_count; vrf_num++) {
        mcast_status = (vrf_num & 1) ? true : false;
        curr_vrf_name = "test_vrf_" + to_string(vrf_num);
        ret = (vrf_mcast_status(curr_vrf_name, test_addr_family,
                                mcast_status));
        if (!ret) {
            cout << "Failure setting mcast state for " << curr_vrf_name <<
                endl;
            configure_test_vrfs(false);
            skip_obj_print_during_test = save_skip_print;
            ASSERT_TRUE(ret);
        }
    }
    mc_print_time("Odd VRF mcast enable end");
    sleep(1);


    // Verify the mcast state: Expect a failure (false) return code
    // from the "get" function when the mcast instance is not present,
    // indicating that mcast is disabled for the VRF.
    //
    mc_print_time("Odd VRF mcast enable verify start");
    for (vrf_num = 0; vrf_num < vrf_count; vrf_num++) {
        mcast_status = (vrf_num & 1) ? true : false;
        curr_vrf_name = "test_vrf_" + to_string(vrf_num);
        ret = (vrf_get_mcast_status(curr_vrf_name, test_addr_family,
                                    true, mcast_status));
        if (ret != mcast_status) {
            cout << "Failure verifying mcast state for " <<
                curr_vrf_name << endl;
            configure_test_vrfs(false);
            skip_obj_print_during_test = save_skip_print;
            ASSERT_TRUE(ret == mcast_status);
        }
    }
    mc_print_time("Odd VRF mcast enable verify end");

    // Enable mcast on even VRFs and disable it on odd VRFs.
    cout << "Enabling and verifying mcast in even VRFs; "
        "disabling in odd VRFs." << endl;
    mc_print_time("Even VRF mcast enable start");
    for (vrf_num = 0; vrf_num < vrf_count; vrf_num++) {
        mcast_status = (vrf_num & 1) ? false : true;
        curr_vrf_name = "test_vrf_" + to_string(vrf_num);
        ret = (vrf_mcast_status(curr_vrf_name, test_addr_family,
                                mcast_status));
        if (!ret) {
            cout << "Failure setting mcast state for " << curr_vrf_name << endl;
            configure_test_vrfs(false);
            skip_obj_print_during_test = save_skip_print;
            ASSERT_TRUE(ret);
        }
    }
    mc_print_time("Even VRF mcast enable end");
    sleep(1);

    // Verify the mcast state.
    mc_print_time("Even VRF mcast enable verify start");
    for (vrf_num = 0; vrf_num < vrf_count; vrf_num++) {
        mcast_status = (vrf_num & 1) ? false : true;
        curr_vrf_name = "test_vrf_" + to_string(vrf_num);
        ret = (vrf_get_mcast_status(curr_vrf_name, test_addr_family,
                                    true, mcast_status));
        if (ret != mcast_status) {
            cout << "Failure verifying mcast state for " <<
                curr_vrf_name << endl;
            configure_test_vrfs(false);
            skip_obj_print_during_test = save_skip_print;
            ASSERT_TRUE(ret == mcast_status);
        }
    }
    mc_print_time("Even VRF mcast enable verify end");

    // De-configure the test VRFs.
    skip_obj_print_during_test = save_skip_print;
    mc_print_time("VRF de-config start");
    ASSERT_TRUE(configure_test_vrfs(false));
    mc_print_time("VRF de-config end");
}

TEST(nas_l3_mcast, send_ipv4_StarG_route_config_and_oif_cleanup_cli)
{
    //this test is not applicable for non-default vrf; so skip this test
    if (is_non_default_vrf_test) return;

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_OIF_LIST_2, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_OIF_LIST_2, 1));

    //change the interface mode to L2 via CLI and check route OIF is removed
    send_cfg_to_switch (TEST_ROUTE_OIF_NAME_2_L2_MODE_CLI_CFG);
    sleep (2);

    //validate route is present in cache with updated oif (after interface mode change)
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_OIF_LIST_1, 1));

    //change the interface mode to L2 for IIF via CLI and check route is removed
    send_cfg_to_switch (TEST_ROUTE_IF_NAME_1_L2_MODE_CLI_CFG);
    sleep (2);

    //validate route is removed in cache
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, TEST_OIF_NULL_LIST, 0));

    send_cfg_to_switch (TEST_ROUTE_IF_NAME_1_L3_MODE_CLI_CFG);
    send_cfg_to_switch (TEST_ROUTE_OIF_NAME_2_L3_MODE_CLI_CFG);

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_2, test_addr_family, true));
}


TEST(nas_l3_mcast, send_ipv4_StarG_route_config_and_oif_cleanup_rpc)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_OIF_LIST_2, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_OIF_LIST_2, 1));

    sleep (2);
    //delete one OIF and do route get and validate the OIF is removed from route
    ASSERT_TRUE(send_l3_mc_cleanup_rpc(BASE_CLEANUP_EVENT_TYPE_INTERFACE_DELETE, "", ROUTE_OIF_NAME_2, BASE_IF_MODE_MODE_L3));

    //validate route is present in cache with updated oif (after interface deletion)
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_OIF_LIST_1, 1));

    sleep (2);

    //this specific case of the test is not applicable for non-default vrf; so skip this test scenario
    if (!is_non_default_vrf_test) {
        //delete one OIF and do route get and validate the OIF is removed from route
        ASSERT_TRUE(send_l3_mc_cleanup_rpc(BASE_CLEANUP_EVENT_TYPE_INTERFACE_MODE_CHANGE, "", ROUTE_OIF_NAME_1, BASE_IF_MODE_MODE_L2));

        //validate route is present in cache with updated oif (after interface deletion)
        ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                    TEST_GRP_IP_ADDR,
                    TEST_NULL_LIST,
                    test_addr_family, 1, TEST_OIF_NULL_LIST, 1));
    }

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, TEST_OIF_NULL_LIST, cps_api_oper_DELETE));
    sleep (2);
    //validate route is removed in cache
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, TEST_OIF_NULL_LIST, 0));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_1, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_2, test_addr_family, true));
}

TEST(nas_l3_mcast, send_ipv4_StarG_route_config_and_clean_up_on_pim_disable)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_OIF_LIST_2, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_OIF_LIST_2, 1));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                TEST_GRP_IP_ADDR,
                TEST_SRC_IP_ADDR,
                test_addr_family, 2, ROUTE_OIF_LIST_2, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_2, 1));

    //disable PIM on one OIF and check if the OIF is removed from the route.
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_2, test_addr_family, false));

    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_OIF_LIST_1, 1));

    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_1, 1));

    //disable PIM on IIF and check if the route is removed
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, test_addr_family, false));

    //validate route is removed in cache
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, TEST_OIF_NULL_LIST, 0));
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, TEST_OIF_NULL_LIST, 0));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_2, test_addr_family, true));
}

TEST(nas_l3_mcast, send_route_config_and_clean_up_on_mcast_disable)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_OIF_LIST_2, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_OIF_LIST_2, 1));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                TEST_GRP_IP_ADDR,
                TEST_SRC_IP_ADDR,
                test_addr_family, 2, ROUTE_OIF_LIST_2, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_2, 1));

    //disable VRF MCAST and check if the route is removed
    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, test_addr_family, false));

    ASSERT_TRUE(!vrf_get_mcast_status (TEST_VRF_NAME, test_addr_family, false, false));
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, test_addr_family, false, false));
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_1, test_addr_family, false, false));
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_2, test_addr_family, false, false));
    //validate route is removed in cache
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, TEST_OIF_NULL_LIST, 0));
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, TEST_OIF_NULL_LIST, 0));

    //reset the config back to value before the test
    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_1, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_2, test_addr_family, true));
}


TEST(nas_l3_mcast, intf_pim_disable)
{
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, test_addr_family, false));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_1, test_addr_family, false));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_2, test_addr_family, false));
}


//validate following:
//pim interface instance should not be returned by default w/o creation.
//create pim instance with status enable and validate it is returned properly
//delete pim instance and validate it is not returned.
TEST(nas_l3_mcast, intf_get_pim_status)
{
    //this test is not applicable for non-default vrf; so skip this test
    if (is_non_default_vrf_test) return;

    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, false, false));
    send_cfg_to_switch (TEST_VLAN_4_CLI_CFG);
    sleep (5);
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, true, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, false));
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, false, false));
    send_cfg_to_switch (TEST_VLAN_4_CLI_NO_CFG);
}

TEST(nas_l3_mcast, intf_config_ip_addr_and_pim_status)
{
    //this test is not applicable for non-default vrf; so skip this test
    if (is_non_default_vrf_test) return;

    send_cfg_to_switch (TEST_VLAN_MBR_1_MODE_CLI_CFG);
    send_cfg_to_switch (TEST_VLAN_MBR_2_MODE_CLI_CFG);
    send_cfg_to_switch (TEST_VLAN_4_CLI_CFG);
    sleep (10);

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, true));
    sleep(5);
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, true, true));

    //delete the interface and check PIM status on interface is cleared
    send_cfg_to_switch (TEST_VLAN_4_CLI_NO_CFG);

    //PIM status get should fail after interface deletion.
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, false, false));
}


// enable PIM on interface in shutdown state (no v4/v6 ip address should be present)
// then validate PIM status at each step after disabling/enabling PIM repeatedly for few times.
TEST(nas_l3_mcast, intf_config_pim_status_shut_no_ip_addr)
{
    //this test is not applicable for non-default vrf; so skip this test
    if (is_non_default_vrf_test) return;

    send_cfg_to_switch (TEST_VLAN_MBR_1_MODE_CLI_CFG);
    send_cfg_to_switch (TEST_VLAN_MBR_2_MODE_CLI_CFG);
    send_cfg_to_switch (TEST_VLAN_4_CLI_CFG);
    sleep (10);
    //shutdown interface and remove ip address
    send_cfg_to_switch (TEST_VLAN_4_CLI_SHUT_NO_IP_CFG);
    sleep (5);

    //enable PIM on interface
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, true));
    //validate PIM status to enabled
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, true, true));

    //disable PIM on interface
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, false));
    //validate PIM status to disabled
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, false, false));

    //do repeated enable/disable to see if it is handled correctly.
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, true, true));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, false));
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, false, false));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, true, true));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, false));
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, false, false));

    //delete the interface
    send_cfg_to_switch (TEST_VLAN_4_CLI_NO_CFG);
}

// enable PIM on interface in shutdown state (no v4/v6 ip address should be present)
// then validate PIM status and then do 'no shutdown' & assign ip address for RIF count to update.
// disable/enable PIM status and validate it.
TEST(nas_l3_mcast, intf_config_pim_status_no_shut_ip_addr)
{
    //this test is not applicable for non-default vrf; so skip this test
    if (is_non_default_vrf_test) return;

    send_cfg_to_switch (TEST_VLAN_MBR_1_MODE_CLI_CFG);
    send_cfg_to_switch (TEST_VLAN_MBR_2_MODE_CLI_CFG);
    send_cfg_to_switch (TEST_VLAN_4_CLI_CFG);
    sleep (10);
    //shutdown interface and remove ip address
    send_cfg_to_switch (TEST_VLAN_4_CLI_SHUT_NO_IP_CFG);
    sleep (5);

    //enable PIM on interface
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, true));
    //validate PIM status to enabled
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, true, true));

    //no-shutdown interface and assign ip address
    send_cfg_to_switch (TEST_VLAN_4_CLI_NO_SHUT_IP_CFG);
    sleep (5);

    //validate PIM status to enabled
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, true, true));

    //disable PIM on interface
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, false));
    sleep(2);
    //validate PIM status to disabled
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, false, false));

    //do repeated enable/disable to see if it is handled correctly.
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, true, true));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, false));
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, TEST_VLAN_4, test_addr_family, false, false));

    //delete the interface
    send_cfg_to_switch (TEST_VLAN_4_CLI_NO_CFG);
}


TEST(nas_l3_mcast, vrf_mcast_disable)
{
    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, test_addr_family, false));
    ASSERT_TRUE(!vrf_get_mcast_status (TEST_VRF_NAME, test_addr_family, false, false));
}

//VLAN interface route test

TEST(nas_l3_mcast, vlan_test_pre_req_config)
{
    send_cfg_to_switch (TEST_VLAN_MBR_1_MODE_CLI_CFG);
    send_cfg_to_switch (TEST_VLAN_MBR_2_MODE_CLI_CFG);
    send_cfg_to_switch (TEST_VLAN_1_CLI_CFG);
    send_cfg_to_switch (TEST_VLAN_2_CLI_CFG);
    send_cfg_to_switch (TEST_VLAN_3_CLI_CFG);
    sleep (10);
}

TEST(nas_l3_mcast, vrf_vlan_mcast_enable)
{
    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, test_addr_family, true));
    sleep(2);
    ASSERT_TRUE(vrf_get_mcast_status (TEST_VRF_NAME, test_addr_family, true, true));
}

TEST(nas_l3_mcast, intf_vlan_pim_enable)
{
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1, test_addr_family, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1, test_addr_family, true, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_VLAN_OIF_NAME_1, test_addr_family, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, ROUTE_VLAN_OIF_NAME_1, test_addr_family, true, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_VLAN_OIF_NAME_2, test_addr_family, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, ROUTE_VLAN_OIF_NAME_2, test_addr_family, true, true));
}

TEST(nas_l3_mcast, send_vlan_ipv4_StarG_route_add_event)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, TEST_OIF_NULL_LIST, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, TEST_OIF_NULL_LIST, 1));
}

TEST(nas_l3_mcast, get_vlan_ipv4_StarG_route)
{
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, TEST_OIF_NULL_LIST, 1));
}

TEST(nas_l3_mcast, send_vlan_ipv4_StarG_route_del_event)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, TEST_OIF_NULL_LIST, cps_api_oper_DELETE));

    sleep (2);
    //validate route is NOT present in cache
    ASSERT_TRUE((!send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, TEST_OIF_NULL_LIST, 0)));
}

TEST(nas_l3_mcast, send_vlan_ipv4_SG_route_add_event)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, TEST_OIF_NULL_LIST, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, TEST_OIF_NULL_LIST, 1));
}

TEST(nas_l3_mcast, send_vlan_ipv4_SG_route_del_event)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, TEST_OIF_NULL_LIST, cps_api_oper_DELETE));
    sleep (2);
    //validate route is NOT present in NPU
    ASSERT_TRUE((!send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, TEST_OIF_NULL_LIST, 0)));
}

TEST(nas_l3_mcast, send_vlan_ipv4_StarG_route_add_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_VLAN_OIF_LIST_1, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_VLAN_OIF_LIST_1, 1));

    //negative check - validate with invalid route OIF
    std::cout << "Negative check" <<std::endl;
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, INVALID_ROUTE_VLAN_OIF_LIST_1, 0));
}

TEST(nas_l3_mcast, send_vlan_ipv4_StarG_route_del_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_VLAN_OIF_LIST_1, cps_api_oper_DELETE));
    sleep (2);
    //validate route is NOT present in cache
    ASSERT_TRUE((!send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_VLAN_OIF_LIST_1, 0)));
}

TEST(nas_l3_mcast, send_vlan_ipv4_StarG_route_update_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_VLAN_OIF_LIST_1, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_VLAN_OIF_LIST_1, 1));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_VLAN_OIF_LIST_2, cps_api_oper_SET));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_VLAN_OIF_LIST_2, 1));


    //negative check - validate with invalid route OIF
    std::cout << "Negative check" <<std::endl;
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, INVALID_ROUTE_VLAN_OIF_LIST_1, 0));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_VLAN_OIF_LIST_2, cps_api_oper_DELETE));
    sleep (2);

    //validate route is not present in cache
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_VLAN_OIF_LIST_2, 0));
}

TEST(nas_l3_mcast, send_vlan_ipv4_SG_route_add_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_VLAN_OIF_LIST_1, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_VLAN_OIF_LIST_1, 1));

    //negative check - validate with invalid route oif
    std::cout << "Negative check" <<std::endl;
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, INVALID_ROUTE_VLAN_OIF_LIST_1, 0));
}

TEST(nas_l3_mcast, send_vlan_ipv4_SG_route_del_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_VLAN_OIF_LIST_1, cps_api_oper_DELETE));

    sleep (2);
    //validate route is NOT present in cache
    ASSERT_TRUE((!send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_VLAN_OIF_LIST_1, 0)));
}

TEST(nas_l3_mcast, send_vlan_ipv4_SG_route_update_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_VLAN_OIF_LIST_1, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_VLAN_OIF_LIST_1, 1));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_VLAN_OIF_LIST_2, cps_api_oper_SET));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_VLAN_OIF_LIST_2, 1));


    //negative check - validate with invalid route OIF
    std::cout << "Negative check" <<std::endl;
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, INVALID_ROUTE_VLAN_OIF_LIST_1, 0));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_VLAN_OIF_LIST_2, cps_api_oper_DELETE));
    sleep (2);

    //validate route is not present in cache
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_VLAN_OIF_LIST_2, 0));
}

TEST(nas_l3_mcast, send_vlan_ipv4_SG_route_with_oif_add)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_VLAN_OIF_LIST_2, cps_api_oper_CREATE));
    sleep (2);

    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_VLAN_OIF_LIST_2, 1));

}

TEST(nas_l3_mcast, send_vlan_ipv4_SG_route_with_oif_del)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_VLAN_OIF_LIST_2, cps_api_oper_DELETE));
    sleep (2);

    //validate route is not present in cache
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_VLAN_OIF_LIST_2, 0));
}

TEST(nas_l3_mcast, intf_vlan_pim_disable)
{
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_VLAN_IF_NAME_1, test_addr_family, false));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_VLAN_OIF_NAME_1, test_addr_family, false));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_VLAN_OIF_NAME_2, test_addr_family, false));
}

TEST(nas_l3_mcast, vrf_vlan_mcast_disable)
{
    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, test_addr_family, false));
}

TEST(nas_l3_mcast, vlan_test_pre_req_undo_config)
{
    send_cfg_to_switch (TEST_VLAN_1_CLI_NO_CFG);
    send_cfg_to_switch (TEST_VLAN_2_CLI_NO_CFG);
    send_cfg_to_switch (TEST_VLAN_3_CLI_NO_CFG);
    send_cfg_to_switch (TEST_VLAN_MBR_1_MODE_CLI_NO_CFG);
    send_cfg_to_switch (TEST_VLAN_MBR_2_MODE_CLI_NO_CFG);
}
//end of VLAN interface route config test

//LAG interface route config test

TEST(nas_l3_mcast, lag_test_pre_req_config)
{
    send_cfg_to_switch (TEST_LAG_L3_1_CLI_DYN_CFG);
    send_cfg_to_switch (TEST_LAG_L3_2_CLI_DYN_CFG);
    send_cfg_to_switch (TEST_LAG_L2_CLI_DYN_CFG);

    sleep (10);
}

TEST(nas_l3_mcast, vrf_lag_mcast_enable)
{

    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, test_addr_family, true));
}

TEST(nas_l3_mcast, intf_lag_pim_enable)
{
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_LAG_IF_NAME, test_addr_family, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, ROUTE_LAG_IF_NAME, test_addr_family, true, true));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_LAG_OIF_NAME, test_addr_family, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, ROUTE_LAG_OIF_NAME, test_addr_family, true, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_LAG_VLAN_OIF_NAME, test_addr_family, true));
    ASSERT_TRUE(intf_get_pim_status(TEST_VRF_NAME, ROUTE_LAG_VLAN_OIF_NAME, test_addr_family, true, true));
}

TEST(nas_l3_mcast, send_lag_ipv4_StarG_route_add_event)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, TEST_OIF_NULL_LIST, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, TEST_OIF_NULL_LIST, 1));
}

TEST(nas_l3_mcast, get_lag_ipv4_StarG_route)
{
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, TEST_OIF_NULL_LIST, 1));
}

TEST(nas_l3_mcast, send_lag_ipv4_StarG_route_del_event)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, TEST_OIF_NULL_LIST, cps_api_oper_DELETE));

    sleep (2);
    //validate route is NOT present in cache
    ASSERT_TRUE((!send_l3_mc_get (TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, TEST_OIF_NULL_LIST, 0)));
}

TEST(nas_l3_mcast, send_lag_ipv4_SG_route_add_event)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, TEST_OIF_NULL_LIST, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, TEST_OIF_NULL_LIST, 1));
}

TEST(nas_l3_mcast, send_lag_ipv4_SG_route_del_event)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, TEST_OIF_NULL_LIST, cps_api_oper_DELETE));
    sleep (2);
    //validate route is NOT present in NPU
    ASSERT_TRUE((!send_l3_mc_get (TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, TEST_OIF_NULL_LIST, 0)));
}

TEST(nas_l3_mcast, send_lag_ipv4_StarG_route_add_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_LAG_OIF_LIST_1, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_LAG_OIF_LIST_1, 1));
}

TEST(nas_l3_mcast, send_lag_ipv4_StarG_route_del_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_LAG_OIF_LIST_1, cps_api_oper_DELETE));
    sleep (2);
    //validate route is NOT present in cache
    ASSERT_TRUE((!send_l3_mc_get (TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_LAG_OIF_LIST_1, 0)));
}

TEST(nas_l3_mcast, send_lag_ipv4_StarG_route_update_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_LAG_OIF_LIST_1, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_LAG_OIF_LIST_1, 1));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_LAG_OIF_LIST_2, cps_api_oper_SET));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_LAG_OIF_LIST_2, 1));


    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_LAG_OIF_LIST_2, cps_api_oper_DELETE));
    sleep (2);

    //validate route is not present in cache
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_LAG_OIF_LIST_2, 0));
}

TEST(nas_l3_mcast, send_lag_ipv4_SG_route_add_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_LAG_OIF_LIST_1, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_LAG_OIF_LIST_1, 1));
}

TEST(nas_l3_mcast, send_lag_ipv4_SG_route_del_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_LAG_OIF_LIST_1, cps_api_oper_DELETE));

    sleep (2);
    //validate route is NOT present in cache
    ASSERT_TRUE((!send_l3_mc_get (TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_LAG_OIF_LIST_1, 0)));
}

TEST(nas_l3_mcast, send_lag_ipv4_SG_route_update_event_with_oif)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_LAG_OIF_LIST_1, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_LAG_OIF_LIST_1, 1));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_LAG_OIF_LIST_2, cps_api_oper_SET));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_LAG_OIF_LIST_2, 1));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_LAG_OIF_LIST_2, cps_api_oper_DELETE));
    sleep (2);

    //validate route is not present in cache
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_LAG_OIF_LIST_2, 0));
}

TEST(nas_l3_mcast, send_lag_ipv4_SG_route_with_oif_add)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_LAG_OIF_LIST_2, cps_api_oper_CREATE));
    sleep (2);

    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_LAG_OIF_LIST_2, 1));

}


TEST(nas_l3_mcast, send_lag_ipv4_SG_route_with_oif_del)
{
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_LAG_OIF_LIST_2, cps_api_oper_DELETE));
    sleep (2);

    //validate route is not present in cache
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_LAG_IF_NAME,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_LAG_OIF_LIST_2, 0));
}

TEST(nas_l3_mcast, intf_lag_pim_disable)
{
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_LAG_IF_NAME, test_addr_family, false));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_LAG_OIF_NAME, test_addr_family, false));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_LAG_VLAN_OIF_NAME, test_addr_family, false));
}

TEST(nas_l3_mcast, vrf_lag_mcast_disable)
{
    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, test_addr_family, false));
}

TEST(nas_l3_mcast, lag_test_pre_req_undo_config)
{
    send_cfg_to_switch (TEST_LAG_L3_1_CLI_NO_DYN_CFG);
    send_cfg_to_switch (TEST_LAG_L3_2_CLI_NO_DYN_CFG);
    send_cfg_to_switch (TEST_LAG_L2_CLI_NO_DYN_CFG);
}

//end of LAG interface route config test

//scaled test

//test for msg thread to walker thread optimization
TEST(nas_l3_mcast, send_scaled_route_cfg_for_msg_bulking_b4_walker_thread)
{
    skip_obj_print_during_test = true;
    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_1, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_2, test_addr_family, true));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_OIF_LIST_1, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_OIF_LIST_1, 1));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_OIF_LIST_1, cps_api_oper_CREATE));
    sleep (2);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_1, 1));


    for (int iter = 0; iter < 1000; iter++) {
        ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                    TEST_GRP_IP_ADDR,
                    TEST_NULL_LIST,
                    test_addr_family, 1, ROUTE_OIF_LIST_2, cps_api_oper_SET));

        ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                    TEST_GRP_IP_ADDR,
                    TEST_SRC_IP_ADDR,
                    test_addr_family, 2, ROUTE_OIF_LIST_2, cps_api_oper_SET));


        ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                    TEST_GRP_IP_ADDR,
                    TEST_NULL_LIST,
                    test_addr_family, 1, ROUTE_OIF_LIST_1, cps_api_oper_SET));

        ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                    TEST_GRP_IP_ADDR,
                    TEST_SRC_IP_ADDR,
                    test_addr_family, 2, ROUTE_OIF_LIST_1, cps_api_oper_SET));
    }

    sleep (5);
    //validate route is present in cache with correct OIF & is also present in NPU
    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_OIF_LIST_1, 1));

    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_1, 1));


    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_NULL_LIST,
                                 test_addr_family, 1, ROUTE_OIF_LIST_2, cps_api_oper_DELETE));

    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                 TEST_GRP_IP_ADDR,
                                 TEST_SRC_IP_ADDR,
                                 test_addr_family, 2, ROUTE_OIF_LIST_2, cps_api_oper_DELETE));
    sleep (2);

    //validate route is not present in cache
    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_NULL_LIST,
                                test_addr_family, 1, ROUTE_OIF_LIST_2, 0));

    ASSERT_TRUE(!send_l3_mc_get (TEST_VRF_NAME, ROUTE_IF_NAME_1,
                                TEST_GRP_IP_ADDR,
                                TEST_SRC_IP_ADDR,
                                test_addr_family, 2, ROUTE_OIF_LIST_2, 0));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_2, test_addr_family, false));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_OIF_NAME_1, test_addr_family, false));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, ROUTE_IF_NAME_1, test_addr_family, false));

    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, test_addr_family, false));
    skip_obj_print_during_test = false;
}

//end of scaled test

//start of Negative test cases
TEST(nas_l3_mcast, intf_invalid_pim_enable)
{
    //this test is not applicable for non-default vrf; so skip this test
    if (is_non_default_vrf_test) return;

    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, AF_INET, true));
    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, AF_INET6, true));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, "br5000", AF_INET, true));
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, "br5000", AF_INET, false, false));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, "br5000", AF_INET6, true));
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, "br5000", AF_INET6, false, false));

    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, "br5000", AF_INET, false));
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, "br5000", AF_INET, false, false));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, "br5000", AF_INET6, false));
    ASSERT_TRUE(!intf_get_pim_status(TEST_VRF_NAME, "br5000", AF_INET6, false, false));

    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, AF_INET, false));
    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, AF_INET6, false));
}
//end of Negative test cases

// Route OIF Exclude interface test

static const string IIF_INTF_NAME_1{"e101-010-0"};
static const string IIF_INTF_NAME_2{"e101-011-0"};
static const string IIF_INTF_NAME_3{"e101-012-0"};
static const string OIF_1_INTF_NAME_1{"e101-015-0"};
static const string OIF_1_INTF_NAME_2{"e101-016-0"};
static const string OIF_1_INTF_NAME_3{"e101-017-0"};
static const string OIF_2_INTF_NAME_1{"e101-020-0"};
static const string OIF_2_INTF_NAME_2{"e101-021-0"};
static const string OIF_2_INTF_NAME_3{"e101-022-0"};
static const string IIF_VLAN_IF_NAME_1{"br901"};
static const string OIF_VLAN_IF_NAME_1{"br905"};
static const string OIF_VLAN_IF_NAME_2{"br910"};
static const string OIF_1_INTF_EXCLUDE{OIF_1_INTF_NAME_2};
static const string OIF_2_INTF_EXCLUDE{OIF_2_INTF_NAME_3};


static vector<string> TEST_ROUTE_EXL_2_OIF_1_CFG = {
    "end",
    "configure terminal",
    "interface vlan 905",
    "exit",
    "interface port-channel 6",
    "exit",
    "interface ethernet 1/1/15",
    "channel-group 6",
    "exit",
    "interface ethernet 1/1/16",
    "channel-group 6",
    "exit",
    "interface port-channel 6",
    "switchport mode trunk",
    "switchport trunk allowed vlan 905",
    "exit",
    "interface ethernet 1/1/17",
    "switchport mode trunk",
    "switchport trunk allowed vlan 905",
    "exit",
};

static vector<string> TEST_ROUTE_EXL_2_OIF_1_NO_CFG = {
    "end",
    "configure terminal",
    "interface ethernet 1/1/15",
    "no channel-group",
    "exit",
    "interface ethernet 1/1/16",
    "no channel-group",
    "exit",
    "no interface port-channel 6",
    "interface ethernet 1/1/17",
    "no switchport trunk allowed vlan 905",
    "exit",
    "no interface vlan 905",
    "exit",
};

static vector<string> TEST_ROUTE_EXL_2_OIF_2_CFG = {
    "end",
    "configure terminal",
    "interface vlan 910",
    "exit",
    "interface port-channel 7",
    "exit",
    "interface ethernet 1/1/20",
    "channel-group 7",
    "exit",
    "interface ethernet 1/1/21",
    "channel-group 7",
    "exit",
    "interface ethernet 1/1/22",
    "channel-group 7",
    "exit",
    "interface port-channel 7",
    "switchport mode trunk",
    "switchport trunk allowed vlan 910",
    "exit",
};

static vector<string> TEST_ROUTE_EXL_2_OIF_2_NO_CFG = {
    "end",
    "configure terminal",
    "interface ethernet 1/1/20",
    "no channel-group",
    "exit",
    "interface ethernet 1/1/21",
    "no channel-group",
    "exit",
    "interface ethernet 1/1/22",
    "no channel-group",
    "exit",
    "no interface port-channel 7",
    "no interface vlan 910",
    "exit",
};

static const string OIF_1_LAG_IF_NAME_1{"bo6"};
static const string OIF_2_LAG_IF_NAME_2{"bo7"};


TEST(nas_l3_mcast, route_oif_exclude_test_pre_req_config)
{
    //@@TODO - handle non-default vrf test for exlude OIF test.
    //this test is not applicable for non-default vrf; so skip this test
    if (is_non_default_vrf_test) return;

    send_cfg_to_switch (TEST_ROUTE_EXL_1_IIF_CFG);
    send_cfg_to_switch (TEST_ROUTE_EXL_1_OIF_1_CFG);
    send_cfg_to_switch (TEST_ROUTE_EXL_1_OIF_2_CFG);
    send_cfg_to_switch (TEST_ROUTE_EXL_2_OIF_1_CFG);
    send_cfg_to_switch (TEST_ROUTE_EXL_2_OIF_2_CFG);

    sleep (10);
}

TEST(nas_l3_mcast, route_oif_exclude_intf_1)
{
    //this test is not applicable for non-default vrf; so skip this test
    if (is_non_default_vrf_test) return;

    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, IIF_VLAN_IF_NAME_1, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, OIF_VLAN_IF_NAME_1, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, OIF_VLAN_IF_NAME_2, test_addr_family, true));
    sleep (2);
    vector<oif_data_t> oif_v = {{OIF_VLAN_IF_NAME_1, true, OIF_1_INTF_NAME_2}, {OIF_VLAN_IF_NAME_2, true, OIF_2_INTF_NAME_3}};
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, IIF_VLAN_IF_NAME_1,
                 TEST_GRP_IP_ADDR, TEST_NULL_LIST, test_addr_family, 1, oif_v, cps_api_oper_CREATE));
    sleep(2);

    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, IIF_VLAN_IF_NAME_1, TEST_GRP_IP_ADDR, TEST_NULL_LIST, test_addr_family, 1, oif_v, 1));

    sleep(2);

    //Cleanup the IFF and OIF interfaces
    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, test_addr_family, false));
    sleep (10);
}
TEST(nas_l3_mcast, route_oif_exclude_intf_2)
{
    //this test is not applicable for non-default vrf; so skip this test
    if (is_non_default_vrf_test) return;

    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, IIF_VLAN_IF_NAME_1, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, OIF_VLAN_IF_NAME_1, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, OIF_VLAN_IF_NAME_2, test_addr_family, true));
    sleep (2);
    vector<oif_data_t> oif_v = {{OIF_VLAN_IF_NAME_1, true, OIF_1_LAG_IF_NAME_1}, {OIF_VLAN_IF_NAME_2, true, OIF_2_LAG_IF_NAME_2}};
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, IIF_VLAN_IF_NAME_1,
                 TEST_GRP_IP_ADDR, TEST_NULL_LIST, test_addr_family, 1, oif_v, cps_api_oper_CREATE));

    sleep(2);

    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, IIF_VLAN_IF_NAME_1, TEST_GRP_IP_ADDR, TEST_NULL_LIST, test_addr_family, 1, oif_v, 1));

    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, test_addr_family, false));
    sleep(4);

    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, test_addr_family, false));
    sleep (10);
}

TEST(nas_l3_mcast, route_oif_exclude_intf_3)
{
    //this test is not applicable for non-default vrf; so skip this test
    if (is_non_default_vrf_test) return;

    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, IIF_VLAN_IF_NAME_1, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, OIF_VLAN_IF_NAME_1, test_addr_family, true));
    ASSERT_TRUE(intf_pim_status(TEST_VRF_NAME, OIF_VLAN_IF_NAME_2, test_addr_family, true));
    sleep (2);

    vector<oif_data_t> oif_v = {{OIF_VLAN_IF_NAME_1, true, OIF_1_INTF_NAME_2}, {OIF_VLAN_IF_NAME_2, true, OIF_1_LAG_IF_NAME_1}};
    ASSERT_TRUE(send_l3_mc_update_event(TEST_VRF_NAME, IIF_VLAN_IF_NAME_1,
                 TEST_GRP_IP_ADDR, TEST_NULL_LIST, test_addr_family, 1, oif_v, cps_api_oper_CREATE));
    sleep(4);

    ASSERT_TRUE(send_l3_mc_get (TEST_VRF_NAME, IIF_VLAN_IF_NAME_1, TEST_GRP_IP_ADDR, TEST_NULL_LIST, test_addr_family, 1, oif_v, 1));

    sleep(2);

    //Cleanup the IFF and OIF interfaces
    ASSERT_TRUE(vrf_mcast_status (TEST_VRF_NAME, test_addr_family, false));
}

TEST(nas_l3_mcast, route_oif_exclude_test_pre_req_undo_config)
{
    //this test is not applicable for non-default vrf; so skip this test
    if (is_non_default_vrf_test) return;

    send_cfg_to_switch (TEST_ROUTE_EXL_1_IIF_NO_CFG);
    send_cfg_to_switch (TEST_ROUTE_EXL_1_OIF_1_NO_CFG);
    send_cfg_to_switch (TEST_ROUTE_EXL_1_OIF_2_NO_CFG);
    send_cfg_to_switch (TEST_ROUTE_EXL_2_OIF_1_NO_CFG);
    send_cfg_to_switch (TEST_ROUTE_EXL_2_OIF_2_NO_CFG);
    sleep (10);
}

void nas_l3_mcast_config_test_pre_req()
{
    send_cfg_to_switch(TEST_INTF_VLAN_1_CLI_CFG);
    send_cfg_to_switch(TEST_INTF_VLAN_2_CLI_CFG);
    send_cfg_to_switch(TEST_INTF_VLAN_3_CLI_CFG);

    send_cfg_to_switch (TEST_ROUTE_IF_NAME_1_L3_MODE_CLI_CFG);
    send_cfg_to_switch (TEST_ROUTE_IF_NAME_2_L3_MODE_CLI_CFG);
    send_cfg_to_switch (TEST_ROUTE_OIF_NAME_1_L3_MODE_CLI_CFG);
    send_cfg_to_switch (TEST_ROUTE_OIF_NAME_2_L3_MODE_CLI_CFG);

    send_cfg_to_switch(TEST_LAG_L3_1_CLI_CFG);
    send_cfg_to_switch(TEST_LAG_L3_2_CLI_CFG);
    send_cfg_to_switch(TEST_LAG_L2_CLI_CFG);

    if(is_non_default_vrf_test) {
        send_cfg_to_switch (TEST_VRF_CLI_CFG);

        send_cfg_to_switch (TEST_VRF_ROUTE_IF_NAME_1_L3_MODE_CLI_CFG);
        send_cfg_to_switch (TEST_VRF_ROUTE_IF_NAME_2_L3_MODE_CLI_CFG);
        send_cfg_to_switch (TEST_VRF_ROUTE_OIF_NAME_1_L3_MODE_CLI_CFG);
        send_cfg_to_switch (TEST_VRF_ROUTE_OIF_NAME_2_L3_MODE_CLI_CFG);

        send_cfg_to_switch (TEST_VRF_ROUTE_VLAN_IF_NAME_1_L3_MODE_CLI_CFG);
        send_cfg_to_switch (TEST_VRF_ROUTE_VLAN_OIF_NAME_1_L3_MODE_CLI_CFG);
        send_cfg_to_switch (TEST_VRF_ROUTE_VLAN_OIF_NAME_2_L3_MODE_CLI_CFG);

        send_cfg_to_switch (TEST_LAG_L3_1_VRF_CLI_CFG);
        send_cfg_to_switch (TEST_LAG_L3_2_VRF_CLI_CFG);
    }

    sleep(5);
}

void nas_l3_mcast_test_config_clean_up()
{
    if(is_non_default_vrf_test) {

        send_cfg_to_switch (TEST_VRF_ROUTE_VLAN_IF_NAME_1_L3_MODE_CLI_NO_CFG);
        send_cfg_to_switch (TEST_VRF_ROUTE_VLAN_OIF_NAME_1_L3_MODE_CLI_NO_CFG);
        send_cfg_to_switch (TEST_VRF_ROUTE_VLAN_OIF_NAME_2_L3_MODE_CLI_NO_CFG);

        send_cfg_to_switch (TEST_VRF_ROUTE_OIF_NAME_2_L3_MODE_CLI_NO_CFG);
        send_cfg_to_switch (TEST_VRF_ROUTE_OIF_NAME_1_L3_MODE_CLI_NO_CFG);
        send_cfg_to_switch (TEST_VRF_ROUTE_IF_NAME_1_L3_MODE_CLI_NO_CFG);
        send_cfg_to_switch (TEST_VRF_ROUTE_IF_NAME_2_L3_MODE_CLI_NO_CFG);

        send_cfg_to_switch (TEST_LAG_L3_1_VRF_CLI_NO_CFG);
        send_cfg_to_switch (TEST_LAG_L3_2_VRF_CLI_NO_CFG);
        send_cfg_to_switch (TEST_LAG_L2_VRF_CLI_NO_CFG);

        send_cfg_to_switch (TEST_VRF_CLI_NO_CFG);
    }
    send_cfg_to_switch(TEST_INTF_VLAN_1_CLI_NO_CFG);
    send_cfg_to_switch(TEST_INTF_VLAN_2_CLI_NO_CFG);
    send_cfg_to_switch(TEST_INTF_VLAN_3_CLI_NO_CFG);

    send_cfg_to_switch(TEST_LAG_L3_1_CLI_NO_CFG);
    send_cfg_to_switch(TEST_LAG_L3_2_CLI_NO_CFG);
    send_cfg_to_switch(TEST_LAG_L2_CLI_NO_CFG);

    sleep(5);
}

int main(int argc, char *argv[])
{
    bool skip_pre_cfg = 0;
    bool clean_up_cfg = 0;
    int tmp_sources, tmp_groups, tmp_vrfs;
    ::testing::InitGoogleTest(&argc, argv);

    std::cout << "Usage: " << std::endl;
    std::cout << "====== " << std::endl;
    std::cout << argv[0] << " [skip-pre-cfg] [vrf-name <test>] " << endl;
    std::cout << "[af ipv4/ipv6] " << endl;
    std::cout << "[groups <# of groups>] [sources <# of sources per group>]" <<
        endl;
    std::cout << "[vrfs <# of vrfs>]" << endl;
    std::cout << "[clean-up]\n\n" << std::endl;
    std::cout << "ARG Count : " << argc << std::endl;
    if (argc > 1) {
        int i = 1;
        while (i < argc) {
            std::cout << "ARG : " << i << " Value : " << argv[i] << std::endl;
            if ((strcmp(argv[i], "af") == 0) && (argc > i+1)) {
                std::cout << "ARG : " << i+1 << " Value : " << argv[i+1] <<
                    std::endl;
                if (strcmp(argv[i+1], "ipv4") == 0) {
                    test_addr_family = AF_INET;
                } else if (strcmp(argv[i+1], "ipv6") == 0) {
                    test_addr_family = AF_INET6;
                }
                i++;
            } else if ((strcmp(argv[i], "vrf-name") == 0) && (argc > i+1)) {
                std::cout << "ARG : " << i+1 << " Value : " << argv[i+1] <<
                    std::endl;
                TEST_VRF_NAME.assign((const char *) argv[i+1]);
                if (strncmp(argv[i], NAS_DEFAULT_VRF_NAME,
                            strlen(NAS_DEFAULT_VRF_NAME))!= 0)
                    is_non_default_vrf_test = true;
                i++;
            } else if ((strcmp(argv[i], "groups") == 0) && (argc > i+1)) {
                if ((tmp_groups = atoi(argv[i+1])) &&
                    (tmp_groups <= MAX_TEST_GROUPS)) {
                    group_count = (uint32_t)tmp_groups;
                    i++;
                }
            } else if ((strcmp(argv[i], "sources") == 0) && (argc > i+1)) {
                if ((tmp_sources = atoi(argv[i+1])) &&
                    (tmp_sources <= MAX_TEST_SOURCES)) {
                    source_count = (uint32_t)tmp_sources;
                    i++;
                }
            } else if ((strcmp(argv[i], "vrfs") == 0) && (argc > i+1)) {
                if ((tmp_vrfs = atoi(argv[i+1])) &&
                    (tmp_vrfs <= MAX_TEST_VRFS)) {
                    vrf_count = (uint32_t)tmp_vrfs;
                    i++;
                }
            } else if ((strcmp(argv[i], "skip-pre-cfg") == 0)) {
                skip_pre_cfg = 1;
            } else if ((strcmp(argv[i], "clean-up") == 0)) {
                clean_up_cfg = true;
            }
            i++;
        }
    }

    std::cout << "Running Test for VRF: " << TEST_VRF_NAME << ", AF: " <<
        ((test_addr_family == AF_INET6) ? "IPv6":"IPv4") << std::endl;
    std::cout << "=======================================================" << std::endl;
    if (test_addr_family == AF_INET6) {
        TEST_GRP_IP_ADDR = TEST_GRP_IPV6;
        TEST_SRC_IP_ADDR = TEST_SRC_IPV6;
        TEST_GRP_RANGE_IP_ADDR = TEST_GRP_RANGE_IPV6;
        TEST_SRC_RANGE_IP_ADDR = TEST_SRC_RANGE_IPV6;
    }

    if(is_non_default_vrf_test) {
        ROUTE_IF_NAME_1.assign("v-e101-001-0");
        ROUTE_IF_NAME_2.assign("v-e101-004-0");
        ROUTE_OIF_NAME_1.assign("v-e101-002-0");
        ROUTE_OIF_NAME_2.assign("v-e101-003-0");

        ROUTE_OIF_LIST_1 = {{ROUTE_OIF_NAME_1, false, NULL_STRING}};
        ROUTE_OIF_LIST_2 = {{ROUTE_OIF_NAME_1, false, NULL_STRING},
                            {ROUTE_OIF_NAME_2, false, NULL_STRING}};
        ROUTE_OIF_LIST_3 = {{ROUTE_OIF_NAME_2, false, NULL_STRING}};

        ROUTE_VLAN_IF_NAME_1.assign("v-br201");
        ROUTE_VLAN_OIF_NAME_1.assign("v-br202");
        ROUTE_VLAN_OIF_NAME_2.assign("v-br203");

        ROUTE_VLAN_OIF_LIST_1 = {{ROUTE_VLAN_OIF_NAME_1, false, NULL_STRING}};
        ROUTE_VLAN_OIF_LIST_2 = {{ROUTE_VLAN_OIF_NAME_1, false, NULL_STRING},
                                 {ROUTE_VLAN_OIF_NAME_2, false, NULL_STRING}};
        ROUTE_VLAN_OIF_LIST_3 = {{ROUTE_VLAN_OIF_NAME_2, false, NULL_STRING}};

        ROUTE_LAG_IF_NAME.assign("v-bo15");
        ROUTE_LAG_OIF_NAME.assign("v-bo16");
        ROUTE_LAG_VLAN_MBR_NAME.assign("v-bo17");
        ROUTE_LAG_VLAN_OIF_NAME.assign("v-br201");
        ROUTE_LAG_OIF_LIST_1 = {{ROUTE_LAG_OIF_NAME, false, NULL_STRING}};
        ROUTE_LAG_OIF_LIST_2 = {{ROUTE_LAG_OIF_NAME, false, NULL_STRING},
                                {ROUTE_LAG_VLAN_OIF_NAME, false, NULL_STRING}};

        LAG_IF_NAME_1.assign("v-e101-013-0");
        LAG_IF_NAME_2.assign("v-e101-014-0");
        LAG_IF_NAME_3.assign("v-e101-015-0");
        LAG_IF_NAME_4.assign("v-e101-016-0");
        LAG_IF_NAME_5.assign("v-e101-017-0");
        LAG_IF_NAME_6.assign("v-e101-018-0");

    }
    if (clean_up_cfg) {
        nas_l3_mcast_test_config_clean_up();
        return 0;
    }

    if (!skip_pre_cfg)
        nas_l3_mcast_config_test_pre_req();

    return RUN_ALL_TESTS();
}
