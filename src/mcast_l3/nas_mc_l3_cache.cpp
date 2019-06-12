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
 * filename: nas_mc_l3_cache.cpp
 */

#include "hal_if_mapping.h"
#include "nas_mc_l3_util.h"
#include "nas_types.h"
#include "nas_vrf_utils.h"
#include "l3-multicast.h"
#include "std_utils.h"
#include "nas_mc_l3_cache.h"
#include "nas_base_utils.h"

#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <list>
#include <iostream>


struct intf_id_cache_key_hash {
    size_t operator()(const intf_id_cache_key_t& key) const {
        size_t hash = 0;
        hash ^= (std::hash<uint32_t>()(key.if_index) << 1);
        hash ^= (std::hash<uint32_t>()(key.vrf_id) << 1);

        return hash;
    }
};


struct intf_id_cache_key_equal {
    bool operator()(const intf_id_cache_key_t& k1, const intf_id_cache_key_t& k2) const{

        if ((k1.if_index != k2.if_index) || (k1.vrf_id != k2.vrf_id)) {
            return false;
        }

        return true;
    }
};

static std::mutex _intf_cache_mutex;
using if_ptr = std::shared_ptr<if_str_t>;
static auto &intf_cache = *new std::unordered_map<std::string, if_ptr>;
static auto &intf_id_cache = *new std::unordered_map<intf_id_cache_key_t, if_ptr,
            intf_id_cache_key_hash, intf_id_cache_key_equal>;

static std::mutex _vrf_cache_mutex;
using vrf_ptr = std::unique_ptr<vrf_str_t>;
static auto &vrf_cache = *new std::unordered_map<uint32_t, vrf_ptr>;

static std::mutex _intf_mlist_mutex;
static auto &intf_tagged_mlist_map = *(new mcast_intf_mlist_map_t);
static auto &intf_untagged_mlist_map = *(new mcast_intf_mlist_map_t);


static void mcast_vrf_cache_copy (vrf_str_t *dst, vrf_str_t *src)
{
    if ((dst != nullptr) && (src != nullptr)) {
        if (!src->vrf_name.empty()) dst->vrf_name.assign(src->vrf_name);
        dst->vrf_obj_id = src->vrf_obj_id;
        dst->v4_mcast_valid = src->v4_mcast_valid;
        dst->v4_mcast_status = src->v4_mcast_status;
        dst->v6_mcast_valid = src->v6_mcast_valid;
        dst->v6_mcast_status = src->v6_mcast_status;
    }
}

bool mcast_vrf_cache_get (uint32_t vrf_id, vrf_str_t &_vrf_info)
{
    std::lock_guard<std::mutex> lock(_vrf_cache_mutex);
    auto it = vrf_cache.find(vrf_id);
    if (it != vrf_cache.end()) {
        vrf_str_t *vrf_inst = it->second.get();
        if (vrf_inst != nullptr) {
            mcast_vrf_cache_copy(&_vrf_info, vrf_inst);
            return true;
        }
    }
    return false;
}

bool mcast_vrf_cache_get (std::string vrf_name, vrf_str_t &_vrf_info)
{
    std::lock_guard<std::mutex> lock(_vrf_cache_mutex);
    for (auto &it : vrf_cache) {
        vrf_str_t *vrf_inst = it.second.get();
        if ((vrf_inst != nullptr) &&
            (vrf_name.length() == vrf_inst->vrf_name.length()) &&
            !(strncmp (vrf_name.c_str(), vrf_inst->vrf_name.c_str(), vrf_name.length()))) {
            mcast_vrf_cache_copy(&_vrf_info, vrf_inst);
            return true;
        }
    }
    return false;
}

void mcast_vrf_cache_dump (void)
{
    auto it = vrf_cache.begin();
    std::cout << "mcast_vrf_cache_dump : \n";
    for (; it != vrf_cache.end(); ++it) {
        std::cout << "key: " << it->first << ", data: ";
        vrf_str_t *vrf_inst = it->second.get();
        if (vrf_inst != nullptr) {
            std::cout << "vrf_name: " << vrf_inst->vrf_name << ", vrf_obj_id: " << vrf_inst->vrf_obj_id;
            std::cout << ", v4_mcast_status: " << vrf_inst->v4_mcast_status << ", v6_mcast_status: ";
            std::cout << vrf_inst->v6_mcast_status << "\n";
        }
    }
}

void mcast_vrf_cache_for_each_entry_cps_get(cps_api_get_params_t *param, cps_api_qualifier_t qual,
                                            mcast_vrf_obj_get_cb fn)
{
    if (fn != NULL) {
        std::lock_guard<std::mutex> lock(_vrf_cache_mutex);
        auto it = vrf_cache.begin();
        for (; it != vrf_cache.end(); ++it) {
            vrf_str_t *vrf_inst = it->second.get();
            if (vrf_inst != nullptr) {
                vrf_str_t _vrf_info;
                mcast_vrf_cache_copy(&_vrf_info, vrf_inst);
                fn(_vrf_info, param, qual);
            }
        }
    }
}

bool mcast_vrf_cache_update (uint32_t vrf_id, vrf_str_t *vrf_info)
{
    bool rc = false;
    std::lock_guard<std::mutex> lock(_vrf_cache_mutex);

    if (vrf_info != nullptr) {
        auto it = vrf_cache.find(vrf_id);
        if (it != vrf_cache.end()) {
            vrf_str_t *vrf_inst = it->second.get();
            if (vrf_inst != nullptr) {
                mcast_vrf_cache_copy(vrf_inst, vrf_info);
                rc = true;
            } else {
                vrf_cache.erase(vrf_id);
                std::unique_ptr<vrf_str_t> vrf_ptr_inst(new vrf_str_t);
                vrf_inst = vrf_ptr_inst.get();
                if (vrf_inst != nullptr) {
                    mcast_vrf_cache_copy(vrf_inst, vrf_info);
                    vrf_cache.insert(std::make_pair(vrf_id, std::move(vrf_ptr_inst)));
                    rc = true;
                }
            }
        } else {
            std::unique_ptr<vrf_str_t> vrf_ptr_inst(new vrf_str_t);
            vrf_str_t *vrf_inst = vrf_ptr_inst.get();
            if (vrf_inst != nullptr) {
                mcast_vrf_cache_copy(vrf_inst, vrf_info);
                vrf_cache.insert(std::make_pair(vrf_id, std::move(vrf_ptr_inst)));
                rc = true;
            }
        }
    } else {
        auto it = vrf_cache.find(vrf_id);
        if (it != vrf_cache.end()) {
            vrf_cache.erase(vrf_id);
            rc = true;
        }
    }

    return rc;
}

static void mcast_intf_cache_copy (if_str_t *dst, if_str_t *src)
{
    if ((dst != nullptr) && (src != nullptr)) {
        if (!src->if_name.empty()) dst->if_name.assign(src->if_name);
        dst->if_index = src->if_index;
        dst->vrf_id = src->vrf_id;
        if (!src->vrf_name.empty()) dst->vrf_name.assign(src->vrf_name);
        dst->if_type = src->if_type;
        dst->vlan_id = src->vlan_id;
        dst->rif_id = src->rif_id;
        dst->v4_pim_valid = src->v4_pim_valid;
        dst->v4_pim_status = src->v4_pim_status;
        dst->v6_pim_valid = src->v6_pim_valid;
        dst->v6_pim_status = src->v6_pim_status;
    }
}
bool mcast_intf_cache_get (std::string if_name, if_str_t &_intf_info)
{
    std::lock_guard<std::mutex> lock(_intf_cache_mutex);
    auto it = intf_cache.find(if_name);
    if (it != intf_cache.end()) {
        if_str_t *if_inst = it->second.get();
        if (if_inst != nullptr) {
            mcast_intf_cache_copy(&_intf_info, if_inst);
            return true;
        }
    }
    return false;
}
bool mcast_intf_cache_get (intf_id_cache_key_t &key, if_str_t &_intf_info)
{
    std::lock_guard<std::mutex> lock(_intf_cache_mutex);
    auto it = intf_id_cache.find(key);
    if (it != intf_id_cache.end()) {
        if_str_t *if_inst = it->second.get();
        if (if_inst != nullptr) {
            mcast_intf_cache_copy(&_intf_info, if_inst);
            return true;
        }
    }
    return false;
}

void mcast_intf_cache_get_all_interfaces_for_vrf(hal_vrf_id_t vrf_id, std::list<std::string>& vrf_intf_list)
{
    std::lock_guard<std::mutex> lock(_intf_cache_mutex);

    auto it = intf_cache.begin();
    for (; it != intf_cache.end(); ++it) {
        if_str_t *intf_inst = it->second.get();

        if (intf_inst != nullptr) {
            //skip other vrf interfaces
            if (intf_inst->vrf_id != vrf_id)
                continue;

            vrf_intf_list.push_back(intf_inst->if_name);
        }
    }
}


void mcast_intf_cache_for_each_entry_cps_get(cps_api_get_params_t *param, cps_api_qualifier_t qual,
                                            mcast_intf_obj_get_cb fn, bool vrf_valid, hal_vrf_id_t vrf_id,
                                            bool af_valid, BASE_CMN_AF_TYPE_t af)
{
    if (fn != NULL) {
        std::lock_guard<std::mutex> lock(_intf_cache_mutex);
        auto it = intf_cache.begin();
        for (; it != intf_cache.end(); ++it) {
            if_str_t *intf_inst = it->second.get();
            if (intf_inst != nullptr) {
                if_str_t intf_info;
                mcast_intf_cache_copy(&intf_info, intf_inst);
                if ((vrf_valid == false) || (vrf_id == intf_info.vrf_id)) {
                    fn(intf_info, param, qual, af_valid, af);
                }
            }
        }
    }
}

bool mcast_intf_cache_get_rif_id (hal_vrf_id_t vrf_id, hal_ifindex_t if_index,
                                  ndi_rif_id_t *rif_id)
{
    intf_id_cache_key_t key;
    if_str_t *if_inst = NULL;

    key.vrf_id = vrf_id;
    key.if_index = if_index;

    std::lock_guard<std::mutex> lock(_intf_cache_mutex);
    auto it = intf_id_cache.find(key);
    if (it != intf_id_cache.end()) {
        if_inst = it->second.get();
        if (if_inst != nullptr) {
            if (if_inst->rif_id != INVALID_RIF_ID) {
                *rif_id = if_inst->rif_id;
                return true;
            }
        }
    }
    //if rif_id in local cache is not valid,
    //then return failure.
    return false;
}

static void _print_intf_data(if_str_t *intf_inst)
{
    std::cout << "if_name: " << intf_inst->if_name;
    std::cout << ", if_index: " << intf_inst->if_index;
    std::cout << ", vrf_name: " << intf_inst->vrf_name;
    std::cout << ", if_type: " << intf_inst->if_type;
    std::cout << ", vlan_id: " << intf_inst->vlan_id;
    std::cout << ", rif_id: " << intf_inst->rif_id;
    std::cout << ", v4_pim_status: " << intf_inst->v4_pim_status;
    std::cout << ", v6_pim_status: " << intf_inst->v6_pim_status << "\n";
}

void mcast_intf_cache_dump (void)
{
    auto it = intf_cache.begin();
    std::cout << "mcast_intf_cache_dump: \n";
    for (; it != intf_cache.end(); ++it) {
        std::cout << "key: " << it->first << ", data: ";
        if_str_t *intf_inst = it->second.get();
        if (intf_inst != nullptr) {
            _print_intf_data(intf_inst);
       }
    }
}

void mcast_intf_id_cache_dump (void)
{
    auto it = intf_id_cache.begin();
    std::cout << "mcast_intf_id_cache_dump: \n";
    for (; it != intf_id_cache.end(); ++it) {
        intf_id_cache_key_t id_key = it->first;

        std::cout << "key: vrf:" << id_key.vrf_id << " if_idx:" << id_key.if_index << ", ";
        if_str_t *intf_inst = it->second.get();
        if (intf_inst != nullptr) {
            _print_intf_data(intf_inst);
        }
    }
}

bool mcast_intf_cache_update (std::string if_name, if_str_t *intf_info)
{
    bool rc = false;
    std::lock_guard<std::mutex> lock(_intf_cache_mutex);
    if (intf_info != nullptr) {
        NAS_MC_L3_LOG_DEBUG("MCAST-CACHE", "Interface cache update (add interface: %s)",
                if_name.c_str());
        auto it = intf_cache.find(if_name);
        if (it != intf_cache.end()) {
            if_str_t *if_inst = it->second.get();
            if (if_inst != nullptr) {
                mcast_intf_cache_copy(if_inst, intf_info);
                rc = true;
            } else {
                intf_cache.erase(if_name);
                if_ptr if_ptr_inst(new if_str_t);
                if_inst = if_ptr_inst.get();
                if (if_inst != nullptr) {
                    intf_id_cache_key_t id_key;
                    if_ptr if_id_ptr_inst(if_ptr_inst);
                    hal_vrf_id_t vrf_id = NAS_DEFAULT_VRF_ID;

                    if ((intf_info->vrf_name.empty()) && (intf_info->vrf_id == NAS_DEFAULT_VRF_ID)) {
                        intf_info->vrf_name.assign(NAS_DEFAULT_VRF_NAME);
                        intf_info->vrf_id = vrf_id;
                    } else if(nas_get_vrf_internal_id_from_vrf_name(intf_info->vrf_name.c_str(), &vrf_id) == STD_ERR_OK) {
                        id_key.vrf_id = vrf_id;
                        intf_info->vrf_id = vrf_id;
                    }

                    mcast_intf_cache_copy(if_inst, intf_info);
                    intf_cache.insert(std::make_pair(if_name, std::move(if_ptr_inst)));
                    id_key.if_index = if_inst->if_index;
                    id_key.vrf_id = if_inst->vrf_id;
                    intf_id_cache.insert(std::make_pair(id_key, std::move(if_id_ptr_inst)));
                    rc = true;
                }
            }
        } else {
            if_ptr if_ptr_inst(new if_str_t);
            if_str_t *if_inst = if_ptr_inst.get();
            if(if_inst != nullptr) {
                intf_id_cache_key_t id_key;
                if_ptr if_id_ptr_inst(if_ptr_inst);
                hal_vrf_id_t vrf_id = NAS_DEFAULT_VRF_ID;

                if ((intf_info->vrf_name.empty()) && (intf_info->vrf_id == NAS_DEFAULT_VRF_ID)) {
                    intf_info->vrf_name.assign(NAS_DEFAULT_VRF_NAME);
                    intf_info->vrf_id = vrf_id;
                } else if(nas_get_vrf_internal_id_from_vrf_name(intf_info->vrf_name.c_str(), &vrf_id) == STD_ERR_OK) {
                    id_key.vrf_id = vrf_id;
                    intf_info->vrf_id = vrf_id;
                }

                mcast_intf_cache_copy(if_inst, intf_info);
                intf_cache.insert(std::make_pair(if_name, std::move(if_ptr_inst)));
                id_key.if_index = if_inst->if_index;
                id_key.vrf_id = if_inst->vrf_id;
                intf_id_cache.insert(std::make_pair(id_key, std::move(if_id_ptr_inst)));
                rc = true;
            }
        }
    } else {
        NAS_MC_L3_LOG_DEBUG("MCAST-CACHE", "Interface cache update (delete interface: %s)",
                if_name.c_str());
        auto it = intf_cache.find(if_name);
        if (it != intf_cache.end()) {
            intf_id_cache_key_t id_key;
            hal_vrf_id_t vrfid = 0;
            if_str_t *if_inst = it->second.get();
            id_key.if_index = if_inst->if_index;
            if(nas_get_vrf_internal_id_from_vrf_name(if_inst->vrf_name.c_str(), &vrfid) == STD_ERR_OK) {
                id_key.vrf_id = vrfid;
                intf_id_cache.erase(id_key);
            }
            intf_cache.erase(if_name);
            rc = true;
        }
    }

    return rc;

}

bool mcast_intf_mlist_map_mlist_dump (const char *vlan_if_name)
{
    std::lock_guard<std::mutex> lock(_intf_mlist_mutex);

    if (vlan_if_name == NULL)
    {
        std::cout << "VLAN interface list dump - provide valid interface name (ex: br1) \n";
        return false;
    }
    auto intf_it = intf_tagged_mlist_map.find(vlan_if_name);
    if (intf_it != intf_tagged_mlist_map.end()) {
        std::cout << "VLAN Tagged interface list dump: \n";
        std::cout << "  Mbr IfIndex : " ;
        for (auto mbr_it = intf_it->second.begin();
                mbr_it != intf_it->second.end(); ++mbr_it) {
            std::cout << *mbr_it << ", ";
        }
    }

    std::cout << "\n";
    auto intf_untag_it = intf_untagged_mlist_map.find(vlan_if_name);
    if (intf_untag_it != intf_untagged_mlist_map.end()) {
        std::cout << "VLAN Un-tagged interface list dump: \n";
        std::cout << "  Mbr IfIndex : " ;
        for (auto mbr_it = intf_untag_it->second.begin();
                mbr_it != intf_untag_it->second.end(); ++mbr_it) {
            std::cout << *mbr_it << ", ";
        }
    }

    std::cout << "\n";
    return true;
}



/*
 * if_name : vlan interface name
 * mem_index: if_index of the member port to be added/removed
 * add: operation add or remove
 */
void mcast_intf_mlist_map_update (std::string if_name, vlan_member_type_t mtype,
                              hal_ifindex_t mem_index, bool add)
{
    std::lock_guard<std::mutex> lock(_intf_mlist_mutex);
    mcast_intf_mlist_map_t *pmlist_map = NULL;

    if (mtype == tagged) {
        pmlist_map = &intf_tagged_mlist_map;
    } else {
        pmlist_map = &intf_untagged_mlist_map;
    }
    if (add == true) {
        auto intf_it = pmlist_map->find(if_name);
        if (intf_it == pmlist_map->end()) {
            mcast_intf_mlist_t intf_list;
            intf_list.insert(mem_index);
            pmlist_map->insert(mcast_intf_mlist_map_pair_t(if_name, std::move(intf_list)));
        } else {
            intf_it->second.insert(mem_index);
        }

    } else {
        auto intf_it = pmlist_map->find(if_name);
        if (intf_it != pmlist_map->end()) {
            intf_it->second.erase(mem_index);
            if (intf_it->second.size() == 0) {
                pmlist_map->erase(if_name);
            }
        }
    }

}

bool mcast_intf_mlist_map_clear (std::string if_name)
{
    bool rc = false;

    std::lock_guard<std::mutex> lock(_intf_mlist_mutex);
    auto tintf_it = intf_tagged_mlist_map.find(if_name);
    if (tintf_it != intf_tagged_mlist_map.end()) {
        tintf_it->second.clear();
        intf_tagged_mlist_map.erase(if_name);
        rc = true;
    }
    auto untintf_it = intf_untagged_mlist_map.find(if_name);
    if (untintf_it != intf_untagged_mlist_map.end()) {
        untintf_it->second.clear();
        intf_untagged_mlist_map.erase(if_name);
        rc = true;
    }

    return rc;
}

bool mcast_intf_mlist_map_mlist_get (std::string if_name, vlan_member_type_t mtype,
                          std::unordered_set<hal_ifindex_t> & intf_list)
{
    std::lock_guard<std::mutex> lock(_intf_mlist_mutex);
    mcast_intf_mlist_map_t *pmlist_map = NULL;
    if (mtype == tagged) {
        pmlist_map = &intf_tagged_mlist_map;
    } else {
        pmlist_map = &intf_untagged_mlist_map;
    }

    auto intf_it = pmlist_map->find(if_name);
    if (intf_it != pmlist_map->end()) {
        intf_list = intf_it->second;
        return true;
    }

    return false;
}

/*
 * mem_index: if_index of the member port to be removed from all VLANs (tagged or untagged member)
 */
void mcast_vlan_member_port_delete (hal_ifindex_t mem_index, std::list<std::string>& vlan_if_name_list)
{
    std::lock_guard<std::mutex> lock(_intf_mlist_mutex);

    for (auto tag_it = intf_tagged_mlist_map.begin(); tag_it != intf_tagged_mlist_map.end(); tag_it++)
    {
        size_t erased = tag_it->second.erase(mem_index);
        if (erased != 0)
        {
            vlan_if_name_list.push_back(tag_it->first);
        }
    }

    for (auto untag_it = intf_untagged_mlist_map.begin(); untag_it != intf_untagged_mlist_map.end(); untag_it++)
    {
        size_t erased = untag_it->second.erase(mem_index);
        if (erased != 0)
        {
            vlan_if_name_list.push_back(untag_it->first);
        }
    }
}

