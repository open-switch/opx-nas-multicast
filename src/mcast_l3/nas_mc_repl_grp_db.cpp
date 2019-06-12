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
 * filename: nas_mc_repl_grp_db.cpp
 */

#include "nas_mc_l3_util.h"
#include "nas_types.h"
#include "nas_vrf_utils.h"
#include "std_utils.h"
#include "nas_base_utils.h"
#include "nas_mc_repl_grp_db.h"

#include <unordered_map>
#include <unordered_set>
#include <iostream>


/*
 * Replication group database
 */

static auto &mcast_grp_id_repl_grp_db = *(new mcast_grp_id_repl_grp_db_t);
static auto &mcast_repl_grp_db = *(new mcast_repl_grp_db_t);

#define MCAST_MAX_REPL_OBJ_ID     (60000)
bool mcast_repl_grp_db_key_gen(mcast_repl_grp_owner_t owner, uint32_t vrf_id, mcast_if_list_t *iif,
                                       mcast_if_list_t *l3_oif_list, bool cptocpu, repl_grp_entry_key_t &key);
nas::id_generator_t mcast_repl_id_gen {MCAST_MAX_REPL_OBJ_ID};

repl_grp_entry_t * mcast_repl_grp_db_entry_get (nas_mcast_obj_id_t obj_id)
{
    repl_grp_entry_t *entry = NULL;
    auto it = mcast_grp_id_repl_grp_db.find(obj_id);

    if (it != mcast_grp_id_repl_grp_db.end()) {
        entry = it->second;
    }
    return entry;
}

t_std_error mcast_repl_grp_db_entry_get_ndi_obj_id (npu_id_t npu_id,
                                                    nas_mcast_obj_id_t repl_grp_id,
                                                    ndi_obj_id_t *ndi_obj_id)
{
    repl_grp_entry_t *entry = NULL;
    auto it = mcast_grp_id_repl_grp_db.find(repl_grp_id);

    if ((ndi_obj_id != NULL) &&
        (it != mcast_grp_id_repl_grp_db.end())) {

        entry = it->second;
        auto it1 = entry->mcast_repl_grp_id_list.find(npu_id);

        if (it1 != entry->mcast_repl_grp_id_list.end()) {
            *ndi_obj_id = (ndi_obj_id_t) (it1->second);
            return STD_ERR_OK;
        }
    }
    return STD_ERR(MCAST_L3, FAIL, 0);
}

bool mcast_repl_grp_db_entry_delete (nas_mcast_obj_id_t obj_id)
{
    auto it = mcast_grp_id_repl_grp_db.find(obj_id);
    if (it == mcast_grp_id_repl_grp_db.end()) {
        NAS_MC_L3_LOG_DEBUG("MCAST-CACHE", "Replication group entry not present object id(%lu)", obj_id);
        return false;
    }
    repl_grp_entry_t *entry = it->second;
    mcast_grp_id_repl_grp_db.erase(obj_id);
    if (entry != NULL) {
        repl_grp_entry_key_t key;
        mcast_repl_grp_db_key_gen(entry->owner, entry->vrf_id, &entry->iif_list,
                                  &entry->oif_list, entry->cptocpu, key);
        mcast_repl_grp_db.erase(key);
        delete entry;
    }
    mcast_repl_id_gen.release_id(obj_id);
    return true;
}

bool mcast_repl_grp_db_key_gen(mcast_repl_grp_owner_t owner, uint32_t vrf_id, mcast_if_list_t *iif,
                               mcast_if_list_t *l3_oif_list, bool cptocpu, repl_grp_entry_key_t &key)
{
    key.owner = owner;
    key.vrf_id = vrf_id;
    key.cptocpu = cptocpu;

    if (iif != NULL) {
        mcast_if_list_t tmp (iif->begin(), iif->end());
        key.iif_list = tmp;
    }
    if (l3_oif_list != NULL) {
        mcast_if_list_t tmp (l3_oif_list->begin(), l3_oif_list->end());
        key.oif_list = tmp;
    }
    return true;
}


bool mcast_repl_grp_db_entry_add (mcast_repl_grp_owner_t owner, uint32_t vrf_id, mcast_if_list_t *iif,
                               mcast_if_list_t *l3_oif_list, bool cptocpu, mcast_repl_grp_id_list_t &grp_id_list,
                               nas_mcast_obj_id_t &obj_id)
{
    repl_grp_entry_key_t key;

    if (mcast_repl_grp_db_key_gen(owner, vrf_id, iif, l3_oif_list, cptocpu, key) == false) {
        NAS_MC_L3_LOG_DEBUG("MCAST-CACHE", "Replication group db key generation failed.");
        return false;
    }


    auto it = mcast_repl_grp_db.find(key);
    if (it != mcast_repl_grp_db.end()) {
        NAS_MC_L3_LOG_DEBUG("MCAST-CACHE", "Replication group db entry is already present");
        return false;
    }

    repl_grp_entry_t *entry_inst(new repl_grp_entry_t);

    entry_inst->owner = owner;
    entry_inst->vrf_id = vrf_id;
    entry_inst->cptocpu = cptocpu;
    entry_inst->mc_repl_id = mcast_repl_id_gen.alloc_id();
    entry_inst->mcast_repl_grp_id_list = grp_id_list;
    if (iif != NULL) {
        mcast_if_list_t tmp (iif->begin(), iif->end());
        entry_inst->iif_list = tmp;
    }
    if (l3_oif_list != NULL) {
        mcast_if_list_t tmp (l3_oif_list->begin(), l3_oif_list->end());
        entry_inst->oif_list = tmp;
    }
    entry_inst->ref_cnt = 0;

    mcast_repl_grp_db.insert(mcast_repl_grp_db_pair_t(key, entry_inst));

    auto id_db_it = mcast_grp_id_repl_grp_db.find(entry_inst->mc_repl_id);
    if (id_db_it != mcast_grp_id_repl_grp_db.end()) {
        mcast_grp_id_repl_grp_db.erase(entry_inst->mc_repl_id);
    }
    mcast_grp_id_repl_grp_db.insert(mcast_grp_id_repl_grp_db_pair_t(entry_inst->mc_repl_id, entry_inst));
    obj_id = entry_inst->mc_repl_id;
    return true;
}

bool mcast_repl_grp_db_entry_delete (mcast_repl_grp_owner_t owner, uint32_t vrf_id, mcast_if_list_t *iif,
                                  mcast_if_list_t *l3_oif_list, bool cptocpu)
{
    repl_grp_entry_key_t key;

    if (mcast_repl_grp_db_key_gen(owner, vrf_id, iif, l3_oif_list, cptocpu, key) == false) {
        NAS_MC_L3_LOG_DEBUG("MCAST-CACHE", "Replication group db key generation failed.");
        return false;
    }

    auto it = mcast_repl_grp_db.find(key);
    if (it == mcast_repl_grp_db.end()) {
        NAS_MC_L3_LOG_DEBUG("MCAST-CACHE", "Replication group db entry not found");
        return false;
    }

    repl_grp_entry_t *entry_inst = it->second;
    mcast_repl_grp_db.erase(key);

    if (entry_inst != NULL) {
        mcast_grp_id_repl_grp_db.erase(entry_inst->mc_repl_id);
        mcast_repl_id_gen.release_id(entry_inst->mc_repl_id);
        delete entry_inst;
    }
    return true;
}

repl_grp_entry_t *mcast_repl_grp_db_entry_get (mcast_repl_grp_owner_t owner, uint32_t vrf_id, mcast_if_list_t *iif,
                                            mcast_if_list_t *l3_oif_list, bool cptocpu)
{
    repl_grp_entry_key_t key;

    if (mcast_repl_grp_db_key_gen(owner, vrf_id, iif, l3_oif_list, cptocpu, key) == false) {
        NAS_MC_L3_LOG_DEBUG("MCAST-CACHE", "Replication group db key generation failed.");
        return NULL;
    }

    auto it = mcast_repl_grp_db.find(key);
    if (it == mcast_repl_grp_db.end()) {
        NAS_MC_L3_LOG_DEBUG("MCAST-CACHE", "Replication group db entry not found");
        return NULL;
    } else {
        return it->second;
    }
}

bool mcast_repl_grp_db_ref_cnt_op (nas_mcast_obj_id_t obj_id, mcast_rgrp_ref_cnt_op_t op, uint32_t &ref_cnt)
{
    repl_grp_entry_t *entry = NULL;
    bool             ret = false;
    auto it = mcast_grp_id_repl_grp_db.find(obj_id);

    if (it != mcast_grp_id_repl_grp_db.end()) {
        entry = it->second;
        switch (op) {
            case MCAST_RGRP_REF_CNT_INC:
                entry->ref_cnt += 1;
                ref_cnt = entry->ref_cnt;
                ret = true;
                break;
            case MCAST_RGRP_REF_CNT_DEC:
                if (entry->ref_cnt >= 1) {
                    entry->ref_cnt -= 1;
                    ret = true;
                }
                ref_cnt = entry->ref_cnt;
                break;
            case MCAST_RGRP_REF_CNT_GET:
                ref_cnt = entry->ref_cnt;
                ret = true;
                break;
            default:
                ret = false;
                break;
        }
    }
    return ret;
}

void mcast_repl_grp_db_dump (void)
{
    std::cout << "mcast_repl_grp_db database dump: \n";
    auto id_it = mcast_repl_grp_db.begin();
    for( ; id_it != mcast_repl_grp_db.end(); id_it++) {
        repl_grp_entry_t *entry = id_it->second;
        //std::cout << "repl_grp_db_key : " << entry->repl_grp_db_key << ", mc_repl_id : " << entry->mc_repl_id << ", ";
        std::cout << "mc_repl_id : " << entry->mc_repl_id << ", ";
        std::cout << "owner: " << entry->owner << ", vrf_id: " << entry->vrf_id << ", cptocpu: " << entry->cptocpu << ", ";
        std::cout << "IIF list: ";
        auto iif_it = entry->iif_list.begin();
        for (;iif_it != entry->iif_list.end(); ++iif_it) {
            std::cout << "VLan : " << iif_it->first << " - ";
            auto mp_it = iif_it->second.begin();
            std::cout << "Mem port list: ";
            for (;mp_it != iif_it->second.end(); ++mp_it) {
                std::cout << *mp_it << ", ";
            }
        }
        std::cout << "OIF list: ";
        auto oif_it = entry->oif_list.begin();
        for (;oif_it != entry->oif_list.end(); ++oif_it) {
            std::cout << "VLan : " << oif_it->first << " - ";
            auto mp_it = oif_it->second.begin();
            std::cout << "Mem port list: ";
            for (;mp_it != oif_it->second.end(); ++mp_it) {
                std::cout << *mp_it << ", ";
            }
        }
        std::cout << "mcast_repl_grp_id_list : ";
        auto sgt = entry->mcast_repl_grp_id_list.begin();
        for (; sgt != entry->mcast_repl_grp_id_list.end(); sgt++) {
            std::cout << "(npuid: " <<  sgt->first << ", repl grpid : " << sgt->second << "), ";
        }
        std::cout << "ref_cnt : " << entry->ref_cnt << "\n";
    }

}

void mcast_grp_id_repl_grp_db_dump (void)
{
    std::cout << "mcast_grp_id_repl_grp_db database dump: \n";

    auto it = mcast_grp_id_repl_grp_db.begin();
    for (; it != mcast_grp_id_repl_grp_db.end(); ++it) {
        repl_grp_entry_t *entry = it->second;
        //std::cout << "repl_grp_db_key : " << entry->repl_grp_db_key << ", mc_repl_id : " << entry->mc_repl_id << ", ";
        std::cout << "mc_repl_id : " << entry->mc_repl_id << ", ";
        std::cout << "owner: " << entry->owner << ", vrf_id: " << entry->vrf_id << ", cptocpu: " << entry->cptocpu << ", ";
        std::cout << "IIF list: ";
        auto iif_it = entry->iif_list.begin();
        for (;iif_it != entry->iif_list.end(); ++iif_it) {
            std::cout << "VLan : " << iif_it->first << " - ";
            auto mp_it = iif_it->second.begin();
            std::cout << "Mem port list: ";
            for (;mp_it != iif_it->second.end(); ++mp_it) {
                std::cout << *mp_it << ", ";
            }
        }
        std::cout << "OIF list: ";
        auto oif_it = entry->oif_list.begin();
        for (;oif_it != entry->oif_list.end(); ++oif_it) {
            std::cout << "VLan : " << oif_it->first << " - ";
            auto mp_it = oif_it->second.begin();
            std::cout << "Mem port list: ";
            for (;mp_it != oif_it->second.end(); ++mp_it) {
                std::cout << *mp_it << ", ";
            }
        }
        std::cout << "mcast_repl_grp_id_list : ";
        auto sgt = entry->mcast_repl_grp_id_list.begin();
        for (; sgt != entry->mcast_repl_grp_id_list.end(); sgt++) {
            std::cout << "(npuid: " <<  sgt->first << ", repl grpid : " << sgt->second << "), ";
        }
        std::cout << "ref_cnt : " << entry->ref_cnt << "\n";
    }
}

