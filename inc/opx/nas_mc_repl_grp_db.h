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
 * filename: nas_mc_repl_grp_db.h
 */

#ifndef __NAS_MC_REPL_GRP_DB_H__
#define __NAS_MC_REPL_GRP_DB_H__


#include "std_error_codes.h"
#include "std_llist.h"
#include "nas_types.h"
#include "ds_common_types.h"
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <memory>
#include <deque>
#include <utility>

/*
 * Replication Group DB data structure declarations and access methods.
 */
typedef enum mcast_repl_grp_owner_e {
    MCAST_SNOOPING = 1,
    MCAST_L3 = 2,
} mcast_repl_grp_owner_t;

typedef uint64_t nas_mcast_obj_id_t;

typedef std::unordered_map<npu_id_t, ndi_obj_id_t> mcast_repl_grp_id_list_t;
typedef std::pair<npu_id_t, ndi_obj_id_t> mcast_repl_grp_id_list_pair_t;

typedef std::set <hal_ifindex_t> mcast_if_set_t;
typedef std::map <hal_ifindex_t, mcast_if_set_t> mcast_if_list_t;   /* Key: vlan ifindex, data: l2 member port ifindex's */
typedef std::pair<hal_ifindex_t, mcast_if_set_t> mcast_if_list_pair_t;

typedef struct repl_grp_entry_key_s {
    mcast_repl_grp_owner_t owner;
    hal_vrf_id_t           vrf_id;
    mcast_if_list_t        iif_list;
    mcast_if_list_t        oif_list;
    bool                   cptocpu;
} repl_grp_entry_key_t;

typedef struct _repl_grp_entry_s {
    mcast_repl_grp_owner_t    owner;
    hal_vrf_id_t              vrf_id;
    nas_mcast_obj_id_t        mc_repl_id;
    mcast_if_list_t           iif_list;
    mcast_if_list_t           oif_list;
    bool                      cptocpu;
    mcast_repl_grp_id_list_t  mcast_repl_grp_id_list;
    uint32_t                  ref_cnt;
} repl_grp_entry_t;

typedef enum mcast_rgrp_ref_cnt_op_e {
    MCAST_RGRP_REF_CNT_INC = 1,
    MCAST_RGRP_REF_CNT_DEC = 2,
    MCAST_RGRP_REF_CNT_GET = 3,
} mcast_rgrp_ref_cnt_op_t;

struct repl_grp_entry_key_hash {
    size_t operator()(const repl_grp_entry_key_t& key) const {
        size_t hash = 0;
        hash ^= (std::hash<mcast_repl_grp_owner_t>()(key.owner) << 1);
        hash ^= (std::hash<hal_vrf_id_t>()(key.vrf_id) << 1);

        if (key.iif_list.empty() == false) {
            auto iif_it = key.iif_list.begin();
            for (; iif_it != key.iif_list.end(); ++iif_it) {
                hash ^= (std::hash<hal_ifindex_t>()(iif_it->first) << 1);
                auto mp_it = iif_it->second.begin();
                for (; mp_it != iif_it->second.end(); ++mp_it) {
                    hash ^= (std::hash<hal_ifindex_t>()(*mp_it) << 1);
                }
            }
        }

        if (key.oif_list.empty() == false) {
            auto oif_it = key.oif_list.begin();
            for (; oif_it != key.oif_list.end(); ++oif_it) {
                hash ^= (std::hash<hal_ifindex_t>()(oif_it->first) << 1);
                auto mp_it = oif_it->second.begin();
                for (; mp_it != oif_it->second.end(); ++mp_it) {
                    hash ^= (std::hash<hal_ifindex_t>()(*mp_it) << 1);
                }
            }
        }
        hash ^= (std::hash<bool>()(key.cptocpu) << 1);

        return hash;
    }
};

struct repl_grp_entry_key_equal {
    bool operator()(const repl_grp_entry_key_t& k1, const repl_grp_entry_key_t& k2) const{

        if ((k1.owner != k2.owner) || (k1.vrf_id != k2.vrf_id)
                || (k1.cptocpu != k2.cptocpu)
                || (k1.iif_list.size() != k2.iif_list.size())
                || (k1.oif_list.size() != k2.oif_list.size())) {
            return false;
        }

        auto k1_iif_it = k1.iif_list.begin();
        auto k2_iif_it = k2.iif_list.begin();
        for (; k1_iif_it != k1.iif_list.end(); ++k1_iif_it, ++k2_iif_it) {
            if (k1_iif_it->first != k2_iif_it->first) return false;
            if (k1_iif_it->second.size() != k2_iif_it->second.size()) return false;
            auto k1_mp_it = k1_iif_it->second.begin();
            auto k2_mp_it = k2_iif_it->second.begin();
            for ( ; k1_mp_it != k1_iif_it->second.end(); ++k1_mp_it, ++k2_mp_it) {
                if (*k1_mp_it != *k2_mp_it) return false;
            }
        }

        auto k1_oif_it = k1.oif_list.begin();
        auto k2_oif_it = k2.oif_list.begin();
        for (; k1_oif_it != k1.oif_list.end(); ++k1_oif_it, ++k2_oif_it) {
            if (k1_oif_it->first != k2_oif_it->first) return false;
            if (k1_oif_it->second.size() != k2_oif_it->second.size()) return false;
            auto k1_mp_it = k1_oif_it->second.begin();
            auto k2_mp_it = k2_oif_it->second.begin();
            for ( ; k1_mp_it != k1_oif_it->second.end(); ++k1_mp_it, ++k2_mp_it) {
                if (*k1_mp_it != *k2_mp_it) return false;
            }
        }
        return true;
    }
};

typedef std::unordered_map<nas_mcast_obj_id_t, repl_grp_entry_t *> mcast_grp_id_repl_grp_db_t;
typedef std::pair<nas_mcast_obj_id_t, repl_grp_entry_t *> mcast_grp_id_repl_grp_db_pair_t;

typedef std::unordered_map<repl_grp_entry_key_t, repl_grp_entry_t *,
                           repl_grp_entry_key_hash, repl_grp_entry_key_equal> mcast_repl_grp_db_t;
typedef std::pair<repl_grp_entry_key_t, repl_grp_entry_t *> mcast_repl_grp_db_pair_t;

repl_grp_entry_t * mcast_repl_grp_db_entry_get (nas_mcast_obj_id_t obj_id);
t_std_error mcast_repl_grp_db_entry_get_ndi_obj_id (npu_id_t npu_id,
                                                    nas_mcast_obj_id_t repl_grp_id,
                                                    ndi_obj_id_t *ndi_obj_id);

bool mcast_repl_grp_db_entry_delete (nas_mcast_obj_id_t obj_id);

bool mcast_repl_grp_db_entry_add (mcast_repl_grp_owner_t owner, uint32_t vrf_id, mcast_if_list_t * iif,
                               mcast_if_list_t *l3_oif_list, bool cptocpu, mcast_repl_grp_id_list_t &grp_id_list,
                               nas_mcast_obj_id_t &obj_id);

bool mcast_repl_grp_db_entry_delete (mcast_repl_grp_owner_t owner, uint32_t vrf_id, mcast_if_list_t *iif,
                                  mcast_if_list_t *l3_oif_list, bool cptocpu);

repl_grp_entry_t *mcast_repl_grp_db_entry_get (mcast_repl_grp_owner_t owner, uint32_t vrf_id, mcast_if_list_t *iif,
                                  mcast_if_list_t *_l3_oif_list, bool cptocpu);
/*
 * mcast_repl_grp_ref_cnt_op api can be used to increment/decrement/get the replication group refrence
 * count.
 */
bool mcast_repl_grp_db_ref_cnt_op (nas_mcast_obj_id_t obj_id, mcast_rgrp_ref_cnt_op_t op, uint32_t &ref_cnt);



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
