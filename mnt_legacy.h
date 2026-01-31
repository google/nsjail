#ifndef NS_MNT_LEGACY_H
#define NS_MNT_LEGACY_H

#include <memory>
#include <string>
#include <vector>

#include "mnt.h"
#include "nsjail.h"

namespace mnt {
namespace legacy {

std::unique_ptr<std::string> buildMountTree(nsj_t* nsj, std::vector<mnt::mount_t>* mounted_mpts);
bool remountPt(mnt::mount_t& mpt);

}  // namespace legacy
}  // namespace mnt

#endif /* NS_MNT_LEGACY_H */
