#ifndef NS_MNT_NEWAPI_H
#define NS_MNT_NEWAPI_H

#include <memory>
#include <string>
#include <vector>

#include "mnt.h"
#include "nsjail.h"

namespace mnt {
namespace newapi {

bool isAvailable();
std::unique_ptr<std::string> buildMountTree(nsj_t* nsj, std::vector<mnt::mount_t>* mounted_mpts);
bool remountPt(mnt::mount_t& mpt);

}  // namespace newapi
}  // namespace mnt

#endif /* NS_MNT_NEWAPI_H */
