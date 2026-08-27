#ifndef NS_MOUNTINFO_H
#define NS_MOUNTINFO_H

#include <string>
#include <string_view>

namespace mountinfo {

bool decodePath(std::string_view encoded, std::string* decoded);

}  // namespace mountinfo

#endif /* NS_MOUNTINFO_H */
