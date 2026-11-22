/*

   nsjail - generic VFS mount option parsing
   -----------------------------------------

   Copyright 2026 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#ifndef NS_MNT_OPTIONS_H
#define NS_MNT_OPTIONS_H

#include <stdint.h>
#include <sys/mount.h>

#include <string>

namespace mnt {

inline bool isGenericMountOption(const std::string& opt) {
	return opt == "ro" || opt == "rw" || opt == "nosuid" || opt == "suid" || opt == "nodev" ||
	       opt == "dev" || opt == "noexec" || opt == "exec";
}

inline void applyGenericMountOption(const std::string& opt, uintptr_t* flags) {
	if (opt == "ro") {
		*flags |= MS_RDONLY;
	} else if (opt == "rw") {
		*flags &= ~static_cast<uintptr_t>(MS_RDONLY);
	} else if (opt == "nosuid") {
		*flags |= MS_NOSUID;
	} else if (opt == "suid") {
		*flags &= ~static_cast<uintptr_t>(MS_NOSUID);
	} else if (opt == "nodev") {
		*flags |= MS_NODEV;
	} else if (opt == "dev") {
		*flags &= ~static_cast<uintptr_t>(MS_NODEV);
	} else if (opt == "noexec") {
		*flags |= MS_NOEXEC;
	} else if (opt == "exec") {
		*flags &= ~static_cast<uintptr_t>(MS_NOEXEC);
	}
}

/*
 * Applies generic VFS mount flags (ro/rw/nosuid/suid/nodev/dev/noexec/exec)
 * found in a comma-separated option string to *flags and returns the remaining
 * filesystem-specific options joined by ','.
 */
inline std::string extractGenericMountOptions(const std::string& options, uintptr_t* flags) {
	std::string fs_opts;
	size_t start = 0;
	while (start <= options.size()) {
		size_t comma = options.find(',', start);
		std::string opt = (comma == std::string::npos)
				      ? options.substr(start)
				      : options.substr(start, comma - start);
		if (!opt.empty()) {
			if (isGenericMountOption(opt)) {
				applyGenericMountOption(opt, flags);
			} else {
				if (!fs_opts.empty()) {
					fs_opts.push_back(',');
				}
				fs_opts.append(opt);
			}
		}
		if (comma == std::string::npos) {
			break;
		}
		start = comma + 1;
	}
	return fs_opts;
}

}  // namespace mnt

#endif /* NS_MNT_OPTIONS_H */
