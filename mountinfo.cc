#include "mountinfo.h"

namespace mountinfo {

bool decodePath(std::string_view encoded, std::string* decoded) {
	decoded->clear();
	decoded->reserve(encoded.size());

	for (size_t i = 0; i < encoded.size();) {
		if (encoded[i] != '\\') {
			decoded->push_back(encoded[i++]);
			continue;
		}

		if (i + 3 >= encoded.size()) {
			return false;
		}
		unsigned value = 0;
		for (size_t j = 1; j <= 3; ++j) {
			const char digit = encoded[i + j];
			if (digit < '0' || digit > '7') {
				return false;
			}
			value = (value << 3) | static_cast<unsigned>(digit - '0');
		}
		if (value == 0 || value > 0xff) {
			return false;
		}
		decoded->push_back(static_cast<char>(value));
		i += 4;
	}

	return true;
}

}  // namespace mountinfo
