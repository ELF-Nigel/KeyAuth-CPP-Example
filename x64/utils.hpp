#pragma once
#include "storage.hpp"
#include "auth_guard.hpp"

inline bool CheckIfJsonKeyExists(const std::string& path, const std::string& section)
{
    auto data = saved_data_detail::read(path);
    saved_data_detail::JsonWipe wipe{data};
    return data.contains(section);
}
