#pragma once

#include "auth.hpp"
#include <filesystem>
#include <fstream>
#include <string>

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;

namespace saved_data_detail {
struct StringWipe final {
    std::string& value;
    ~StringWipe() { if (!value.empty()) SecureZeroMemory(value.data(), value.size()); }
};
struct JsonWipe final {
    json& value;
    ~JsonWipe() {
        if (!value.is_object()) return;
        for (auto& item : value.items()) {
            if (!item.value().is_string()) continue;
            auto& text = item.value().get_ref<std::string&>();
            if (!text.empty()) SecureZeroMemory(text.data(), text.size());
        }
    }
};
inline json read(const std::string& path) {
    try {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.good()) return json::object();
        const auto size = file.tellg();
        if (size < 0 || size > 1024 * 1024) return json::object();
        std::string raw(static_cast<size_t>(size), '\0');
        StringWipe wipe{raw};
        file.seekg(0);
        if (!raw.empty() && !file.read(raw.data(), static_cast<std::streamsize>(raw.size())))
            return json::object();
        if (raw.rfind("keyauth:dpapi:", 0) == 0) raw = KeyAuth::api::unprotect_data(raw);
        auto data = json::parse(raw, nullptr, false);
        return data.is_object() ? std::move(data) : json::object();
    } catch (const std::exception&) {
        return json::object();
    }
}
}

inline std::string ReadFromJson(const std::string& path, const std::string& section)
{
    auto data = saved_data_detail::read(path);
    saved_data_detail::JsonWipe wipe{data};
    if (!data.contains(section) || !data[section].is_string()) return "";
    return data[section].get<std::string>();
}

inline bool WriteToJson(const std::string& path, const std::string& name, const std::string& value, bool userpass,
    const std::string& name2, const std::string& value2)
{
    try {
        json data = json::object();
        saved_data_detail::JsonWipe wipe_data{data};
        data[name] = value;
        if (userpass) data[name2] = value2;
        std::string plain = data.dump();
        saved_data_detail::StringWipe wipe_plain{plain};
        const auto encrypted = KeyAuth::api::protect_data(plain);
        if (encrypted.size() > 1024 * 1024) return false;
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file.good()) return false;
        file.write(encrypted.data(), static_cast<std::streamsize>(encrypted.size()));
        file.flush();
        return file.good();
    } catch (const std::exception&) {
        return false;
    }
}
