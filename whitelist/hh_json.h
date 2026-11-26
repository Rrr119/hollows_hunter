#pragma once

#include <string>
#include <map>
#include <vector>

namespace hh_white {

// Minimal, dependency-free JSON model. It supports the subset emitted by
// PE-sieve: objects, arrays, strings (with standard escapes), numbers,
// booleans and null. The goal is to avoid pulling a third-party library into
// the tree while keeping the post-processing code unit-testable on Linux.
class JsonValue {
public:
    typedef enum { J_NULL, J_BOOL, J_NUMBER, J_STRING, J_ARRAY, J_OBJECT } Type;

    JsonValue() : type(J_NULL), bool_val(false), num_val(0) {}

    Type type;
    bool bool_val;
    long long num_val;
    std::string str_val;
    std::vector<JsonValue> arr_val;
    std::map<std::string, JsonValue> obj_val;

    bool isObject() const { return type == J_OBJECT; }
    bool isArray() const { return type == J_ARRAY; }

    const JsonValue* get(const std::string& key) const
    {
        if (type != J_OBJECT) return nullptr;
        std::map<std::string, JsonValue>::const_iterator itr = obj_val.find(key);
        return itr == obj_val.end() ? nullptr : &itr->second;
    }

    bool getBool(const std::string& key, bool fallback = false) const
    {
        const JsonValue* val = get(key);
        return (val && val->type == J_BOOL) ? val->bool_val : fallback;
    }

    long long getNumber(const std::string& key, long long fallback = 0) const
    {
        const JsonValue* val = get(key);
        return (val && val->type == J_NUMBER) ? val->num_val : fallback;
    }

    std::string getString(const std::string& key, const std::string& fallback = "") const
    {
        const JsonValue* val = get(key);
        return (val && val->type == J_STRING) ? val->str_val : fallback;
    }
};

class JsonParser {
public:
    // Parses the full buffer. Returns true on success.
    static bool parse(const std::string& text, JsonValue& out);

private:
    JsonParser(const std::string& text) : src(text), pos(0) {}
    bool parseValue(JsonValue& out);
    bool parseObject(JsonValue& out);
    bool parseArray(JsonValue& out);
    bool parseString(std::string& out);
    bool parseNumber(JsonValue& out);
    bool parseLiteral(const char* literal, JsonValue& out, bool value);
    void skipWhitespace();
    char peek() const;
    char next();

    const std::string& src;
    size_t pos;
};

} // namespace hh_white
