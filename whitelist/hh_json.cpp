#include "hh_json.h"

#include <cstdlib>

namespace hh_white {

char JsonParser::peek() const
{
    return pos < src.size() ? src[pos] : '\0';
}

char JsonParser::next()
{
    return pos < src.size() ? src[pos++] : '\0';
}

void JsonParser::skipWhitespace()
{
    while (pos < src.size()) {
        char c = src[pos];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            ++pos;
        }
        else {
            break;
        }
    }
}

bool JsonParser::parseString(std::string& out)
{
    if (peek() != '"') return false;
    ++pos;
    out.clear();
    while (pos < src.size()) {
        char c = src[pos++];
        if (c == '"') {
            return true;
        }
        if (c == '\\') {
            if (pos >= src.size()) return false;
            char esc = src[pos++];
            switch (esc) {
            case '"':  out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/':  out.push_back('/'); break;
            case 'b':  out.push_back('\b'); break;
            case 'f':  out.push_back('\f'); break;
            case 'n':  out.push_back('\n'); break;
            case 'r':  out.push_back('\r'); break;
            case 't':  out.push_back('\t'); break;
            case 'u': {
                if (pos + 4 > src.size()) return false;
                // Encode the BMP code point as UTF-8. Surrogate pairs are
                // rare in PE-sieve paths; handle the common single unit case.
                std::string hex = src.substr(pos, 4);
                pos += 4;
                unsigned int code = (unsigned int)strtoul(hex.c_str(), nullptr, 16);
                if (code < 0x80) {
                    out.push_back(char(code));
                }
                else if (code < 0x800) {
                    out.push_back(char(0xC0 | (code >> 6)));
                    out.push_back(char(0x80 | (code & 0x3F)));
                }
                else {
                    out.push_back(char(0xE0 | (code >> 12)));
                    out.push_back(char(0x80 | ((code >> 6) & 0x3F)));
                    out.push_back(char(0x80 | (code & 0x3F)));
                }
                break;
            }
            default:
                return false;
            }
        }
        else {
            out.push_back(c);
        }
    }
    return false; // unterminated string
}

bool JsonParser::parseNumber(JsonValue& out)
{
    size_t start = pos;
    if (peek() == '-') ++pos;
    while (pos < src.size()) {
        char c = src[pos];
        if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' ||
            c == '+' || c == '-') {
            ++pos;
        }
        else {
            break;
        }
    }
    if (pos == start) return false;
    out.type = JsonValue::J_NUMBER;
    out.num_val = (long long)strtoll(src.substr(start, pos - start).c_str(), nullptr, 10);
    return true;
}

bool JsonParser::parseLiteral(const char* literal, JsonValue& out, bool value)
{
    size_t len = 0;
    while (literal[len]) ++len;
    if (src.compare(pos, len, literal) != 0) {
        return false;
    }
    pos += len;
    out.type = JsonValue::J_BOOL;
    out.bool_val = value;
    return true;
}

bool JsonParser::parseArray(JsonValue& out)
{
    ++pos; // '['
    out.type = JsonValue::J_ARRAY;
    skipWhitespace();
    if (peek() == ']') { ++pos; return true; }
    while (true) {
        skipWhitespace();
        JsonValue element;
        if (!parseValue(element)) return false;
        out.arr_val.push_back(element);
        skipWhitespace();
        char c = next();
        if (c == ',') continue;
        if (c == ']') return true;
        return false;
    }
}

bool JsonParser::parseObject(JsonValue& out)
{
    ++pos; // '{'
    out.type = JsonValue::J_OBJECT;
    skipWhitespace();
    if (peek() == '}') { ++pos; return true; }
    while (true) {
        skipWhitespace();
        std::string key;
        if (!parseString(key)) return false;
        skipWhitespace();
        if (next() != ':') return false;
        skipWhitespace();
        JsonValue value;
        if (!parseValue(value)) return false;
        out.obj_val[key] = value;
        skipWhitespace();
        char c = next();
        if (c == ',') continue;
        if (c == '}') return true;
        return false;
    }
}

bool JsonParser::parseValue(JsonValue& out)
{
    skipWhitespace();
    char c = peek();
    switch (c) {
    case '{': return parseObject(out);
    case '[': return parseArray(out);
    case '"':
        out.type = JsonValue::J_STRING;
        return parseString(out.str_val);
    case 't': return parseLiteral("true", out, true);
    case 'f': return parseLiteral("false", out, false);
    case 'n':
        if (src.compare(pos, 4, "null") != 0) return false;
        pos += 4;
        out.type = JsonValue::J_NULL;
        return true;
    default:
        if (c == '-' || (c >= '0' && c <= '9')) {
            return parseNumber(out);
        }
        return false;
    }
}

bool JsonParser::parse(const std::string& text, JsonValue& out)
{
    JsonParser parser(text);
    parser.skipWhitespace();
    if (!parser.parseValue(out)) {
        return false;
    }
    parser.skipWhitespace();
    return parser.pos == text.size();
}

} // namespace hh_white
