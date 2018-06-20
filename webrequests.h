#pragma once
SSL_CTX * OpenSSL_Init();
void SSL_Shutdown(SSL_CTX* ctx);

std::string url_encode(const std::string &value);
std::string escape_json(const std::string &s);
std::string extract_header(const std::string& headers, const std::string& hdr);

namespace WebRequest {
	std::string https(SSL_CTX * ctx, std::string url, std::string data = "", std::string extra_headers = "", bool bIncludeHdrs = false/*include headers in response*/, std::string content_type = "application/x-www-form-urlencoded");
	std::string http(std::string url, std::string data = "", std::string extra_headers = "", bool bIncludeHdrs = false/*include headers in response*/, std::string content_type = "application/x-www-form-urlencoded");
};