#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <cryptuiapi.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>

//#include <openssl/applink.c>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#include <openssl/crypto.h>
#include <openssl/opensslconf.h> /* for OPENSSL_NO_EC */
#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif /* OPENSSL_NO_EC */
#endif /* OPENSSL_VERSION_NUMBER >= 0x10000000L */

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include <cctype>
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>
#include "webrequests.h"

using namespace std;

//#pragma comment(lib, "openssl.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

/*
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")
*/

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Cryptui.lib")
#pragma comment(lib, "Ws2_32.lib")

std::string url_encode(const std::string &value) {
	ostringstream escaped;
	escaped.fill('0');
	escaped << hex;

	for (string::const_iterator i = value.begin(), n = value.end(); i != n; ++i) {
		string::value_type c = (*i);

		// Keep alphanumeric and other accepted characters intact
		if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
			escaped << c;
			continue;
		}

		// Any other characters are percent-encoded
		escaped << uppercase;
		escaped << '%' << setw(2) << int((unsigned char)c);
		escaped << nouppercase;
	}

	return escaped.str();
}

//pilfered from: http://stackoverflow.com/a/33799784
std::string escape_json(const std::string &s) {
	std::ostringstream o;
	for (auto c = s.cbegin(); c != s.cend(); c++) {
		if (*c == '"' || *c == '\\' || ('\x00' <= *c && *c <= '\x1f')) {
			o << "\\u"
				<< std::hex << std::setw(4) << std::setfill('0') << (int)*c;
		}
		else {
			o << *c;
		}
	}
	return o.str();
}

SSL_CTX * OpenSSL_Init()
{
	SSL_library_init();
	SSLeay_add_ssl_algorithms(); //OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	/*
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	*/

	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method()); //TLSv1_2_client_method()
	if (!ctx)
		return nullptr;

	X509_STORE* store = SSL_CTX_get_cert_store(ctx);
	//load default certificates from Windows store
	HCERTSTORE hStore = CertOpenSystemStore(NULL, L"ROOT");
	if (hStore == NULL) {
		SSL_CTX_free(ctx);
		return nullptr;
	}

	for (PCCERT_CONTEXT pCertContext = CertEnumCertificatesInStore(hStore, NULL);
		pCertContext != nullptr;
		pCertContext = CertEnumCertificatesInStore(hStore, pCertContext))
	{
		//CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT, pCertContext, NULL, NULL, 0, NULL);
		X509* cert = d2i_X509(nullptr, (const unsigned char**)&pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);
		X509_STORE_add_cert(store, cert);
		X509_free(cert);
	}
	CertCloseStore(hStore, 0);
	return ctx;
}

void SSL_Shutdown(SSL_CTX* ctx)
{
	SSL_CTX_free(ctx);
	EVP_cleanup();
	/* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
}

std::string extract_header(const std::string& headers, const std::string& hdr)
{
	auto start = headers.find(hdr);
	if (start == std::string::npos)
		return "";
	auto end = headers.find("\r\n", start);
	if (end == std::string::npos)
		return "";
	start += hdr.length();
	return headers.substr(start, end - start);
}

namespace WebRequest {

	std::string https(SSL_CTX * ctx, std::string url, std::string data, std::string extra_headers, bool bIncludeHdrs, string content_type)
	{
		if (url.empty())
			return "";
		if (url.find("://") == string::npos)
			return "";
		std::string host, resource, buf, result, headers, extra_data;
		char tmp[1024];
		int iRead;
		SSL * ssl;
		BIO * bio;
		bio = BIO_new_ssl_connect(ctx);
		if (bio == nullptr)
			return "";
		BIO_get_ssl(bio, &ssl);
		SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
		host = url.substr(url.find("://") + 3, url.find("/", url.find("://") + 3) - (url.find("://") + 3));
		resource = url.substr(url.find("/", url.find("://") + 3));
		//cout << "Host: " << host << ", resource: " << resource << endl;
		BIO_set_conn_hostname(bio, (host + ":443").c_str());
		if (BIO_do_connect(bio) <= 0) {
			//SSL_free(ssl);
			//BIO_free(bio);
			BIO_free_all(bio);
			cout << "Error: unable to connect to " + host + ":443" << endl;
			return "";
		}
		
		if (SSL_get_verify_result(ssl) != X509_V_OK)
		{
			cout << "Unable to verify certificate." << endl;
			BIO_free_all(bio);
			//SSL_free(ssl);
			return "";
		}

		buf = url.substr(0, url.find(" ") + 1);
		buf += resource + " HTTP/1.1\r\nHost: " + host + "\r\n" +
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.21 Safari/537.36\r\n" +
			"Accept: text/html,application/xhtml+xml,application/xml, application/json, text/javascript;q=0.9,image/webp,*/*;q=0.8\r\n" +
			"Connection: keep-alive\r\n" +
			"Cache-Control: max-age=0\r\n" +
			"Accept-Encoding: null\r\n" +
			"Accept-Language: en-US,en;q=0.8\r\n" +
			"Origin: https://" + host + "\r\n" +
			extra_headers;

		if (url.at(0) == 'G' || url.at(0) == 'D') { //GET/DELETE request
			buf += "\r\n";
		}
		else {
			//POST/PUT request(idk if i'm doing it right for put but...)
			char tmp[1024];
			//application/json / application/x-www-form-urlencoded
			sprintf_s(tmp, "Content-Type: %s\r\nContent-Length: %d\r\n\r\n", content_type.c_str(), static_cast<DWORD>(data.length()));
			buf += string(tmp) + data;
		}
		//send the buffer
		int sent = 0;
		bool bFail = false;
		while (sent < (int)buf.length()) {
			int written = BIO_write(bio, &buf[sent], static_cast<int>(buf.length()) - sent);
			if (written <= 0) {
				if (BIO_should_retry(bio)) {
					Sleep(100);
					continue;
				}
				else {
					bFail = true;
					break;
				}
			}
			sent += written;
		}
		if (bFail)
			goto done;
		//cout << "Sent https request. Receiving response." << endl;
		buf.clear();

		while ((iRead = BIO_read(bio, tmp, sizeof(tmp))) > 0) {
			buf += string(tmp, iRead);
			if (buf.find("\r\n\r\n") != std::string::npos)
				break;
		}
		if (buf.find("\r\n\r\n") == std::string::npos)
			return buf;
		//extract headers
		headers = buf.substr(0, buf.find("\r\n\r\n"));
		extra_data = buf.substr(buf.find("\r\n\r\n") + 4);
		if (bIncludeHdrs)
			result += headers + "\r\n\r\n";
		if (headers.find("Transfer-Encoding: chunked") != std::string::npos) {
			cout << "chunked transfer encoding" << endl;
			//chunked transfer encoding
			//parse chunked data
			bool bJustCompletedChunkRead = false;
			while (true) {

				while (extra_data.find("\r\n") == string::npos || extra_data.find("\r\n") == 0) {
					//we still need to receive data from the server in order to get the length.
					iRead = BIO_read(bio, tmp, sizeof(tmp));
					if (iRead <= 0) {
						cout << "An error occured while receiving data from the server." << endl;
						bFail = true;
						break;
					}
					extra_data += std::string(tmp, iRead);

					if (extra_data.find("\r\n") == 0 && bJustCompletedChunkRead) {
						bJustCompletedChunkRead = false;
						extra_data = extra_data.substr(2);
					}

				}

				if (bFail)
					break;
				string chunk_length = extra_data.substr(0, extra_data.find("\r\n"));
				//cout << "chunk len=" << chunk_length << ", extra_data=" << extra_data << endl;
				DWORD nLength = strtoul(chunk_length.c_str(), nullptr, 16);
				//cout << "chunk len(confirmed): " << nLength << endl;
				if (nLength == 0)
					break;
				extra_data = extra_data.substr(chunk_length.length() + 2);

				if (extra_data.length() > nLength) {
					//cout << "extra_data.length() > nLength" << endl;
					result += extra_data.substr(0, nLength);
					extra_data = extra_data.substr(nLength);
					//cout << "Extra Data = " << extra_data << "NDELIMITER" << endl;
					nLength = 0;
				}
				else {
					//cout << "extra_data.length() < nLength" << endl;
					nLength -= static_cast<DWORD>(extra_data.length());
					result += extra_data;
					extra_data.clear();
				}
				
				while (nLength > 0) {
					iRead = BIO_read(bio, tmp, nLength > sizeof(tmp) ? sizeof(tmp) : nLength);
					if (iRead <= 0) {
						cout << "An error occured while receiving data from the server[2]." << endl;
						bFail = true;
						break;
					}
					result += string(tmp, iRead);
					nLength -= iRead;
				}

				bJustCompletedChunkRead = true;

				if (bFail)
					break;
			}

		}
		else if (headers.find("Content-Length: ") != std::string::npos) {
			cout << "content length" << endl;
			auto length = extract_header(headers, "Content-Length: ");
			auto len = std::stoi(length.c_str());
			result += extra_data;
			len -= static_cast<DWORD>(extra_data.length());
			while (len) {
				iRead = BIO_read(bio, tmp, len > sizeof(tmp) ? sizeof(tmp) : len);
				if (iRead <= 0) {
					cout << "An error occured while receiving data from the server[2]." << endl;
					bFail = true;
					break;
				}
				result += string(tmp, iRead);
				len -= iRead;
			}
		}
		else
			result = buf;
	done:
		BIO_free_all(bio);
		//SSL_free(ssl);
		return result;
	}

	std::string http(std::string url, std::string data, std::string extra_headers, bool bIncludeHdrs, std::string content_type)
	{
		if (url.empty())
			return "";
		if (url.find("://") == string::npos)
			return "";
		std::string host, resource, buf, result, headers, extra_data;
		char tmp[1024];
		int iRead;
		host = url.substr(url.find("://") + 3, url.find("/", url.find("://") + 3) - (url.find("://") + 3));
		resource = url.substr(url.find("/", url.find("://") + 3));
		BIO * bio;
		bio = BIO_new_connect((host + ":80").c_str());
		if (bio == nullptr)
			return "";
		//cout << "Host: " << host << ", resource: " << resource << endl;
		if (BIO_do_connect(bio) <= 0) {
			BIO_free_all(bio);
			//SSL_free(ssl);
			cout << "Error: unable to connect to " + host + ":80" << endl;
			return "";
		}
		buf = url.substr(0, url.find(" ") + 1);
		buf += resource + " HTTP/1.1\r\nHost: " + host + "\r\n" +
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.21 Safari/537.36\r\n" +
			"Accept: text/html,application/xhtml+xml,application/xml, application/json, text/javascript;q=0.9,image/webp,*/*;q=0.8\r\n" +
			"Connection: keep-alive\r\n" +
			"Cache-Control: max-age=0\r\n" +
			"Accept-Encoding: null\r\n" +
			"Accept-Language: en-US,en;q=0.8\r\n" +
			"Origin: http://" + host + "\r\n" +
			extra_headers;

		if (url.at(0) == 'G' || url.at(0) == 'D') { //GET/DELETE request
			buf += "\r\n";
		}
		else {
			//POST/PUT request(idk if i'm doing it right for put but...)
			char tmp[1024];
			//application/json / application/x-www-form-urlencoded
			sprintf_s(tmp, "Content-Type: %s\r\nContent-Length: %d\r\n\r\n", content_type.c_str(), static_cast<DWORD>(data.length()));
			buf += string(tmp) + data;
		}
		//send the buffer
		int sent = 0;
		bool bFail = false;
		while (sent < (int)buf.length()) {
			int written = BIO_write(bio, &buf[sent], static_cast<int>(buf.length()) - sent);
			if (written <= 0) {
				if (BIO_should_retry(bio)) {
					Sleep(100);
					continue;
				}
				else {
					bFail = true;
					break;
				}
			}
			sent += written;
		}
		if (bFail)
			goto done;
		//cout << "Sent https request. Receiving response." << endl;
		buf.clear();

		while ((iRead = BIO_read(bio, tmp, sizeof(tmp))) > 0) {
			buf += string(tmp, iRead);
			if (buf.find("\r\n\r\n") != std::string::npos)
				break;
		}
		if (buf.find("\r\n\r\n") == std::string::npos)
			return buf;
		//extract headers
		headers = buf.substr(0, buf.find("\r\n\r\n"));
		extra_data = buf.substr(buf.find("\r\n\r\n") + 4);
		if (bIncludeHdrs)
			result += headers + "\r\n\r\n";
		if (headers.find("Transfer-Encoding: chunked") != std::string::npos) {
			//chunked transfer encoding
			//parse chunked data
			while (true) {
				while (extra_data.find("\r\n") == string::npos) {
					//we still need to receive data from the server in order to get the length.
					iRead = BIO_read(bio, tmp, sizeof(tmp));
					if (iRead <= 0) {
						cout << "An error occured while receiving data from the server." << endl;
						bFail = true;
						break;
					}
					extra_data += std::string(tmp, iRead);
				}
				if (bFail)
					break;
				string chunk_length = extra_data.substr(0, extra_data.find("\r\n"));
				DWORD nLength = strtoul(chunk_length.c_str(), nullptr, 16);
				cout << "chunk len: " << nLength << endl;
				if (nLength == 0)
					break;
				extra_data = extra_data.substr(extra_data.find("\r\n") + 2);
				if (extra_data.length() < nLength) {
					nLength -= static_cast<DWORD>(extra_data.length());
					result += extra_data;
					extra_data.clear();
					while (nLength) {
						iRead = BIO_read(bio, tmp, sizeof(tmp) > nLength ? nLength : sizeof(tmp));
						if (iRead <= 0) {
							cout << "An error occured while receiving data from the server[2]." << endl;
							bFail = true;
							break;
						}
						result += string(tmp, iRead);
						nLength -= iRead;
					}
					if (bFail)
						break;
				}
				else {
					result += extra_data.substr(0, nLength);
					extra_data = extra_data.substr(nLength);
				}
			}

		}
		else if (headers.find("Content-Length: ") != std::string::npos) {
			auto start = headers.find("Content-Length: ");
			auto end = headers.find("\r\n", start);
			if (start == std::string::npos)
				goto done;
			start += strlen("Content-Length: ");
			string length = headers.substr(start, end - start);
			auto len = std::stoi(length);
			result += extra_data;
			len -= static_cast<int>(extra_data.length());
			while (len) {
				iRead = BIO_read(bio, tmp, len > sizeof(tmp) ? sizeof(tmp) : len);
				if (iRead <= 0) {
					cout << "An error occured while receiving data from the server[2]." << endl;
					bFail = true;
					break;
				}
				result += string(tmp, iRead);
				len -= iRead;
			}
		}
		else
			result = buf;
	done:
		BIO_free_all(bio);
		//SSL_free(ssl);
		return result;
	}

};