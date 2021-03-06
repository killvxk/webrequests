#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <memory>
#include <iostream>
#include <Psapi.h>
#include <intrin.h>
#include <iphlpapi.h>

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

#include "webrequests.h"

using namespace std;


bool dump(const std::string& data, const std::string& filename)
{
	HANDLE hFile = CreateFileA(std::string("dumped/" + filename).c_str(), GENERIC_WRITE, NULL, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	DWORD w;
	::WriteFile(hFile, data.data(), data.length(), &w, nullptr);

	::CloseHandle(hFile);
	return true;
}

std::string between(const std::string & search_str, const std::string & str1, const std::string & str2)
{
	auto pos = search_str.find(str1);
	if (pos == std::string::npos)
		return "";
	pos += str1.length();
	auto pos2 = search_str.find(str2, pos);
	if (pos2 == std::string::npos)
		return "";
	return search_str.substr(pos, pos2 - pos);
}

int main()
{
	/*
	WIN32_FIND_DATAA fnd;
	HANDLE hSearch = FindFirstFileA("dumped/*.htm", &fnd);
	do {
		auto filename = std::string(fnd.cFileName);
		auto old_fn = "dumped/" + filename;
		auto n_fn = "dumped/" + filename + "l";
		if (old_fn.find("html") == std::string::npos)
			MoveFileA(old_fn.c_str(), n_fn.c_str());
	} while (FindNextFileA(hSearch, &fnd));
	*/

	::CreateDirectory(L"dumped", nullptr);

	auto ctx = OpenSSL_Init();

	for (int i = 55; i <= 126; i++) {
		auto response = WebRequest::https(ctx, "GET https://www.wuxiaworld.com/novel/condeming-the-heavens/cth-chapter-" + std::to_string(i), "", "Cookie: WuxiaWorld.Auth=CfDJ8LG47MCaQc1FgDJwKbE24WRdvfH6gganEct1pMDqlkxqaxMTjvHpPY6W5dekb8D5ZwmNQU-Ov1vUS7bUxhM0fGD6fIXTimxIx_8LCtchKH9X2GH8lfdMuJJiBWMPWT1-CoeQwsB2NYQITl8bCEsWvK2rw7EeY81qC2EwMOWCeC17IUwWI-zJAWkKr0XWJ1an7n-13rG4yOwRN2JiOSYc9eIRAUuVRB-UAKWOy1-JIiZGkvT-NpBvsYE7VaTX653BgmXWqfRgC9WyXPpscpCuDmtd3Od3DGGYzAr8otRWbj6TMuY2nK_RdKy7j__f3b7HTdmLfKbgtOWWaQM7nxt8Rcn_vZmjR5-y7SPjmyPoMVEuVyobikMb-ON2MVc6OyK-b4DnZQFp-joOqvSRKVcoCywI7fHd9C8TQmnBMLjMo6kxgX0zmRrdULE_jPrAiLA79JIkdPyGlyHTTfWcz8Y_WImdyzuik8Eeh6hdnrDDphhEmSkE7oZ1dokb9xUw39OvBAKmENOTmUG6WtrLA7Vc8s4a-6lgMecfp9F_qZDA-UNIljFnJs3zy-rN_4s0yh2CdgAb2FnTwYO8Pw5rDS87JxpmbkA65Y8VM1XwaY39aln3Sv1L-0dQt2SwU5t1HSbS5sMI2rF0-fn1nbC3tTuBh4VWjsAART0s9SvAxyzCnWlJ0ZNw-iP-vtl5VHiS5qKp9BIPp1s2A3m8yXEY1L6doVFfuH8L92yANJWyx-bpwKPQ\r\n");

		auto text = between(response, "<div class=\"fr-view\">", "Next Chapter\n</a>");

		if (!text.empty())
			text += "<br><h1><a href='" + std::to_string(i + 1) + ".htm'>" + std::to_string(i + 1) + "</a></h1>";
		if (text.empty()) {
			cout << "Failed to dump page #" << i << endl;
			Sleep(3000);
			i--;
		}
		else
			dump(text, std::to_string(i) + ".htm");
	}

	system("PAUSE");
	SSL_Shutdown(ctx);
    return 0;
}