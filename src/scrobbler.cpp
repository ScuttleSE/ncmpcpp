/***************************************************************************
 *   Copyright (C) 2008-2021 by Andrzej Rybczak                            *
 *   andrzej@rybczak.net                                                   *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.              *
 ***************************************************************************/

#include "scrobbler.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <thread>

#include "curl_handle.h"
#include "settings.h"

// ============================================================================
// Minimal public-domain MD5 implementation
// Based on the RSA Data Security, Inc. MD5 Message-Digest Algorithm.
// ============================================================================

namespace {

// MD5 context
struct MD5Context {
	uint32_t state[4];
	uint32_t count[2];
	uint8_t  buffer[64];
};

static const uint8_t MD5_PADDING[64] = { 0x80 };

static void md5_encode(uint8_t *out, const uint32_t *in, size_t len)
{
	for (size_t i = 0, j = 0; j < len; ++i, j += 4) {
		out[j]   = (uint8_t)(in[i] & 0xff);
		out[j+1] = (uint8_t)((in[i] >> 8)  & 0xff);
		out[j+2] = (uint8_t)((in[i] >> 16) & 0xff);
		out[j+3] = (uint8_t)((in[i] >> 24) & 0xff);
	}
}

static void md5_decode(uint32_t *out, const uint8_t *in, size_t len)
{
	for (size_t i = 0, j = 0; j < len; ++i, j += 4)
		out[i] = ((uint32_t)in[j]) | (((uint32_t)in[j+1]) << 8)
		       | (((uint32_t)in[j+2]) << 16) | (((uint32_t)in[j+3]) << 24);
}

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

#define F(x,y,z) (((x)&(y))|((~x)&(z)))
#define G(x,y,z) (((x)&(z))|((y)&(~z)))
#define H(x,y,z) ((x)^(y)^(z))
#define I(x,y,z) ((y)^((x)|(~z)))
#define ROTATE(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define FF(a,b,c,d,x,s,ac) { (a)+=F((b),(c),(d))+(x)+(uint32_t)(ac); (a)=ROTATE((a),(s)); (a)+=(b); }
#define GG(a,b,c,d,x,s,ac) { (a)+=G((b),(c),(d))+(x)+(uint32_t)(ac); (a)=ROTATE((a),(s)); (a)+=(b); }
#define HH(a,b,c,d,x,s,ac) { (a)+=H((b),(c),(d))+(x)+(uint32_t)(ac); (a)=ROTATE((a),(s)); (a)+=(b); }
#define II(a,b,c,d,x,s,ac) { (a)+=I((b),(c),(d))+(x)+(uint32_t)(ac); (a)=ROTATE((a),(s)); (a)+=(b); }

static void md5_transform(uint32_t state[4], const uint8_t block[64])
{
	uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];
	md5_decode(x, block, 64);
	FF(a,b,c,d,x[ 0],S11,0xd76aa478); FF(d,a,b,c,x[ 1],S12,0xe8c7b756);
	FF(c,d,a,b,x[ 2],S13,0x242070db); FF(b,c,d,a,x[ 3],S14,0xc1bdceee);
	FF(a,b,c,d,x[ 4],S11,0xf57c0faf); FF(d,a,b,c,x[ 5],S12,0x4787c62a);
	FF(c,d,a,b,x[ 6],S13,0xa8304613); FF(b,c,d,a,x[ 7],S14,0xfd469501);
	FF(a,b,c,d,x[ 8],S11,0x698098d8); FF(d,a,b,c,x[ 9],S12,0x8b44f7af);
	FF(c,d,a,b,x[10],S13,0xffff5bb1); FF(b,c,d,a,x[11],S14,0x895cd7be);
	FF(a,b,c,d,x[12],S11,0x6b901122); FF(d,a,b,c,x[13],S12,0xfd987193);
	FF(c,d,a,b,x[14],S13,0xa679438e); FF(b,c,d,a,x[15],S14,0x49b40821);
	GG(a,b,c,d,x[ 1],S21,0xf61e2562); GG(d,a,b,c,x[ 6],S22,0xc040b340);
	GG(c,d,a,b,x[11],S23,0x265e5a51); GG(b,c,d,a,x[ 0],S24,0xe9b6c7aa);
	GG(a,b,c,d,x[ 5],S21,0xd62f105d); GG(d,a,b,c,x[10],S22,0x02441453);
	GG(c,d,a,b,x[15],S23,0xd8a1e681); GG(b,c,d,a,x[ 4],S24,0xe7d3fbc8);
	GG(a,b,c,d,x[ 9],S21,0x21e1cde6); GG(d,a,b,c,x[14],S22,0xc33707d6);
	GG(c,d,a,b,x[ 3],S23,0xf4d50d87); GG(b,c,d,a,x[ 8],S24,0x455a14ed);
	GG(a,b,c,d,x[13],S21,0xa9e3e905); GG(d,a,b,c,x[ 2],S22,0xfcefa3f8);
	GG(c,d,a,b,x[ 7],S23,0x676f02d9); GG(b,c,d,a,x[12],S24,0x8d2a4c8a);
	HH(a,b,c,d,x[ 5],S31,0xfffa3942); HH(d,a,b,c,x[ 8],S32,0x8771f681);
	HH(c,d,a,b,x[11],S33,0x6d9d6122); HH(b,c,d,a,x[14],S34,0xfde5380c);
	HH(a,b,c,d,x[ 1],S31,0xa4beea44); HH(d,a,b,c,x[ 4],S32,0x4bdecfa9);
	HH(c,d,a,b,x[ 7],S33,0xf6bb4b60); HH(b,c,d,a,x[10],S34,0xbebfbc70);
	HH(a,b,c,d,x[13],S31,0x289b7ec6); HH(d,a,b,c,x[ 0],S32,0xeaa127fa);
	HH(c,d,a,b,x[ 3],S33,0xd4ef3085); HH(b,c,d,a,x[ 6],S34,0x04881d05);
	HH(a,b,c,d,x[ 9],S31,0xd9d4d039); HH(d,a,b,c,x[12],S32,0xe6db99e5);
	HH(c,d,a,b,x[15],S33,0x1fa27cf8); HH(b,c,d,a,x[ 2],S34,0xc4ac5665);
	II(a,b,c,d,x[ 0],S41,0xf4292244); II(d,a,b,c,x[ 7],S42,0x432aff97);
	II(c,d,a,b,x[14],S43,0xab9423a7); II(b,c,d,a,x[ 5],S44,0xfc93a039);
	II(a,b,c,d,x[12],S41,0x655b59c3); II(d,a,b,c,x[ 3],S42,0x8f0ccc92);
	II(c,d,a,b,x[10],S43,0xffeff47d); II(b,c,d,a,x[ 1],S44,0x85845dd1);
	II(a,b,c,d,x[ 8],S41,0x6fa87e4f); II(d,a,b,c,x[15],S42,0xfe2ce6e0);
	II(c,d,a,b,x[ 6],S43,0xa3014314); II(b,c,d,a,x[13],S44,0x4e0811a1);
	II(a,b,c,d,x[ 4],S41,0xf7537e82); II(d,a,b,c,x[11],S42,0xbd3af235);
	II(c,d,a,b,x[ 2],S43,0x2ad7d2bb); II(b,c,d,a,x[ 9],S44,0xeb86d391);
	state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
	std::memset(x, 0, sizeof(x));
}

static void md5_init(MD5Context &ctx)
{
	ctx.count[0] = ctx.count[1] = 0;
	ctx.state[0] = 0x67452301;
	ctx.state[1] = 0xefcdab89;
	ctx.state[2] = 0x98badcfe;
	ctx.state[3] = 0x10325476;
}

static void md5_update(MD5Context &ctx, const uint8_t *input, size_t len)
{
	size_t index = (ctx.count[0] >> 3) & 0x3f;
	if ((ctx.count[0] += (uint32_t)(len << 3)) < (uint32_t)(len << 3))
		ctx.count[1]++;
	ctx.count[1] += (uint32_t)(len >> 29);
	size_t partLen = 64 - index;
	size_t i = 0;
	if (len >= partLen) {
		std::memcpy(&ctx.buffer[index], input, partLen);
		md5_transform(ctx.state, ctx.buffer);
		for (i = partLen; i + 63 < len; i += 64)
			md5_transform(ctx.state, &input[i]);
		index = 0;
	}
	std::memcpy(&ctx.buffer[index], &input[i], len - i);
}

static void md5_final(uint8_t digest[16], MD5Context &ctx)
{
	uint8_t bits[8];
	md5_encode(bits, ctx.count, 8);
	size_t index = (ctx.count[0] >> 3) & 0x3f;
	size_t padLen = (index < 56) ? (56 - index) : (120 - index);
	md5_update(ctx, MD5_PADDING, padLen);
	md5_update(ctx, bits, 8);
	md5_encode(digest, ctx.state, 16);
	std::memset(&ctx, 0, sizeof(ctx));
}

// Compute MD5 of a UTF-8 string and return lowercase hex digest.
std::string md5hex(const std::string &s)
{
	MD5Context ctx;
	md5_init(ctx);
	md5_update(ctx, reinterpret_cast<const uint8_t *>(s.data()), s.size());
	uint8_t digest[16];
	md5_final(digest, ctx);

	static const char hex[] = "0123456789abcdef";
	std::string result(32, '\0');
	for (int i = 0; i < 16; ++i) {
		result[2*i]   = hex[(digest[i] >> 4) & 0xf];
		result[2*i+1] = hex[digest[i] & 0xf];
	}
	return result;
}

// ============================================================================
// Last.fm API helpers
// ============================================================================

// Registered ncmpcpp Last.fm API application credentials.
// api_secret is used only for signing; never sent in plain text over the wire.
const char *LASTFM_API_KEY    = "0a08c5b3b0f694eebbe2e4bf3ec840b1";
const char *LASTFM_API_SECRET = "8407b6f73dfb343657dc502e1963ab7d"; // placeholder — see note below
const char *LASTFM_API_URL    = "https://ws.audioscrobbler.com/2.0/";

// NOTE: LASTFM_API_SECRET above is a placeholder.  To use scrobbling you must
// register your own application at https://www.last.fm/api/account/create and
// set both LASTFM_API_KEY and LASTFM_API_SECRET to your own credentials, then
// recompile.  The read-only key used by the existing artist-info feature does
// not have a corresponding secret and cannot sign authenticated requests.

// Session key persisted between runs.
std::string g_session_key;

// Build an API method signature: sort params, concat key+value, append secret,
// then MD5 the whole string.  The "format" param is excluded per Last.fm spec.
std::string makeSignature(const std::map<std::string, std::string> &params)
{
	std::string raw;
	for (auto &kv : params) {
		if (kv.first == "format")
			continue;
		raw += kv.first;
		raw += kv.second;
	}
	raw += LASTFM_API_SECRET;
	return md5hex(raw);
}

// Build a URL-encoded POST body from a parameter map, appending the signature.
std::string buildPostBody(std::map<std::string, std::string> params)
{
	params["api_sig"] = makeSignature(params);
	params["format"]  = "json";
	std::string body;
	for (auto &kv : params) {
		if (!body.empty()) body += '&';
		body += Curl::escape(kv.first);
		body += '=';
		body += Curl::escape(kv.second);
	}
	return body;
}

// Read the session key from the cache file.
// Returns empty string if the file does not exist or is empty.
std::string readSessionKey()
{
	std::string path = Config.ncmpcpp_directory + "lastfm_session";
	std::ifstream f(path);
	if (!f.is_open())
		return {};
	std::string key;
	std::getline(f, key);
	return key;
}

// Write the session key to the cache file.
void writeSessionKey(const std::string &key)
{
	std::string path = Config.ncmpcpp_directory + "lastfm_session";
	std::ofstream f(path, std::ios::trunc);
	if (f.is_open())
		f << key << '\n';
	else
		std::cerr << "ncmpcpp: scrobbler: could not write session key to " << path << '\n';
}

// Extract a JSON string value for the given key from a flat JSON response.
// e.g. extractJson(resp, "key") finds "key":"VALUE" and returns VALUE.
std::string extractJson(const std::string &json, const std::string &key)
{
	std::string needle = "\"" + key + "\":\"";
	auto pos = json.find(needle);
	if (pos == std::string::npos)
		return {};
	pos += needle.size();
	auto end = json.find('"', pos);
	if (end == std::string::npos)
		return {};
	return json.substr(pos, end - pos);
}

// Step 1: call auth.getToken — returns an unauthorized token string.
std::string getToken()
{
	std::string url = std::string(LASTFM_API_URL)
	    + "?method=auth.getToken&api_key=" + LASTFM_API_KEY + "&format=json";
	std::string response;
	CURLcode code = Curl::perform(response, url);
	if (code != CURLE_OK) {
		std::cerr << "ncmpcpp: scrobbler: getToken failed: "
		          << curl_easy_strerror(code) << '\n';
		return {};
	}
	std::string token = extractJson(response, "token");
	if (token.empty())
		std::cerr << "ncmpcpp: scrobbler: getToken unexpected response: "
		          << response << '\n';
	return token;
}

// Step 2: call auth.getSession with an authorized token.
// Returns the session key on success, empty string on failure.
std::string getSession(const std::string &token)
{
	std::map<std::string, std::string> params = {
		{"method",  "auth.getSession"},
		{"api_key", LASTFM_API_KEY},
		{"token",   token},
	};
	std::string body = buildPostBody(params);
	std::string response;
	CURLcode code = Curl::post(response, LASTFM_API_URL, body);
	if (code != CURLE_OK) {
		std::cerr << "ncmpcpp: scrobbler: getSession failed: "
		          << curl_easy_strerror(code) << '\n';
		return {};
	}
	return extractJson(response, "key");
}

// Authenticate via the desktop auth flow:
//   1. Obtain a token from auth.getToken
//   2. Print an authorization URL for the user to visit in their browser
//   3. Poll auth.getSession until the user has authorized (up to ~90 seconds)
// On success, stores the session key in g_session_key and persists it to disk.
// Returns true on success.
bool authenticate()
{
	std::string token = getToken();
	if (token.empty())
		return false;

	std::cerr << "\nncmpcpp: scrobbler: authorize this app by opening the following URL:\n"
	          << "  https://www.last.fm/api/auth/?api_key=" << LASTFM_API_KEY
	          << "&token=" << token << '\n'
	          << "ncmpcpp: scrobbler: waiting for authorization"
	          << std::flush;

	// Poll auth.getSession every 5 seconds for up to 90 seconds.
	for (int attempt = 0; attempt < 18; ++attempt) {
		std::this_thread::sleep_for(std::chrono::seconds(5));
		std::cerr << '.' << std::flush;

		std::string key = getSession(token);
		if (!key.empty()) {
			std::cerr << "\nncmpcpp: scrobbler: authorized successfully\n";
			g_session_key = key;
			writeSessionKey(g_session_key);
			return true;
		}
	}

	std::cerr << "\nncmpcpp: scrobbler: timed out waiting for authorization\n";
	return false;
}

// Ensure we have a valid session key.  Returns true if ready to scrobble.
bool ensureAuthenticated()
{
	if (!g_session_key.empty())
		return true;
	g_session_key = readSessionKey();
	if (!g_session_key.empty())
		return true;
	return authenticate();
}

// Send track.updateNowPlaying.  Runs in a background thread.
void doUpdateNowPlaying(const std::string &artist,
                        const std::string &title,
                        const std::string &album,
                        unsigned duration)
{
	if (!ensureAuthenticated())
		return;

	std::map<std::string, std::string> params = {
		{"method",   "track.updateNowPlaying"},
		{"api_key",  LASTFM_API_KEY},
		{"sk",       g_session_key},
		{"artist",   artist},
		{"track",    title},
	};
	if (!album.empty())
		params["album"] = album;
	if (duration > 0)
		params["duration"] = std::to_string(duration);

	std::string body = buildPostBody(params);
	std::string response;
	CURLcode code = Curl::post(response, LASTFM_API_URL, body);
	if (code != CURLE_OK)
		std::cerr << "ncmpcpp: scrobbler: updateNowPlaying failed: "
		          << curl_easy_strerror(code) << '\n';
}

// Send track.scrobble.  Runs in a background thread.
void doScrobble(const std::string &artist,
                const std::string &title,
                const std::string &album,
                unsigned timestamp,
                unsigned duration)
{
	if (!ensureAuthenticated())
		return;

	std::map<std::string, std::string> params = {
		{"method",    "track.scrobble"},
		{"api_key",   LASTFM_API_KEY},
		{"sk",        g_session_key},
		{"artist",    artist},
		{"track",     title},
		{"timestamp", std::to_string(timestamp)},
	};
	if (!album.empty())
		params["album"] = album;
	if (duration > 0)
		params["duration"] = std::to_string(duration);

	std::string body = buildPostBody(params);
	std::string response;
	CURLcode code = Curl::post(response, LASTFM_API_URL, body);
	if (code != CURLE_OK)
		std::cerr << "ncmpcpp: scrobbler: scrobble failed: "
		          << curl_easy_strerror(code) << '\n';
}

// Returns true if the song is scrobbleable (has artist+title and duration>=30s).
bool isScrobbleable(const MPD::Song &s)
{
	return !s.empty()
	    && !s.getArtist().empty()
	    && !s.getTitle().empty()
	    && s.getDuration() >= 30;
}

} // anonymous namespace

// ============================================================================
// Public API
// ============================================================================

void Scrobbler::initialize()
{
	if (!Config.lastfm_scrobble)
		return;

	static bool initialized = false;
	if (initialized)
		return;
	initialized = true;

	// Pre-load the session key from disk so that the first song change does
	// not need to block on disk I/O or a network round-trip.
	g_session_key = readSessionKey();

	// If no cached key, run the desktop auth flow now (in the calling thread,
	// which is still early startup).  The user will be prompted to visit a URL.
	if (g_session_key.empty())
		authenticate();
}

void Scrobbler::songChanged(const MPD::Song &prev,
                            unsigned prev_start_time,
                            bool prev_threshold_met,
                            const MPD::Song &next)
{
	if (!Config.lastfm_scrobble)
		return;

	// Scrobble the previous song if eligible.
	if (prev_threshold_met && isScrobbleable(prev)) {
		std::string artist   = prev.getArtist();
		std::string title    = prev.getTitle();
		std::string album    = prev.getAlbum();
		unsigned    duration = prev.getDuration();
		unsigned    ts       = prev_start_time;
		std::thread([artist, title, album, duration, ts]() {
			doScrobble(artist, title, album, ts, duration);
		}).detach();
	}

	// Send now-playing for the new song.
	if (isScrobbleable(next)) {
		std::string artist   = next.getArtist();
		std::string title    = next.getTitle();
		std::string album    = next.getAlbum();
		unsigned    duration = next.getDuration();
		std::thread([artist, title, album, duration]() {
			doUpdateNowPlaying(artist, title, album, duration);
		}).detach();
	}
}

void Scrobbler::playerStopped(const MPD::Song &last,
                              unsigned last_start_time,
                              bool last_threshold_met)
{
	if (!Config.lastfm_scrobble)
		return;

	if (last_threshold_met && isScrobbleable(last)) {
		std::string artist   = last.getArtist();
		std::string title    = last.getTitle();
		std::string album    = last.getAlbum();
		unsigned    duration = last.getDuration();
		unsigned    ts       = last_start_time;
		std::thread([artist, title, album, duration, ts]() {
			doScrobble(artist, title, album, ts, duration);
		}).detach();
	}
}
