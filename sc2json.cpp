// sc2kfix sc2json.cpp: test for reading .sc2 files and turning them into JSON/ZIP
// (c) 2025 sc2kfix project (https://sc2kfix.net) - released under the MIT license

// This particular file has to be UNICODE for wxWidgets
//#undef UNICODE

// This is also something for wxWidgets
#define _CRT_SECURE_NO_WARNINGS

#define WIN32_LEAN_AND_MEAN
#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <windows.h>
#include <winsock.h>
#include "json-small.hpp"
#include "deflate.h"

#include <wx/wfstream.h>
#include <wx/zipstrm.h>

enum {
	SC2X_SIZE_VANILLA		= 128,
	SC2X_SIZE_SMALL			= 128,
	SC2X_SIZE_MEDIUM		= 256,
	SC2X_SIZE_LARGE			= 512,
	SC2X_SIZE_EXTRA_LARGE	= 1024		// unlikely to ever be used, but added for completion
};

enum {
	SC2X_VERSION_UNKNOWN	= 0,
	SC2X_VERSION_JSONPROTO	= 1,
	SC2X_VERSION_SC2KFIX	= 1000,
	SC2X_VERSION_OC2K_PROTO	= 2000
};

#define IFF_HEAD(a, b, c, d) ((DWORD)d << 24 | (DWORD)c << 16 | (DWORD)b << 8 | (DWORD)a)
#define DWORD_NTOHL_CHECK(x) (bBigEndian ? ntohl(x) : x)
#define DWORD_HTONL_CHECK(x) (bBigEndian ? htonl(x) : x)

#define USE_DEFLATE TRUE

#define BAILOUT(s, ...) do { \
	printf("ERROR: " s, __VA_ARGS__); \
	system("pause"); \
	exit(0); \
} while (0)

/*
* Base64 encoding/decoding (RFC1341)
* Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
*
* This software may be distributed under the terms of the BSD license.
* See README for more details.
*/
// 2016-12-12 - Gaspard Petit : Slightly modified to return a std::string 
// instead of a buffer allocated with malloc.
static const unsigned char base64_encodetable[65] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const unsigned char base64_decodetable[256] = {
	128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
	128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
	128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
	62, 128, 128, 128, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60,
	61, 128, 128, 128, 0, 128, 128, 128, 0, 1, 2, 3, 4, 5,
	6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
	20, 21, 22, 23, 24, 25, 128, 128, 128, 128, 128, 128, 26, 27,
	28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
	42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 128, 128, 128, 128,
	128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
	128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
	128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
	128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
	128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
	128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
	128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
	128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
	128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
	128, 128, 128
};

std::string Base64Encode(const unsigned char* src, size_t len) {
	unsigned char* out, * pos;
	const unsigned char* end, * in;

	size_t olen;

	olen = 4 * ((len + 2) / 3); /* 3-byte blocks to 4-byte */

	if (olen < len)
		return std::string(); /* integer overflow */

	std::string outStr;
	outStr.resize(olen);
	out = (unsigned char*)&outStr[0];

	end = src + len;
	in = src;
	pos = out;
	while (end - in >= 3) {
		*pos++ = base64_encodetable[in[0] >> 2];
		*pos++ = base64_encodetable[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_encodetable[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_encodetable[in[2] & 0x3f];
		in += 3;
	}

	if (end - in) {
		*pos++ = base64_encodetable[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_encodetable[(in[0] & 0x03) << 4];
			*pos++ = '=';
		}
		else {
			*pos++ = base64_encodetable[((in[0] & 0x03) << 4) |
				(in[1] >> 4)];
			*pos++ = base64_encodetable[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
	}

	return outStr;
}

size_t Base64Decode(BYTE* pBuffer, size_t iBufSize, const unsigned char* src, size_t len) {
	unsigned char* pos, block[4], tmp;
	size_t i, count, olen;
	int pad = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (base64_decodetable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return 0;

	olen = count / 4 * 3;
	if (olen > iBufSize) {
		return 0;
	}
	pos = pBuffer;
	if (pBuffer == NULL) {
		return 0;
	}

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = base64_decodetable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
					/* Invalid padding */
					return 0;
				}
				break;
			}
		}
	}

	return pos - pBuffer;
}

bool FileExists(const char* name) {
	FILE* fdTest;
	if (!fopen_s(&fdTest, name, "r")) {
		fclose(fdTest);
		return true;
	}
	return false;
}

// not the safest function
int MaxisDecompress(BYTE* pBuffer, size_t iBufSize, BYTE* pCompressedData, int iCompressedSize) {
	int i = 0, j = 0;

	for (; i < iCompressedSize && j < iBufSize;) {
		if (pCompressedData[i] < 128) {
			memcpy(pBuffer + j, pCompressedData + i + 1, pCompressedData[i]);
			j += pCompressedData[i];
			i += pCompressedData[i] + 1;
		}
		else if (pCompressedData[i] > 128) {
			memset(pBuffer + j, pCompressedData[i + 1], pCompressedData[i] - 127);
			j += pCompressedData[i] - 127;
			i += 2;
		}
		else {
			printf("WARN: why did we get an 0x80? mods???\n");
		}
	}
	printf("Uncompressed %d bytes into %d bytes.\n", i, j);
	return j;
}

json::JSON EncodeDWORDArray(DWORD* dwArray, size_t iCount, BOOL bBigEndian) {
	json::JSON jsonArray = json::Array();
	for (int i = 0; i < iCount; i++) {
		jsonArray.append<DWORD>(DWORD_NTOHL_CHECK(dwArray[i]));
	}
	return jsonArray;
}

json::JSON EncodeBudgetArray(DWORD* dwBudgetArray, BOOL bBigEndian) {
	json::JSON jsonObject = json::Object();
	jsonObject["iCurrentCosts"] = DWORD_NTOHL_CHECK(dwBudgetArray[0]);
	jsonObject["iFundingPercent"] = DWORD_NTOHL_CHECK(dwBudgetArray[1]);
	jsonObject["iYearToDateCost"] = DWORD_NTOHL_CHECK(dwBudgetArray[2]);
	
	jsonObject["iCountMonth"] = json::Array<DWORD>(
		DWORD_NTOHL_CHECK(dwBudgetArray[3]), DWORD_NTOHL_CHECK(dwBudgetArray[5]), DWORD_NTOHL_CHECK(dwBudgetArray[7]),
		DWORD_NTOHL_CHECK(dwBudgetArray[9]), DWORD_NTOHL_CHECK(dwBudgetArray[11]), DWORD_NTOHL_CHECK(dwBudgetArray[13]),
		DWORD_NTOHL_CHECK(dwBudgetArray[15]), DWORD_NTOHL_CHECK(dwBudgetArray[17]), DWORD_NTOHL_CHECK(dwBudgetArray[19]),
		DWORD_NTOHL_CHECK(dwBudgetArray[21]), DWORD_NTOHL_CHECK(dwBudgetArray[23]), DWORD_NTOHL_CHECK(dwBudgetArray[25]));
	jsonObject["iFundMonth"] = json::Array<DWORD>(
		DWORD_NTOHL_CHECK(dwBudgetArray[4]), DWORD_NTOHL_CHECK(dwBudgetArray[6]), DWORD_NTOHL_CHECK(dwBudgetArray[8]),
		DWORD_NTOHL_CHECK(dwBudgetArray[10]), DWORD_NTOHL_CHECK(dwBudgetArray[12]), DWORD_NTOHL_CHECK(dwBudgetArray[14]),
		DWORD_NTOHL_CHECK(dwBudgetArray[16]), DWORD_NTOHL_CHECK(dwBudgetArray[18]), DWORD_NTOHL_CHECK(dwBudgetArray[20]),
		DWORD_NTOHL_CHECK(dwBudgetArray[22]), DWORD_NTOHL_CHECK(dwBudgetArray[24]), DWORD_NTOHL_CHECK(dwBudgetArray[26]));
	return jsonObject;
}

// Scary function! Overflows abound! Be careful!
void DecodeDWORDArray(DWORD* dwArray, json::JSON jsonArray, size_t iCount, BOOL bBigEndian) {
	for (int i = 0; i < iCount; i++)
		dwArray[i] = DWORD_HTONL_CHECK(jsonArray[i].ToInt());
}

int main(int argc, char** argv) {
	if (argc != 2 || argc == 2 && !FileExists(argv[1]))
		BAILOUT("pass me a file you goober\n");

	std::ifstream infile(argv[1], std::ios::binary | std::ios::ate);
	size_t sc2size = infile.tellg();
	BYTE* sc2file = (BYTE*)malloc(sc2size);
	if (!sc2file)
		BAILOUT("Couldn't malloc %d bytes for sc2file.\n", sc2size);

	infile.seekg(0, std::ios::beg);
	infile.read((char*)sc2file, sc2size);
	infile.close();

	printf("Read %d bytes of %s into sc2file buffer.\n", sc2size, argv[1]);

	if (*(DWORD*)&sc2file[0] != IFF_HEAD('F', 'O', 'R', 'M'))
		BAILOUT("pass me an actual friggin .sc2 file you goober\n");
	if (*(DWORD*)&sc2file[8] != IFF_HEAD('S', 'C', 'D', 'H'))
		BAILOUT("pass me an actual friggin .sc2 file you goober\n");

	printf("Container size: %d bytes\n", ntohl(*(DWORD*)&sc2file[4]));

	std::string strOutFilename = std::regex_replace(argv[1], std::regex("\.[Ss][Cc][Nn]$"), ".scnx");
	if (strOutFilename == argv[1]) {
		printf("Not a scenario, trying .sc2.\n");
		strOutFilename = std::regex_replace(argv[1], std::regex("\.[Ss][Cc]2$"), ".sc2x");

		if (strOutFilename == argv[1])
			BAILOUT("whatever you passed me wasn't an .sc2 or .scn, you goober\n");
	}
	wxFFileOutputStream fileStream(strOutFilename);
	wxZipOutputStream zipStream(fileStream);

	printf("Writing to %s...\n\n", strOutFilename.c_str());

	// TIME TO DIE
	json::JSON sc2json = json::Object();
	int iChunkStart = 12;
	int iChunkSize = 0;
	int iConvertedChunks = 0;

	do {
		iChunkStart += iChunkSize;
		iChunkSize = ntohl(*(DWORD*)&sc2file[iChunkStart + 4]);
		printf("dwChunkType = '%c%c%c%c', iChunkStart = 0x%08X, iChunkSize = %d\n", sc2file[iChunkStart], sc2file[iChunkStart + 1], sc2file[iChunkStart + 2], sc2file[iChunkStart + 3], iChunkStart, iChunkSize);

		for (int i = 0; i < iChunkSize; ) {
			if (*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('C', 'N', 'A', 'M')) {
				std::string strCityName((char*)&sc2file[iChunkStart + 9]);
				sc2json["CNAM"]["strCityName"] = strCityName;
				i += iChunkSize;
				iConvertedChunks++;
			}
			else if (*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('M', 'I', 'S', 'C')) {
				// Allocate and decompressed a fixed length chunk
				BYTE* pChunkMISC = (BYTE*)malloc(4800);
				if (!pChunkMISC)
					BAILOUT("Couldn't malloc 4800 bytes for MISC.");

				MaxisDecompress(pChunkMISC, 4800, &sc2file[iChunkStart + 8], ntohl(*(DWORD*)&sc2file[iChunkStart + 4]));

				sc2json["MISC"]["dwAlways290"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wCityMode"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wViewRotation"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wCityStartYear"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityDays"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityFunds"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityBonds"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wCityDifficulty"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wCityProgression"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityValue"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityLandValue"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityCrime"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityTraffic"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityPollution"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityFame"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityAdvertising"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityGarbage"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityWorkforcePercent"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityWorkforceLE"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityWorkforceEQ"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwNationalPopulation"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwNationalValue"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wNationalTax"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wNationalEconomyTrend"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["bWeatherHeat"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["bWeatherWind"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["bWeatherHumidity"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["bWeatherTrend"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wDisasterType"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityResidentialPopulation"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityRewardsUnlocked"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwArrCityPHEGraphData"] = Base64Encode(&pChunkMISC[i], 4 * 60);
				i += 4 * 60;

				sc2json["MISC"]["dwArrCityIndustryGraphData"] = Base64Encode(&pChunkMISC[i], 4 * 33);
				i += 4 * 33;

				// This table is staying as a Base64Encode because you SHOULD NOT mess with it
				sc2json["MISC"]["dwTileCount"] = Base64Encode(&pChunkMISC[i], 4 * 256);
				i += 4 * 256;

				sc2json["MISC"]["dwArrZonePops"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 8, TRUE);
				i += 4 * 8;

				sc2json["MISC"]["dwCityBondData"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 50, TRUE);
				i += 4 * 50;

				// TODO: Encode as arrays of useful JSON
				sc2json["MISC"]["stNeighborCities"]["south"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 4, TRUE);
				i += 4 * 4;
				sc2json["MISC"]["stNeighborCities"]["west"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 4, TRUE);
				i += 4 * 4;
				sc2json["MISC"]["stNeighborCities"]["north"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 4, TRUE);
				i += 4 * 4;
				sc2json["MISC"]["stNeighborCities"]["east"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 4, TRUE);
				i += 4 * 4;

				sc2json["MISC"]["wCityDemands"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 8, TRUE);
				i += 4 * 8;

				sc2json["MISC"]["wCityInventionYears"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 17, TRUE);
				i += 4 * 17;

				sc2json["MISC"]["dwBudgetArrResidentialTax"] = EncodeBudgetArray((DWORD*)&pChunkMISC[i], TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwBudgetArrCommercialTax"] = EncodeBudgetArray((DWORD*)&pChunkMISC[i], TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwBudgetArrIndustrialTax"] = EncodeBudgetArray((DWORD*)&pChunkMISC[i], TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwBudgetArrOrdinance"] = EncodeBudgetArray((DWORD*)&pChunkMISC[i], TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwBudgetArrBond"] = EncodeBudgetArray((DWORD*)&pChunkMISC[i], TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwBudgetArrPolice"] = EncodeBudgetArray((DWORD*)&pChunkMISC[i], TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwBudgetArrFire"] = EncodeBudgetArray((DWORD*)&pChunkMISC[i], TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwBudgetArrHealthcare"] = EncodeBudgetArray((DWORD*)&pChunkMISC[i], TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwBudgetArrEducationSchool"] = EncodeBudgetArray((DWORD*)&pChunkMISC[i], TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwBudgetArrEducationCollege"] = EncodeBudgetArray((DWORD*)&pChunkMISC[i], TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwBudgetArrTransitRoad"] = EncodeBudgetArray((DWORD*)&pChunkMISC[i], TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwBudgetArrTransitHighway"] = EncodeBudgetArray((DWORD*)&pChunkMISC[i], TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwBudgetArrTransitBridge"] = EncodeBudgetArray((DWORD*)&pChunkMISC[i], TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwBudgetArrTransitRail"] = EncodeBudgetArray((DWORD*)&pChunkMISC[i], TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwBudgetArrTransitSubway"] = EncodeBudgetArray((DWORD*)&pChunkMISC[i], TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwBudgetArrTransitTunnel"] = EncodeBudgetArray((DWORD*)&pChunkMISC[i], TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwYearEndFlag"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wWaterLevel"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["bCityHasOcean"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["bCityHasRiver"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["bMiltaryBaseType"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				// TODO: Encode as arrays of useful JSON
				sc2json["MISC"]["dwArrNewspaperTable1"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 30, TRUE);
				i += 4 * 30;

				// TODO: Encode as arrays of useful JSON
				sc2json["MISC"]["dwArrNewspaperTable2"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 54, TRUE);
				i += 4 * 54;

				sc2json["MISC"]["dwCityOrdinances"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityUnemployment"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				// This table is staying as a Base64Encode because you SHOULD NOT mess with it
				sc2json["MISC"]["dwMilitaryTiles"] = Base64Encode(&pChunkMISC[i], 4 * 16);
				i += 4 * 16;

				sc2json["MISC"]["wSubwayXUNDCount"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["bSimulationSpeed"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["bOptionsAutoBudget"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["bOptionsAutoGoto"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["bOptionsSound"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["bOptionsMusic"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["bNoDisasters"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["bNewspaperSubscription"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["bNewspaperExtra"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wNewspaperChoice"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wViewCoords"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wViewZoom"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wCityCenterX"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wCityCenterY"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwArcologyPopulation"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wUnused"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wSportsTeams"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["dwCityPopulation"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wIndustrialMixBonus"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wIndustrialMixPollutionBonus"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wOldArrests"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wPrisonBonus"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wMonsterXTHGIndex"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wCurrentDisasterID"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["bDisasterActive"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				sc2json["MISC"]["wSewerBonus"] = ntohl(*(DWORD*)&pChunkMISC[i]);
				i += 4;

				free(pChunkMISC);
				iConvertedChunks++;
			}

			else if (*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('A', 'L', 'T', 'M')) {
				zipStream.PutNextEntry("ALTM");
				zipStream.Write(&sc2file[iChunkStart + 8], 32768);
				iConvertedChunks++;
			}

			else if (*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'T', 'E', 'R') ||
				*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'B', 'L', 'D') ||
				*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'Z', 'O', 'N') ||
				*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'U', 'N', 'D') ||
				*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'T', 'X', 'T') ||
				*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'B', 'I', 'T')) {
				std::string strIFFHead((const char*)&sc2file[iChunkStart], 4);

				// Allocate and decompressed a fixed length chunk
				BYTE* pChunkData = (BYTE*)malloc(16384);
				if (!pChunkData)
					BAILOUT("Couldn't malloc 16384 bytes for %s.", strIFFHead.c_str());

				MaxisDecompress(pChunkData, 16384, &sc2file[iChunkStart + 8], ntohl(*(DWORD*)&sc2file[iChunkStart + 4]));
				zipStream.PutNextEntry(strIFFHead);
				zipStream.Write(pChunkData, 16384);
				free(pChunkData);
				iConvertedChunks++;
			}

			else if (*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'L', 'A', 'B')) {
				std::string strIFFHead((const char*)&sc2file[iChunkStart], 4);

				// Allocate and decompressed a fixed length chunk
				BYTE* pChunkData = (BYTE*)malloc(6400);
				if (!pChunkData)
					BAILOUT("Couldn't malloc 6400 bytes for XLAB.");

				MaxisDecompress(pChunkData, 6400, &sc2file[iChunkStart + 8], ntohl(*(DWORD*)&sc2file[iChunkStart + 4]));
				zipStream.PutNextEntry(strIFFHead);
				zipStream.Write(pChunkData, 6400);
				free(pChunkData);
				iConvertedChunks++;
			}

			else if (*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'T', 'R', 'F') ||
				*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'P', 'L', 'T') ||
				*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'V', 'A', 'L') ||
				*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'C', 'R', 'M')) {
					std::string strIFFHead((const char*)&sc2file[iChunkStart], 4);

					// Allocate and decompressed a fixed length chunk
					BYTE* pChunkData = (BYTE*)malloc(4096);
					if (!pChunkData)
						BAILOUT("Couldn't malloc 4096 bytes for %s.", strIFFHead.c_str());

					MaxisDecompress(pChunkData, 4096, &sc2file[iChunkStart + 8], ntohl(*(DWORD*)&sc2file[iChunkStart + 4]));
					zipStream.PutNextEntry(strIFFHead);
					zipStream.Write(pChunkData, 4096);
					free(pChunkData);
					iConvertedChunks++;
			}

			else if (*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'G', 'R', 'P')) {
				std::string strIFFHead((const char*)&sc2file[iChunkStart], 4);

				// Allocate and decompressed a fixed length chunk
				BYTE* pChunkData = (BYTE*)malloc(3328);
				if (!pChunkData)
					BAILOUT("Couldn't malloc 3328 bytes for XGRP.");

				MaxisDecompress(pChunkData, 3328, &sc2file[iChunkStart + 8], ntohl(*(DWORD*)&sc2file[iChunkStart + 4]));
				zipStream.PutNextEntry(strIFFHead);
				zipStream.Write(pChunkData, 3328);
				free(pChunkData);
				iConvertedChunks++;
			}

			else if (*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'M', 'I', 'C')) {
				std::string strIFFHead((const char*)&sc2file[iChunkStart], 4);

				// Allocate and decompressed a fixed length chunk
				BYTE* pChunkData = (BYTE*)malloc(1200);
				if (!pChunkData)
					BAILOUT("Couldn't malloc 1200 bytes for XMIC.");

				MaxisDecompress(pChunkData, 1200, &sc2file[iChunkStart + 8], ntohl(*(DWORD*)&sc2file[iChunkStart + 4]));
				zipStream.PutNextEntry(strIFFHead);
				zipStream.Write(pChunkData, 1200);
				free(pChunkData);
				iConvertedChunks++;
			}

			else if (*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'P', 'L', 'C') ||
				*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'F', 'I', 'R') ||
				*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'P', 'O', 'P') ||
				*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'R', 'O', 'G')) {
				std::string strIFFHead((const char*)&sc2file[iChunkStart], 4);

				// Allocate and decompressed a fixed length chunk
				BYTE* pChunkData = (BYTE*)malloc(1024);
				if (!pChunkData)
					BAILOUT("Couldn't malloc 1024 bytes for %s.", strIFFHead.c_str());

				MaxisDecompress(pChunkData, 1024, &sc2file[iChunkStart + 8], ntohl(*(DWORD*)&sc2file[iChunkStart + 4]));
				zipStream.PutNextEntry(strIFFHead);
				zipStream.Write(pChunkData, 1024);
				free(pChunkData);
				iConvertedChunks++;
			}

			else if (*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('X', 'T', 'H', 'G')) {
				std::string strIFFHead((const char*)&sc2file[iChunkStart], 4);

				// Allocate and decompressed a fixed length chunk
				BYTE* pChunkData = (BYTE*)malloc(480);
				if (!pChunkData)
					BAILOUT("Couldn't malloc 480 bytes for XTHG.");

				MaxisDecompress(pChunkData, 480, &sc2file[iChunkStart + 8], ntohl(*(DWORD*)&sc2file[iChunkStart + 4]));
				zipStream.PutNextEntry(strIFFHead);
				zipStream.Write(pChunkData, 480);
				free(pChunkData);
				iConvertedChunks++;
			}

			else if (*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('T', 'E', 'X', 'T')) {
				std::string strText((char*)&sc2file[iChunkStart + 12], ntohl(*(DWORD*)&sc2file[iChunkStart + 4]) - 4);
				if (*(DWORD*)&sc2file[iChunkStart + 8] == 0x00000080)
					sc2json["SCEN"]["strDescriptionMenu"] = strText;
				else if (*(DWORD*)&sc2file[iChunkStart + 8] == 0x00000081)
					sc2json["SCEN"]["strDescriptionExtended"] = strText;
				else {
					char szChunkName[50] = { 0 };
					sprintf_s(szChunkName, "TEXT(0x%08X)", *(DWORD*)&sc2file[iChunkStart + 8]);
					printf("Skipping unknown TEXT chunk 0x%08X.\n", *(DWORD*)&sc2file[iChunkStart + 8]);
					sc2json["sc2x"]["conversion"]["skipped_chunks"].append(szChunkName);
					goto next;
				}
				iConvertedChunks++;
			}

			// TODO: decode and convert this to something actually useful
			else if (*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('P', 'I', 'C', 'T')) {
				sc2json["SCEN"]["bArrMenuImage"] = Base64Encode(&sc2file[iChunkStart + 8], ntohl(*(DWORD*)&sc2file[iChunkStart + 4]));
				iConvertedChunks++;
			}

			else if (*(DWORD*)&sc2file[iChunkStart] == IFF_HEAD('S', 'C', 'E', 'N')) {
				// Skip the header
				BYTE* pChunkSCEN = &sc2file[iChunkStart + 12];
				int i = 0;

				sc2json["SCEN"]["wScenarioDisasterID"] = ntohs(*(WORD*)&pChunkSCEN[i]);
				i += 2;

				// NOTE: this is a single byte in the original SCN format
				sc2json["SCEN"]["wScenarioDisasterX"] = pChunkSCEN[i];
				i++;

				// NOTE: this is a single byte in the original SCN format
				sc2json["SCEN"]["wScenarioDisasterY"] = pChunkSCEN[i];
				i++;

				sc2json["SCEN"]["wScenarioTimeLimit"] = ntohs(*(DWORD*)&pChunkSCEN[i]);
				i += 2;

				sc2json["SCEN"]["dwScenarioCitySize"] = ntohl(*(DWORD*)&pChunkSCEN[i]);
				i += 4;

				sc2json["SCEN"]["dwScenarioResPopulation"] = ntohl(*(DWORD*)&pChunkSCEN[i]);
				i += 4;

				sc2json["SCEN"]["dwScenarioComPopulation"] = ntohl(*(DWORD*)&pChunkSCEN[i]);
				i += 4;

				sc2json["SCEN"]["dwScenarioIndPopulation"] = ntohl(*(DWORD*)&pChunkSCEN[i]);
				i += 4;

				sc2json["SCEN"]["dwScenarioCashGoal"] = ntohl(*(DWORD*)&pChunkSCEN[i]);
				i += 4;

				sc2json["SCEN"]["dwScenarioLandValueGoal"] = ntohl(*(DWORD*)&pChunkSCEN[i]);
				i += 4;

				sc2json["SCEN"]["wScenarioLEGoal"] = ntohs(*(WORD*)&pChunkSCEN[i]);
				i += 2;

				sc2json["SCEN"]["wScenarioEQGoal"] = ntohs(*(WORD*)&pChunkSCEN[i]);
				i += 2;

				sc2json["SCEN"]["dwScenarioPollutionLimit"] = ntohl(*(DWORD*)&pChunkSCEN[i]);
				i += 4;

				sc2json["SCEN"]["dwScenarioCrimeLimit"] = ntohl(*(DWORD*)&pChunkSCEN[i]);
				i += 4;

				sc2json["SCEN"]["dwScenarioTrafficLimit"] = ntohl(*(DWORD*)&pChunkSCEN[i]);
				i += 4;

				sc2json["SCEN"]["bScenarioBuildingGoal1"] = pChunkSCEN[i];
				i++;

				sc2json["SCEN"]["bScenarioBuildingGoal2"] = pChunkSCEN[i];
				i++;

				sc2json["SCEN"]["bScenarioBuildingGoal1Count"] = ntohs(*(WORD*)&pChunkSCEN[i]);
				i += 2;

				sc2json["SCEN"]["bScenarioBuildingGoal2Count"] = ntohs(*(WORD*)&pChunkSCEN[i]);
				i += 2;

				iConvertedChunks++;
			}

			else {
				printf("Skipping unknown chunk\n");
				char szChunkName[5] = { 0 };
				memcpy(szChunkName, &sc2file[iChunkStart], 4);
				sc2json["sc2x"]["conversion"]["skipped_chunks"].append(szChunkName);
			}

next:
			i += iChunkSize;
		}

		iChunkStart += 8;
	} while (iChunkStart + iChunkSize < sc2size);

	sc2json["sc2x"]["meta"]["creator"] = "sc2json v0.4-dev";
	sc2json["sc2x"]["meta"]["timestamp"] = time(NULL);
	sc2json["sc2x"]["meta"]["version"] = (int)SC2X_VERSION_JSONPROTO;
	sc2json["sc2x"]["meta"]["dimensions"] = (int)SC2X_SIZE_VANILLA;
	sc2json["sc2x"]["conversion"]["chunks"] = iConvertedChunks;

	// Write the JSON out to the ZIP
	std::string strJSON = sc2json.dump();
	zipStream.PutNextEntry("MISC.json");
	zipStream.Write(strJSON.c_str(), strJSON.length());

	// NOTE: This is where mod data would get saved in the actual save function.

	printf("Done writing!\n");
	system("pause");
	return 0;
}
