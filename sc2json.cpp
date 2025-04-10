// sc2kfix sc2json.cpp: test for reading .sc2 files and turning them into JSON
// (c) 2025 sc2kfix project (https://sc2kfix.net) - released under the MIT license

#undef UNICODE
#define WIN32_LEAN_AND_MEAN
#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <windows.h>
#include <winsock.h>
#include "json-small.hpp"
#include "deflate.h"

#define IFF_HEAD(a, b, c, d) ((DWORD)d << 24 | (DWORD)c << 16 | (DWORD)b << 8 | (DWORD)a)

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
		if (bBigEndian)
			jsonArray.append<DWORD>(ntohl(dwArray[i]));
		else
			jsonArray.append<DWORD>(dwArray[i]);
	}
	return jsonArray;
}

// Scary function! Overflows abound! Be careful!
void DecodeDWORDArray(DWORD* dwArray, json::JSON jsonArray, size_t iCount, BOOL bBigEndian) {
	for (int i = 0; i < iCount; i++)
		dwArray[i] = (bBigEndian ? htonl(jsonArray[i].ToInt()) : jsonArray[i].ToInt());
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

				sc2json["MISC"]["dwArrResidentialTaxTable"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 27, TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwArrCommercialTaxTable"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 27, TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwArrIndustrialTaxTable"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 27, TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwArrOrdinanceBudgetTable"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 27, TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwArrBondBudgetTable"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 27, TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwArrPoliceBudgetTable"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 27, TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwArrFireBudgetTable"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 27, TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwArrHealthcareBudgetTable"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 27, TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwArrEducationSchoolBudgetTable"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 27, TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwArrEducationCollegeBudgetTable"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 27, TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwArrTransitRoadBudgetTable"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 27, TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwArrTransitHighwayBudgetTable"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 27, TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwArrTransitBridgeBudgetTable"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 27, TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwArrTransitRailBudgetTable"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 27, TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwArrTransitSubwayBudgetTable"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 27, TRUE);
				i += 4 * 27;

				sc2json["MISC"]["dwArrTransitTunnelBudgetTable"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 27, TRUE);
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

				sc2json["MISC"]["dwArrNewspaperTable1"] = EncodeDWORDArray((DWORD*)&pChunkMISC[i], 30, TRUE);
				i += 4 * 30;

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
				if (USE_DEFLATE) {
					struct sdefl stDeflate = { 0 };
					BYTE* pChunkDeflated = (BYTE*)malloc(sdefl_bound(32768));
					if (!pChunkDeflated)
						BAILOUT("FUCK!");
					size_t iDeflateSize = sdeflate(&stDeflate, pChunkDeflated, &sc2file[iChunkStart + 8], sdefl_bound(32768), SDEFL_LVL_DEF);
					sc2json["ALTM"]["data"] = Base64Encode(pChunkDeflated, iDeflateSize);
					printf("Deflated %s to %d bytes.\n", "ALTM", iDeflateSize);
				}
				else
					sc2json["ALTM"]["data"] = Base64Encode(&sc2file[iChunkStart + 8], 32768);
				sc2json["ALTM"]["compression"] = (USE_DEFLATE ? "deflate" : "none");
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
				sc2json[strIFFHead]["compression"] = (USE_DEFLATE ? "deflate" : "none");
				if (USE_DEFLATE) {
					struct sdefl stDeflate = { 0 };
					BYTE* pChunkDeflated = (BYTE*)malloc(sdefl_bound(16384));
					if (!pChunkDeflated)
						BAILOUT("FUCK!");
					size_t iDeflateSize = sdeflate(&stDeflate, pChunkDeflated, pChunkData, sdefl_bound(16384), SDEFL_LVL_DEF);
					sc2json[strIFFHead]["data"] = Base64Encode(pChunkDeflated, iDeflateSize);
					printf("Deflated %s to %d bytes.\n", strIFFHead.c_str(), iDeflateSize);
				}
				else
					sc2json[strIFFHead]["data"] = Base64Encode(pChunkData, 16384);
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
				sc2json[strIFFHead]["compression"] = (USE_DEFLATE ? "deflate" : "none");
				if (USE_DEFLATE) {
					struct sdefl stDeflate = { 0 };
					BYTE* pChunkDeflated = (BYTE*)malloc(sdefl_bound(6400));
					if (!pChunkDeflated)
						BAILOUT("FUCK!");
					size_t iDeflateSize = sdeflate(&stDeflate, pChunkDeflated, pChunkData, sdefl_bound(6400), SDEFL_LVL_DEF);
					sc2json[strIFFHead]["data"] = Base64Encode(pChunkDeflated, iDeflateSize);
					printf("Deflated %s to %d bytes.\n", strIFFHead.c_str(), iDeflateSize);
				}
				else
					sc2json[strIFFHead]["data"] = Base64Encode(pChunkData, 6400);
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

					sc2json[strIFFHead]["compression"] = (USE_DEFLATE ? "deflate" : "none");
					if (USE_DEFLATE) {
						struct sdefl stDeflate = { 0 };
						BYTE* pChunkDeflated = (BYTE*)malloc(sdefl_bound(4096));
						if (!pChunkDeflated)
							BAILOUT("FUCK!");
						size_t iDeflateSize = sdeflate(&stDeflate, pChunkDeflated, pChunkData, sdefl_bound(4096), SDEFL_LVL_DEF);
						sc2json[strIFFHead]["data"] = Base64Encode(pChunkDeflated, iDeflateSize);
						printf("Deflated %s to %d bytes.\n", strIFFHead.c_str(), iDeflateSize);
					}
					else
						sc2json[strIFFHead]["data"] = Base64Encode(pChunkData, 4096);
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

				sc2json[strIFFHead]["compression"] = (USE_DEFLATE ? "deflate" : "none");
				if (USE_DEFLATE) {
					struct sdefl stDeflate = { 0 };
					BYTE* pChunkDeflated = (BYTE*)malloc(sdefl_bound(3328));
					if (!pChunkDeflated)
						BAILOUT("FUCK!");
					size_t iDeflateSize = sdeflate(&stDeflate, pChunkDeflated, pChunkData, sdefl_bound(3328), SDEFL_LVL_DEF);
					sc2json[strIFFHead]["data"] = Base64Encode(pChunkDeflated, iDeflateSize);
					printf("Deflated %s to %d bytes.\n", strIFFHead.c_str(), iDeflateSize);
				}
				else
					sc2json[strIFFHead]["data"] = Base64Encode(pChunkData, 3328);
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

				sc2json[strIFFHead]["compression"] = (USE_DEFLATE ? "deflate" : "none");
				if (USE_DEFLATE) {
					struct sdefl stDeflate = { 0 };
					BYTE* pChunkDeflated = (BYTE*)malloc(sdefl_bound(1200));
					if (!pChunkDeflated)
						BAILOUT("FUCK!");
					size_t iDeflateSize = sdeflate(&stDeflate, pChunkDeflated, pChunkData, sdefl_bound(1200), SDEFL_LVL_DEF);
					sc2json[strIFFHead]["data"] = Base64Encode(pChunkDeflated, iDeflateSize);
					printf("Deflated %s to %d bytes.\n", strIFFHead.c_str(), iDeflateSize);
				}
				else
					sc2json[strIFFHead]["data"] = Base64Encode(pChunkData, 1200);
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

				sc2json[strIFFHead]["compression"] = (USE_DEFLATE ? "deflate" : "none");
				if (USE_DEFLATE) {
					struct sdefl stDeflate = { 0 };
					BYTE* pChunkDeflated = (BYTE*)malloc(sdefl_bound(1024));
					if (!pChunkDeflated)
						BAILOUT("FUCK!");
					size_t iDeflateSize = sdeflate(&stDeflate, pChunkDeflated, pChunkData, sdefl_bound(1024), SDEFL_LVL_DEF);
					sc2json[strIFFHead]["data"] = Base64Encode(pChunkDeflated, iDeflateSize);
					printf("Deflated %s to %d bytes.\n", strIFFHead.c_str(), iDeflateSize);
				} else
					sc2json[strIFFHead]["data"] = Base64Encode(pChunkData, 1024);
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

				sc2json[strIFFHead]["compression"] = (USE_DEFLATE ? "deflate" : "none");
				if (USE_DEFLATE) {
					struct sdefl stDeflate = { 0 };
					BYTE* pChunkDeflated = (BYTE*)malloc(sdefl_bound(480));
					if (!pChunkDeflated)
						BAILOUT("FUCK!");
					size_t iDeflateSize = sdeflate(&stDeflate, pChunkDeflated, pChunkData, sdefl_bound(480), SDEFL_LVL_DEF);
					sc2json[strIFFHead]["data"] = Base64Encode(pChunkDeflated, iDeflateSize);
					printf("Deflated %s to %d bytes.\n", strIFFHead.c_str(), iDeflateSize);
				}
				else
					sc2json[strIFFHead]["data"] = Base64Encode(pChunkData, 480);
				free(pChunkData);
				iConvertedChunks++;
				}

			else {
				printf("Skipping unknown chunk\n");
				char szChunkName[5] = { 0 };
				memcpy(szChunkName, &sc2file[iChunkStart], 4);
				sc2json["sc2x"]["conversion"]["skipped_chunks"].append(szChunkName);
			}

			i += iChunkSize;
		}

		iChunkStart += 8;
	} while (iChunkStart + iChunkSize < sc2size);

	sc2json["sc2x"]["meta"]["creator"] = "sc2json v0.3-dev";
	sc2json["sc2x"]["meta"]["timestamp"] = time(NULL);
	sc2json["sc2x"]["conversion"]["chunks"] = iConvertedChunks;

	std::string strOutFilename = std::regex_replace(argv[1], std::regex("\.[Ss][Cc]2$"), ".sc2x");
	printf("Writing to %s...", strOutFilename.c_str());
	std::ofstream outfile(strOutFilename, std::ios::trunc);
	outfile << sc2json;
	printf(" done!\n");
	system("pause");
	return 0;
}
