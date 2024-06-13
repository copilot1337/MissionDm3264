#include <iostream>
#include <Windows.h>
#include "obj.h"

// 吹水QQ群: 925801017 

HRESULT __stdcall CreateRegKeyW(HKEY hKeyParent, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition) {
	// 尝试打开现有的键，如果不存在则创建它
	HKEY hKey = NULL;
	LONG lRet = RegOpenKeyExW(hKeyParent, lpSubKey, Reserved, samDesired, &hKey);
	if (lRet == ERROR_SUCCESS) {
		// 打开现有键
	}
	else if (lRet == ERROR_FILE_NOT_FOUND) {
		// 键不存在，尝试创建它
		lRet = RegCreateKeyExW(hKeyParent, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, &hKey, lpdwDisposition);
	}
	else {
		// 其他错误
	}

	if (lRet == ERROR_SUCCESS && phkResult) {
		*phkResult = hKey;
	}
	else {
		if (hKey) {
			RegCloseKey(hKey);
		}
	}

	return lRet == ERROR_SUCCESS ? S_OK : HRESULT_FROM_WIN32(lRet);
}

bool ManualMapComRegister(
	const wchar_t* progId,
	const wchar_t* threadingModel,
	const wchar_t* clsid,
	const wchar_t* szPath,
	bool bForce64Bit = false,
	const wchar_t* typeLibName = nullptr,
	const wchar_t* typeLibGuid = nullptr) {



	HKEY hKey = NULL, hSubKey = NULL,
		hAppIDKey = NULL, hAppIDSubKey = NULL,
		hClsidKey = NULL, hClsidSubKey = NULL,
		hTypeLibKey = NULL, hSubTypeLibKey = NULL;
	DWORD dwDisposition = NULL;
	WCHAR szSoftwareClassesProgId[MAX_PATH] = { NULL };
	WCHAR szSoftwareClassecTypeLib[MAX_PATH] = { NULL };
	WCHAR szSoftwareClassecClsid[MAX_PATH] = { NULL };
	WCHAR szSoftwareClassesAppID[MAX_PATH] = { NULL };
	wsprintfW(szSoftwareClassesProgId, L"SOFTWARE\\Classes\\%s", progId);

	HRESULT hr = CreateRegKeyW(
		HKEY_LOCAL_MACHINE,
		szSoftwareClassesProgId,
		0,
		NULL,
		0,
		KEY_ALL_ACCESS,
		NULL,
		&hKey,
		&dwDisposition);

	if (!hKey) return false;
	//if (!SUCCEEDED(hr) || !(dwDisposition == REG_CREATED_NEW_KEY || dwDisposition == REG_OPENED_EXISTING_KEY)) return false;
	if (!SUCCEEDED(hr)) return false;

	if (RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)progId, (wcslen(progId) + 1) * sizeof(WCHAR)) != ERROR_SUCCESS) return false;


	if (RegCreateKeyExW(hKey, L"CLSID", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hSubKey, &dwDisposition) != ERROR_SUCCESS) {
		RegCloseKey(hKey);
		hKey = NULL;
		return false;
	}

	if (RegSetValueExW(hSubKey, NULL, 0, REG_SZ, (const BYTE*)clsid, (wcslen(clsid) + 1) * sizeof(WCHAR)) != ERROR_SUCCESS) return false;

	if (RegCreateKeyExW(hKey, L"CurVer", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hSubKey, &dwDisposition) != ERROR_SUCCESS) {
		RegCloseKey(hKey);
		hKey = NULL;
		return false;
	}

	if (RegSetValueExW(hSubKey, NULL, 0, REG_SZ, (const BYTE*)progId, (wcslen(progId) + 1) * sizeof(WCHAR)) != ERROR_SUCCESS) return false;

	if (typeLibName && typeLibGuid) {
		dwDisposition = NULL;
		wsprintfW(szSoftwareClassecTypeLib, L"SOFTWARE\\Classes\\TypeLib\\%s", typeLibGuid);
		hr = CreateRegKeyW(
			HKEY_LOCAL_MACHINE,
			szSoftwareClassecTypeLib,
			0,
			NULL,
			0,
			KEY_ALL_ACCESS,
			NULL,
			&hTypeLibKey,
			&dwDisposition);

		if (!hTypeLibKey) return false;
		if (!SUCCEEDED(hr)) {
			RegCloseKey(hKey);
			hKey = NULL;
			return false;
		}

		if (RegCreateKeyExW(hTypeLibKey, L"1.0", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hSubTypeLibKey, &dwDisposition) != ERROR_SUCCESS) {
			RegCloseKey(hTypeLibKey);
			RegCloseKey(hKey);
			hTypeLibKey = NULL;
			hKey = NULL;
			return false;
		}

		if (RegCreateKeyExW(hSubTypeLibKey, L"0", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hSubTypeLibKey, &dwDisposition) != ERROR_SUCCESS) {
			RegCloseKey(hTypeLibKey);
			RegCloseKey(hKey);
			hTypeLibKey = NULL;
			hKey = NULL;
			return false;
		}

		if (RegCreateKeyExW(hSubTypeLibKey, L"win32", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hSubTypeLibKey, &dwDisposition) != ERROR_SUCCESS) {
			RegCloseKey(hTypeLibKey);
			RegCloseKey(hKey);
			hTypeLibKey = NULL;
			hKey = NULL;
			return false;
		}

		if (RegSetValueExW(hSubTypeLibKey, NULL, 0, REG_SZ, (const BYTE*)szPath, (wcslen(szPath) + 1) * sizeof(WCHAR)) != ERROR_SUCCESS) return false;

		if (hTypeLibKey) {
			RegCloseKey(hTypeLibKey);
			hTypeLibKey = NULL;
		}

		if (hSubTypeLibKey) {
			RegCloseKey(hSubTypeLibKey);
			hSubTypeLibKey = NULL;
		}
	}

	dwDisposition = NULL;
	wsprintfW(szSoftwareClassecClsid, L"SOFTWARE\\Classes\\WOW6432Node\\CLSID\\%s", clsid);
	hr = CreateRegKeyW(
		HKEY_LOCAL_MACHINE,
		szSoftwareClassecClsid,
		0,
		NULL,
		0,
		KEY_ALL_ACCESS,
		NULL,
		&hClsidKey,
		&dwDisposition);

	if (!hClsidKey) return false;
	if (!SUCCEEDED(hr)) {
		RegCloseKey(hKey);
		hKey = NULL;
		return false;
	}

	if (RegSetValueExW(hClsidKey, NULL, 0, REG_SZ, (const BYTE*)progId, (wcslen(progId) + 1) * sizeof(WCHAR)) != ERROR_SUCCESS) return false;

	if (bForce64Bit) {
		if (RegSetValueExW(hClsidKey, L"AppID", 0, REG_SZ, (const BYTE*)clsid, (wcslen(clsid) + 1) * sizeof(WCHAR)) != ERROR_SUCCESS) return false;
		dwDisposition = NULL;
		wsprintfW(szSoftwareClassesAppID, L"SOFTWARE\\Classes\\WOW6432Node\\AppID\\%s", clsid);
		hr = CreateRegKeyW(
			HKEY_LOCAL_MACHINE,
			szSoftwareClassesAppID,
			0,
			NULL,
			0,
			KEY_ALL_ACCESS,
			NULL,
			&hAppIDKey,
			&dwDisposition);

		if (!hAppIDKey) return false;
		if (!SUCCEEDED(hr)) {
			RegCloseKey(hKey);
			hKey = NULL;
			return false;
		}

		WCHAR szEmptyValue[1] = { NULL };
		if (RegSetValueExW(hAppIDKey, L"DllSurrogate", 0, REG_SZ, (const BYTE*)szEmptyValue, (wcslen(szEmptyValue) + 1) * sizeof(WCHAR)) != ERROR_SUCCESS) return false;
	}

	if (RegCreateKeyExW(hClsidKey, L"InprocServer32", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hClsidSubKey, &dwDisposition) != ERROR_SUCCESS) {
		RegCloseKey(hClsidKey);
		RegCloseKey(hKey);
		hClsidKey = NULL;
		hKey = NULL;
		return false;
	}

	if (RegSetValueExW(hClsidSubKey, NULL, 0, REG_SZ, (const BYTE*)szPath, (wcslen(szPath) + 1) * sizeof(WCHAR)) != ERROR_SUCCESS) return false;
	if (RegSetValueExW(hClsidSubKey, L"ThreadingModel", 0, REG_SZ, (const BYTE*)threadingModel, (wcslen(threadingModel) + 1) * sizeof(WCHAR)) != ERROR_SUCCESS) return false;

	if (RegCreateKeyExW(hClsidKey, L"ProgID", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hClsidSubKey, &dwDisposition) != ERROR_SUCCESS) {
		RegCloseKey(hClsidKey);
		RegCloseKey(hKey);
		hClsidKey = NULL;
		hKey = NULL;
		return false;
	}

	if (RegSetValueExW(hClsidSubKey, NULL, 0, REG_SZ, (const BYTE*)progId, (wcslen(progId) + 1) * sizeof(WCHAR)) != ERROR_SUCCESS) return false;

	if (hKey) {
		RegCloseKey(hKey);
		hKey = NULL;
	}

	if (hSubKey) {
		RegCloseKey(hSubKey);
		hSubKey = NULL;
	}




	return true;
}

int main() {
	ManualMapComRegister(
		L"dm.dmsoft",
		L"Both",
		L"{26037A0E-7CBD-4FFF-9C63-56F2D0770214}",
		L"D:\\dm.dll",
		true,
		L"dm",
		L"{84288AAD-BA02-4EF2-85EC-3FAD4D11354D}"
	);
	CoInitializeEx(NULL, COINIT_MULTITHREADED);
	dmsoft* dm = new dmsoft;
	auto str = dm->Ver();
	std::wcout << str.GetString() << '\n';
	system("pause");
	return 0;
}