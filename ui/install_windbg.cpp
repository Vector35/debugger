/*
Copyright 2020-2025 Vector 35 Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifdef WIN32

#include "install_windbg.h"
#include <windows.h>
#include <urlmon.h>
#include <shlobj.h>
#include <objbase.h>
#include <shldisp.h>
#include <comdef.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <functional>
#include "../vendor/pugixml/pugixml.hpp"
#include <binaryninjaapi.h>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

using namespace BinaryNinja;
using namespace std;
namespace fs = std::filesystem;

namespace BinaryNinjaDebugger
{
	namespace
	{
		/// Download a file from URL to a temporary location
		/// @param url URL to download from
		/// @param localPath Path where to save the downloaded file
		/// @return true if download was successful, false otherwise
		bool DownloadFile(const std::string& url, const std::string& localPath)
		{
			LogInfo("Downloading from: %s", url.c_str());
			
			// Remove existing file if it exists
			std::error_code ec;
			fs::remove(localPath, ec);
			
			HRESULT hr = URLDownloadToFileA(nullptr, url.c_str(), localPath.c_str(), 0, nullptr);
			if (SUCCEEDED(hr))
			{
				// Verify the file was actually downloaded
				if (fs::exists(localPath) && fs::file_size(localPath, ec) > 0)
				{
					LogInfo("Successfully downloaded to: %s", localPath.c_str());
					return true;
				}
				else
				{
					LogError("Downloaded file is empty or doesn't exist: %s", localPath.c_str());
					return false;
				}
			}
			else
			{
				LogError("Failed to download from %s (HRESULT: 0x%08x)", url.c_str(), hr);
				return false;
			}
		}

		/// Extract a ZIP archive using Windows Shell COM interface (secure)
		/// @param zipPath Path to the ZIP file
		/// @param extractPath Directory where to extract contents
		/// @return true if extraction was successful, false otherwise
		bool ExtractZip(const std::string& zipPath, const std::string& extractPath)
		{
			LogInfo("Extracting %s to %s", zipPath.c_str(), extractPath.c_str());

			// Create destination directory if it doesn't exist
			std::error_code ec;
			fs::create_directories(extractPath, ec);
			if (ec)
			{
				LogError("Failed to create extract directory: %s", ec.message().c_str());
				return false;
			}

			// Initialize COM
			HRESULT hr = CoInitialize(nullptr);
			if (FAILED(hr))
			{
				LogError("Failed to initialize COM: 0x%08x", hr);
				return false;
			}

			bool success = false;
			try
			{
				// Create Shell Application object
				IShellDispatch* pShellApp = nullptr;
				hr = CoCreateInstance(CLSID_Shell, nullptr, CLSCTX_INPROC_SERVER, IID_IShellDispatch, (void**)&pShellApp);
				if (FAILED(hr))
				{
					LogError("Failed to create Shell Application: 0x%08x", hr);
					CoUninitialize();
					return false;
				}

				// Convert paths to BSTRs and then to VARIANTs
				_bstr_t bstrZipPath(zipPath.c_str());
				_bstr_t bstrExtractPath(extractPath.c_str());

				VARIANT vZipPath, vExtractPath;
				vZipPath.vt = VT_BSTR;
				vZipPath.bstrVal = bstrZipPath.Detach();
				vExtractPath.vt = VT_BSTR;
				vExtractPath.bstrVal = bstrExtractPath.Detach();

				// Get folder objects
				Folder* pZipFolder = nullptr;
				Folder* pDestFolder = nullptr;

				hr = pShellApp->NameSpace(vZipPath, &pZipFolder);
				if (SUCCEEDED(hr) && pZipFolder)
				{
					hr = pShellApp->NameSpace(vExtractPath, &pDestFolder);
					if (SUCCEEDED(hr) && pDestFolder)
					{
						// Get items from zip folder
						FolderItems* pItems = nullptr;
						hr = pZipFolder->Items(&pItems);
						if (SUCCEEDED(hr) && pItems)
						{
							// Copy items with no progress dialog and overwrite existing
							VARIANT vOptions;
							vOptions.vt = VT_I4;
							vOptions.lVal = 0x14; // FOF_NOCONFIRMATION | FOF_NOERRORUI

							hr = pDestFolder->CopyHere(_variant_t(pItems), vOptions);
							if (SUCCEEDED(hr))
							{
								LogInfo("Successfully extracted ZIP archive using Shell API");
								success = true;
							}
							else
							{
								LogError("Shell CopyHere failed: 0x%08x", hr);
							}

							pItems->Release();
						}
						else
						{
							LogError("Failed to get items from zip folder: 0x%08x", hr);
						}

						pDestFolder->Release();
					}
					else
					{
						LogError("Failed to get destination folder: 0x%08x", hr);
					}

					pZipFolder->Release();
				}
				else
				{
					LogError("Failed to open zip file as folder: 0x%08x", hr);
				}

				// Clean up VARIANTs
				VariantClear(&vZipPath);
				VariantClear(&vExtractPath);

				pShellApp->Release();
			}
			catch (...)
			{
				LogError("Exception during ZIP extraction");
			}

			CoUninitialize();
			return success;
		}

		/// Extract a specific file from a ZIP archive using Windows Shell COM interface (secure)
		/// @param zipPath Path to the ZIP file
		/// @param fileName Name of file to extract
		/// @param extractDir Directory where to extract the file
		/// @return Path to extracted file, or empty string if extraction failed
		std::string ExtractFileFromZip(const std::string& zipPath, const std::string& fileName, const std::string& extractDir)
		{
			LogInfo("Extracting %s from %s", fileName.c_str(), zipPath.c_str());

			// Create destination directory if it doesn't exist
			std::error_code ec;
			fs::create_directories(extractDir, ec);
			if (ec)
			{
				LogError("Failed to create extract directory: %s", ec.message().c_str());
				return "";
			}

			// Initialize COM
			HRESULT hr = CoInitialize(nullptr);
			if (FAILED(hr))
			{
				LogError("Failed to initialize COM: 0x%08x", hr);
				return "";
			}

			std::string outputPath;
			try
			{
				// Create Shell Application object
				IShellDispatch* pShellApp = nullptr;
				hr = CoCreateInstance(CLSID_Shell, nullptr, CLSCTX_INPROC_SERVER, IID_IShellDispatch, (void**)&pShellApp);
				if (FAILED(hr))
				{
					LogError("Failed to create Shell Application: 0x%08x", hr);
					CoUninitialize();
					return "";
				}

				// Convert paths to BSTRs and then to VARIANTs
				_bstr_t bstrZipPath(zipPath.c_str());
				_bstr_t bstrExtractPath(extractDir.c_str());

				VARIANT vZipPath, vExtractPath;
				vZipPath.vt = VT_BSTR;
				vZipPath.bstrVal = bstrZipPath.Detach();
				vExtractPath.vt = VT_BSTR;
				vExtractPath.bstrVal = bstrExtractPath.Detach();

				// Get folder objects
				Folder* pZipFolder = nullptr;
				Folder* pDestFolder = nullptr;

				hr = pShellApp->NameSpace(vZipPath, &pZipFolder);
				if (SUCCEEDED(hr) && pZipFolder)
				{
					hr = pShellApp->NameSpace(vExtractPath, &pDestFolder);
					if (SUCCEEDED(hr) && pDestFolder)
					{
						// Get items from zip folder
						FolderItems* pItems = nullptr;
						hr = pZipFolder->Items(&pItems);
						if (SUCCEEDED(hr) && pItems)
						{
							// Look for specific file
							long itemCount = 0;
							pItems->get_Count(&itemCount);
							
							for (long i = 0; i < itemCount; i++)
							{
								VARIANT vIndex;
								vIndex.vt = VT_I4;
								vIndex.lVal = i;
								
								FolderItem* pItem = nullptr;
								hr = pItems->Item(vIndex, &pItem);
								if (SUCCEEDED(hr) && pItem)
								{
									BSTR bstrName = nullptr;
									hr = pItem->get_Name(&bstrName);
									if (SUCCEEDED(hr) && bstrName)
									{
										_bstr_t itemName(bstrName, false); // Don't copy, take ownership
										
										if (_stricmp(itemName, fileName.c_str()) == 0)
										{
											// Found the file, extract it
											VARIANT vOptions;
											vOptions.vt = VT_I4;
											vOptions.lVal = 0x14; // FOF_NOCONFIRMATION | FOF_NOERRORUI

											hr = pDestFolder->CopyHere(_variant_t(pItem), vOptions);
											if (SUCCEEDED(hr))
											{
												outputPath = extractDir + "\\" + fileName;
												LogInfo("Successfully extracted %s", fileName.c_str());
											}
											else
											{
												LogError("Failed to extract file: 0x%08x", hr);
											}
											
											pItem->Release();
											break;
										}
									}
									
									pItem->Release();
								}
							}

							if (outputPath.empty())
							{
								LogError("File %s not found in ZIP archive", fileName.c_str());
							}

							pItems->Release();
						}
						else
						{
							LogError("Failed to get items from zip folder: 0x%08x", hr);
						}

						pDestFolder->Release();
					}
					else
					{
						LogError("Failed to get destination folder: 0x%08x", hr);
					}

					pZipFolder->Release();
				}
				else
				{
					LogError("Failed to open zip file as folder: 0x%08x", hr);
				}

				// Clean up VARIANTs
				VariantClear(&vZipPath);
				VariantClear(&vExtractPath);

				pShellApp->Release();
			}
			catch (...)
			{
				LogError("Exception during file extraction");
			}

			CoUninitialize();
			
			// Verify the file exists before returning
			if (!outputPath.empty() && fs::exists(outputPath))
			{
				return outputPath;
			}
			
			return "";
		}

		/// Get a temporary file path
		/// @param extension File extension (with dot)
		/// @return Path to temporary file
		std::string GetTempFilePath(const std::string& extension)
		{
			char tempPath[MAX_PATH];
			
			GetTempPathA(MAX_PATH, tempPath);
			
			// Generate a unique filename
			GUID guid;
			CoCreateGuid(&guid);
			char guidStr[40];
			sprintf_s(guidStr, sizeof(guidStr), "{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
				guid.Data1, guid.Data2, guid.Data3,
				guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
				guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
			
			std::string result = std::string(tempPath) + "windbg_" + guidStr + extension;
			
			return result;
		}

		/// Parse XML to extract MSIX bundle URL
		/// @param appInstallerPath Path to the appinstaller XML file
		/// @return MSIX bundle URL, or empty string if parsing failed
		std::string ParseAppInstallerXml(const std::string& appInstallerPath)
		{
			LogInfo("Parsing appinstaller XML: %s", appInstallerPath.c_str());

			pugi::xml_document doc;
			pugi::xml_parse_result result = doc.load_file(appInstallerPath.c_str());

			if (!result)
			{
				LogError("Failed to parse XML: %s", result.description());
				return "";
			}

			// Look for MainBundle element with Uri attribute
			pugi::xml_node mainBundle = doc.child("AppInstaller").child("MainBundle");
			if (!mainBundle)
			{
				LogError("MainBundle element not found in XML");
				return "";
			}

			pugi::xml_attribute uriAttr = mainBundle.attribute("Uri");
			if (!uriAttr)
			{
				LogError("Uri attribute not found in MainBundle element");
				return "";
			}

			std::string msixUrl = uriAttr.value();
			LogInfo("Found MSIX bundle URL: %s", msixUrl.c_str());
			return msixUrl;
		}
	}

	bool CheckInstallOk(const std::string& path)
	{
		// Check for required WinDbg/TTD files
		std::vector<std::string> requiredFiles = {
			"amd64\\dbgeng.dll",
			"amd64\\dbghelp.dll", 
			"amd64\\dbgmodel.dll",
			"amd64\\dbgcore.dll",
			"amd64\\ttd\\TTD.exe",
			"amd64\\ttd\\TTDRecord.dll"
		};

		for (const auto& file : requiredFiles)
		{
			fs::path fullPath = fs::path(path) / file;
			if (!fs::exists(fullPath))
			{
				LogWarn("Required file not found: %s", fullPath.string().c_str());
				return false;
			}
		}

		return true;
	}

	bool InstallWinDbg(InstallProgressCallback progressCallback)
	{
		try
		{
			LogInfo("Starting WinDbg/TTD installation");
			
			if (progressCallback)
				progressCallback("Initializing installation...", 0);

			// Step 1: Download appinstaller file
			if (progressCallback)
				progressCallback("Downloading WinDbg package information...", 10);
				
			const std::string ttdUrl = "https://aka.ms/windbg/download";
			std::string appInstallerPath = GetTempFilePath(".appinstaller");
			
			if (!DownloadFile(ttdUrl, appInstallerPath))
			{
				LogError("Failed to download appinstaller file");
				return false;
			}

			// Step 2: Parse XML to get MSIX bundle URL
			if (progressCallback)
				progressCallback("Parsing package information...", 20);
				
			std::string msixUrl = ParseAppInstallerXml(appInstallerPath);
			if (msixUrl.empty())
			{
				LogError("Failed to parse appinstaller XML");
				return false;
			}

			// Step 3: Download MSIX bundle
			if (progressCallback)
				progressCallback("Downloading WinDbg/TTD package...", 30);
				
			std::string msixPath = GetTempFilePath(".msixbundle.zip");  // Use .zip extension for COM Shell compatibility
			if (!DownloadFile(msixUrl, msixPath))
			{
				LogError("Failed to download MSIX bundle");
				return false;
			}

			// Step 4: Extract inner MSIX file from bundle
			if (progressCallback)
				progressCallback("Extracting package contents...", 60);
				
			std::string tempExtractDir = GetTempFilePath("_extract");
			std::string innerMsixPath = ExtractFileFromZip(msixPath, "windbg_win-x64.msix", tempExtractDir);
			if (innerMsixPath.empty())
			{
				LogError("Failed to extract inner MSIX file");
				return false;
			}
			
			// Rename the extracted MSIX file to have .zip extension for COM Shell compatibility
			std::string innerZipPath = GetTempFilePath(".zip");
			std::error_code ec;
			fs::rename(innerMsixPath, innerZipPath, ec);
			if (ec)
			{
				LogError("Failed to rename inner MSIX file to .zip: %s", ec.message().c_str());
				return false;
			}
			LogInfo("Renamed %s to %s for COM Shell compatibility", innerMsixPath.c_str(), innerZipPath.c_str());

			// Step 5: Extract WinDbg contents to installation directory
			if (progressCallback)
				progressCallback("Installing WinDbg/TTD files...", 80);
				
			std::string userDir = GetUserDirectory();
			std::string installTarget = (fs::path(userDir) / "windbg").string();
			
			if (!ExtractZip(innerZipPath, installTarget))
			{
				LogError("Failed to extract WinDbg contents");
				return false;
			}

			// Step 6: Verify installation
			if (progressCallback)
				progressCallback("Verifying installation...", 90);
				
			if (!CheckInstallOk(installTarget))
			{
				LogError("WinDbg/TTD installation appears successful, but important files are missing from %s", installTarget.c_str());
				return false;
			}

			LogInfo("WinDbg/TTD installed to %s!", installTarget.c_str());

			// Step 7: Update settings
			if (progressCallback)
				progressCallback("Configuring Binary Ninja settings...", 95);
				
			std::string x64dbgEngPath = (fs::path(installTarget) / "amd64").string();
			if (Settings::Instance()->Set("debugger.x64dbgEngPath", x64dbgEngPath))
			{
				LogInfo("Updated debugger.x64dbgEngPath setting to: %s", x64dbgEngPath.c_str());
				LogInfo("Please restart Binary Ninja to make the changes take effect!");
			}
			else
			{
				LogError("Failed to set debugger.x64dbgEngPath to %s", x64dbgEngPath.c_str());
				return false;
			}

			// Cleanup temporary files
			try 
			{
				fs::remove(appInstallerPath);
				fs::remove(msixPath);
				fs::remove(innerZipPath);
				fs::remove_all(tempExtractDir);
			}
			catch (...) 
			{
				// Ignore cleanup errors
			}

			if (progressCallback)
				progressCallback("Installation completed successfully!", 100);

			return true;
		}
		catch (const std::exception& e)
		{
			LogError("Exception during WinDbg installation: %s", e.what());
			return false;
		}
	}
}

#endif // WIN32