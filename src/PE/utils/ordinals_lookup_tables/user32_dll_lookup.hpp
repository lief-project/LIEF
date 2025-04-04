/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef LIEF_PE_USER32_DLL_LOOKUP_H
#define LIEF_PE_USER32_DLL_LOOKUP_H
#include <cstdint>

namespace LIEF {
namespace PE {

inline const char* user32_dll_lookup(uint32_t i) {
  switch(i) {
  case 0x0001: return "ActivateKeyboardLayout";
  case 0x0002: return "AdjustWindowRect";
  case 0x0003: return "AdjustWindowRectEx";
  case 0x0004: return "AlignRects";
  case 0x0005: return "AllowForegroundActivation";
  case 0x0006: return "AllowSetForegroundWindow";
  case 0x0007: return "AnimateWindow";
  case 0x0008: return "AnyPopup";
  case 0x0009: return "AppendMenuA";
  case 0x000a: return "AppendMenuW";
  case 0x000b: return "ArrangeIconicWindows";
  case 0x000c: return "AttachThreadInput";
  case 0x000d: return "BeginDeferWindowPos";
  case 0x000e: return "BeginPaint";
  case 0x000f: return "BlockInput";
  case 0x0010: return "BringWindowToTop";
  case 0x0011: return "BroadcastSystemMessage";
  case 0x0012: return "BroadcastSystemMessageA";
  case 0x0013: return "BroadcastSystemMessageExA";
  case 0x0014: return "BroadcastSystemMessageExW";
  case 0x0015: return "BroadcastSystemMessageW";
  case 0x0016: return "BuildReasonArray";
  case 0x0017: return "CalcMenuBar";
  case 0x0018: return "CallMsgFilter";
  case 0x0019: return "CallMsgFilterA";
  case 0x001a: return "CallMsgFilterW";
  case 0x001b: return "CallNextHookEx";
  case 0x001c: return "CallWindowProcA";
  case 0x001d: return "CallWindowProcW";
  case 0x001e: return "CascadeChildWindows";
  case 0x001f: return "CascadeWindows";
  case 0x0020: return "ChangeClipboardChain";
  case 0x0021: return "ChangeDisplaySettingsA";
  case 0x0022: return "ChangeDisplaySettingsExA";
  case 0x0023: return "ChangeDisplaySettingsExW";
  case 0x0024: return "ChangeDisplaySettingsW";
  case 0x0025: return "ChangeMenuA";
  case 0x0026: return "ChangeMenuW";
  case 0x0027: return "CharLowerA";
  case 0x0028: return "CharLowerBuffA";
  case 0x0029: return "CharLowerBuffW";
  case 0x002a: return "CharLowerW";
  case 0x002b: return "CharNextA";
  case 0x002c: return "CharNextExA";
  case 0x002d: return "CharNextW";
  case 0x002e: return "CharPrevA";
  case 0x002f: return "CharPrevExA";
  case 0x0030: return "CharPrevW";
  case 0x0031: return "CharToOemA";
  case 0x0032: return "CharToOemBuffA";
  case 0x0033: return "CharToOemBuffW";
  case 0x0034: return "CharToOemW";
  case 0x0035: return "CharUpperA";
  case 0x0036: return "CharUpperBuffA";
  case 0x0037: return "CharUpperBuffW";
  case 0x0038: return "CharUpperW";
  case 0x0039: return "CheckDlgButton";
  case 0x003a: return "CheckMenuItem";
  case 0x003b: return "CheckMenuRadioItem";
  case 0x003c: return "CheckRadioButton";
  case 0x003d: return "ChildWindowFromPoint";
  case 0x003e: return "ChildWindowFromPointEx";
  case 0x003f: return "CliImmSetHotKey";
  case 0x0040: return "ClientThreadSetup";
  case 0x0041: return "ClientToScreen";
  case 0x0042: return "ClipCursor";
  case 0x0043: return "CloseClipboard";
  case 0x0044: return "CloseDesktop";
  case 0x0045: return "CloseWindow";
  case 0x0046: return "CloseWindowStation";
  case 0x0047: return "CopyAcceleratorTableA";
  case 0x0048: return "CopyAcceleratorTableW";
  case 0x0049: return "CopyIcon";
  case 0x004a: return "CopyImage";
  case 0x004b: return "CopyRect";
  case 0x004c: return "CountClipboardFormats";
  case 0x004d: return "CreateAcceleratorTableA";
  case 0x004e: return "CreateAcceleratorTableW";
  case 0x004f: return "CreateCaret";
  case 0x0050: return "CreateCursor";
  case 0x0051: return "CreateDesktopA";
  case 0x0052: return "CreateDesktopW";
  case 0x0053: return "CreateDialogIndirectParamA";
  case 0x0054: return "CreateDialogIndirectParamAorW";
  case 0x0055: return "CreateDialogIndirectParamW";
  case 0x0056: return "CreateDialogParamA";
  case 0x0057: return "CreateDialogParamW";
  case 0x0058: return "CreateIcon";
  case 0x0059: return "CreateIconFromResource";
  case 0x005a: return "CreateIconFromResourceEx";
  case 0x005b: return "CreateIconIndirect";
  case 0x005c: return "CreateMDIWindowA";
  case 0x005d: return "CreateMDIWindowW";
  case 0x005e: return "CreateMenu";
  case 0x005f: return "CreatePopupMenu";
  case 0x0060: return "CreateSystemThreads";
  case 0x0061: return "CreateWindowExA";
  case 0x0062: return "CreateWindowExW";
  case 0x0063: return "CreateWindowStationA";
  case 0x0064: return "CreateWindowStationW";
  case 0x0065: return "CsrBroadcastSystemMessageExW";
  case 0x0066: return "CtxInitUser32";
  case 0x0067: return "DdeAbandonTransaction";
  case 0x0068: return "DdeAccessData";
  case 0x0069: return "DdeAddData";
  case 0x006a: return "DdeClientTransaction";
  case 0x006b: return "DdeCmpStringHandles";
  case 0x006c: return "DdeConnect";
  case 0x006d: return "DdeConnectList";
  case 0x006e: return "DdeCreateDataHandle";
  case 0x006f: return "DdeCreateStringHandleA";
  case 0x0070: return "DdeCreateStringHandleW";
  case 0x0071: return "DdeDisconnect";
  case 0x0072: return "DdeDisconnectList";
  case 0x0073: return "DdeEnableCallback";
  case 0x0074: return "DdeFreeDataHandle";
  case 0x0075: return "DdeFreeStringHandle";
  case 0x0076: return "DdeGetData";
  case 0x0077: return "DdeGetLastError";
  case 0x0078: return "DdeGetQualityOfService";
  case 0x0079: return "DdeImpersonateClient";
  case 0x007a: return "DdeInitializeA";
  case 0x007b: return "DdeInitializeW";
  case 0x007c: return "DdeKeepStringHandle";
  case 0x007d: return "DdeNameService";
  case 0x007e: return "DdePostAdvise";
  case 0x007f: return "DdeQueryConvInfo";
  case 0x0080: return "DdeQueryNextServer";
  case 0x0081: return "DdeQueryStringA";
  case 0x0082: return "DdeQueryStringW";
  case 0x0083: return "DdeReconnect";
  case 0x0084: return "DdeSetQualityOfService";
  case 0x0085: return "DdeSetUserHandle";
  case 0x0086: return "DdeUnaccessData";
  case 0x0087: return "DdeUninitialize";
  case 0x0088: return "DefDlgProcA";
  case 0x0089: return "DefDlgProcW";
  case 0x008a: return "DefFrameProcA";
  case 0x008b: return "DefFrameProcW";
  case 0x008c: return "DefMDIChildProcA";
  case 0x008d: return "DefMDIChildProcW";
  case 0x008e: return "DefRawInputProc";
  case 0x008f: return "DefWindowProcA";
  case 0x0090: return "DefWindowProcW";
  case 0x0091: return "DeferWindowPos";
  case 0x0092: return "DeleteMenu";
  case 0x0093: return "DeregisterShellHookWindow";
  case 0x0094: return "DestroyAcceleratorTable";
  case 0x0095: return "DestroyCaret";
  case 0x0096: return "DestroyCursor";
  case 0x0097: return "DestroyIcon";
  case 0x0098: return "DestroyMenu";
  case 0x0099: return "DestroyReasons";
  case 0x009a: return "DestroyWindow";
  case 0x009b: return "DeviceEventWorker";
  case 0x009c: return "DialogBoxIndirectParamA";
  case 0x009d: return "DialogBoxIndirectParamAorW";
  case 0x009e: return "DialogBoxIndirectParamW";
  case 0x009f: return "DialogBoxParamA";
  case 0x00a0: return "DialogBoxParamW";
  case 0x00a1: return "DisableProcessWindowsGhosting";
  case 0x00a2: return "DispatchMessageA";
  case 0x00a3: return "DispatchMessageW";
  case 0x00a4: return "DisplayExitWindowsWarnings";
  case 0x00a5: return "DlgDirListA";
  case 0x00a6: return "DlgDirListComboBoxA";
  case 0x00a7: return "DlgDirListComboBoxW";
  case 0x00a8: return "DlgDirListW";
  case 0x00a9: return "DlgDirSelectComboBoxExA";
  case 0x00aa: return "DlgDirSelectComboBoxExW";
  case 0x00ab: return "DlgDirSelectExA";
  case 0x00ac: return "DlgDirSelectExW";
  case 0x00ad: return "DragDetect";
  case 0x00ae: return "DragObject";
  case 0x00af: return "DrawAnimatedRects";
  case 0x00b0: return "DrawCaption";
  case 0x00b1: return "DrawCaptionTempA";
  case 0x00b2: return "DrawCaptionTempW";
  case 0x00b3: return "DrawEdge";
  case 0x00b4: return "DrawFocusRect";
  case 0x00b5: return "DrawFrame";
  case 0x00b6: return "DrawFrameControl";
  case 0x00b7: return "DrawIcon";
  case 0x00b8: return "DrawIconEx";
  case 0x00b9: return "DrawMenuBar";
  case 0x00ba: return "DrawMenuBarTemp";
  case 0x00bb: return "DrawStateA";
  case 0x00bc: return "DrawStateW";
  case 0x00bd: return "DrawTextA";
  case 0x00be: return "DrawTextExA";
  case 0x00bf: return "DrawTextExW";
  case 0x00c0: return "DrawTextW";
  case 0x00c1: return "EditWndProc";
  case 0x00c2: return "EmptyClipboard";
  case 0x00c3: return "EnableMenuItem";
  case 0x00c4: return "EnableScrollBar";
  case 0x00c5: return "EnableWindow";
  case 0x00c6: return "EndDeferWindowPos";
  case 0x00c7: return "EndDialog";
  case 0x00c8: return "EndMenu";
  case 0x00c9: return "EndPaint";
  case 0x00ca: return "EndTask";
  case 0x00cb: return "EnterReaderModeHelper";
  case 0x00cc: return "EnumChildWindows";
  case 0x00cd: return "EnumClipboardFormats";
  case 0x00ce: return "EnumDesktopWindows";
  case 0x00cf: return "EnumDesktopsA";
  case 0x00d0: return "EnumDesktopsW";
  case 0x00d1: return "EnumDisplayDevicesA";
  case 0x00d2: return "EnumDisplayDevicesW";
  case 0x00d3: return "EnumDisplayMonitors";
  case 0x00d4: return "EnumDisplaySettingsA";
  case 0x00d5: return "EnumDisplaySettingsExA";
  case 0x00d6: return "EnumDisplaySettingsExW";
  case 0x00d7: return "EnumDisplaySettingsW";
  case 0x00d8: return "EnumPropsA";
  case 0x00d9: return "EnumPropsExA";
  case 0x00da: return "EnumPropsExW";
  case 0x00db: return "EnumPropsW";
  case 0x00dc: return "EnumThreadWindows";
  case 0x00dd: return "EnumWindowStationsA";
  case 0x00de: return "EnumWindowStationsW";
  case 0x00df: return "EnumWindows";
  case 0x00e0: return "EqualRect";
  case 0x00e1: return "ExcludeUpdateRgn";
  case 0x00e2: return "ExitWindowsEx";
  case 0x00e3: return "FillRect";
  case 0x00e4: return "FindWindowA";
  case 0x00e5: return "FindWindowExA";
  case 0x00e6: return "FindWindowExW";
  case 0x00e7: return "FindWindowW";
  case 0x00e8: return "FlashWindow";
  case 0x00e9: return "FlashWindowEx";
  case 0x00ea: return "FrameRect";
  case 0x00eb: return "FreeDDElParam";
  case 0x00ec: return "GetActiveWindow";
  case 0x00ed: return "GetAltTabInfo";
  case 0x00ee: return "GetAltTabInfoA";
  case 0x00ef: return "GetAltTabInfoW";
  case 0x00f0: return "GetAncestor";
  case 0x00f2: return "GetAppCompatFlags";
  case 0x00f1: return "GetAppCompatFlags2";
  case 0x00f3: return "GetAsyncKeyState";
  case 0x00f4: return "GetCapture";
  case 0x00f5: return "GetCaretBlinkTime";
  case 0x00f6: return "GetCaretPos";
  case 0x00f7: return "GetClassInfoA";
  case 0x00f8: return "GetClassInfoExA";
  case 0x00f9: return "GetClassInfoExW";
  case 0x00fa: return "GetClassInfoW";
  case 0x00fb: return "GetClassLongA";
  case 0x00fc: return "GetClassLongW";
  case 0x00fd: return "GetClassNameA";
  case 0x00fe: return "GetClassNameW";
  case 0x00ff: return "GetClassWord";
  case 0x0100: return "GetClientRect";
  case 0x0101: return "GetClipCursor";
  case 0x0102: return "GetClipboardData";
  case 0x0103: return "GetClipboardFormatNameA";
  case 0x0104: return "GetClipboardFormatNameW";
  case 0x0105: return "GetClipboardOwner";
  case 0x0106: return "GetClipboardSequenceNumber";
  case 0x0107: return "GetClipboardViewer";
  case 0x0108: return "GetComboBoxInfo";
  case 0x0109: return "GetCursor";
  case 0x010a: return "GetCursorFrameInfo";
  case 0x010b: return "GetCursorInfo";
  case 0x010c: return "GetCursorPos";
  case 0x010d: return "GetDC";
  case 0x010e: return "GetDCEx";
  case 0x010f: return "GetDesktopWindow";
  case 0x0110: return "GetDialogBaseUnits";
  case 0x0111: return "GetDlgCtrlID";
  case 0x0112: return "GetDlgItem";
  case 0x0113: return "GetDlgItemInt";
  case 0x0114: return "GetDlgItemTextA";
  case 0x0115: return "GetDlgItemTextW";
  case 0x0116: return "GetDoubleClickTime";
  case 0x0117: return "GetFocus";
  case 0x0118: return "GetForegroundWindow";
  case 0x0119: return "GetGUIThreadInfo";
  case 0x011a: return "GetGuiResources";
  case 0x011b: return "GetIconInfo";
  case 0x011c: return "GetInputDesktop";
  case 0x011d: return "GetInputState";
  case 0x011e: return "GetInternalWindowPos";
  case 0x011f: return "GetKBCodePage";
  case 0x0120: return "GetKeyNameTextA";
  case 0x0121: return "GetKeyNameTextW";
  case 0x0122: return "GetKeyState";
  case 0x0123: return "GetKeyboardLayout";
  case 0x0124: return "GetKeyboardLayoutList";
  case 0x0125: return "GetKeyboardLayoutNameA";
  case 0x0126: return "GetKeyboardLayoutNameW";
  case 0x0127: return "GetKeyboardState";
  case 0x0128: return "GetKeyboardType";
  case 0x0129: return "GetLastActivePopup";
  case 0x012a: return "GetLastInputInfo";
  case 0x012b: return "GetLayeredWindowAttributes";
  case 0x012c: return "GetListBoxInfo";
  case 0x012d: return "GetMenu";
  case 0x012e: return "GetMenuBarInfo";
  case 0x012f: return "GetMenuCheckMarkDimensions";
  case 0x0130: return "GetMenuContextHelpId";
  case 0x0131: return "GetMenuDefaultItem";
  case 0x0132: return "GetMenuInfo";
  case 0x0133: return "GetMenuItemCount";
  case 0x0134: return "GetMenuItemID";
  case 0x0135: return "GetMenuItemInfoA";
  case 0x0136: return "GetMenuItemInfoW";
  case 0x0137: return "GetMenuItemRect";
  case 0x0138: return "GetMenuState";
  case 0x0139: return "GetMenuStringA";
  case 0x013a: return "GetMenuStringW";
  case 0x013b: return "GetMessageA";
  case 0x013c: return "GetMessageExtraInfo";
  case 0x013d: return "GetMessagePos";
  case 0x013e: return "GetMessageTime";
  case 0x013f: return "GetMessageW";
  case 0x0140: return "GetMonitorInfoA";
  case 0x0141: return "GetMonitorInfoW";
  case 0x0142: return "GetMouseMovePointsEx";
  case 0x0143: return "GetNextDlgGroupItem";
  case 0x0144: return "GetNextDlgTabItem";
  case 0x0145: return "GetOpenClipboardWindow";
  case 0x0146: return "GetParent";
  case 0x0147: return "GetPriorityClipboardFormat";
  case 0x0148: return "GetProcessDefaultLayout";
  case 0x0149: return "GetProcessWindowStation";
  case 0x014a: return "GetProgmanWindow";
  case 0x014b: return "GetPropA";
  case 0x014c: return "GetPropW";
  case 0x014d: return "GetQueueStatus";
  case 0x014e: return "GetRawInputBuffer";
  case 0x014f: return "GetRawInputData";
  case 0x0150: return "GetRawInputDeviceInfoA";
  case 0x0151: return "GetRawInputDeviceInfoW";
  case 0x0152: return "GetRawInputDeviceList";
  case 0x0153: return "GetReasonTitleFromReasonCode";
  case 0x0154: return "GetRegisteredRawInputDevices";
  case 0x0155: return "GetScrollBarInfo";
  case 0x0156: return "GetScrollInfo";
  case 0x0157: return "GetScrollPos";
  case 0x0158: return "GetScrollRange";
  case 0x0159: return "GetShellWindow";
  case 0x015a: return "GetSubMenu";
  case 0x015b: return "GetSysColor";
  case 0x015c: return "GetSysColorBrush";
  case 0x015d: return "GetSystemMenu";
  case 0x015e: return "GetSystemMetrics";
  case 0x015f: return "GetTabbedTextExtentA";
  case 0x0160: return "GetTabbedTextExtentW";
  case 0x0161: return "GetTaskmanWindow";
  case 0x0162: return "GetThreadDesktop";
  case 0x0163: return "GetTitleBarInfo";
  case 0x0164: return "GetTopWindow";
  case 0x0165: return "GetUpdateRect";
  case 0x0166: return "GetUpdateRgn";
  case 0x0167: return "GetUserObjectInformationA";
  case 0x0168: return "GetUserObjectInformationW";
  case 0x0169: return "GetUserObjectSecurity";
  case 0x016a: return "GetWinStationInfo";
  case 0x016b: return "GetWindow";
  case 0x016c: return "GetWindowContextHelpId";
  case 0x016d: return "GetWindowDC";
  case 0x016e: return "GetWindowInfo";
  case 0x016f: return "GetWindowLongA";
  case 0x0170: return "GetWindowLongW";
  case 0x0171: return "GetWindowModuleFileName";
  case 0x0172: return "GetWindowModuleFileNameA";
  case 0x0173: return "GetWindowModuleFileNameW";
  case 0x0174: return "GetWindowPlacement";
  case 0x0175: return "GetWindowRect";
  case 0x0176: return "GetWindowRgn";
  case 0x0177: return "GetWindowRgnBox";
  case 0x0178: return "GetWindowTextA";
  case 0x0179: return "GetWindowTextLengthA";
  case 0x017a: return "GetWindowTextLengthW";
  case 0x017b: return "GetWindowTextW";
  case 0x017c: return "GetWindowThreadProcessId";
  case 0x017d: return "GetWindowWord";
  case 0x017e: return "GrayStringA";
  case 0x017f: return "GrayStringW";
  case 0x0180: return "HideCaret";
  case 0x0181: return "HiliteMenuItem";
  case 0x0182: return "IMPGetIMEA";
  case 0x0183: return "IMPGetIMEW";
  case 0x0184: return "IMPQueryIMEA";
  case 0x0185: return "IMPQueryIMEW";
  case 0x0186: return "IMPSetIMEA";
  case 0x0187: return "IMPSetIMEW";
  case 0x0188: return "ImpersonateDdeClientWindow";
  case 0x0189: return "InSendMessage";
  case 0x018a: return "InSendMessageEx";
  case 0x018b: return "InflateRect";
  case 0x018c: return "InitializeLpkHooks";
  case 0x018d: return "InitializeWin32EntryTable";
  case 0x018e: return "InsertMenuA";
  case 0x018f: return "InsertMenuItemA";
  case 0x0190: return "InsertMenuItemW";
  case 0x0191: return "InsertMenuW";
  case 0x0192: return "InternalGetWindowText";
  case 0x0193: return "IntersectRect";
  case 0x0194: return "InvalidateRect";
  case 0x0195: return "InvalidateRgn";
  case 0x0196: return "InvertRect";
  case 0x0197: return "IsCharAlphaA";
  case 0x0198: return "IsCharAlphaNumericA";
  case 0x0199: return "IsCharAlphaNumericW";
  case 0x019a: return "IsCharAlphaW";
  case 0x019b: return "IsCharLowerA";
  case 0x019c: return "IsCharLowerW";
  case 0x019d: return "IsCharUpperA";
  case 0x019e: return "IsCharUpperW";
  case 0x019f: return "IsChild";
  case 0x01a0: return "IsClipboardFormatAvailable";
  case 0x01a1: return "IsDialogMessage";
  case 0x01a2: return "IsDialogMessageA";
  case 0x01a3: return "IsDialogMessageW";
  case 0x01a4: return "IsDlgButtonChecked";
  case 0x01a5: return "IsGUIThread";
  case 0x01a6: return "IsHungAppWindow";
  case 0x01a7: return "IsIconic";
  case 0x01a8: return "IsMenu";
  case 0x01a9: return "IsRectEmpty";
  case 0x01aa: return "IsServerSideWindow";
  case 0x01ab: return "IsWinEventHookInstalled";
  case 0x01ac: return "IsWindow";
  case 0x01ad: return "IsWindowEnabled";
  case 0x01ae: return "IsWindowInDestroy";
  case 0x01af: return "IsWindowUnicode";
  case 0x01b0: return "IsWindowVisible";
  case 0x01b1: return "IsZoomed";
  case 0x01b2: return "KillSystemTimer";
  case 0x01b3: return "KillTimer";
  case 0x01b4: return "LoadAcceleratorsA";
  case 0x01b5: return "LoadAcceleratorsW";
  case 0x01b6: return "LoadBitmapA";
  case 0x01b7: return "LoadBitmapW";
  case 0x01b8: return "LoadCursorA";
  case 0x01b9: return "LoadCursorFromFileA";
  case 0x01ba: return "LoadCursorFromFileW";
  case 0x01bb: return "LoadCursorW";
  case 0x01bc: return "LoadIconA";
  case 0x01bd: return "LoadIconW";
  case 0x01be: return "LoadImageA";
  case 0x01bf: return "LoadImageW";
  case 0x01c0: return "LoadKeyboardLayoutA";
  case 0x01c1: return "LoadKeyboardLayoutEx";
  case 0x01c2: return "LoadKeyboardLayoutW";
  case 0x01c3: return "LoadLocalFonts";
  case 0x01c4: return "LoadMenuA";
  case 0x01c5: return "LoadMenuIndirectA";
  case 0x01c6: return "LoadMenuIndirectW";
  case 0x01c7: return "LoadMenuW";
  case 0x01c8: return "LoadRemoteFonts";
  case 0x01c9: return "LoadStringA";
  case 0x01ca: return "LoadStringW";
  case 0x01cb: return "LockSetForegroundWindow";
  case 0x01cc: return "LockWindowStation";
  case 0x01cd: return "LockWindowUpdate";
  case 0x01ce: return "LockWorkStation";
  case 0x01cf: return "LookupIconIdFromDirectory";
  case 0x01d0: return "LookupIconIdFromDirectoryEx";
  case 0x01d1: return "MBToWCSEx";
  case 0x01d2: return "MB_GetString";
  case 0x01d3: return "MapDialogRect";
  case 0x01d4: return "MapVirtualKeyA";
  case 0x01d5: return "MapVirtualKeyExA";
  case 0x01d6: return "MapVirtualKeyExW";
  case 0x01d7: return "MapVirtualKeyW";
  case 0x01d8: return "MapWindowPoints";
  case 0x01d9: return "MenuItemFromPoint";
  case 0x01da: return "MenuWindowProcA";
  case 0x01db: return "MenuWindowProcW";
  case 0x01dc: return "MessageBeep";
  case 0x01dd: return "MessageBoxA";
  case 0x01de: return "MessageBoxExA";
  case 0x01df: return "MessageBoxExW";
  case 0x01e0: return "MessageBoxIndirectA";
  case 0x01e1: return "MessageBoxIndirectW";
  case 0x01e2: return "MessageBoxTimeoutA";
  case 0x01e3: return "MessageBoxTimeoutW";
  case 0x01e4: return "MessageBoxW";
  case 0x01e5: return "ModifyMenuA";
  case 0x01e6: return "ModifyMenuW";
  case 0x01e7: return "MonitorFromPoint";
  case 0x01e8: return "MonitorFromRect";
  case 0x01e9: return "MonitorFromWindow";
  case 0x01ea: return "MoveWindow";
  case 0x01eb: return "MsgWaitForMultipleObjects";
  case 0x01ec: return "MsgWaitForMultipleObjectsEx";
  case 0x01ed: return "NotifyWinEvent";
  case 0x01ee: return "OemKeyScan";
  case 0x01ef: return "OemToCharA";
  case 0x01f0: return "OemToCharBuffA";
  case 0x01f1: return "OemToCharBuffW";
  case 0x01f2: return "OemToCharW";
  case 0x01f3: return "OffsetRect";
  case 0x01f4: return "OpenClipboard";
  case 0x01f5: return "OpenDesktopA";
  case 0x01f6: return "OpenDesktopW";
  case 0x01f7: return "OpenIcon";
  case 0x01f8: return "OpenInputDesktop";
  case 0x01f9: return "OpenWindowStationA";
  case 0x01fa: return "OpenWindowStationW";
  case 0x01fb: return "PackDDElParam";
  case 0x01fc: return "PaintDesktop";
  case 0x01fd: return "PaintMenuBar";
  case 0x01fe: return "PeekMessageA";
  case 0x01ff: return "PeekMessageW";
  case 0x0200: return "PostMessageA";
  case 0x0201: return "PostMessageW";
  case 0x0202: return "PostQuitMessage";
  case 0x0203: return "PostThreadMessageA";
  case 0x0204: return "PostThreadMessageW";
  case 0x0205: return "PrintWindow";
  case 0x0206: return "PrivateExtractIconExA";
  case 0x0207: return "PrivateExtractIconExW";
  case 0x0208: return "PrivateExtractIconsA";
  case 0x0209: return "PrivateExtractIconsW";
  case 0x020a: return "PrivateSetDbgTag";
  case 0x020b: return "PrivateSetRipFlags";
  case 0x020c: return "PtInRect";
  case 0x020d: return "QuerySendMessage";
  case 0x020e: return "QueryUserCounters";
  case 0x020f: return "RealChildWindowFromPoint";
  case 0x0210: return "RealGetWindowClass";
  case 0x0211: return "RealGetWindowClassA";
  case 0x0212: return "RealGetWindowClassW";
  case 0x0213: return "ReasonCodeNeedsBugID";
  case 0x0214: return "ReasonCodeNeedsComment";
  case 0x0215: return "RecordShutdownReason";
  case 0x0216: return "RedrawWindow";
  case 0x0217: return "RegisterClassA";
  case 0x0218: return "RegisterClassExA";
  case 0x0219: return "RegisterClassExW";
  case 0x021a: return "RegisterClassW";
  case 0x021b: return "RegisterClipboardFormatA";
  case 0x021c: return "RegisterClipboardFormatW";
  case 0x021d: return "RegisterDeviceNotificationA";
  case 0x021e: return "RegisterDeviceNotificationW";
  case 0x021f: return "RegisterHotKey";
  case 0x0220: return "RegisterLogonProcess";
  case 0x0221: return "RegisterMessagePumpHook";
  case 0x0222: return "RegisterRawInputDevices";
  case 0x0223: return "RegisterServicesProcess";
  case 0x0224: return "RegisterShellHookWindow";
  case 0x0225: return "RegisterSystemThread";
  case 0x0226: return "RegisterTasklist";
  case 0x0227: return "RegisterUserApiHook";
  case 0x0228: return "RegisterWindowMessageA";
  case 0x0229: return "RegisterWindowMessageW";
  case 0x022a: return "ReleaseCapture";
  case 0x022b: return "ReleaseDC";
  case 0x022c: return "RemoveMenu";
  case 0x022d: return "RemovePropA";
  case 0x022e: return "RemovePropW";
  case 0x022f: return "ReplyMessage";
  case 0x0230: return "ResolveDesktopForWOW";
  case 0x0231: return "ReuseDDElParam";
  case 0x0232: return "ScreenToClient";
  case 0x0233: return "ScrollChildren";
  case 0x0234: return "ScrollDC";
  case 0x0235: return "ScrollWindow";
  case 0x0236: return "ScrollWindowEx";
  case 0x0237: return "SendDlgItemMessageA";
  case 0x0238: return "SendDlgItemMessageW";
  case 0x0239: return "SendIMEMessageExA";
  case 0x023a: return "SendIMEMessageExW";
  case 0x023b: return "SendInput";
  case 0x023c: return "SendMessageA";
  case 0x023d: return "SendMessageCallbackA";
  case 0x023e: return "SendMessageCallbackW";
  case 0x023f: return "SendMessageTimeoutA";
  case 0x0240: return "SendMessageTimeoutW";
  case 0x0241: return "SendMessageW";
  case 0x0242: return "SendNotifyMessageA";
  case 0x0243: return "SendNotifyMessageW";
  case 0x0244: return "SetActiveWindow";
  case 0x0245: return "SetCapture";
  case 0x0246: return "SetCaretBlinkTime";
  case 0x0247: return "SetCaretPos";
  case 0x0248: return "SetClassLongA";
  case 0x0249: return "SetClassLongW";
  case 0x024a: return "SetClassWord";
  case 0x024b: return "SetClipboardData";
  case 0x024c: return "SetClipboardViewer";
  case 0x024d: return "SetConsoleReserveKeys";
  case 0x024e: return "SetCursor";
  case 0x024f: return "SetCursorContents";
  case 0x0250: return "SetCursorPos";
  case 0x0251: return "SetDebugErrorLevel";
  case 0x0252: return "SetDeskWallpaper";
  case 0x0253: return "SetDlgItemInt";
  case 0x0254: return "SetDlgItemTextA";
  case 0x0255: return "SetDlgItemTextW";
  case 0x0256: return "SetDoubleClickTime";
  case 0x0257: return "SetFocus";
  case 0x0258: return "SetForegroundWindow";
  case 0x0259: return "SetInternalWindowPos";
  case 0x025a: return "SetKeyboardState";
  case 0x025b: return "SetLastErrorEx";
  case 0x025c: return "SetLayeredWindowAttributes";
  case 0x025d: return "SetLogonNotifyWindow";
  case 0x025e: return "SetMenu";
  case 0x025f: return "SetMenuContextHelpId";
  case 0x0260: return "SetMenuDefaultItem";
  case 0x0261: return "SetMenuInfo";
  case 0x0262: return "SetMenuItemBitmaps";
  case 0x0263: return "SetMenuItemInfoA";
  case 0x0264: return "SetMenuItemInfoW";
  case 0x0265: return "SetMessageExtraInfo";
  case 0x0266: return "SetMessageQueue";
  case 0x0267: return "SetParent";
  case 0x0268: return "SetProcessDefaultLayout";
  case 0x0269: return "SetProcessWindowStation";
  case 0x026a: return "SetProgmanWindow";
  case 0x026b: return "SetPropA";
  case 0x026c: return "SetPropW";
  case 0x026d: return "SetRect";
  case 0x026e: return "SetRectEmpty";
  case 0x026f: return "SetScrollInfo";
  case 0x0270: return "SetScrollPos";
  case 0x0271: return "SetScrollRange";
  case 0x0272: return "SetShellWindow";
  case 0x0273: return "SetShellWindowEx";
  case 0x0274: return "SetSysColors";
  case 0x0275: return "SetSysColorsTemp";
  case 0x0276: return "SetSystemCursor";
  case 0x0277: return "SetSystemMenu";
  case 0x0278: return "SetSystemTimer";
  case 0x0279: return "SetTaskmanWindow";
  case 0x027a: return "SetThreadDesktop";
  case 0x027b: return "SetTimer";
  case 0x027c: return "SetUserObjectInformationA";
  case 0x027d: return "SetUserObjectInformationW";
  case 0x027e: return "SetUserObjectSecurity";
  case 0x027f: return "SetWinEventHook";
  case 0x0280: return "SetWindowContextHelpId";
  case 0x0281: return "SetWindowLongA";
  case 0x0282: return "SetWindowLongW";
  case 0x0283: return "SetWindowPlacement";
  case 0x0284: return "SetWindowPos";
  case 0x0285: return "SetWindowRgn";
  case 0x0286: return "SetWindowStationUser";
  case 0x0287: return "SetWindowTextA";
  case 0x0288: return "SetWindowTextW";
  case 0x0289: return "SetWindowWord";
  case 0x028a: return "SetWindowsHookA";
  case 0x028b: return "SetWindowsHookExA";
  case 0x028c: return "SetWindowsHookExW";
  case 0x028d: return "SetWindowsHookW";
  case 0x028e: return "ShowCaret";
  case 0x028f: return "ShowCursor";
  case 0x0290: return "ShowOwnedPopups";
  case 0x0291: return "ShowScrollBar";
  case 0x0292: return "ShowStartGlass";
  case 0x0293: return "ShowWindow";
  case 0x0294: return "ShowWindowAsync";
  case 0x0295: return "SoftModalMessageBox";
  case 0x0296: return "SubtractRect";
  case 0x0297: return "SwapMouseButton";
  case 0x0298: return "SwitchDesktop";
  case 0x0299: return "SwitchToThisWindow";
  case 0x029a: return "SystemParametersInfoA";
  case 0x029b: return "SystemParametersInfoW";
  case 0x029c: return "TabbedTextOutA";
  case 0x029d: return "TabbedTextOutW";
  case 0x029e: return "TileChildWindows";
  case 0x029f: return "TileWindows";
  case 0x02a0: return "ToAscii";
  case 0x02a1: return "ToAsciiEx";
  case 0x02a2: return "ToUnicode";
  case 0x02a3: return "ToUnicodeEx";
  case 0x02a4: return "TrackMouseEvent";
  case 0x02a5: return "TrackPopupMenu";
  case 0x02a6: return "TrackPopupMenuEx";
  case 0x02a7: return "TranslateAccelerator";
  case 0x02a8: return "TranslateAcceleratorA";
  case 0x02a9: return "TranslateAcceleratorW";
  case 0x02aa: return "TranslateMDISysAccel";
  case 0x02ab: return "TranslateMessage";
  case 0x02ac: return "TranslateMessageEx";
  case 0x02ad: return "UnhookWinEvent";
  case 0x02ae: return "UnhookWindowsHook";
  case 0x02af: return "UnhookWindowsHookEx";
  case 0x02b0: return "UnionRect";
  case 0x02b1: return "UnloadKeyboardLayout";
  case 0x02b2: return "UnlockWindowStation";
  case 0x02b3: return "UnpackDDElParam";
  case 0x02b4: return "UnregisterClassA";
  case 0x02b5: return "UnregisterClassW";
  case 0x02b6: return "UnregisterDeviceNotification";
  case 0x02b7: return "UnregisterHotKey";
  case 0x02b8: return "UnregisterMessagePumpHook";
  case 0x02b9: return "UnregisterUserApiHook";
  case 0x02ba: return "UpdateLayeredWindow";
  case 0x02bb: return "UpdatePerUserSystemParameters";
  case 0x02bc: return "UpdateWindow";
  case 0x02bd: return "User32InitializeImmEntryTable";
  case 0x02be: return "UserClientDllInitialize";
  case 0x02bf: return "UserHandleGrantAccess";
  case 0x02c0: return "UserLpkPSMTextOut";
  case 0x02c1: return "UserLpkTabbedTextOut";
  case 0x02c2: return "UserRealizePalette";
  case 0x02c3: return "UserRegisterWowHandlers";
  case 0x02c4: return "VRipOutput";
  case 0x02c5: return "VTagOutput";
  case 0x02c6: return "ValidateRect";
  case 0x02c7: return "ValidateRgn";
  case 0x02c8: return "VkKeyScanA";
  case 0x02c9: return "VkKeyScanExA";
  case 0x02ca: return "VkKeyScanExW";
  case 0x02cb: return "VkKeyScanW";
  case 0x02cc: return "WCSToMBEx";
  case 0x02cd: return "WINNLSEnableIME";
  case 0x02ce: return "WINNLSGetEnableStatus";
  case 0x02cf: return "WINNLSGetIMEHotkey";
  case 0x02d0: return "WaitForInputIdle";
  case 0x02d1: return "WaitMessage";
  case 0x02d2: return "Win32PoolAllocationStats";
  case 0x02d3: return "WinHelpA";
  case 0x02d4: return "WinHelpW";
  case 0x02d5: return "WindowFromDC";
  case 0x02d6: return "WindowFromPoint";
  case 0x02d7: return "keybd_event";
  case 0x02d8: return "mouse_event";
  case 0x02d9: return "wsprintfA";
  case 0x02da: return "wsprintfW";
  case 0x02db: return "wvsprintfA";
  case 0x02dc: return "wvsprintfW";
  }
  return nullptr;
}


}
}

#endif

