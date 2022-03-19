/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#ifndef LIEF_PE_MSVCP120_DLL_LOOKUP_H_
#define LIEF_PE_MSVCP120_DLL_LOOKUP_H_

namespace LIEF {
namespace PE {

const char* msvcp120_dll_lookup(uint32_t i) {
  switch (i) {
    case 0x0001:
      return "??$_Getvals@_W@?$time_get@DV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@std@@@std@@IEAAX_WAEBV_Locinfo@1@@Z";
    case 0x0002:
      return "??$_Getvals@_W@?$time_get@GV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@std@@@std@@IEAAX_WAEBV_Locinfo@1@@Z";
    case 0x0003:
      return "??$_Getvals@_W@?$time_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@IEAAX_WAEBV_Locinfo@1@@Z";
    case 0x0004:
      return "??0?$_Yarn@D@std@@QEAA@AEBV01@@Z";
    case 0x0005:
      return "??0?$_Yarn@D@std@@QEAA@PEBD@Z";
    case 0x0006:
      return "??0?$_Yarn@D@std@@QEAA@XZ";
    case 0x0007:
      return "??0?$_Yarn@_W@std@@QEAA@XZ";
    case 0x0008:
      return "??0?$basic_ios@DU?$char_traits@D@std@@@std@@IEAA@XZ";
    case 0x0009:
      return "??0?$basic_ios@DU?$char_traits@D@std@@@std@@QEAA@PEAV?$basic_"
             "streambuf@DU?$char_traits@D@std@@@1@@Z";
    case 0x000a:
      return "??0?$basic_ios@GU?$char_traits@G@std@@@std@@IEAA@XZ";
    case 0x000b:
      return "??0?$basic_ios@GU?$char_traits@G@std@@@std@@QEAA@PEAV?$basic_"
             "streambuf@GU?$char_traits@G@std@@@1@@Z";
    case 0x000c:
      return "??0?$basic_ios@_WU?$char_traits@_W@std@@@std@@IEAA@XZ";
    case 0x000d:
      return "??0?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAA@PEAV?$basic_"
             "streambuf@_WU?$char_traits@_W@std@@@1@@Z";
    case 0x000e:
      return "??0?$basic_iostream@DU?$char_traits@D@std@@@std@@IEAA@$$QEAV01@@"
             "Z";
    case 0x000f:
      return "??0?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAA@PEAV?$"
             "basic_streambuf@DU?$char_traits@D@std@@@1@@Z";
    case 0x0010:
      return "??0?$basic_iostream@GU?$char_traits@G@std@@@std@@IEAA@$$QEAV01@@"
             "Z";
    case 0x0011:
      return "??0?$basic_iostream@GU?$char_traits@G@std@@@std@@QEAA@PEAV?$"
             "basic_streambuf@GU?$char_traits@G@std@@@1@@Z";
    case 0x0012:
      return "??0?$basic_iostream@_WU?$char_traits@_W@std@@@std@@IEAA@$$QEAV01@"
             "@Z";
    case 0x0013:
      return "??0?$basic_iostream@_WU?$char_traits@_W@std@@@std@@QEAA@PEAV?$"
             "basic_streambuf@_WU?$char_traits@_W@std@@@1@@Z";
    case 0x0014:
      return "??0?$basic_istream@DU?$char_traits@D@std@@@std@@IEAA@$$QEAV01@@Z";
    case 0x0015:
      return "??0?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA@PEAV?$basic_"
             "streambuf@DU?$char_traits@D@std@@@1@_N1@Z";
    case 0x0016:
      return "??0?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA@PEAV?$basic_"
             "streambuf@DU?$char_traits@D@std@@@1@_N@Z";
    case 0x0017:
      return "??0?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA@W4_"
             "Uninitialized@1@@Z";
    case 0x0018:
      return "??0?$basic_istream@GU?$char_traits@G@std@@@std@@IEAA@$$QEAV01@@Z";
    case 0x0019:
      return "??0?$basic_istream@GU?$char_traits@G@std@@@std@@QEAA@PEAV?$basic_"
             "streambuf@GU?$char_traits@G@std@@@1@_N1@Z";
    case 0x001a:
      return "??0?$basic_istream@GU?$char_traits@G@std@@@std@@QEAA@PEAV?$basic_"
             "streambuf@GU?$char_traits@G@std@@@1@_N@Z";
    case 0x001b:
      return "??0?$basic_istream@GU?$char_traits@G@std@@@std@@QEAA@W4_"
             "Uninitialized@1@@Z";
    case 0x001c:
      return "??0?$basic_istream@_WU?$char_traits@_W@std@@@std@@IEAA@$$QEAV01@@"
             "Z";
    case 0x001d:
      return "??0?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAA@PEAV?$"
             "basic_streambuf@_WU?$char_traits@_W@std@@@1@_N1@Z";
    case 0x001e:
      return "??0?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAA@PEAV?$"
             "basic_streambuf@_WU?$char_traits@_W@std@@@1@_N@Z";
    case 0x001f:
      return "??0?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAA@W4_"
             "Uninitialized@1@@Z";
    case 0x0020:
      return "??0?$basic_ostream@DU?$char_traits@D@std@@@std@@IEAA@$$QEAV01@@Z";
    case 0x0021:
      return "??0?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAA@PEAV?$basic_"
             "streambuf@DU?$char_traits@D@std@@@1@_N@Z";
    case 0x0022:
      return "??0?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAA@W4_"
             "Uninitialized@1@_N@Z";
    case 0x0023:
      return "??0?$basic_ostream@GU?$char_traits@G@std@@@std@@IEAA@$$QEAV01@@Z";
    case 0x0024:
      return "??0?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAA@PEAV?$basic_"
             "streambuf@GU?$char_traits@G@std@@@1@_N@Z";
    case 0x0025:
      return "??0?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAA@W4_"
             "Uninitialized@1@_N@Z";
    case 0x0026:
      return "??0?$basic_ostream@_WU?$char_traits@_W@std@@@std@@IEAA@$$QEAV01@@"
             "Z";
    case 0x0027:
      return "??0?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAA@PEAV?$"
             "basic_streambuf@_WU?$char_traits@_W@std@@@1@_N@Z";
    case 0x0028:
      return "??0?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAA@W4_"
             "Uninitialized@1@_N@Z";
    case 0x0029:
      return "??0?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAA@AEBV01@@Z";
    case 0x002a:
      return "??0?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAA@W4_"
             "Uninitialized@1@@Z";
    case 0x002b:
      return "??0?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAA@XZ";
    case 0x002c:
      return "??0?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAA@AEBV01@@Z";
    case 0x002d:
      return "??0?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAA@W4_"
             "Uninitialized@1@@Z";
    case 0x002e:
      return "??0?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAA@XZ";
    case 0x002f:
      return "??0?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAA@AEBV01@@"
             "Z";
    case 0x0030:
      return "??0?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAA@W4_"
             "Uninitialized@1@@Z";
    case 0x0031:
      return "??0?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAA@XZ";
    case 0x0032:
      return "??0?$codecvt@DDH@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x0033:
      return "??0?$codecvt@DDH@std@@QEAA@_K@Z";
    case 0x0034:
      return "??0?$codecvt@GDH@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x0035:
      return "??0?$codecvt@GDH@std@@QEAA@_K@Z";
    case 0x0036:
      return "??0?$codecvt@_WDH@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x0037:
      return "??0?$codecvt@_WDH@std@@QEAA@_K@Z";
    case 0x0038:
      return "??0?$ctype@D@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x0039:
      return "??0?$ctype@D@std@@QEAA@PEBF_N_K@Z";
    case 0x003a:
      return "??0?$ctype@G@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x003b:
      return "??0?$ctype@G@std@@QEAA@_K@Z";
    case 0x003c:
      return "??0?$ctype@_W@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x003d:
      return "??0?$ctype@_W@std@@QEAA@_K@Z";
    case 0x003e:
      return "??0?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@std@"
             "@@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x003f:
      return "??0?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@std@"
             "@@std@@QEAA@_K@Z";
    case 0x0040:
      return "??0?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@std@"
             "@@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x0041:
      return "??0?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@std@"
             "@@std@@QEAA@_K@Z";
    case 0x0042:
      return "??0?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x0043:
      return "??0?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@QEAA@_K@Z";
    case 0x0044:
      return "??0?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@std@"
             "@@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x0045:
      return "??0?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@std@"
             "@@std@@QEAA@_K@Z";
    case 0x0046:
      return "??0?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@std@"
             "@@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x0047:
      return "??0?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@std@"
             "@@std@@QEAA@_K@Z";
    case 0x0048:
      return "??0?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x0049:
      return "??0?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@QEAA@_K@Z";
    case 0x004a:
      return "??0?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@IEAA@PEBD_K@Z";
    case 0x004b:
      return "??0?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x004c:
      return "??0?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEAA@_K@Z";
    case 0x004d:
      return "??0?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@IEAA@PEBD_K@Z";
    case 0x004e:
      return "??0?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x004f:
      return "??0?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEAA@_K@Z";
    case 0x0050:
      return "??0?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@IEAA@PEBD_K@Z";
    case 0x0051:
      return "??0?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x0052:
      return "??0?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@QEAA@_K@Z";
    case 0x0053:
      return "??0?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x0054:
      return "??0?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEAA@_K@Z";
    case 0x0055:
      return "??0?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@IEAA@PEBD_K@Z";
    case 0x0056:
      return "??0?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x0057:
      return "??0?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEAA@_K@Z";
    case 0x0058:
      return "??0?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@IEAA@PEBD_K@Z";
    case 0x0059:
      return "??0?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@QEAA@AEBV_Locinfo@1@_K@Z";
    case 0x005a:
      return "??0?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@QEAA@_K@Z";
    case 0x005b:
      return "??0Init@ios_base@std@@QEAA@XZ";
    case 0x005c:
      return "??0_Concurrent_queue_base_v4@details@Concurrency@@IEAA@_K@Z";
    case 0x005d:
      return "??0_Concurrent_queue_iterator_base_v4@details@Concurrency@@IEAA@"
             "AEBV_Concurrent_queue_base_v4@12@@Z";
    case 0x005e:
      return "??0_Container_base12@std@@QEAA@AEBU01@@Z";
    case 0x005f:
      return "??0_Container_base12@std@@QEAA@XZ";
    case 0x0060:
      return "??0_Facet_base@std@@QEAA@AEBV01@@Z";
    case 0x0061:
      return "??0_Facet_base@std@@QEAA@XZ";
    case 0x0062:
      return "??0_Init_locks@std@@QEAA@XZ";
    case 0x0063:
      return "??0_Locimp@locale@std@@AEAA@AEBV012@@Z";
    case 0x0064:
      return "??0_Locimp@locale@std@@AEAA@_N@Z";
    case 0x0065:
      return "??0_Locinfo@std@@QEAA@HPEBD@Z";
    case 0x0066:
      return "??0_Locinfo@std@@QEAA@PEBD@Z";
    case 0x0067:
      return "??0_Lockit@std@@QEAA@H@Z";
    case 0x0068:
      return "??0_Lockit@std@@QEAA@XZ";
    case 0x0069:
      return "??0_Pad@std@@QEAA@AEBV01@@Z";
    case 0x006a:
      return "??0_Pad@std@@QEAA@XZ";
    case 0x006b:
      return "??0_Runtime_object@details@Concurrency@@QEAA@H@Z";
    case 0x006c:
      return "??0_Runtime_object@details@Concurrency@@QEAA@XZ";
    case 0x006d:
      return "??0_Timevec@std@@QEAA@AEBV01@@Z";
    case 0x006e:
      return "??0_Timevec@std@@QEAA@PEAX@Z";
    case 0x006f:
      return "??0_UShinit@std@@QEAA@XZ";
    case 0x0070:
      return "??0_Winit@std@@QEAA@XZ";
    case 0x0071:
      return "??0agent@Concurrency@@QEAA@AEAVScheduleGroup@1@@Z";
    case 0x0072:
      return "??0agent@Concurrency@@QEAA@AEAVScheduler@1@@Z";
    case 0x0073:
      return "??0agent@Concurrency@@QEAA@XZ";
    case 0x0074:
      return "??0codecvt_base@std@@QEAA@_K@Z";
    case 0x0075:
      return "??0ctype_base@std@@QEAA@_K@Z";
    case 0x0076:
      return "??0facet@locale@std@@IEAA@_K@Z";
    case 0x0077:
      return "??0id@locale@std@@QEAA@_K@Z";
    case 0x0078:
      return "??0ios_base@std@@IEAA@XZ";
    case 0x0079:
      return "??0time_base@std@@QEAA@_K@Z";
    case 0x007a:
      return "??1?$_Yarn@D@std@@QEAA@XZ";
    case 0x007b:
      return "??1?$_Yarn@_W@std@@QEAA@XZ";
    case 0x007c:
      return "??1?$basic_ios@DU?$char_traits@D@std@@@std@@UEAA@XZ";
    case 0x007d:
      return "??1?$basic_ios@GU?$char_traits@G@std@@@std@@UEAA@XZ";
    case 0x007e:
      return "??1?$basic_ios@_WU?$char_traits@_W@std@@@std@@UEAA@XZ";
    case 0x007f:
      return "??1?$basic_iostream@DU?$char_traits@D@std@@@std@@UEAA@XZ";
    case 0x0080:
      return "??1?$basic_iostream@GU?$char_traits@G@std@@@std@@UEAA@XZ";
    case 0x0081:
      return "??1?$basic_iostream@_WU?$char_traits@_W@std@@@std@@UEAA@XZ";
    case 0x0082:
      return "??1?$basic_istream@DU?$char_traits@D@std@@@std@@UEAA@XZ";
    case 0x0083:
      return "??1?$basic_istream@GU?$char_traits@G@std@@@std@@UEAA@XZ";
    case 0x0084:
      return "??1?$basic_istream@_WU?$char_traits@_W@std@@@std@@UEAA@XZ";
    case 0x0085:
      return "??1?$basic_ostream@DU?$char_traits@D@std@@@std@@UEAA@XZ";
    case 0x0086:
      return "??1?$basic_ostream@GU?$char_traits@G@std@@@std@@UEAA@XZ";
    case 0x0087:
      return "??1?$basic_ostream@_WU?$char_traits@_W@std@@@std@@UEAA@XZ";
    case 0x0088:
      return "??1?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAA@XZ";
    case 0x0089:
      return "??1?$basic_streambuf@GU?$char_traits@G@std@@@std@@UEAA@XZ";
    case 0x008a:
      return "??1?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@UEAA@XZ";
    case 0x008b:
      return "??1?$codecvt@DDH@std@@MEAA@XZ";
    case 0x008c:
      return "??1?$codecvt@GDH@std@@MEAA@XZ";
    case 0x008d:
      return "??1?$codecvt@_WDH@std@@MEAA@XZ";
    case 0x008e:
      return "??1?$ctype@D@std@@MEAA@XZ";
    case 0x008f:
      return "??1?$ctype@G@std@@MEAA@XZ";
    case 0x0090:
      return "??1?$ctype@_W@std@@MEAA@XZ";
    case 0x0091:
      return "??1?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@std@"
             "@@std@@MEAA@XZ";
    case 0x0092:
      return "??1?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@std@"
             "@@std@@MEAA@XZ";
    case 0x0093:
      return "??1?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@MEAA@XZ";
    case 0x0094:
      return "??1?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@std@"
             "@@std@@MEAA@XZ";
    case 0x0095:
      return "??1?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@std@"
             "@@std@@MEAA@XZ";
    case 0x0096:
      return "??1?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@MEAA@XZ";
    case 0x0097:
      return "??1?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@MEAA@XZ";
    case 0x0098:
      return "??1?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@MEAA@XZ";
    case 0x0099:
      return "??1?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@MEAA@XZ";
    case 0x009a:
      return "??1?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@MEAA@XZ";
    case 0x009b:
      return "??1?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@MEAA@XZ";
    case 0x009c:
      return "??1?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@MEAA@XZ";
    case 0x009d:
      return "??1Init@ios_base@std@@QEAA@XZ";
    case 0x009e:
      return "??1_Concurrent_queue_base_v4@details@Concurrency@@MEAA@XZ";
    case 0x009f:
      return "??1_Concurrent_queue_iterator_base_v4@details@Concurrency@@IEAA@"
             "XZ";
    case 0x00a0:
      return "??1_Concurrent_vector_base_v4@details@Concurrency@@IEAA@XZ";
    case 0x00a1:
      return "??1_Container_base12@std@@QEAA@XZ";
    case 0x00a2:
      return "??1_Facet_base@std@@UEAA@XZ";
    case 0x00a3:
      return "??1_Init_locks@std@@QEAA@XZ";
    case 0x00a4:
      return "??1_Locimp@locale@std@@MEAA@XZ";
    case 0x00a5:
      return "??1_Locinfo@std@@QEAA@XZ";
    case 0x00a6:
      return "??1_Lockit@std@@QEAA@XZ";
    case 0x00a7:
      return "??1_Pad@std@@QEAA@XZ";
    case 0x00a8:
      return "??1_Timevec@std@@QEAA@XZ";
    case 0x00a9:
      return "??1_UShinit@std@@QEAA@XZ";
    case 0x00aa:
      return "??1_Winit@std@@QEAA@XZ";
    case 0x00ab:
      return "??1agent@Concurrency@@UEAA@XZ";
    case 0x00ac:
      return "??1codecvt_base@std@@UEAA@XZ";
    case 0x00ad:
      return "??1ctype_base@std@@UEAA@XZ";
    case 0x00ae:
      return "??1facet@locale@std@@MEAA@XZ";
    case 0x00af:
      return "??1ios_base@std@@UEAA@XZ";
    case 0x00b0:
      return "??1time_base@std@@UEAA@XZ";
    case 0x00b1:
      return "??4?$_Iosb@H@std@@QEAAAEAV01@AEBV01@@Z";
    case 0x00b2:
      return "??4?$_Yarn@D@std@@QEAAAEAV01@AEBV01@@Z";
    case 0x00b3:
      return "??4?$_Yarn@D@std@@QEAAAEAV01@PEBD@Z";
    case 0x00b4:
      return "??4?$_Yarn@_W@std@@QEAAAEAV01@PEB_W@Z";
    case 0x00b5:
      return "??4?$basic_iostream@DU?$char_traits@D@std@@@std@@IEAAAEAV01@$$"
             "QEAV01@@Z";
    case 0x00b6:
      return "??4?$basic_iostream@GU?$char_traits@G@std@@@std@@IEAAAEAV01@$$"
             "QEAV01@@Z";
    case 0x00b7:
      return "??4?$basic_iostream@_WU?$char_traits@_W@std@@@std@@IEAAAEAV01@$$"
             "QEAV01@@Z";
    case 0x00b8:
      return "??4?$basic_istream@DU?$char_traits@D@std@@@std@@IEAAAEAV01@$$"
             "QEAV01@@Z";
    case 0x00b9:
      return "??4?$basic_istream@GU?$char_traits@G@std@@@std@@IEAAAEAV01@$$"
             "QEAV01@@Z";
    case 0x00ba:
      return "??4?$basic_istream@_WU?$char_traits@_W@std@@@std@@IEAAAEAV01@$$"
             "QEAV01@@Z";
    case 0x00bb:
      return "??4?$basic_ostream@DU?$char_traits@D@std@@@std@@IEAAAEAV01@$$"
             "QEAV01@@Z";
    case 0x00bc:
      return "??4?$basic_ostream@GU?$char_traits@G@std@@@std@@IEAAAEAV01@$$"
             "QEAV01@@Z";
    case 0x00bd:
      return "??4?$basic_ostream@_WU?$char_traits@_W@std@@@std@@IEAAAEAV01@$$"
             "QEAV01@@Z";
    case 0x00be:
      return "??4?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAAEAV01@"
             "AEBV01@@Z";
    case 0x00bf:
      return "??4?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAAAEAV01@"
             "AEBV01@@Z";
    case 0x00c0:
      return "??4?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAAEAV01@"
             "AEBV01@@Z";
    case 0x00c1:
      return "??4Init@ios_base@std@@QEAAAEAV012@AEBV012@@Z";
    case 0x00c2:
      return "??4_Container_base0@std@@QEAAAEAU01@AEBU01@@Z";
    case 0x00c3:
      return "??4_Container_base12@std@@QEAAAEAU01@AEBU01@@Z";
    case 0x00c4:
      return "??4_Facet_base@std@@QEAAAEAV01@AEBV01@@Z";
    case 0x00c5:
      return "??4_Init_locks@std@@QEAAAEAV01@AEBV01@@Z";
    case 0x00c6:
      return "??4_Pad@std@@QEAAAEAV01@AEBV01@@Z";
    case 0x00c7:
      return "??4_Timevec@std@@QEAAAEAV01@AEBV01@@Z";
    case 0x00c8:
      return "??4_UShinit@std@@QEAAAEAV01@AEBV01@@Z";
    case 0x00c9:
      return "??4_Winit@std@@QEAAAEAV01@AEBV01@@Z";
    case 0x00ca:
      return "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAF@"
             "Z";
    case 0x00cb:
      return "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAG@"
             "Z";
    case 0x00cc:
      return "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAH@"
             "Z";
    case 0x00cd:
      return "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAI@"
             "Z";
    case 0x00ce:
      return "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAJ@"
             "Z";
    case 0x00cf:
      return "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAK@"
             "Z";
    case 0x00d0:
      return "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAM@"
             "Z";
    case 0x00d1:
      return "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAN@"
             "Z";
    case 0x00d2:
      return "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAO@"
             "Z";
    case 0x00d3:
      return "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@"
             "AEAPEAX@Z";
    case 0x00d4:
      return "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEA_J@"
             "Z";
    case 0x00d5:
      return "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEA_K@"
             "Z";
    case 0x00d6:
      return "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEA_N@"
             "Z";
    case 0x00d7:
      return "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@"
             "P6AAEAV01@AEAV01@@Z@Z";
    case 0x00d8:
      return "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@"
             "P6AAEAV?$basic_ios@DU?$char_traits@D@std@@@1@AEAV21@@Z@Z";
    case 0x00d9:
      return "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@"
             "P6AAEAVios_base@1@AEAV21@@Z@Z";
    case 0x00da:
      return "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@PEAV?$"
             "basic_streambuf@DU?$char_traits@D@std@@@1@@Z";
    case 0x00db:
      return "??5?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@AEAF@"
             "Z";
    case 0x00dc:
      return "??5?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@AEAG@"
             "Z";
    case 0x00dd:
      return "??5?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@AEAH@"
             "Z";
    case 0x00de:
      return "??5?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@AEAI@"
             "Z";
    case 0x00df:
      return "??5?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@AEAJ@"
             "Z";
    case 0x00e0:
      return "??5?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@AEAK@"
             "Z";
    case 0x00e1:
      return "??5?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@AEAM@"
             "Z";
    case 0x00e2:
      return "??5?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@AEAN@"
             "Z";
    case 0x00e3:
      return "??5?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@AEAO@"
             "Z";
    case 0x00e4:
      return "??5?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@"
             "AEAPEAX@Z";
    case 0x00e5:
      return "??5?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@AEA_J@"
             "Z";
    case 0x00e6:
      return "??5?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@AEA_K@"
             "Z";
    case 0x00e7:
      return "??5?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@AEA_N@"
             "Z";
    case 0x00e8:
      return "??5?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@"
             "P6AAEAV01@AEAV01@@Z@Z";
    case 0x00e9:
      return "??5?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@"
             "P6AAEAV?$basic_ios@GU?$char_traits@G@std@@@1@AEAV21@@Z@Z";
    case 0x00ea:
      return "??5?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@"
             "P6AAEAVios_base@1@AEAV21@@Z@Z";
    case 0x00eb:
      return "??5?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@PEAV?$"
             "basic_streambuf@GU?$char_traits@G@std@@@1@@Z";
    case 0x00ec:
      return "??5?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "AEAF@Z";
    case 0x00ed:
      return "??5?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "AEAG@Z";
    case 0x00ee:
      return "??5?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "AEAH@Z";
    case 0x00ef:
      return "??5?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "AEAI@Z";
    case 0x00f0:
      return "??5?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "AEAJ@Z";
    case 0x00f1:
      return "??5?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "AEAK@Z";
    case 0x00f2:
      return "??5?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "AEAM@Z";
    case 0x00f3:
      return "??5?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "AEAN@Z";
    case 0x00f4:
      return "??5?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "AEAO@Z";
    case 0x00f5:
      return "??5?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "AEAPEAX@Z";
    case 0x00f6:
      return "??5?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@AEA_"
             "J@Z";
    case 0x00f7:
      return "??5?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@AEA_"
             "K@Z";
    case 0x00f8:
      return "??5?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@AEA_"
             "N@Z";
    case 0x00f9:
      return "??5?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "P6AAEAV01@AEAV01@@Z@Z";
    case 0x00fa:
      return "??5?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "P6AAEAV?$basic_ios@_WU?$char_traits@_W@std@@@1@AEAV21@@Z@Z";
    case 0x00fb:
      return "??5?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "P6AAEAVios_base@1@AEAV21@@Z@Z";
    case 0x00fc:
      return "??5?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "PEAV?$basic_streambuf@_WU?$char_traits@_W@std@@@1@@Z";
    case 0x00fd:
      return "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@F@Z";
    case 0x00fe:
      return "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@G@Z";
    case 0x00ff:
      return "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@H@Z";
    case 0x0100:
      return "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@I@Z";
    case 0x0101:
      return "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@J@Z";
    case 0x0102:
      return "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@K@Z";
    case 0x0103:
      return "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@M@Z";
    case 0x0104:
      return "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@N@Z";
    case 0x0105:
      return "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@O@Z";
    case 0x0106:
      return "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@"
             "P6AAEAV01@AEAV01@@Z@Z";
    case 0x0107:
      return "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@"
             "P6AAEAV?$basic_ios@DU?$char_traits@D@std@@@1@AEAV21@@Z@Z";
    case 0x0108:
      return "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@"
             "P6AAEAVios_base@1@AEAV21@@Z@Z";
    case 0x0109:
      return "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@PEAV?$"
             "basic_streambuf@DU?$char_traits@D@std@@@1@@Z";
    case 0x010a:
      return "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@PEBX@"
             "Z";
    case 0x010b:
      return "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@_J@Z";
    case 0x010c:
      return "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@_K@Z";
    case 0x010d:
      return "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@_N@Z";
    case 0x010e:
      return "??6?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@F@Z";
    case 0x010f:
      return "??6?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@G@Z";
    case 0x0110:
      return "??6?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@H@Z";
    case 0x0111:
      return "??6?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@I@Z";
    case 0x0112:
      return "??6?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@J@Z";
    case 0x0113:
      return "??6?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@K@Z";
    case 0x0114:
      return "??6?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@M@Z";
    case 0x0115:
      return "??6?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@N@Z";
    case 0x0116:
      return "??6?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@O@Z";
    case 0x0117:
      return "??6?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@"
             "P6AAEAV01@AEAV01@@Z@Z";
    case 0x0118:
      return "??6?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@"
             "P6AAEAV?$basic_ios@GU?$char_traits@G@std@@@1@AEAV21@@Z@Z";
    case 0x0119:
      return "??6?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@"
             "P6AAEAVios_base@1@AEAV21@@Z@Z";
    case 0x011a:
      return "??6?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@PEAV?$"
             "basic_streambuf@GU?$char_traits@G@std@@@1@@Z";
    case 0x011b:
      return "??6?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@PEBX@"
             "Z";
    case 0x011c:
      return "??6?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@_J@Z";
    case 0x011d:
      return "??6?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@_K@Z";
    case 0x011e:
      return "??6?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV01@_N@Z";
    case 0x011f:
      return "??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@F@Z";
    case 0x0120:
      return "??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@G@Z";
    case 0x0121:
      return "??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@H@Z";
    case 0x0122:
      return "??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@I@Z";
    case 0x0123:
      return "??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@J@Z";
    case 0x0124:
      return "??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@K@Z";
    case 0x0125:
      return "??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@M@Z";
    case 0x0126:
      return "??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@N@Z";
    case 0x0127:
      return "??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@O@Z";
    case 0x0128:
      return "??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "P6AAEAV01@AEAV01@@Z@Z";
    case 0x0129:
      return "??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "P6AAEAV?$basic_ios@_WU?$char_traits@_W@std@@@1@AEAV21@@Z@Z";
    case 0x012a:
      return "??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "P6AAEAVios_base@1@AEAV21@@Z@Z";
    case 0x012b:
      return "??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "PEAV?$basic_streambuf@_WU?$char_traits@_W@std@@@1@@Z";
    case 0x012c:
      return "??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@"
             "PEBX@Z";
    case 0x012d:
      return "??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@_J@"
             "Z";
    case 0x012e:
      return "??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@_K@"
             "Z";
    case 0x012f:
      return "??6?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV01@_N@"
             "Z";
    case 0x0130:
      return "??7ios_base@std@@QEBA_NXZ";
    case 0x0131:
      return "??Bid@locale@std@@QEAA_KXZ";
    case 0x0132:
      return "??Bios_base@std@@QEBA_NXZ";
    case 0x0133:
      return "??_7?$basic_ios@DU?$char_traits@D@std@@@std@@6B@";
    case 0x0134:
      return "??_7?$basic_ios@GU?$char_traits@G@std@@@std@@6B@";
    case 0x0135:
      return "??_7?$basic_ios@_WU?$char_traits@_W@std@@@std@@6B@";
    case 0x0136:
      return "??_7?$basic_iostream@DU?$char_traits@D@std@@@std@@6B@";
    case 0x0137:
      return "??_7?$basic_iostream@GU?$char_traits@G@std@@@std@@6B@";
    case 0x0138:
      return "??_7?$basic_iostream@_WU?$char_traits@_W@std@@@std@@6B@";
    case 0x0139:
      return "??_7?$basic_istream@DU?$char_traits@D@std@@@std@@6B@";
    case 0x013a:
      return "??_7?$basic_istream@GU?$char_traits@G@std@@@std@@6B@";
    case 0x013b:
      return "??_7?$basic_istream@_WU?$char_traits@_W@std@@@std@@6B@";
    case 0x013c:
      return "??_7?$basic_ostream@DU?$char_traits@D@std@@@std@@6B@";
    case 0x013d:
      return "??_7?$basic_ostream@GU?$char_traits@G@std@@@std@@6B@";
    case 0x013e:
      return "??_7?$basic_ostream@_WU?$char_traits@_W@std@@@std@@6B@";
    case 0x013f:
      return "??_7?$basic_streambuf@DU?$char_traits@D@std@@@std@@6B@";
    case 0x0140:
      return "??_7?$basic_streambuf@GU?$char_traits@G@std@@@std@@6B@";
    case 0x0141:
      return "??_7?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@6B@";
    case 0x0142:
      return "??_7?$codecvt@DDH@std@@6B@";
    case 0x0143:
      return "??_7?$codecvt@GDH@std@@6B@";
    case 0x0144:
      return "??_7?$codecvt@_WDH@std@@6B@";
    case 0x0145:
      return "??_7?$ctype@D@std@@6B@";
    case 0x0146:
      return "??_7?$ctype@G@std@@6B@";
    case 0x0147:
      return "??_7?$ctype@_W@std@@6B@";
    case 0x0148:
      return "??_7?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@6B@";
    case 0x0149:
      return "??_7?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@6B@";
    case 0x014a:
      return "??_7?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@6B@";
    case 0x014b:
      return "??_7?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@6B@";
    case 0x014c:
      return "??_7?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@6B@";
    case 0x014d:
      return "??_7?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@6B@";
    case 0x014e:
      return "??_7?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@6B@";
    case 0x014f:
      return "??_7?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@6B@";
    case 0x0150:
      return "??_7?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@6B@";
    case 0x0151:
      return "??_7?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@6B@";
    case 0x0152:
      return "??_7?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@6B@";
    case 0x0153:
      return "??_7?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@6B@";
    case 0x0154:
      return "??_7_Facet_base@std@@6B@";
    case 0x0155:
      return "??_7_Locimp@locale@std@@6B@";
    case 0x0156:
      return "??_7_Pad@std@@6B@";
    case 0x0157:
      return "??_7codecvt_base@std@@6B@";
    case 0x0158:
      return "??_7ctype_base@std@@6B@";
    case 0x0159:
      return "??_7facet@locale@std@@6B@";
    case 0x015a:
      return "??_7ios_base@std@@6B@";
    case 0x015b:
      return "??_7time_base@std@@6B@";
    case 0x015c:
      return "??_8?$basic_iostream@DU?$char_traits@D@std@@@std@@7B?$basic_"
             "istream@DU?$char_traits@D@std@@@1@@";
    case 0x015d:
      return "??_8?$basic_iostream@DU?$char_traits@D@std@@@std@@7B?$basic_"
             "ostream@DU?$char_traits@D@std@@@1@@";
    case 0x015e:
      return "??_8?$basic_iostream@GU?$char_traits@G@std@@@std@@7B?$basic_"
             "istream@GU?$char_traits@G@std@@@1@@";
    case 0x015f:
      return "??_8?$basic_iostream@GU?$char_traits@G@std@@@std@@7B?$basic_"
             "ostream@GU?$char_traits@G@std@@@1@@";
    case 0x0160:
      return "??_8?$basic_iostream@_WU?$char_traits@_W@std@@@std@@7B?$basic_"
             "istream@_WU?$char_traits@_W@std@@@1@@";
    case 0x0161:
      return "??_8?$basic_iostream@_WU?$char_traits@_W@std@@@std@@7B?$basic_"
             "ostream@_WU?$char_traits@_W@std@@@1@@";
    case 0x0162:
      return "??_8?$basic_istream@DU?$char_traits@D@std@@@std@@7B@";
    case 0x0163:
      return "??_8?$basic_istream@GU?$char_traits@G@std@@@std@@7B@";
    case 0x0164:
      return "??_8?$basic_istream@_WU?$char_traits@_W@std@@@std@@7B@";
    case 0x0165:
      return "??_8?$basic_ostream@DU?$char_traits@D@std@@@std@@7B@";
    case 0x0166:
      return "??_8?$basic_ostream@GU?$char_traits@G@std@@@std@@7B@";
    case 0x0167:
      return "??_8?$basic_ostream@_WU?$char_traits@_W@std@@@std@@7B@";
    case 0x0168:
      return "??_D?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAAXXZ";
    case 0x0169:
      return "??_D?$basic_iostream@GU?$char_traits@G@std@@@std@@QEAAXXZ";
    case 0x016a:
      return "??_D?$basic_iostream@_WU?$char_traits@_W@std@@@std@@QEAAXXZ";
    case 0x016b:
      return "??_D?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAXXZ";
    case 0x016c:
      return "??_D?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAXXZ";
    case 0x016d:
      return "??_D?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAXXZ";
    case 0x016e:
      return "??_D?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ";
    case 0x016f:
      return "??_D?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAXXZ";
    case 0x0170:
      return "??_D?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAXXZ";
    case 0x0171:
      return "??_F?$codecvt@DDH@std@@QEAAXXZ";
    case 0x0172:
      return "??_F?$codecvt@GDH@std@@QEAAXXZ";
    case 0x0173:
      return "??_F?$codecvt@_WDH@std@@QEAAXXZ";
    case 0x0174:
      return "??_F?$ctype@D@std@@QEAAXXZ";
    case 0x0175:
      return "??_F?$ctype@G@std@@QEAAXXZ";
    case 0x0176:
      return "??_F?$ctype@_W@std@@QEAAXXZ";
    case 0x0177:
      return "??_F?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEAAXXZ";
    case 0x0178:
      return "??_F?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEAAXXZ";
    case 0x0179:
      return "??_F?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@QEAAXXZ";
    case 0x017a:
      return "??_F?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEAAXXZ";
    case 0x017b:
      return "??_F?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEAAXXZ";
    case 0x017c:
      return "??_F?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@QEAAXXZ";
    case 0x017d:
      return "??_F?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEAAXXZ";
    case 0x017e:
      return "??_F?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEAAXXZ";
    case 0x017f:
      return "??_F?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEAAXXZ";
    case 0x0180:
      return "??_F?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEAAXXZ";
    case 0x0181:
      return "??_F?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEAAXXZ";
    case 0x0182:
      return "??_F?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEAAXXZ";
    case 0x0183:
      return "??_F_Locinfo@std@@QEAAXXZ";
    case 0x0184:
      return "??_F_Timevec@std@@QEAAXXZ";
    case 0x0185:
      return "??_Fcodecvt_base@std@@QEAAXXZ";
    case 0x0186:
      return "??_Fctype_base@std@@QEAAXXZ";
    case 0x0187:
      return "??_Ffacet@locale@std@@QEAAXXZ";
    case 0x0188:
      return "??_Fid@locale@std@@QEAAXXZ";
    case 0x0189:
      return "??_Ftime_base@std@@QEAAXXZ";
    case 0x018a:
      return "?GetNextAsyncId@platform@details@Concurrency@@YAIXZ";
    case 0x018b:
      return "?NFS_Allocate@details@Concurrency@@YAPEAX_K0PEAX@Z";
    case 0x018c:
      return "?NFS_Free@details@Concurrency@@YAXPEAX@Z";
    case 0x018d:
      return "?NFS_GetLineSize@details@Concurrency@@YA_KXZ";
    case 0x018e:
      return "?_10@placeholders@std@@3V?$_Ph@$09@2@A";
    case 0x018f:
      return "?_11@placeholders@std@@3V?$_Ph@$0L@@2@A";
    case 0x0190:
      return "?_12@placeholders@std@@3V?$_Ph@$0M@@2@A";
    case 0x0191:
      return "?_13@placeholders@std@@3V?$_Ph@$0N@@2@A";
    case 0x0192:
      return "?_14@placeholders@std@@3V?$_Ph@$0O@@2@A";
    case 0x0193:
      return "?_15@placeholders@std@@3V?$_Ph@$0P@@2@A";
    case 0x0194:
      return "?_16@placeholders@std@@3V?$_Ph@$0BA@@2@A";
    case 0x0195:
      return "?_17@placeholders@std@@3V?$_Ph@$0BB@@2@A";
    case 0x0196:
      return "?_18@placeholders@std@@3V?$_Ph@$0BC@@2@A";
    case 0x0197:
      return "?_19@placeholders@std@@3V?$_Ph@$0BD@@2@A";
    case 0x0198:
      return "?_1@placeholders@std@@3V?$_Ph@$00@2@A";
    case 0x0199:
      return "?_20@placeholders@std@@3V?$_Ph@$0BE@@2@A";
    case 0x019a:
      return "?_2@placeholders@std@@3V?$_Ph@$01@2@A";
    case 0x019b:
      return "?_3@placeholders@std@@3V?$_Ph@$02@2@A";
    case 0x019c:
      return "?_4@placeholders@std@@3V?$_Ph@$03@2@A";
    case 0x019d:
      return "?_5@placeholders@std@@3V?$_Ph@$04@2@A";
    case 0x019e:
      return "?_6@placeholders@std@@3V?$_Ph@$05@2@A";
    case 0x019f:
      return "?_7@placeholders@std@@3V?$_Ph@$06@2@A";
    case 0x01a0:
      return "?_8@placeholders@std@@3V?$_Ph@$07@2@A";
    case 0x01a1:
      return "?_9@placeholders@std@@3V?$_Ph@$08@2@A";
    case 0x01a2:
      return "?_Addcats@_Locinfo@std@@QEAAAEAV12@HPEBD@Z";
    case 0x01a3:
      return "?_Addfac@_Locimp@locale@std@@AEAAXPEAVfacet@23@_K@Z";
    case 0x01a4:
      return "?_Addstd@ios_base@std@@SAXPEAV12@@Z";
    case 0x01a5:
      return "?_Advance@_Concurrent_queue_iterator_base_v4@details@Concurrency@"
             "@IEAAXXZ";
    case 0x01a6:
      return "?_Assign@_Concurrent_queue_iterator_base_v4@details@Concurrency@@"
             "IEAAXAEBV123@@Z";
    case 0x01a7:
      return "?_Atexit@@YAXP6AXXZ@Z";
    case 0x01a8:
      return "?_BADOFF@std@@3_JB";
    case 0x01a9:
      return "?_Byte_reverse_table@details@Concurrency@@3QBEB";
    case 0x01aa:
      return "?_C_str@?$_Yarn@D@std@@QEBAPEBDXZ";
    case 0x01ab:
      return "?_C_str@?$_Yarn@_W@std@@QEBAPEB_WXZ";
    case 0x01ac:
      return "?_Callfns@ios_base@std@@AEAAXW4event@12@@Z";
    case 0x01ad:
      return "?_Clocptr@_Locimp@locale@std@@0PEAV123@EA";
    case 0x01ae:
      return "?_Close_dir@sys@tr2@std@@YAXPEAX@Z";
    case 0x01af:
      return "?_Copy_file@sys@tr2@std@@YAHPEBD0_N@Z";
    case 0x01b0:
      return "?_Copy_file@sys@tr2@std@@YAHPEB_W0_N@Z";
    case 0x01b1:
      return "?_Current_get@sys@tr2@std@@YAPEADAEAY0BAE@D@Z";
    case 0x01b2:
      return "?_Current_get@sys@tr2@std@@YAPEA_WAEAY0BAE@_W@Z";
    case 0x01b3:
      return "?_Current_set@sys@tr2@std@@YA_NPEBD@Z";
    case 0x01b4:
      return "?_Current_set@sys@tr2@std@@YA_NPEB_W@Z";
    case 0x01b5:
      return "?_Decref@facet@locale@std@@UEAAPEAV_Facet_base@3@XZ";
    case 0x01b6:
      return "?_Donarrow@?$ctype@G@std@@IEBADGD@Z";
    case 0x01b7:
      return "?_Donarrow@?$ctype@_W@std@@IEBAD_WD@Z";
    case 0x01b8:
      return "?_Dowiden@?$ctype@G@std@@IEBAGD@Z";
    case 0x01b9:
      return "?_Dowiden@?$ctype@_W@std@@IEBA_WD@Z";
    case 0x01ba:
      return "?_Empty@?$_Yarn@D@std@@QEBA_NXZ";
    case 0x01bb:
      return "?_Empty@?$_Yarn@_W@std@@QEBA_NXZ";
    case 0x01bc:
      return "?_Equivalent@sys@tr2@std@@YAHPEBD0@Z";
    case 0x01bd:
      return "?_Equivalent@sys@tr2@std@@YAHPEB_W0@Z";
    case 0x01be:
      return "?_Ffmt@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@AEBAPEADPEADDH@Z";
    case 0x01bf:
      return "?_Ffmt@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@AEBAPEADPEADDH@Z";
    case 0x01c0:
      return "?_Ffmt@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@AEBAPEADPEADDH@Z";
    case 0x01c1:
      return "?_File_size@sys@tr2@std@@YA_KPEBD@Z";
    case 0x01c2:
      return "?_File_size@sys@tr2@std@@YA_KPEB_W@Z";
    case 0x01c3:
      return "?_Findarr@ios_base@std@@AEAAAEAU_Iosarray@12@H@Z";
    case 0x01c4:
      return "?_Fiopen@std@@YAPEAU_iobuf@@PEBDHH@Z";
    case 0x01c5:
      return "?_Fiopen@std@@YAPEAU_iobuf@@PEBGHH@Z";
    case 0x01c6:
      return "?_Fiopen@std@@YAPEAU_iobuf@@PEB_WHH@Z";
    case 0x01c7:
      return "?_Fput@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@AEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DPEBD_K333@Z";
    case 0x01c8:
      return "?_Fput@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@AEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GPEBD_K333@Z";
    case 0x01c9:
      return "?_Fput@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@AEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_WPEBD_K444@Z";
    case 0x01ca:
      return "?_Future_error_map@std@@YAPEBDH@Z";
    case 0x01cb:
      return "?_GetCombinableSize@details@Concurrency@@YA_KXZ";
    case 0x01cc:
      return "?_Getcat@?$codecvt@DDH@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01cd:
      return "?_Getcat@?$codecvt@GDH@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01ce:
      return "?_Getcat@?$codecvt@_WDH@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01cf:
      return "?_Getcat@?$ctype@D@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01d0:
      return "?_Getcat@?$ctype@G@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01d1:
      return "?_Getcat@?$ctype@_W@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01d2:
      return "?_Getcat@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@"
             "@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01d3:
      return "?_Getcat@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@"
             "@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01d4:
      return "?_Getcat@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01d5:
      return "?_Getcat@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@"
             "@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01d6:
      return "?_Getcat@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@"
             "@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01d7:
      return "?_Getcat@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01d8:
      return "?_Getcat@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01d9:
      return "?_Getcat@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01da:
      return "?_Getcat@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01db:
      return "?_Getcat@?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01dc:
      return "?_Getcat@?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01dd:
      return "?_Getcat@?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01de:
      return "?_Getcat@facet@locale@std@@SA_KPEAPEBV123@PEBV23@@Z";
    case 0x01df:
      return "?_Getcoll@_Locinfo@std@@QEBA?AU_Collvec@@XZ";
    case 0x01e0:
      return "?_Getctype@_Locinfo@std@@QEBA?AU_Ctypevec@@XZ";
    case 0x01e1:
      return "?_Getcvt@_Locinfo@std@@QEBA?AU_Cvtvec@@XZ";
    case 0x01e2:
      return "?_Getdateorder@_Locinfo@std@@QEBAHXZ";
    case 0x01e3:
      return "?_Getdays@_Locinfo@std@@QEBAPEBDXZ";
    case 0x01e4:
      return "?_Getfalse@_Locinfo@std@@QEBAPEBDXZ";
    case 0x01e5:
      return "?_Getffld@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@2@1AEAVios_base@2@PEAH@Z";
    case 0x01e6:
      return "?_Getffld@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@2@1AEAVios_base@2@PEAH@Z";
    case 0x01e7:
      return "?_Getffld@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@2@1AEAVios_base@2@PEAH@Z";
    case 0x01e8:
      return "?_Getffldx@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@2@1AEAVios_base@2@PEAH@Z";
    case 0x01e9:
      return "?_Getffldx@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@2@1AEAVios_base@2@PEAH@Z";
    case 0x01ea:
      return "?_Getffldx@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@2@1AEAVios_base@2@PEAH@Z";
    case 0x01eb:
      return "?_Getfmt@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@IEBA?AV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@PEBD@Z";
    case 0x01ec:
      return "?_Getfmt@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@IEBA?AV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@PEBD@Z";
    case 0x01ed:
      return "?_Getfmt@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@IEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@PEBD@Z";
    case 0x01ee:
      return "?_Getgloballocale@locale@std@@CAPEAV_Locimp@12@XZ";
    case 0x01ef:
      return "?_Getifld@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@2@1HAEBVlocale@2@@Z";
    case 0x01f0:
      return "?_Getifld@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@2@1HAEBVlocale@2@@Z";
    case 0x01f1:
      return "?_Getifld@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@2@1HAEBVlocale@2@@Z";
    case 0x01f2:
      return "?_Getint@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@AEBAHAEAV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@2@0HHAEAHAEBV?$ctype@D@2@@Z";
    case 0x01f3:
      return "?_Getint@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@AEBAHAEAV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@2@0HHAEAHAEBV?$ctype@G@2@@Z";
    case 0x01f4:
      return "?_Getint@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@AEBAHAEAV?$istreambuf_iterator@_WU?$char_traits@"
             "_W@std@@@2@0HHAEAHAEBV?$ctype@_W@2@@Z";
    case 0x01f5:
      return "?_Getlconv@_Locinfo@std@@QEBAPEBUlconv@@XZ";
    case 0x01f6:
      return "?_Getmonths@_Locinfo@std@@QEBAPEBDXZ";
    case 0x01f7:
      return "?_Getname@_Locinfo@std@@QEBAPEBDXZ";
    case 0x01f8:
      return "?_Getpfirst@_Container_base12@std@@QEBAPEAPEAU_Iterator_base12@2@"
             "XZ";
    case 0x01f9:
      return "?_Getptr@_Timevec@std@@QEBAPEAXXZ";
    case 0x01fa:
      return "?_Gettnames@_Locinfo@std@@QEBA?AV_Timevec@2@XZ";
    case 0x01fb:
      return "?_Gettrue@_Locinfo@std@@QEBAPEBDXZ";
    case 0x01fc:
      return "?_Gnavail@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBA_"
             "JXZ";
    case 0x01fd:
      return "?_Gnavail@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEBA_"
             "JXZ";
    case 0x01fe:
      return "?_Gnavail@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEBA_"
             "JXZ";
    case 0x01ff:
      return "?_Gndec@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "IEAAPEADXZ";
    case 0x0200:
      return "?_Gndec@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "IEAAPEAGXZ";
    case 0x0201:
      return "?_Gndec@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAPEA_"
             "WXZ";
    case 0x0202:
      return "?_Gninc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "IEAAPEADXZ";
    case 0x0203:
      return "?_Gninc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "IEAAPEAGXZ";
    case 0x0204:
      return "?_Gninc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAPEA_"
             "WXZ";
    case 0x0205:
      return "?_Gnpreinc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "IEAAPEADXZ";
    case 0x0206:
      return "?_Gnpreinc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "IEAAPEAGXZ";
    case 0x0207:
      return "?_Gnpreinc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "IEAAPEA_WXZ";
    case 0x0208:
      return "?_Id_cnt@id@locale@std@@0HA";
    case 0x0209:
      return "?_Ifmt@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@AEBAPEADPEADPEBDH@Z";
    case 0x020a:
      return "?_Ifmt@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@AEBAPEADPEADPEBDH@Z";
    case 0x020b:
      return "?_Ifmt@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@AEBAPEADPEADPEBDH@Z";
    case 0x020c:
      return "?_Incref@facet@locale@std@@UEAAXXZ";
    case 0x020d:
      return "?_Index@ios_base@std@@0HA";
    case 0x020e:
      return "?_Init@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "IEAAXPEAPEAD0PEAH001@Z";
    case 0x020f:
      return "?_Init@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXXZ";
    case 0x0210:
      return "?_Init@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "IEAAXPEAPEAG0PEAH001@Z";
    case 0x0211:
      return "?_Init@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAAXXZ";
    case 0x0212:
      return "?_Init@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "IEAAXPEAPEA_W0PEAH001@Z";
    case 0x0213:
      return "?_Init@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAXXZ";
    case 0x0214:
      return "?_Init@?$codecvt@DDH@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0215:
      return "?_Init@?$codecvt@GDH@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0216:
      return "?_Init@?$codecvt@_WDH@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0217:
      return "?_Init@?$ctype@D@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0218:
      return "?_Init@?$ctype@G@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0219:
      return "?_Init@?$ctype@_W@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x021a:
      return "?_Init@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x021b:
      return "?_Init@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x021c:
      return "?_Init@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x021d:
      return "?_Init@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x021e:
      return "?_Init@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x021f:
      return "?_Init@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0220:
      return "?_Init@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0221:
      return "?_Init@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0222:
      return "?_Init@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0223:
      return "?_Init@?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0224:
      return "?_Init@?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0225:
      return "?_Init@?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0226:
      return "?_Init@ios_base@std@@IEAAXXZ";
    case 0x0227:
      return "?_Init@locale@std@@CAPEAV_Locimp@12@_N@Z";
    case 0x0228:
      return "?_Init_cnt@Init@ios_base@std@@0HA";
    case 0x0229:
      return "?_Init_cnt@_UShinit@std@@0HA";
    case 0x022a:
      return "?_Init_cnt@_Winit@std@@0HA";
    case 0x022b:
      return "?_Init_cnt_func@Init@ios_base@std@@CAAEAHXZ";
    case 0x022c:
      return "?_Init_ctor@Init@ios_base@std@@CAXPEAV123@@Z";
    case 0x022d:
      return "?_Init_dtor@Init@ios_base@std@@CAXPEAV123@@Z";
    case 0x022e:
      return "?_Init_locks_ctor@_Init_locks@std@@CAXPEAV12@@Z";
    case 0x022f:
      return "?_Init_locks_dtor@_Init_locks@std@@CAXPEAV12@@Z";
    case 0x0230:
      return "?_Internal_assign@_Concurrent_vector_base_v4@details@Concurrency@"
             "@IEAAXAEBV123@_KP6AXPEAX1@ZP6AX2PEBX1@Z5@Z";
    case 0x0231:
      return "?_Internal_capacity@_Concurrent_vector_base_v4@details@"
             "Concurrency@@IEBA_KXZ";
    case 0x0232:
      return "?_Internal_clear@_Concurrent_vector_base_v4@details@Concurrency@@"
             "IEAA_KP6AXPEAX_K@Z@Z";
    case 0x0233:
      return "?_Internal_compact@_Concurrent_vector_base_v4@details@"
             "Concurrency@@IEAAPEAX_KPEAXP6AX10@ZP6AX1PEBX0@Z@Z";
    case 0x0234:
      return "?_Internal_copy@_Concurrent_vector_base_v4@details@Concurrency@@"
             "IEAAXAEBV123@_KP6AXPEAXPEBX1@Z@Z";
    case 0x0235:
      return "?_Internal_empty@_Concurrent_queue_base_v4@details@Concurrency@@"
             "IEBA_NXZ";
    case 0x0236:
      return "?_Internal_finish_clear@_Concurrent_queue_base_v4@details@"
             "Concurrency@@IEAAXXZ";
    case 0x0237:
      return "?_Internal_grow_by@_Concurrent_vector_base_v4@details@"
             "Concurrency@@IEAA_K_K0P6AXPEAXPEBX0@Z2@Z";
    case 0x0238:
      return "?_Internal_grow_to_at_least_with_result@_Concurrent_vector_base_"
             "v4@details@Concurrency@@IEAA_K_K0P6AXPEAXPEBX0@Z2@Z";
    case 0x0239:
      return "?_Internal_move_push@_Concurrent_queue_base_v4@details@"
             "Concurrency@@IEAAXPEAX@Z";
    case 0x023a:
      return "?_Internal_pop_if_present@_Concurrent_queue_base_v4@details@"
             "Concurrency@@IEAA_NPEAX@Z";
    case 0x023b:
      return "?_Internal_push@_Concurrent_queue_base_v4@details@Concurrency@@"
             "IEAAXPEBX@Z";
    case 0x023c:
      return "?_Internal_push_back@_Concurrent_vector_base_v4@details@"
             "Concurrency@@IEAAPEAX_KAEA_K@Z";
    case 0x023d:
      return "?_Internal_reserve@_Concurrent_vector_base_v4@details@"
             "Concurrency@@IEAAX_K00@Z";
    case 0x023e:
      return "?_Internal_resize@_Concurrent_vector_base_v4@details@Concurrency@"
             "@IEAAX_K00P6AXPEAX0@ZP6AX1PEBX0@Z3@Z";
    case 0x023f:
      return "?_Internal_size@_Concurrent_queue_base_v4@details@Concurrency@@"
             "IEBA_KXZ";
    case 0x0240:
      return "?_Internal_swap@_Concurrent_queue_base_v4@details@Concurrency@@"
             "IEAAXAEAV123@@Z";
    case 0x0241:
      return "?_Internal_swap@_Concurrent_vector_base_v4@details@Concurrency@@"
             "IEAAXAEAV123@@Z";
    case 0x0242:
      return "?_Internal_throw_exception@_Concurrent_queue_base_v4@details@"
             "Concurrency@@IEBAXXZ";
    case 0x0243:
      return "?_Internal_throw_exception@_Concurrent_vector_base_v4@details@"
             "Concurrency@@IEBAX_K@Z";
    case 0x0244:
      return "?_Ios_base_dtor@ios_base@std@@CAXPEAV12@@Z";
    case 0x0245:
      return "?_Ipfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA_N_N@Z";
    case 0x0246:
      return "?_Ipfx@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAA_N_N@Z";
    case 0x0247:
      return "?_Ipfx@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAA_N_N@Z";
    case 0x0248:
      return "?_Iput@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@AEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DPEAD_K@Z";
    case 0x0249:
      return "?_Iput@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@AEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GPEAD_K@Z";
    case 0x024a:
      return "?_Iput@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@AEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_WPEAD_K@Z";
    case 0x024b:
      return "?_Last_write_time@sys@tr2@std@@YAXPEBD_J@Z";
    case 0x024c:
      return "?_Last_write_time@sys@tr2@std@@YAXPEB_W_J@Z";
    case 0x024d:
      return "?_Last_write_time@sys@tr2@std@@YA_JPEBD@Z";
    case 0x024e:
      return "?_Last_write_time@sys@tr2@std@@YA_JPEB_W@Z";
    case 0x024f:
      return "?_Launch@_Pad@std@@QEAAXPEAU_Thrd_imp_t@@@Z";
    case 0x0250:
      return "?_Link@sys@tr2@std@@YAHPEBD0@Z";
    case 0x0251:
      return "?_Link@sys@tr2@std@@YAHPEB_W0@Z";
    case 0x0252:
      return "?_Locimp_Addfac@_Locimp@locale@std@@CAXPEAV123@PEAVfacet@23@_K@Z";
    case 0x0253:
      return "?_Locimp_ctor@_Locimp@locale@std@@CAXPEAV123@AEBV123@@Z";
    case 0x0254:
      return "?_Locimp_dtor@_Locimp@locale@std@@CAXPEAV123@@Z";
    case 0x0255:
      return "?_Locinfo_Addcats@_Locinfo@std@@SAAEAV12@PEAV12@HPEBD@Z";
    case 0x0256:
      return "?_Locinfo_ctor@_Locinfo@std@@SAXPEAV12@HPEBD@Z";
    case 0x0257:
      return "?_Locinfo_ctor@_Locinfo@std@@SAXPEAV12@PEBD@Z";
    case 0x0258:
      return "?_Locinfo_dtor@_Locinfo@std@@SAXPEAV12@@Z";
    case 0x0259:
      return "?_Lock@?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAAXXZ";
    case 0x025a:
      return "?_Lock@?$basic_streambuf@GU?$char_traits@G@std@@@std@@UEAAXXZ";
    case 0x025b:
      return "?_Lock@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@UEAAXXZ";
    case 0x025c:
      return "?_Lockit_ctor@_Lockit@std@@CAXPEAV12@@Z";
    case 0x025d:
      return "?_Lockit_ctor@_Lockit@std@@CAXPEAV12@H@Z";
    case 0x025e:
      return "?_Lockit_ctor@_Lockit@std@@SAXH@Z";
    case 0x025f:
      return "?_Lockit_dtor@_Lockit@std@@CAXPEAV12@@Z";
    case 0x0260:
      return "?_Lockit_dtor@_Lockit@std@@SAXH@Z";
    case 0x0261:
      return "?_Lstat@sys@tr2@std@@YA?AW4file_type@123@PEBDAEAH@Z";
    case 0x0262:
      return "?_Lstat@sys@tr2@std@@YA?AW4file_type@123@PEB_WAEAH@Z";
    case 0x0263:
      return "?_MP_Add@std@@YAXQEA_K_K@Z";
    case 0x0264:
      return "?_MP_Get@std@@YA_KQEA_K@Z";
    case 0x0265:
      return "?_MP_Mul@std@@YAXQEA_K_K1@Z";
    case 0x0266:
      return "?_MP_Rem@std@@YAXQEA_K_K@Z";
    case 0x0267:
      return "?_Make_dir@sys@tr2@std@@YAHPEBD@Z";
    case 0x0268:
      return "?_Make_dir@sys@tr2@std@@YAHPEB_W@Z";
    case 0x0269:
      return "?_Makeloc@_Locimp@locale@std@@CAPEAV123@AEBV_Locinfo@3@HPEAV123@"
             "PEBV23@@Z";
    case 0x026a:
      return "?_Makeushloc@_Locimp@locale@std@@CAXAEBV_Locinfo@3@HPEAV123@"
             "PEBV23@@Z";
    case 0x026b:
      return "?_Makewloc@_Locimp@locale@std@@CAXAEBV_Locinfo@3@HPEAV123@PEBV23@"
             "@Z";
    case 0x026c:
      return "?_Makexloc@_Locimp@locale@std@@CAXAEBV_Locinfo@3@HPEAV123@PEBV23@"
             "@Z";
    case 0x026d:
      return "?_Mtx_delete@threads@stdext@@YAXPEAX@Z";
    case 0x026e:
      return "?_Mtx_lock@threads@stdext@@YAXPEAX@Z";
    case 0x026f:
      return "?_Mtx_new@threads@stdext@@YAXAEAPEAX@Z";
    case 0x0270:
      return "?_Mtx_unlock@threads@stdext@@YAXPEAX@Z";
    case 0x0271:
      return "?_New_Locimp@_Locimp@locale@std@@CAPEAV123@AEBV123@@Z";
    case 0x0272:
      return "?_New_Locimp@_Locimp@locale@std@@CAPEAV123@_N@Z";
    case 0x0273:
      return "?_Open_dir@sys@tr2@std@@YAPEAXAEAY0BAE@DPEBDAEAHAEAW4file_type@"
             "123@@Z";
    case 0x0274:
      return "?_Open_dir@sys@tr2@std@@YAPEAXAEAY0BAE@_WPEB_WAEAHAEAW4file_type@"
             "123@@Z";
    case 0x0275:
      return "?_Orphan_all@_Container_base0@std@@QEAAXXZ";
    case 0x0276:
      return "?_Orphan_all@_Container_base12@std@@QEAAXXZ";
    case 0x0277:
      return "?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ";
    case 0x0278:
      return "?_Osfx@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAXXZ";
    case 0x0279:
      return "?_Osfx@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAXXZ";
    case 0x027a:
      return "?_Pnavail@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBA_"
             "JXZ";
    case 0x027b:
      return "?_Pnavail@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEBA_"
             "JXZ";
    case 0x027c:
      return "?_Pnavail@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEBA_"
             "JXZ";
    case 0x027d:
      return "?_Pninc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "IEAAPEADXZ";
    case 0x027e:
      return "?_Pninc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "IEAAPEAGXZ";
    case 0x027f:
      return "?_Pninc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAPEA_"
             "WXZ";
    case 0x0280:
      return "?_Ptr_cerr@std@@3PEAV?$basic_ostream@DU?$char_traits@D@std@@@1@"
             "EA";
    case 0x0281:
      return "?_Ptr_cin@std@@3PEAV?$basic_istream@DU?$char_traits@D@std@@@1@EA";
    case 0x0282:
      return "?_Ptr_clog@std@@3PEAV?$basic_ostream@DU?$char_traits@D@std@@@1@"
             "EA";
    case 0x0283:
      return "?_Ptr_cout@std@@3PEAV?$basic_ostream@DU?$char_traits@D@std@@@1@"
             "EA";
    case 0x0284:
      return "?_Ptr_wcerr@std@@3PEAV?$basic_ostream@GU?$char_traits@G@std@@@1@"
             "EA";
    case 0x0285:
      return "?_Ptr_wcerr@std@@3PEAV?$basic_ostream@_WU?$char_traits@_W@std@@@"
             "1@EA";
    case 0x0286:
      return "?_Ptr_wcin@std@@3PEAV?$basic_istream@GU?$char_traits@G@std@@@1@"
             "EA";
    case 0x0287:
      return "?_Ptr_wcin@std@@3PEAV?$basic_istream@_WU?$char_traits@_W@std@@@1@"
             "EA";
    case 0x0288:
      return "?_Ptr_wclog@std@@3PEAV?$basic_ostream@GU?$char_traits@G@std@@@1@"
             "EA";
    case 0x0289:
      return "?_Ptr_wclog@std@@3PEAV?$basic_ostream@_WU?$char_traits@_W@std@@@"
             "1@EA";
    case 0x028a:
      return "?_Ptr_wcout@std@@3PEAV?$basic_ostream@GU?$char_traits@G@std@@@1@"
             "EA";
    case 0x028b:
      return "?_Ptr_wcout@std@@3PEAV?$basic_ostream@_WU?$char_traits@_W@std@@@"
             "1@EA";
    case 0x028c:
      return "?_Put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@AEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@PEBD_K@Z";
    case 0x028d:
      return "?_Put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@AEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@PEBG_K@Z";
    case 0x028e:
      return "?_Put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@std@@@std@@AEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@2@V32@PEB_W_K@Z";
    case 0x028f:
      return "?_Raise_handler@std@@3P6AXAEBVexception@stdext@@@ZEA";
    case 0x0290:
      return "?_Random_device@std@@YAIXZ";
    case 0x0291:
      return "?_Read_dir@sys@tr2@std@@YAPEADAEAY0BAE@DPEAXAEAW4file_type@123@@"
             "Z";
    case 0x0292:
      return "?_Read_dir@sys@tr2@std@@YAPEA_WAEAY0BAE@_WPEAXAEAW4file_type@123@"
             "@Z";
    case 0x0293:
      return "?_Release@_Pad@std@@QEAAXXZ";
    case 0x0294:
      return "?_Remove_dir@sys@tr2@std@@YA_NPEBD@Z";
    case 0x0295:
      return "?_Remove_dir@sys@tr2@std@@YA_NPEB_W@Z";
    case 0x0296:
      return "?_Rename@sys@tr2@std@@YAHPEBD0@Z";
    case 0x0297:
      return "?_Rename@sys@tr2@std@@YAHPEB_W0@Z";
    case 0x0298:
      return "?_Rep@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@AEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@D_K@Z";
    case 0x0299:
      return "?_Rep@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@AEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@G_K@Z";
    case 0x029a:
      return "?_Rep@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@std@@@std@@AEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@2@V32@_W_K@Z";
    case 0x029b:
      return "?_Rethrow_future_exception@std@@YAXVexception_ptr@1@@Z";
    case 0x029c:
      return "?_Rng_abort@std@@YAXPEBD@Z";
    case 0x029d:
      return "?_Segment_index_of@_Concurrent_vector_base_v4@details@"
             "Concurrency@@KA_K_K@Z";
    case 0x029e:
      return "?_Setgloballocale@locale@std@@CAXPEAX@Z";
    case 0x029f:
      return "?_Src@?1??_Getffldx@?$num_get@DV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@DU?$"
             "char_traits@D@std@@@3@1AEAVios_base@3@PEAH@Z@4QBDB";
    case 0x02a0:
      return "?_Src@?1??_Getffldx@?$num_get@GV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@GU?$"
             "char_traits@G@std@@@3@1AEAVios_base@3@PEAH@Z@4QBDB";
    case 0x02a1:
      return "?_Src@?1??_Getffldx@?$num_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@_"
             "WU?$char_traits@_W@std@@@3@1AEAVios_base@3@PEAH@Z@4QBDB";
    case 0x02a2:
      return "?_Src@?1??_Getifld@?$num_get@DV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@DU?$"
             "char_traits@D@std@@@3@1HAEBVlocale@3@@Z@4QBDB";
    case 0x02a3:
      return "?_Src@?1??_Getifld@?$num_get@GV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@GU?$"
             "char_traits@G@std@@@3@1HAEBVlocale@3@@Z@4QBDB";
    case 0x02a4:
      return "?_Src@?1??_Getifld@?$num_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@_"
             "WU?$char_traits@_W@std@@@3@1HAEBVlocale@3@@Z@4QBDB";
    case 0x02a5:
      return "?_Src@?3??_Getffld@?$num_get@DV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@DU?$"
             "char_traits@D@std@@@3@1AEAVios_base@3@PEAH@Z@4QBDB";
    case 0x02a6:
      return "?_Src@?3??_Getffld@?$num_get@GV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@GU?$"
             "char_traits@G@std@@@3@1AEAVios_base@3@PEAH@Z@4QBDB";
    case 0x02a7:
      return "?_Src@?3??_Getffld@?$num_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@_"
             "WU?$char_traits@_W@std@@@3@1AEAVios_base@3@PEAH@Z@4QBDB";
    case 0x02a8:
      return "?_Stat@sys@tr2@std@@YA?AW4file_type@123@PEBDAEAH@Z";
    case 0x02a9:
      return "?_Stat@sys@tr2@std@@YA?AW4file_type@123@PEB_WAEAH@Z";
    case 0x02aa:
      return "?_Statvfs@sys@tr2@std@@YA?AUspace_info@123@PEBD@Z";
    case 0x02ab:
      return "?_Statvfs@sys@tr2@std@@YA?AUspace_info@123@PEB_W@Z";
    case 0x02ac:
      return "?_Swap_all@_Container_base0@std@@QEAAXAEAU12@@Z";
    case 0x02ad:
      return "?_Swap_all@_Container_base12@std@@QEAAXAEAU12@@Z";
    case 0x02ae:
      return "?_Symlink@sys@tr2@std@@YAHPEBD0@Z";
    case 0x02af:
      return "?_Symlink@sys@tr2@std@@YAHPEB_W0@Z";
    case 0x02b0:
      return "?_Sync@ios_base@std@@0_NA";
    case 0x02b1:
      return "?_Syserror_map@std@@YAPEBDH@Z";
    case 0x02b2:
      return "?_Throw_C_error@std@@YAXH@Z";
    case 0x02b3:
      return "?_Throw_Cpp_error@std@@YAXH@Z";
    case 0x02b4:
      return "?_Throw_future_error@std@@YAXAEBVerror_code@1@@Z";
    case 0x02b5:
      return "?_Throw_lock_error@threads@stdext@@YAXXZ";
    case 0x02b6:
      return "?_Throw_resource_error@threads@stdext@@YAXXZ";
    case 0x02b7:
      return "?_Tidy@?$_Yarn@D@std@@AEAAXXZ";
    case 0x02b8:
      return "?_Tidy@?$_Yarn@_W@std@@AEAAXXZ";
    case 0x02b9:
      return "?_Tidy@?$ctype@D@std@@IEAAXXZ";
    case 0x02ba:
      return "?_Tidy@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@AEAAXXZ";
    case 0x02bb:
      return "?_Tidy@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@AEAAXXZ";
    case 0x02bc:
      return "?_Tidy@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@AEAAXXZ";
    case 0x02bd:
      return "?_Tidy@ios_base@std@@AEAAXXZ";
    case 0x02be:
      return "?_Unlink@sys@tr2@std@@YAHPEBD@Z";
    case 0x02bf:
      return "?_Unlink@sys@tr2@std@@YAHPEB_W@Z";
    case 0x02c0:
      return "?_Unlock@?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAAXXZ";
    case 0x02c1:
      return "?_Unlock@?$basic_streambuf@GU?$char_traits@G@std@@@std@@UEAAXXZ";
    case 0x02c2:
      return "?_Unlock@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "UEAAXXZ";
    case 0x02c3:
      return "?_W_Getdays@_Locinfo@std@@QEBAPEBGXZ";
    case 0x02c4:
      return "?_W_Getmonths@_Locinfo@std@@QEBAPEBGXZ";
    case 0x02c5:
      return "?_W_Gettnames@_Locinfo@std@@QEBA?AV_Timevec@2@XZ";
    case 0x02c6:
      return "?_Winerror_map@std@@YAPEBDH@Z";
    case 0x02c7:
      return "?_XLgamma@std@@YAMM@Z";
    case 0x02c8:
      return "?_XLgamma@std@@YANN@Z";
    case 0x02c9:
      return "?_XLgamma@std@@YAOO@Z";
    case 0x02ca:
      return "?_Xbad_alloc@std@@YAXXZ";
    case 0x02cb:
      return "?_Xbad_function_call@std@@YAXXZ";
    case 0x02cc:
      return "?_Xinvalid_argument@std@@YAXPEBD@Z";
    case 0x02cd:
      return "?_Xlength_error@std@@YAXPEBD@Z";
    case 0x02ce:
      return "?_Xout_of_range@std@@YAXPEBD@Z";
    case 0x02cf:
      return "?_Xoverflow_error@std@@YAXPEBD@Z";
    case 0x02d0:
      return "?_Xregex_error@std@@YAXW4error_type@regex_constants@1@@Z";
    case 0x02d1:
      return "?_Xruntime_error@std@@YAXPEBD@Z";
    case 0x02d2:
      return "?adopt_lock@std@@3Uadopt_lock_t@1@B";
    case 0x02d3:
      return "?always_noconv@codecvt_base@std@@QEBA_NXZ";
    case 0x02d4:
      return "?bad@ios_base@std@@QEBA_NXZ";
    case 0x02d5:
      return "?c_str@?$_Yarn@D@std@@QEBAPEBDXZ";
    case 0x02d6:
      return "?cancel@agent@Concurrency@@QEAA_NXZ";
    case 0x02d7:
      return "?cerr@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A";
    case 0x02d8:
      return "?cin@std@@3V?$basic_istream@DU?$char_traits@D@std@@@1@A";
    case 0x02d9:
      return "?classic@locale@std@@SAAEBV12@XZ";
    case 0x02da:
      return "?classic_table@?$ctype@D@std@@SAPEBFXZ";
    case 0x02db:
      return "?clear@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z";
    case 0x02dc:
      return "?clear@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXI@Z";
    case 0x02dd:
      return "?clear@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAXH_N@Z";
    case 0x02de:
      return "?clear@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAXI@Z";
    case 0x02df:
      return "?clear@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXH_N@Z";
    case 0x02e0:
      return "?clear@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXI@Z";
    case 0x02e1:
      return "?clear@ios_base@std@@QEAAXH@Z";
    case 0x02e2:
      return "?clear@ios_base@std@@QEAAXH_N@Z";
    case 0x02e3:
      return "?clear@ios_base@std@@QEAAXI@Z";
    case 0x02e4:
      return "?clog@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A";
    case 0x02e5:
      return "?copyfmt@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "AEBV12@@Z";
    case 0x02e6:
      return "?copyfmt@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "AEBV12@@Z";
    case 0x02e7:
      return "?copyfmt@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "AEBV12@@Z";
    case 0x02e8:
      return "?copyfmt@ios_base@std@@QEAAAEAV12@AEBV12@@Z";
    case 0x02e9:
      return "?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A";
    case 0x02ea:
      return "?date_order@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@QEBA?AW4dateorder@time_base@2@XZ";
    case 0x02eb:
      return "?date_order@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@QEBA?AW4dateorder@time_base@2@XZ";
    case 0x02ec:
      return "?date_order@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@"
             "_W@std@@@std@@@std@@QEBA?AW4dateorder@time_base@2@XZ";
    case 0x02ed:
      return "?defer_lock@std@@3Udefer_lock_t@1@B";
    case 0x02ee:
      return "?do_always_noconv@?$codecvt@DDH@std@@MEBA_NXZ";
    case 0x02ef:
      return "?do_always_noconv@?$codecvt@GDH@std@@MEBA_NXZ";
    case 0x02f0:
      return "?do_always_noconv@?$codecvt@_WDH@std@@MEBA_NXZ";
    case 0x02f1:
      return "?do_always_noconv@codecvt_base@std@@MEBA_NXZ";
    case 0x02f2:
      return "?do_date_order@?$time_get@DV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@std@@@std@@MEBA?AW4dateorder@time_base@2@XZ";
    case 0x02f3:
      return "?do_date_order@?$time_get@GV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@std@@@std@@MEBA?AW4dateorder@time_base@2@XZ";
    case 0x02f4:
      return "?do_date_order@?$time_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@MEBA?AW4dateorder@time_base@2@XZ";
    case 0x02f5:
      return "?do_encoding@?$codecvt@GDH@std@@MEBAHXZ";
    case 0x02f6:
      return "?do_encoding@?$codecvt@_WDH@std@@MEBAHXZ";
    case 0x02f7:
      return "?do_encoding@codecvt_base@std@@MEBAHXZ";
    case 0x02f8:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAG@Z";
    case 0x02f9:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAI@Z";
    case 0x02fa:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAJ@Z";
    case 0x02fb:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAK@Z";
    case 0x02fc:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAM@Z";
    case 0x02fd:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAN@Z";
    case 0x02fe:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAO@Z";
    case 0x02ff:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAPEAX@Z";
    case 0x0300:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_J@Z";
    case 0x0301:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_K@Z";
    case 0x0302:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_N@Z";
    case 0x0303:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAG@Z";
    case 0x0304:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAI@Z";
    case 0x0305:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAJ@Z";
    case 0x0306:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAK@Z";
    case 0x0307:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAM@Z";
    case 0x0308:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAN@Z";
    case 0x0309:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAO@Z";
    case 0x030a:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAPEAX@Z";
    case 0x030b:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_J@Z";
    case 0x030c:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_K@Z";
    case 0x030d:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_N@Z";
    case 0x030e:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEAG@Z";
    case 0x030f:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEAI@Z";
    case 0x0310:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEAJ@Z";
    case 0x0311:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEAK@Z";
    case 0x0312:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEAM@Z";
    case 0x0313:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEAN@Z";
    case 0x0314:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEAO@Z";
    case 0x0315:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEAPEAX@Z";
    case 0x0316:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEA_J@Z";
    case 0x0317:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEA_K@Z";
    case 0x0318:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEA_N@Z";
    case 0x0319:
      return "?do_get@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@"
             "@@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@2@V32@0AEAVios_base@2@AEAHPEAUtm@@DD@Z";
    case 0x031a:
      return "?do_get@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@"
             "@@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@2@V32@0AEAVios_base@2@AEAHPEAUtm@@DD@Z";
    case 0x031b:
      return "?do_get@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@DD@Z";
    case 0x031c:
      return "?do_get_date@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x031d:
      return "?do_get_date@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x031e:
      return "?do_get_date@?$time_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$"
             "char_traits@_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x031f:
      return "?do_get_monthname@?$time_get@DV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0320:
      return "?do_get_monthname@?$time_get@GV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0321:
      return "?do_get_monthname@?$time_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$"
             "char_traits@_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0322:
      return "?do_get_time@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0323:
      return "?do_get_time@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0324:
      return "?do_get_time@?$time_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$"
             "char_traits@_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0325:
      return "?do_get_weekday@?$time_get@DV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0326:
      return "?do_get_weekday@?$time_get@GV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0327:
      return "?do_get_weekday@?$time_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$"
             "char_traits@_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0328:
      return "?do_get_year@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0329:
      return "?do_get_year@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x032a:
      return "?do_get_year@?$time_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$"
             "char_traits@_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x032b:
      return "?do_in@?$codecvt@DDH@std@@MEBAHAEAHPEBD1AEAPEBDPEAD3AEAPEAD@Z";
    case 0x032c:
      return "?do_in@?$codecvt@GDH@std@@MEBAHAEAHPEBD1AEAPEBDPEAG3AEAPEAG@Z";
    case 0x032d:
      return "?do_in@?$codecvt@_WDH@std@@MEBAHAEAHPEBD1AEAPEBDPEA_W3AEAPEA_W@Z";
    case 0x032e:
      return "?do_is@?$ctype@G@std@@MEBAPEBGPEBG0PEAF@Z";
    case 0x032f:
      return "?do_is@?$ctype@G@std@@MEBA_NFG@Z";
    case 0x0330:
      return "?do_is@?$ctype@_W@std@@MEBAPEB_WPEB_W0PEAF@Z";
    case 0x0331:
      return "?do_is@?$ctype@_W@std@@MEBA_NF_W@Z";
    case 0x0332:
      return "?do_length@?$codecvt@DDH@std@@MEBAHAEAHPEBD1_K@Z";
    case 0x0333:
      return "?do_length@?$codecvt@GDH@std@@MEBAHAEAHPEBD1_K@Z";
    case 0x0334:
      return "?do_length@?$codecvt@_WDH@std@@MEBAHAEAHPEBD1_K@Z";
    case 0x0335:
      return "?do_max_length@?$codecvt@GDH@std@@MEBAHXZ";
    case 0x0336:
      return "?do_max_length@?$codecvt@_WDH@std@@MEBAHXZ";
    case 0x0337:
      return "?do_max_length@codecvt_base@std@@MEBAHXZ";
    case 0x0338:
      return "?do_narrow@?$ctype@D@std@@MEBADDD@Z";
    case 0x0339:
      return "?do_narrow@?$ctype@D@std@@MEBAPEBDPEBD0DPEAD@Z";
    case 0x033a:
      return "?do_narrow@?$ctype@G@std@@MEBADGD@Z";
    case 0x033b:
      return "?do_narrow@?$ctype@G@std@@MEBAPEBGPEBG0DPEAD@Z";
    case 0x033c:
      return "?do_narrow@?$ctype@_W@std@@MEBAD_WD@Z";
    case 0x033d:
      return "?do_narrow@?$ctype@_W@std@@MEBAPEB_WPEB_W0DPEAD@Z";
    case 0x033e:
      return "?do_out@?$codecvt@DDH@std@@MEBAHAEAHPEBD1AEAPEBDPEAD3AEAPEAD@Z";
    case 0x033f:
      return "?do_out@?$codecvt@GDH@std@@MEBAHAEAHPEBG1AEAPEBGPEAD3AEAPEAD@Z";
    case 0x0340:
      return "?do_out@?$codecvt@_WDH@std@@MEBAHAEAHPEB_W1AEAPEB_WPEAD3AEAPEAD@"
             "Z";
    case 0x0341:
      return "?do_put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DJ@Z";
    case 0x0342:
      return "?do_put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DK@Z";
    case 0x0343:
      return "?do_put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DN@Z";
    case 0x0344:
      return "?do_put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DO@Z";
    case 0x0345:
      return "?do_put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DPEBX@Z";
    case 0x0346:
      return "?do_put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@D_J@Z";
    case 0x0347:
      return "?do_put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@D_K@Z";
    case 0x0348:
      return "?do_put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@D_N@Z";
    case 0x0349:
      return "?do_put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GJ@Z";
    case 0x034a:
      return "?do_put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GK@Z";
    case 0x034b:
      return "?do_put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GN@Z";
    case 0x034c:
      return "?do_put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GO@Z";
    case 0x034d:
      return "?do_put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GPEBX@Z";
    case 0x034e:
      return "?do_put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@G_J@Z";
    case 0x034f:
      return "?do_put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@G_K@Z";
    case 0x0350:
      return "?do_put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@G_N@Z";
    case 0x0351:
      return "?do_put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_WJ@Z";
    case 0x0352:
      return "?do_put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_WK@Z";
    case 0x0353:
      return "?do_put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_WN@Z";
    case 0x0354:
      return "?do_put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_WO@Z";
    case 0x0355:
      return "?do_put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_WPEBX@Z";
    case 0x0356:
      return "?do_put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_W_J@Z";
    case 0x0357:
      return "?do_put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_W_K@Z";
    case 0x0358:
      return "?do_put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_W_N@Z";
    case 0x0359:
      return "?do_put@?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@"
             "@@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@2@V32@AEAVios_base@2@DPEBUtm@@DD@Z";
    case 0x035a:
      return "?do_put@?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@"
             "@@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@2@V32@AEAVios_base@2@GPEBUtm@@DD@Z";
    case 0x035b:
      return "?do_put@?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_WPEBUtm@@DD@Z";
    case 0x035c:
      return "?do_scan_is@?$ctype@G@std@@MEBAPEBGFPEBG0@Z";
    case 0x035d:
      return "?do_scan_is@?$ctype@_W@std@@MEBAPEB_WFPEB_W0@Z";
    case 0x035e:
      return "?do_scan_not@?$ctype@G@std@@MEBAPEBGFPEBG0@Z";
    case 0x035f:
      return "?do_scan_not@?$ctype@_W@std@@MEBAPEB_WFPEB_W0@Z";
    case 0x0360:
      return "?do_tolower@?$ctype@D@std@@MEBADD@Z";
    case 0x0361:
      return "?do_tolower@?$ctype@D@std@@MEBAPEBDPEADPEBD@Z";
    case 0x0362:
      return "?do_tolower@?$ctype@G@std@@MEBAGG@Z";
    case 0x0363:
      return "?do_tolower@?$ctype@G@std@@MEBAPEBGPEAGPEBG@Z";
    case 0x0364:
      return "?do_tolower@?$ctype@_W@std@@MEBAPEB_WPEA_WPEB_W@Z";
    case 0x0365:
      return "?do_tolower@?$ctype@_W@std@@MEBA_W_W@Z";
    case 0x0366:
      return "?do_toupper@?$ctype@D@std@@MEBADD@Z";
    case 0x0367:
      return "?do_toupper@?$ctype@D@std@@MEBAPEBDPEADPEBD@Z";
    case 0x0368:
      return "?do_toupper@?$ctype@G@std@@MEBAGG@Z";
    case 0x0369:
      return "?do_toupper@?$ctype@G@std@@MEBAPEBGPEAGPEBG@Z";
    case 0x036a:
      return "?do_toupper@?$ctype@_W@std@@MEBAPEB_WPEA_WPEB_W@Z";
    case 0x036b:
      return "?do_toupper@?$ctype@_W@std@@MEBA_W_W@Z";
    case 0x036c:
      return "?do_unshift@?$codecvt@DDH@std@@MEBAHAEAHPEAD1AEAPEAD@Z";
    case 0x036d:
      return "?do_unshift@?$codecvt@GDH@std@@MEBAHAEAHPEAD1AEAPEAD@Z";
    case 0x036e:
      return "?do_unshift@?$codecvt@_WDH@std@@MEBAHAEAHPEAD1AEAPEAD@Z";
    case 0x036f:
      return "?do_widen@?$ctype@D@std@@MEBADD@Z";
    case 0x0370:
      return "?do_widen@?$ctype@D@std@@MEBAPEBDPEBD0PEAD@Z";
    case 0x0371:
      return "?do_widen@?$ctype@G@std@@MEBAGD@Z";
    case 0x0372:
      return "?do_widen@?$ctype@G@std@@MEBAPEBDPEBD0PEAG@Z";
    case 0x0373:
      return "?do_widen@?$ctype@_W@std@@MEBAPEBDPEBD0PEA_W@Z";
    case 0x0374:
      return "?do_widen@?$ctype@_W@std@@MEBA_WD@Z";
    case 0x0375:
      return "?done@agent@Concurrency@@IEAA_NXZ";
    case 0x0376:
      return "?eback@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ";
    case 0x0377:
      return "?eback@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEBAPEAGXZ";
    case 0x0378:
      return "?eback@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEBAPEA_"
             "WXZ";
    case 0x0379:
      return "?egptr@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ";
    case 0x037a:
      return "?egptr@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEBAPEAGXZ";
    case 0x037b:
      return "?egptr@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEBAPEA_"
             "WXZ";
    case 0x037c:
      return "?empty@?$_Yarn@D@std@@QEBA_NXZ";
    case 0x037d:
      return "?empty@locale@std@@SA?AV12@XZ";
    case 0x037e:
      return "?encoding@codecvt_base@std@@QEBAHXZ";
    case 0x037f:
      return "?eof@ios_base@std@@QEBA_NXZ";
    case 0x0380:
      return "?epptr@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ";
    case 0x0381:
      return "?epptr@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEBAPEAGXZ";
    case 0x0382:
      return "?epptr@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEBAPEA_"
             "WXZ";
    case 0x0383:
      return "?exceptions@ios_base@std@@QEAAXH@Z";
    case 0x0384:
      return "?exceptions@ios_base@std@@QEAAXI@Z";
    case 0x0385:
      return "?exceptions@ios_base@std@@QEBAHXZ";
    case 0x0386:
      return "?fail@ios_base@std@@QEBA_NXZ";
    case 0x0387:
      return "?fill@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAADD@Z";
    case 0x0388:
      return "?fill@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBADXZ";
    case 0x0389:
      return "?fill@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAGG@Z";
    case 0x038a:
      return "?fill@?$basic_ios@GU?$char_traits@G@std@@@std@@QEBAGXZ";
    case 0x038b:
      return "?fill@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAA_W_W@Z";
    case 0x038c:
      return "?fill@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEBA_WXZ";
    case 0x038d:
      return "?flags@ios_base@std@@QEAAHH@Z";
    case 0x038e:
      return "?flags@ios_base@std@@QEBAHXZ";
    case 0x038f:
      return "?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "XZ";
    case 0x0390:
      return "?flush@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "XZ";
    case 0x0391:
      return "?flush@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "XZ";
    case 0x0392:
      return "?gbump@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXH@Z";
    case 0x0393:
      return "?gbump@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAAXH@Z";
    case 0x0394:
      return "?gbump@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAXH@Z";
    case 0x0395:
      return "?gcount@?$basic_istream@DU?$char_traits@D@std@@@std@@QEBA_JXZ";
    case 0x0396:
      return "?gcount@?$basic_istream@GU?$char_traits@G@std@@@std@@QEBA_JXZ";
    case 0x0397:
      return "?gcount@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEBA_JXZ";
    case 0x0398:
      return "?get@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "AEAD@Z";
    case 0x0399:
      return "?get@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "AEAV?$basic_streambuf@DU?$char_traits@D@std@@@2@@Z";
    case 0x039a:
      return "?get@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "AEAV?$basic_streambuf@DU?$char_traits@D@std@@@2@D@Z";
    case 0x039b:
      return "?get@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "PEAD_J@Z";
    case 0x039c:
      return "?get@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "PEAD_JD@Z";
    case 0x039d:
      return "?get@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAHXZ";
    case 0x039e:
      return "?get@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "AEAG@Z";
    case 0x039f:
      return "?get@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "AEAV?$basic_streambuf@GU?$char_traits@G@std@@@2@@Z";
    case 0x03a0:
      return "?get@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "AEAV?$basic_streambuf@GU?$char_traits@G@std@@@2@G@Z";
    case 0x03a1:
      return "?get@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "PEAG_J@Z";
    case 0x03a2:
      return "?get@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "PEAG_JG@Z";
    case 0x03a3:
      return "?get@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAGXZ";
    case 0x03a4:
      return "?get@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "AEAV?$basic_streambuf@_WU?$char_traits@_W@std@@@2@@Z";
    case 0x03a5:
      return "?get@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "AEAV?$basic_streambuf@_WU?$char_traits@_W@std@@@2@_W@Z";
    case 0x03a6:
      return "?get@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "AEA_W@Z";
    case 0x03a7:
      return "?get@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "PEA_W_J@Z";
    case 0x03a8:
      return "?get@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "PEA_W_J_W@Z";
    case 0x03a9:
      return "?get@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAGXZ";
    case 0x03aa:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAG@Z";
    case 0x03ab:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAI@Z";
    case 0x03ac:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAJ@Z";
    case 0x03ad:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAK@Z";
    case 0x03ae:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAM@Z";
    case 0x03af:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAN@Z";
    case 0x03b0:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAO@Z";
    case 0x03b1:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAPEAX@Z";
    case 0x03b2:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_J@Z";
    case 0x03b3:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_K@Z";
    case 0x03b4:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_N@Z";
    case 0x03b5:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAG@Z";
    case 0x03b6:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAI@Z";
    case 0x03b7:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAJ@Z";
    case 0x03b8:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAK@Z";
    case 0x03b9:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAM@Z";
    case 0x03ba:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAN@Z";
    case 0x03bb:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAO@Z";
    case 0x03bc:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAPEAX@Z";
    case 0x03bd:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_J@Z";
    case 0x03be:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_K@Z";
    case 0x03bf:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_N@Z";
    case 0x03c0:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEAG@Z";
    case 0x03c1:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEAI@Z";
    case 0x03c2:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEAJ@Z";
    case 0x03c3:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEAK@Z";
    case 0x03c4:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEAM@Z";
    case 0x03c5:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEAN@Z";
    case 0x03c6:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEAO@Z";
    case 0x03c7:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEAPEAX@Z";
    case 0x03c8:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEA_J@Z";
    case 0x03c9:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEA_K@Z";
    case 0x03ca:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEA_N@Z";
    case 0x03cb:
      return "?get@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHPEAUtm@@DD@Z";
    case 0x03cc:
      return "?get@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHPEAUtm@@PEBD4@Z";
    case 0x03cd:
      return "?get@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHPEAUtm@@DD@Z";
    case 0x03ce:
      return "?get@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHPEAUtm@@PEBG4@Z";
    case 0x03cf:
      return "?get@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@DD@Z";
    case 0x03d0:
      return "?get@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@PEB_W4@Z";
    case 0x03d1:
      return "?get_date@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03d2:
      return "?get_date@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03d3:
      return "?get_date@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@"
             "_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03d4:
      return "?get_monthname@?$time_get@DV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03d5:
      return "?get_monthname@?$time_get@GV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03d6:
      return "?get_monthname@?$time_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$"
             "char_traits@_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03d7:
      return "?get_new_handler@std@@YAP6AXXZXZ";
    case 0x03d8:
      return "?get_time@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03d9:
      return "?get_time@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03da:
      return "?get_time@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@"
             "_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03db:
      return "?get_weekday@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03dc:
      return "?get_weekday@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03dd:
      return "?get_weekday@?$time_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$"
             "char_traits@_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03de:
      return "?get_year@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03df:
      return "?get_year@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03e0:
      return "?get_year@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@"
             "_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03e1:
      return "?getline@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "PEAD_J@Z";
    case 0x03e2:
      return "?getline@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "PEAD_JD@Z";
    case 0x03e3:
      return "?getline@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "PEAG_J@Z";
    case 0x03e4:
      return "?getline@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "PEAG_JG@Z";
    case 0x03e5:
      return "?getline@?$basic_istream@_WU?$char_traits@_W@std@@@std@@"
             "QEAAAEAV12@PEA_W_J@Z";
    case 0x03e6:
      return "?getline@?$basic_istream@_WU?$char_traits@_W@std@@@std@@"
             "QEAAAEAV12@PEA_W_J_W@Z";
    case 0x03e7:
      return "?getloc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEBA?"
             "AVlocale@2@XZ";
    case 0x03e8:
      return "?getloc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEBA?"
             "AVlocale@2@XZ";
    case 0x03e9:
      return "?getloc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEBA?"
             "AVlocale@2@XZ";
    case 0x03ea:
      return "?getloc@ios_base@std@@QEBA?AVlocale@2@XZ";
    case 0x03eb:
      return "?global@locale@std@@SA?AV12@AEBV12@@Z";
    case 0x03ec:
      return "?good@ios_base@std@@QEBA_NXZ";
    case 0x03ed:
      return "?gptr@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ";
    case 0x03ee:
      return "?gptr@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEBAPEAGXZ";
    case 0x03ef:
      return "?gptr@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEBAPEA_"
             "WXZ";
    case 0x03f0:
      return "?id@?$codecvt@DDH@std@@2V0locale@2@A";
    case 0x03f1:
      return "?id@?$codecvt@GDH@std@@2V0locale@2@A";
    case 0x03f2:
      return "?id@?$codecvt@_WDH@std@@2V0locale@2@A";
    case 0x03f3:
      return "?id@?$collate@D@std@@2V0locale@2@A";
    case 0x03f4:
      return "?id@?$collate@G@std@@2V0locale@2@A";
    case 0x03f5:
      return "?id@?$collate@_W@std@@2V0locale@2@A";
    case 0x03f6:
      return "?id@?$ctype@D@std@@2V0locale@2@A";
    case 0x03f7:
      return "?id@?$ctype@G@std@@2V0locale@2@A";
    case 0x03f8:
      return "?id@?$ctype@_W@std@@2V0locale@2@A";
    case 0x03f9:
      return "?id@?$messages@D@std@@2V0locale@2@A";
    case 0x03fa:
      return "?id@?$messages@G@std@@2V0locale@2@A";
    case 0x03fb:
      return "?id@?$messages@_W@std@@2V0locale@2@A";
    case 0x03fc:
      return "?id@?$money_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x03fd:
      return "?id@?$money_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x03fe:
      return "?id@?$money_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@std@@@std@@2V0locale@2@A";
    case 0x03ff:
      return "?id@?$money_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x0400:
      return "?id@?$money_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x0401:
      return "?id@?$money_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@std@@@std@@2V0locale@2@A";
    case 0x0402:
      return "?id@?$moneypunct@D$00@std@@2V0locale@2@A";
    case 0x0403:
      return "?id@?$moneypunct@D$0A@@std@@2V0locale@2@A";
    case 0x0404:
      return "?id@?$moneypunct@G$00@std@@2V0locale@2@A";
    case 0x0405:
      return "?id@?$moneypunct@G$0A@@std@@2V0locale@2@A";
    case 0x0406:
      return "?id@?$moneypunct@_W$00@std@@2V0locale@2@A";
    case 0x0407:
      return "?id@?$moneypunct@_W$0A@@std@@2V0locale@2@A";
    case 0x0408:
      return "?id@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x0409:
      return "?id@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x040a:
      return "?id@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x040b:
      return "?id@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x040c:
      return "?id@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x040d:
      return "?id@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x040e:
      return "?id@?$numpunct@D@std@@2V0locale@2@A";
    case 0x040f:
      return "?id@?$numpunct@G@std@@2V0locale@2@A";
    case 0x0410:
      return "?id@?$numpunct@_W@std@@2V0locale@2@A";
    case 0x0411:
      return "?id@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x0412:
      return "?id@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x0413:
      return "?id@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@2V0locale@2@A";
    case 0x0414:
      return "?id@?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x0415:
      return "?id@?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x0416:
      return "?id@?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@2V0locale@2@A";
    case 0x0417:
      return "?ignore@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@_"
             "JH@Z";
    case 0x0418:
      return "?ignore@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@_"
             "JG@Z";
    case 0x0419:
      return "?ignore@?$basic_istream@_WU?$char_traits@_W@std@@@std@@"
             "QEAAAEAV12@_JG@Z";
    case 0x041a:
      return "?imbue@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAA?AVlocale@2@"
             "AEBV32@@Z";
    case 0x041b:
      return "?imbue@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAA?AVlocale@2@"
             "AEBV32@@Z";
    case 0x041c:
      return "?imbue@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAA?AVlocale@"
             "2@AEBV32@@Z";
    case 0x041d:
      return "?imbue@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "MEAAXAEBVlocale@2@@Z";
    case 0x041e:
      return "?imbue@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "MEAAXAEBVlocale@2@@Z";
    case 0x041f:
      return "?imbue@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "MEAAXAEBVlocale@2@@Z";
    case 0x0420:
      return "?imbue@ios_base@std@@QEAA?AVlocale@2@AEBV32@@Z";
    case 0x0421:
      return "?in@?$codecvt@DDH@std@@QEBAHAEAHPEBD1AEAPEBDPEAD3AEAPEAD@Z";
    case 0x0422:
      return "?in@?$codecvt@GDH@std@@QEBAHAEAHPEBD1AEAPEBDPEAG3AEAPEAG@Z";
    case 0x0423:
      return "?in@?$codecvt@_WDH@std@@QEBAHAEAHPEBD1AEAPEBDPEA_W3AEAPEA_W@Z";
    case 0x0424:
      return "?in_avail@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_"
             "JXZ";
    case 0x0425:
      return "?in_avail@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAA_"
             "JXZ";
    case 0x0426:
      return "?in_avail@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAA_"
             "JXZ";
    case 0x0427:
      return "?init@?$basic_ios@DU?$char_traits@D@std@@@std@@IEAAXPEAV?$basic_"
             "streambuf@DU?$char_traits@D@std@@@2@_N@Z";
    case 0x0428:
      return "?init@?$basic_ios@GU?$char_traits@G@std@@@std@@IEAAXPEAV?$basic_"
             "streambuf@GU?$char_traits@G@std@@@2@_N@Z";
    case 0x0429:
      return "?init@?$basic_ios@_WU?$char_traits@_W@std@@@std@@IEAAXPEAV?$"
             "basic_streambuf@_WU?$char_traits@_W@std@@@2@_N@Z";
    case 0x042a:
      return "?intl@?$moneypunct@D$00@std@@2_NB";
    case 0x042b:
      return "?intl@?$moneypunct@D$0A@@std@@2_NB";
    case 0x042c:
      return "?intl@?$moneypunct@G$00@std@@2_NB";
    case 0x042d:
      return "?intl@?$moneypunct@G$0A@@std@@2_NB";
    case 0x042e:
      return "?intl@?$moneypunct@_W$00@std@@2_NB";
    case 0x042f:
      return "?intl@?$moneypunct@_W$0A@@std@@2_NB";
    case 0x0430:
      return "?ipfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA_N_N@Z";
    case 0x0431:
      return "?ipfx@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAA_N_N@Z";
    case 0x0432:
      return "?ipfx@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAA_N_N@Z";
    case 0x0433:
      return "?is@?$ctype@D@std@@QEBAPEBDPEBD0PEAF@Z";
    case 0x0434:
      return "?is@?$ctype@D@std@@QEBA_NFD@Z";
    case 0x0435:
      return "?is@?$ctype@G@std@@QEBAPEBGPEBG0PEAF@Z";
    case 0x0436:
      return "?is@?$ctype@G@std@@QEBA_NFG@Z";
    case 0x0437:
      return "?is@?$ctype@_W@std@@QEBAPEB_WPEB_W0PEAF@Z";
    case 0x0438:
      return "?is@?$ctype@_W@std@@QEBA_NF_W@Z";
    case 0x0439:
      return "?is_current_task_group_canceling@Concurrency@@YA_NXZ";
    case 0x043a:
      return "?isfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAXXZ";
    case 0x043b:
      return "?isfx@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAXXZ";
    case 0x043c:
      return "?isfx@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAXXZ";
    case 0x043d:
      return "?iword@ios_base@std@@QEAAAEAJH@Z";
    case 0x043e:
      return "?length@?$codecvt@DDH@std@@QEBAHAEAHPEBD1_K@Z";
    case 0x043f:
      return "?length@?$codecvt@GDH@std@@QEBAHAEAHPEBD1_K@Z";
    case 0x0440:
      return "?length@?$codecvt@_WDH@std@@QEBAHAEAHPEBD1_K@Z";
    case 0x0441:
      return "?max_length@codecvt_base@std@@QEBAHXZ";
    case 0x0442:
      return "?move@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAX$$QEAV12@@Z";
    case 0x0443:
      return "?move@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXAEAV12@@Z";
    case 0x0444:
      return "?move@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAX$$QEAV12@@Z";
    case 0x0445:
      return "?move@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAXAEAV12@@Z";
    case 0x0446:
      return "?move@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAX$$QEAV12@@"
             "Z";
    case 0x0447:
      return "?move@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXAEAV12@@Z";
    case 0x0448:
      return "?narrow@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBADDD@Z";
    case 0x0449:
      return "?narrow@?$basic_ios@GU?$char_traits@G@std@@@std@@QEBADGD@Z";
    case 0x044a:
      return "?narrow@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEBAD_WD@Z";
    case 0x044b:
      return "?narrow@?$ctype@D@std@@QEBADDD@Z";
    case 0x044c:
      return "?narrow@?$ctype@D@std@@QEBAPEBDPEBD0DPEAD@Z";
    case 0x044d:
      return "?narrow@?$ctype@G@std@@QEBADGD@Z";
    case 0x044e:
      return "?narrow@?$ctype@G@std@@QEBAPEBGPEBG0DPEAD@Z";
    case 0x044f:
      return "?narrow@?$ctype@_W@std@@QEBAD_WD@Z";
    case 0x0450:
      return "?narrow@?$ctype@_W@std@@QEBAPEB_WPEB_W0DPEAD@Z";
    case 0x0451:
      return "?opfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAA_NXZ";
    case 0x0452:
      return "?opfx@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAA_NXZ";
    case 0x0453:
      return "?opfx@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAA_NXZ";
    case 0x0454:
      return "?osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ";
    case 0x0455:
      return "?osfx@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAXXZ";
    case 0x0456:
      return "?osfx@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAXXZ";
    case 0x0457:
      return "?out@?$codecvt@DDH@std@@QEBAHAEAHPEBD1AEAPEBDPEAD3AEAPEAD@Z";
    case 0x0458:
      return "?out@?$codecvt@GDH@std@@QEBAHAEAHPEBG1AEAPEBGPEAD3AEAPEAD@Z";
    case 0x0459:
      return "?out@?$codecvt@_WDH@std@@QEBAHAEAHPEB_W1AEAPEB_WPEAD3AEAPEAD@Z";
    case 0x045a:
      return "?overflow@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHH@"
             "Z";
    case 0x045b:
      return "?overflow@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAAGG@"
             "Z";
    case 0x045c:
      return "?overflow@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "MEAAGG@Z";
    case 0x045d:
      return "?pbackfail@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHH@"
             "Z";
    case 0x045e:
      return "?pbackfail@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAAGG@"
             "Z";
    case 0x045f:
      return "?pbackfail@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "MEAAGG@Z";
    case 0x0460:
      return "?pbase@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ";
    case 0x0461:
      return "?pbase@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEBAPEAGXZ";
    case 0x0462:
      return "?pbase@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEBAPEA_"
             "WXZ";
    case 0x0463:
      return "?pbump@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXH@Z";
    case 0x0464:
      return "?pbump@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAAXH@Z";
    case 0x0465:
      return "?pbump@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAXH@Z";
    case 0x0466:
      return "?peek@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAHXZ";
    case 0x0467:
      return "?peek@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAGXZ";
    case 0x0468:
      return "?peek@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAGXZ";
    case 0x0469:
      return "?pptr@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ";
    case 0x046a:
      return "?pptr@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEBAPEAGXZ";
    case 0x046b:
      return "?pptr@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEBAPEA_"
             "WXZ";
    case 0x046c:
      return "?precision@ios_base@std@@QEAA_J_J@Z";
    case 0x046d:
      return "?precision@ios_base@std@@QEBA_JXZ";
    case 0x046e:
      return "?pubimbue@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA?"
             "AVlocale@2@AEBV32@@Z";
    case 0x046f:
      return "?pubimbue@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAA?"
             "AVlocale@2@AEBV32@@Z";
    case 0x0470:
      return "?pubimbue@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAA?"
             "AVlocale@2@AEBV32@@Z";
    case 0x0471:
      return "?pubseekoff@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA?"
             "AV?$fpos@H@2@_JHH@Z";
    case 0x0472:
      return "?pubseekoff@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA?"
             "AV?$fpos@H@2@_JII@Z";
    case 0x0473:
      return "?pubseekoff@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAA?"
             "AV?$fpos@H@2@_JHH@Z";
    case 0x0474:
      return "?pubseekoff@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAA?"
             "AV?$fpos@H@2@_JII@Z";
    case 0x0475:
      return "?pubseekoff@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "QEAA?AV?$fpos@H@2@_JHH@Z";
    case 0x0476:
      return "?pubseekoff@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "QEAA?AV?$fpos@H@2@_JII@Z";
    case 0x0477:
      return "?pubseekpos@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA?"
             "AV?$fpos@H@2@V32@H@Z";
    case 0x0478:
      return "?pubseekpos@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA?"
             "AV?$fpos@H@2@V32@I@Z";
    case 0x0479:
      return "?pubseekpos@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAA?"
             "AV?$fpos@H@2@V32@H@Z";
    case 0x047a:
      return "?pubseekpos@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAA?"
             "AV?$fpos@H@2@V32@I@Z";
    case 0x047b:
      return "?pubseekpos@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "QEAA?AV?$fpos@H@2@V32@H@Z";
    case 0x047c:
      return "?pubseekpos@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "QEAA?AV?$fpos@H@2@V32@I@Z";
    case 0x047d:
      return "?pubsetbuf@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "QEAAPEAV12@PEAD_J@Z";
    case 0x047e:
      return "?pubsetbuf@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "QEAAPEAV12@PEAG_J@Z";
    case 0x047f:
      return "?pubsetbuf@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "QEAAPEAV12@PEA_W_J@Z";
    case 0x0480:
      return "?pubsync@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ";
    case 0x0481:
      return "?pubsync@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAAHXZ";
    case 0x0482:
      return "?pubsync@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "QEAAHXZ";
    case 0x0483:
      return "?put@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@D@Z";
    case 0x0484:
      return "?put@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@G@Z";
    case 0x0485:
      return "?put@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@_"
             "W@Z";
    case 0x0486:
      return "?put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DJ@Z";
    case 0x0487:
      return "?put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DK@Z";
    case 0x0488:
      return "?put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DN@Z";
    case 0x0489:
      return "?put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DO@Z";
    case 0x048a:
      return "?put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DPEBX@Z";
    case 0x048b:
      return "?put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@D_J@Z";
    case 0x048c:
      return "?put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@D_K@Z";
    case 0x048d:
      return "?put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@D_N@Z";
    case 0x048e:
      return "?put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GJ@Z";
    case 0x048f:
      return "?put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GK@Z";
    case 0x0490:
      return "?put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GN@Z";
    case 0x0491:
      return "?put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GO@Z";
    case 0x0492:
      return "?put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GPEBX@Z";
    case 0x0493:
      return "?put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@G_J@Z";
    case 0x0494:
      return "?put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@G_K@Z";
    case 0x0495:
      return "?put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@G_N@Z";
    case 0x0496:
      return "?put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@AEAVios_base@2@_WJ@Z";
    case 0x0497:
      return "?put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@AEAVios_base@2@_WK@Z";
    case 0x0498:
      return "?put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@AEAVios_base@2@_WN@Z";
    case 0x0499:
      return "?put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@AEAVios_base@2@_WO@Z";
    case 0x049a:
      return "?put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@AEAVios_base@2@_WPEBX@Z";
    case 0x049b:
      return "?put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@AEAVios_base@2@_W_J@Z";
    case 0x049c:
      return "?put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@AEAVios_base@2@_W_K@Z";
    case 0x049d:
      return "?put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@AEAVios_base@2@_W_N@Z";
    case 0x049e:
      return "?put@?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DPEBUtm@@DD@Z";
    case 0x049f:
      return "?put@?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DPEBUtm@@PEBD3@Z";
    case 0x04a0:
      return "?put@?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GPEBUtm@@DD@Z";
    case 0x04a1:
      return "?put@?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GPEBUtm@@PEBG3@Z";
    case 0x04a2:
      return "?put@?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@2@V32@AEAVios_base@2@_WPEBUtm@@DD@Z";
    case 0x04a3:
      return "?put@?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@2@V32@AEAVios_base@2@_WPEBUtm@@PEB_W4@Z";
    case 0x04a4:
      return "?putback@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "D@Z";
    case 0x04a5:
      return "?putback@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "G@Z";
    case 0x04a6:
      return "?putback@?$basic_istream@_WU?$char_traits@_W@std@@@std@@"
             "QEAAAEAV12@_W@Z";
    case 0x04a7:
      return "?pword@ios_base@std@@QEAAAEAPEAXH@Z";
    case 0x04a8:
      return "?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAPEAV?$basic_"
             "streambuf@DU?$char_traits@D@std@@@2@PEAV32@@Z";
    case 0x04a9:
      return "?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBAPEAV?$basic_"
             "streambuf@DU?$char_traits@D@std@@@2@XZ";
    case 0x04aa:
      return "?rdbuf@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAPEAV?$basic_"
             "streambuf@GU?$char_traits@G@std@@@2@PEAV32@@Z";
    case 0x04ab:
      return "?rdbuf@?$basic_ios@GU?$char_traits@G@std@@@std@@QEBAPEAV?$basic_"
             "streambuf@GU?$char_traits@G@std@@@2@XZ";
    case 0x04ac:
      return "?rdbuf@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAPEAV?$"
             "basic_streambuf@_WU?$char_traits@_W@std@@@2@PEAV32@@Z";
    case 0x04ad:
      return "?rdbuf@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEBAPEAV?$"
             "basic_streambuf@_WU?$char_traits@_W@std@@@2@XZ";
    case 0x04ae:
      return "?rdstate@ios_base@std@@QEBAHXZ";
    case 0x04af:
      return "?read@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "PEAD_J@Z";
    case 0x04b0:
      return "?read@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "PEAG_J@Z";
    case 0x04b1:
      return "?read@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "PEA_W_J@Z";
    case 0x04b2:
      return "?readsome@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA_"
             "JPEAD_J@Z";
    case 0x04b3:
      return "?readsome@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAA_"
             "JPEAG_J@Z";
    case 0x04b4:
      return "?readsome@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAA_"
             "JPEA_W_J@Z";
    case 0x04b5:
      return "?register_callback@ios_base@std@@QEAAXP6AXW4event@12@AEAV12@H@ZH@"
             "Z";
    case 0x04b6:
      return "?resetiosflags@std@@YA?AU?$_Smanip@H@1@H@Z";
    case 0x04b7:
      return "?sbumpc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ";
    case 0x04b8:
      return "?sbumpc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAAGXZ";
    case 0x04b9:
      return "?sbumpc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAAGXZ";
    case 0x04ba:
      return "?scan_is@?$ctype@D@std@@QEBAPEBDFPEBD0@Z";
    case 0x04bb:
      return "?scan_is@?$ctype@G@std@@QEBAPEBGFPEBG0@Z";
    case 0x04bc:
      return "?scan_is@?$ctype@_W@std@@QEBAPEB_WFPEB_W0@Z";
    case 0x04bd:
      return "?scan_not@?$ctype@D@std@@QEBAPEBDFPEBD0@Z";
    case 0x04be:
      return "?scan_not@?$ctype@G@std@@QEBAPEBGFPEBG0@Z";
    case 0x04bf:
      return "?scan_not@?$ctype@_W@std@@QEBAPEB_WFPEB_W0@Z";
    case 0x04c0:
      return "?seekg@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?"
             "$fpos@H@2@@Z";
    case 0x04c1:
      return "?seekg@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@_"
             "JH@Z";
    case 0x04c2:
      return "?seekg@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@V?"
             "$fpos@H@2@@Z";
    case 0x04c3:
      return "?seekg@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@_"
             "JH@Z";
    case 0x04c4:
      return "?seekg@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "V?$fpos@H@2@@Z";
    case 0x04c5:
      return "?seekg@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "_JH@Z";
    case 0x04c6:
      return "?seekoff@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA?AV?$"
             "fpos@H@2@_JHH@Z";
    case 0x04c7:
      return "?seekoff@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAA?AV?$"
             "fpos@H@2@_JHH@Z";
    case 0x04c8:
      return "?seekoff@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAA?"
             "AV?$fpos@H@2@_JHH@Z";
    case 0x04c9:
      return "?seekp@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?"
             "$fpos@H@2@@Z";
    case 0x04ca:
      return "?seekp@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@_"
             "JH@Z";
    case 0x04cb:
      return "?seekp@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@V?"
             "$fpos@H@2@@Z";
    case 0x04cc:
      return "?seekp@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@_"
             "JH@Z";
    case 0x04cd:
      return "?seekp@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "V?$fpos@H@2@@Z";
    case 0x04ce:
      return "?seekp@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "_JH@Z";
    case 0x04cf:
      return "?seekpos@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA?AV?$"
             "fpos@H@2@V32@H@Z";
    case 0x04d0:
      return "?seekpos@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAA?AV?$"
             "fpos@H@2@V32@H@Z";
    case 0x04d1:
      return "?seekpos@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAA?"
             "AV?$fpos@H@2@V32@H@Z";
    case 0x04d2:
      return "?set_new_handler@std@@YAP6AXXZP6AXXZ@Z";
    case 0x04d3:
      return "?set_rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXPEAV?$"
             "basic_streambuf@DU?$char_traits@D@std@@@2@@Z";
    case 0x04d4:
      return "?set_rdbuf@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAXPEAV?$"
             "basic_streambuf@GU?$char_traits@G@std@@@2@@Z";
    case 0x04d5:
      return "?set_rdbuf@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXPEAV?$"
             "basic_streambuf@_WU?$char_traits@_W@std@@@2@@Z";
    case 0x04d6:
      return "?setbase@std@@YA?AU?$_Smanip@H@1@H@Z";
    case 0x04d7:
      return "?setbuf@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "MEAAPEAV12@PEAD_J@Z";
    case 0x04d8:
      return "?setbuf@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "MEAAPEAV12@PEAG_J@Z";
    case 0x04d9:
      return "?setbuf@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "MEAAPEAV12@PEA_W_J@Z";
    case 0x04da:
      return "?setf@ios_base@std@@QEAAHH@Z";
    case 0x04db:
      return "?setf@ios_base@std@@QEAAHHH@Z";
    case 0x04dc:
      return "?setg@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXPEAD00@"
             "Z";
    case 0x04dd:
      return "?setg@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAAXPEAG00@"
             "Z";
    case 0x04de:
      return "?setg@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAXPEA_"
             "W00@Z";
    case 0x04df:
      return "?setiosflags@std@@YA?AU?$_Smanip@H@1@H@Z";
    case 0x04e0:
      return "?setp@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXPEAD00@"
             "Z";
    case 0x04e1:
      return "?setp@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXPEAD0@"
             "Z";
    case 0x04e2:
      return "?setp@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAAXPEAG00@"
             "Z";
    case 0x04e3:
      return "?setp@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAAXPEAG0@"
             "Z";
    case 0x04e4:
      return "?setp@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAXPEA_"
             "W00@Z";
    case 0x04e5:
      return "?setp@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAXPEA_"
             "W0@Z";
    case 0x04e6:
      return "?setprecision@std@@YA?AU?$_Smanip@_J@1@_J@Z";
    case 0x04e7:
      return "?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z";
    case 0x04e8:
      return "?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXI@Z";
    case 0x04e9:
      return "?setstate@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAXH_N@Z";
    case 0x04ea:
      return "?setstate@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAXI@Z";
    case 0x04eb:
      return "?setstate@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXH_N@Z";
    case 0x04ec:
      return "?setstate@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXI@Z";
    case 0x04ed:
      return "?setstate@ios_base@std@@QEAAXH@Z";
    case 0x04ee:
      return "?setstate@ios_base@std@@QEAAXH_N@Z";
    case 0x04ef:
      return "?setstate@ios_base@std@@QEAAXI@Z";
    case 0x04f0:
      return "?setw@std@@YA?AU?$_Smanip@_J@1@_J@Z";
    case 0x04f1:
      return "?sgetc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ";
    case 0x04f2:
      return "?sgetc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAAGXZ";
    case 0x04f3:
      return "?sgetc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAAGXZ";
    case 0x04f4:
      return "?sgetn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_JPEAD_"
             "J@Z";
    case 0x04f5:
      return "?sgetn@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAA_JPEAG_"
             "J@Z";
    case 0x04f6:
      return "?sgetn@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAA_"
             "JPEA_W_J@Z";
    case 0x04f7:
      return "?showmanyc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_"
             "JXZ";
    case 0x04f8:
      return "?showmanyc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAA_"
             "JXZ";
    case 0x04f9:
      return "?showmanyc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAA_"
             "JXZ";
    case 0x04fa:
      return "?snextc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ";
    case 0x04fb:
      return "?snextc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAAGXZ";
    case 0x04fc:
      return "?snextc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAAGXZ";
    case 0x04fd:
      return "?sputbackc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHD@"
             "Z";
    case 0x04fe:
      return "?sputbackc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAAGG@"
             "Z";
    case 0x04ff:
      return "?sputbackc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "QEAAG_W@Z";
    case 0x0500:
      return "?sputc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHD@Z";
    case 0x0501:
      return "?sputc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAAGG@Z";
    case 0x0502:
      return "?sputc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAAG_W@"
             "Z";
    case 0x0503:
      return "?sputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_JPEBD_"
             "J@Z";
    case 0x0504:
      return "?sputn@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAA_JPEBG_"
             "J@Z";
    case 0x0505:
      return "?sputn@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAA_"
             "JPEB_W_J@Z";
    case 0x0506:
      return "?start@agent@Concurrency@@QEAA_NXZ";
    case 0x0507:
      return "?status@agent@Concurrency@@QEAA?AW4agent_status@2@XZ";
    case 0x0508:
      return "?status_port@agent@Concurrency@@QEAAPEAV?$ISource@W4agent_status@"
             "Concurrency@@@2@XZ";
    case 0x0509:
      return "?stossc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAXXZ";
    case 0x050a:
      return "?stossc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAAXXZ";
    case 0x050b:
      return "?stossc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAAXXZ";
    case 0x050c:
      return "?sungetc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ";
    case 0x050d:
      return "?sungetc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAAGXZ";
    case 0x050e:
      return "?sungetc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "QEAAGXZ";
    case 0x050f:
      return "?swap@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXAEAV12@@Z";
    case 0x0510:
      return "?swap@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAXAEAV12@@Z";
    case 0x0511:
      return "?swap@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXAEAV12@@Z";
    case 0x0512:
      return "?swap@?$basic_iostream@DU?$char_traits@D@std@@@std@@IEAAXAEAV12@@"
             "Z";
    case 0x0513:
      return "?swap@?$basic_iostream@GU?$char_traits@G@std@@@std@@IEAAXAEAV12@@"
             "Z";
    case 0x0514:
      return "?swap@?$basic_iostream@_WU?$char_traits@_W@std@@@std@@"
             "IEAAXAEAV12@@Z";
    case 0x0515:
      return "?swap@?$basic_istream@DU?$char_traits@D@std@@@std@@IEAAXAEAV12@@"
             "Z";
    case 0x0516:
      return "?swap@?$basic_istream@GU?$char_traits@G@std@@@std@@IEAAXAEAV12@@"
             "Z";
    case 0x0517:
      return "?swap@?$basic_istream@_WU?$char_traits@_W@std@@@std@@IEAAXAEAV12@"
             "@Z";
    case 0x0518:
      return "?swap@?$basic_ostream@DU?$char_traits@D@std@@@std@@IEAAXAEAV12@@"
             "Z";
    case 0x0519:
      return "?swap@?$basic_ostream@GU?$char_traits@G@std@@@std@@IEAAXAEAV12@@"
             "Z";
    case 0x051a:
      return "?swap@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@IEAAXAEAV12@"
             "@Z";
    case 0x051b:
      return "?swap@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXAEAV12@"
             "@Z";
    case 0x051c:
      return "?swap@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAAXAEAV12@"
             "@Z";
    case 0x051d:
      return "?swap@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "IEAAXAEAV12@@Z";
    case 0x051e:
      return "?swap@ios_base@std@@QEAAXAEAV12@@Z";
    case 0x051f:
      return "?sync@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAHXZ";
    case 0x0520:
      return "?sync@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAHXZ";
    case 0x0521:
      return "?sync@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAHXZ";
    case 0x0522:
      return "?sync@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHXZ";
    case 0x0523:
      return "?sync@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAAHXZ";
    case 0x0524:
      return "?sync@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAAHXZ";
    case 0x0525:
      return "?sync_with_stdio@ios_base@std@@SA_N_N@Z";
    case 0x0526:
      return "?table@?$ctype@D@std@@QEBAPEBFXZ";
    case 0x0527:
      return "?table_size@?$ctype@D@std@@2_KB";
    case 0x0528:
      return "?tellg@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA?AV?$"
             "fpos@H@2@XZ";
    case 0x0529:
      return "?tellg@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAA?AV?$"
             "fpos@H@2@XZ";
    case 0x052a:
      return "?tellg@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAA?AV?$"
             "fpos@H@2@XZ";
    case 0x052b:
      return "?tellp@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAA?AV?$"
             "fpos@H@2@XZ";
    case 0x052c:
      return "?tellp@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAA?AV?$"
             "fpos@H@2@XZ";
    case 0x052d:
      return "?tellp@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAA?AV?$"
             "fpos@H@2@XZ";
    case 0x052e:
      return "?tie@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAPEAV?$basic_"
             "ostream@DU?$char_traits@D@std@@@2@PEAV32@@Z";
    case 0x052f:
      return "?tie@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBAPEAV?$basic_"
             "ostream@DU?$char_traits@D@std@@@2@XZ";
    case 0x0530:
      return "?tie@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAPEAV?$basic_"
             "ostream@GU?$char_traits@G@std@@@2@PEAV32@@Z";
    case 0x0531:
      return "?tie@?$basic_ios@GU?$char_traits@G@std@@@std@@QEBAPEAV?$basic_"
             "ostream@GU?$char_traits@G@std@@@2@XZ";
    case 0x0532:
      return "?tie@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAPEAV?$basic_"
             "ostream@_WU?$char_traits@_W@std@@@2@PEAV32@@Z";
    case 0x0533:
      return "?tie@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEBAPEAV?$basic_"
             "ostream@_WU?$char_traits@_W@std@@@2@XZ";
    case 0x0534:
      return "?tolower@?$ctype@D@std@@QEBADD@Z";
    case 0x0535:
      return "?tolower@?$ctype@D@std@@QEBAPEBDPEADPEBD@Z";
    case 0x0536:
      return "?tolower@?$ctype@G@std@@QEBAGG@Z";
    case 0x0537:
      return "?tolower@?$ctype@G@std@@QEBAPEBGPEAGPEBG@Z";
    case 0x0538:
      return "?tolower@?$ctype@_W@std@@QEBAPEB_WPEA_WPEB_W@Z";
    case 0x0539:
      return "?tolower@?$ctype@_W@std@@QEBA_W_W@Z";
    case 0x053a:
      return "?toupper@?$ctype@D@std@@QEBADD@Z";
    case 0x053b:
      return "?toupper@?$ctype@D@std@@QEBAPEBDPEADPEBD@Z";
    case 0x053c:
      return "?toupper@?$ctype@G@std@@QEBAGG@Z";
    case 0x053d:
      return "?toupper@?$ctype@G@std@@QEBAPEBGPEAGPEBG@Z";
    case 0x053e:
      return "?toupper@?$ctype@_W@std@@QEBAPEB_WPEA_WPEB_W@Z";
    case 0x053f:
      return "?toupper@?$ctype@_W@std@@QEBA_W_W@Z";
    case 0x0540:
      return "?try_to_lock@std@@3Utry_to_lock_t@1@B";
    case 0x0541:
      return "?uflow@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHXZ";
    case 0x0542:
      return "?uflow@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAAGXZ";
    case 0x0543:
      return "?uflow@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAAGXZ";
    case 0x0544:
      return "?uncaught_exception@std@@YA_NXZ";
    case 0x0545:
      return "?underflow@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "MEAAHXZ";
    case 0x0546:
      return "?underflow@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "MEAAGXZ";
    case 0x0547:
      return "?underflow@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "MEAAGXZ";
    case 0x0548:
      return "?unget@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "XZ";
    case 0x0549:
      return "?unget@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "XZ";
    case 0x054a:
      return "?unget@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "XZ";
    case 0x054b:
      return "?unsetf@ios_base@std@@QEAAXH@Z";
    case 0x054c:
      return "?unshift@?$codecvt@DDH@std@@QEBAHAEAHPEAD1AEAPEAD@Z";
    case 0x054d:
      return "?unshift@?$codecvt@GDH@std@@QEBAHAEAHPEAD1AEAPEAD@Z";
    case 0x054e:
      return "?unshift@?$codecvt@_WDH@std@@QEBAHAEAHPEAD1AEAPEAD@Z";
    case 0x054f:
      return "?wait@agent@Concurrency@@SA?AW4agent_status@2@PEAV12@I@Z";
    case 0x0550:
      return "?wait_for_all@agent@Concurrency@@SAX_KPEAPEAV12@PEAW4agent_"
             "status@2@I@Z";
    case 0x0551:
      return "?wait_for_one@agent@Concurrency@@SAX_KPEAPEAV12@AEAW4agent_"
             "status@2@AEA_KI@Z";
    case 0x0552:
      return "?wcerr@std@@3V?$basic_ostream@GU?$char_traits@G@std@@@1@A";
    case 0x0553:
      return "?wcerr@std@@3V?$basic_ostream@_WU?$char_traits@_W@std@@@1@A";
    case 0x0554:
      return "?wcin@std@@3V?$basic_istream@GU?$char_traits@G@std@@@1@A";
    case 0x0555:
      return "?wcin@std@@3V?$basic_istream@_WU?$char_traits@_W@std@@@1@A";
    case 0x0556:
      return "?wclog@std@@3V?$basic_ostream@GU?$char_traits@G@std@@@1@A";
    case 0x0557:
      return "?wclog@std@@3V?$basic_ostream@_WU?$char_traits@_W@std@@@1@A";
    case 0x0558:
      return "?wcout@std@@3V?$basic_ostream@GU?$char_traits@G@std@@@1@A";
    case 0x0559:
      return "?wcout@std@@3V?$basic_ostream@_WU?$char_traits@_W@std@@@1@A";
    case 0x055a:
      return "?widen@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBADD@Z";
    case 0x055b:
      return "?widen@?$basic_ios@GU?$char_traits@G@std@@@std@@QEBAGD@Z";
    case 0x055c:
      return "?widen@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEBA_WD@Z";
    case 0x055d:
      return "?widen@?$ctype@D@std@@QEBADD@Z";
    case 0x055e:
      return "?widen@?$ctype@D@std@@QEBAPEBDPEBD0PEAD@Z";
    case 0x055f:
      return "?widen@?$ctype@G@std@@QEBAGD@Z";
    case 0x0560:
      return "?widen@?$ctype@G@std@@QEBAPEBDPEBD0PEAG@Z";
    case 0x0561:
      return "?widen@?$ctype@_W@std@@QEBAPEBDPEBD0PEA_W@Z";
    case 0x0562:
      return "?widen@?$ctype@_W@std@@QEBA_WD@Z";
    case 0x0563:
      return "?width@ios_base@std@@QEAA_J_J@Z";
    case 0x0564:
      return "?width@ios_base@std@@QEBA_JXZ";
    case 0x0565:
      return "?write@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "PEBD_J@Z";
    case 0x0566:
      return "?write@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "PEBG_J@Z";
    case 0x0567:
      return "?write@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "PEB_W_J@Z";
    case 0x0568:
      return "?ws@std@@YAAEAV?$basic_istream@DU?$char_traits@D@std@@@1@AEAV21@@"
             "Z";
    case 0x0569:
      return "?ws@std@@YAAEAV?$basic_istream@GU?$char_traits@G@std@@@1@AEAV21@@"
             "Z";
    case 0x056a:
      return "?ws@std@@YAAEAV?$basic_istream@_WU?$char_traits@_W@std@@@1@"
             "AEAV21@@Z";
    case 0x056b:
      return "?xalloc@ios_base@std@@SAHXZ";
    case 0x056c:
      return "?xsgetn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_"
             "JPEAD_J@Z";
    case 0x056d:
      return "?xsgetn@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAA_"
             "JPEAG_J@Z";
    case 0x056e:
      return "?xsgetn@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAA_"
             "JPEA_W_J@Z";
    case 0x056f:
      return "?xsputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_"
             "JPEBD_J@Z";
    case 0x0570:
      return "?xsputn@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAA_"
             "JPEBG_J@Z";
    case 0x0571:
      return "?xsputn@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAA_"
             "JPEB_W_J@Z";
    case 0x0572:
      return "_Call_once";
    case 0x0573:
      return "_Call_onceEx";
    case 0x0574:
      return "_Cnd_broadcast";
    case 0x0575:
      return "_Cnd_destroy";
    case 0x0576:
      return "_Cnd_do_broadcast_at_thread_exit";
    case 0x0577:
      return "_Cnd_init";
    case 0x0578:
      return "_Cnd_register_at_thread_exit";
    case 0x0579:
      return "_Cnd_signal";
    case 0x057a:
      return "_Cnd_timedwait";
    case 0x057b:
      return "_Cnd_unregister_at_thread_exit";
    case 0x057c:
      return "_Cnd_wait";
    case 0x057d:
      return "_Cosh";
    case 0x057e:
      return "_Denorm";
    case 0x057f:
      return "_Dint";
    case 0x0580:
      return "_Dnorm";
    case 0x0581:
      return "_Do_call";
    case 0x0582:
      return "_Dscale";
    case 0x0583:
      return "_Dtento";
    case 0x0584:
      return "_Dtest";
    case 0x0585:
      return "_Dunscale";
    case 0x0586:
      return "_Eps";
    case 0x0587:
      return "_Exp";
    case 0x0588:
      return "_FCosh";
    case 0x0589:
      return "_FDenorm";
    case 0x058a:
      return "_FDint";
    case 0x058b:
      return "_FDnorm";
    case 0x058c:
      return "_FDscale";
    case 0x058d:
      return "_FDtento";
    case 0x058e:
      return "_FDtest";
    case 0x058f:
      return "_FDunscale";
    case 0x0590:
      return "_FEps";
    case 0x0591:
      return "_FExp";
    case 0x0592:
      return "_FInf";
    case 0x0593:
      return "_FNan";
    case 0x0594:
      return "_FPlsw";
    case 0x0595:
      return "_FPmsw";
    case 0x0596:
      return "_FRteps";
    case 0x0597:
      return "_FSinh";
    case 0x0598:
      return "_FSnan";
    case 0x0599:
      return "_FXbig";
    case 0x059a:
      return "_FXp_addh";
    case 0x059b:
      return "_FXp_addx";
    case 0x059c:
      return "_FXp_getw";
    case 0x059d:
      return "_FXp_invx";
    case 0x059e:
      return "_FXp_ldexpx";
    case 0x059f:
      return "_FXp_movx";
    case 0x05a0:
      return "_FXp_mulh";
    case 0x05a1:
      return "_FXp_mulx";
    case 0x05a2:
      return "_FXp_setn";
    case 0x05a3:
      return "_FXp_setw";
    case 0x05a4:
      return "_FXp_sqrtx";
    case 0x05a5:
      return "_FXp_subx";
    case 0x05a6:
      return "_FZero";
    case 0x05a7:
      return "_Getcoll";
    case 0x05a8:
      return "_Getctype";
    case 0x05a9:
      return "_Getcvt";
    case 0x05aa:
      return "_Getdateorder";
    case 0x05ab:
      return "_Getwctype";
    case 0x05ac:
      return "_Getwctypes";
    case 0x05ad:
      return "_Hugeval";
    case 0x05ae:
      return "_Inf";
    case 0x05af:
      return "_LCosh";
    case 0x05b0:
      return "_LDenorm";
    case 0x05b1:
      return "_LDint";
    case 0x05b2:
      return "_LDscale";
    case 0x05b3:
      return "_LDtento";
    case 0x05b4:
      return "_LDtest";
    case 0x05b5:
      return "_LDunscale";
    case 0x05b6:
      return "_LEps";
    case 0x05b7:
      return "_LExp";
    case 0x05b8:
      return "_LInf";
    case 0x05b9:
      return "_LNan";
    case 0x05ba:
      return "_LPlsw";
    case 0x05bb:
      return "_LPmsw";
    case 0x05bc:
      return "_LPoly";
    case 0x05bd:
      return "_LRteps";
    case 0x05be:
      return "_LSinh";
    case 0x05bf:
      return "_LSnan";
    case 0x05c0:
      return "_LXbig";
    case 0x05c1:
      return "_LXp_addh";
    case 0x05c2:
      return "_LXp_addx";
    case 0x05c3:
      return "_LXp_getw";
    case 0x05c4:
      return "_LXp_invx";
    case 0x05c5:
      return "_LXp_ldexpx";
    case 0x05c6:
      return "_LXp_movx";
    case 0x05c7:
      return "_LXp_mulh";
    case 0x05c8:
      return "_LXp_mulx";
    case 0x05c9:
      return "_LXp_setn";
    case 0x05ca:
      return "_LXp_setw";
    case 0x05cb:
      return "_LXp_sqrtx";
    case 0x05cc:
      return "_LXp_subx";
    case 0x05cd:
      return "_LZero";
    case 0x05ce:
      return "_Lock_shared_ptr_spin_lock";
    case 0x05cf:
      return "_Mbrtowc";
    case 0x05d0:
      return "_Mtx_clear_owner";
    case 0x05d1:
      return "_Mtx_current_owns";
    case 0x05d2:
      return "_Mtx_destroy";
    case 0x05d3:
      return "_Mtx_getconcrtcs";
    case 0x05d4:
      return "_Mtx_init";
    case 0x05d5:
      return "_Mtx_lock";
    case 0x05d6:
      return "_Mtx_reset_owner";
    case 0x05d7:
      return "_Mtx_timedlock";
    case 0x05d8:
      return "_Mtx_trylock";
    case 0x05d9:
      return "_Mtx_unlock";
    case 0x05da:
      return "_Mtxdst";
    case 0x05db:
      return "_Mtxinit";
    case 0x05dc:
      return "_Mtxlock";
    case 0x05dd:
      return "_Mtxunlock";
    case 0x05de:
      return "_Nan";
    case 0x05df:
      return "_Once";
    case 0x05e0:
      return "_Plsw";
    case 0x05e1:
      return "_Pmsw";
    case 0x05e2:
      return "_Poly";
    case 0x05e3:
      return "_Rteps";
    case 0x05e4:
      return "_Sinh";
    case 0x05e5:
      return "_Snan";
    case 0x05e6:
      return "_Stod";
    case 0x05e7:
      return "_Stodx";
    case 0x05e8:
      return "_Stof";
    case 0x05e9:
      return "_Stoflt";
    case 0x05ea:
      return "_Stofx";
    case 0x05eb:
      return "_Stold";
    case 0x05ec:
      return "_Stoldx";
    case 0x05ed:
      return "_Stoll";
    case 0x05ee:
      return "_Stollx";
    case 0x05ef:
      return "_Stolx";
    case 0x05f0:
      return "_Stopfx";
    case 0x05f1:
      return "_Stoul";
    case 0x05f2:
      return "_Stoull";
    case 0x05f3:
      return "_Stoullx";
    case 0x05f4:
      return "_Stoulx";
    case 0x05f5:
      return "_Stoxflt";
    case 0x05f6:
      return "_Strcoll";
    case 0x05f7:
      return "_Strxfrm";
    case 0x05f8:
      return "_Thrd_abort";
    case 0x05f9:
      return "_Thrd_create";
    case 0x05fa:
      return "_Thrd_current";
    case 0x05fb:
      return "_Thrd_detach";
    case 0x05fc:
      return "_Thrd_equal";
    case 0x05fd:
      return "_Thrd_exit";
    case 0x05fe:
      return "_Thrd_join";
    case 0x05ff:
      return "_Thrd_lt";
    case 0x0600:
      return "_Thrd_sleep";
    case 0x0601:
      return "_Thrd_start";
    case 0x0602:
      return "_Thrd_yield";
    case 0x0603:
      return "_Tolower";
    case 0x0604:
      return "_Toupper";
    case 0x0605:
      return "_Towlower";
    case 0x0606:
      return "_Towupper";
    case 0x0607:
      return "_Tss_create";
    case 0x0608:
      return "_Tss_delete";
    case 0x0609:
      return "_Tss_get";
    case 0x060a:
      return "_Tss_set";
    case 0x060b:
      return "_Unlock_shared_ptr_spin_lock";
    case 0x060c:
      return "_Wcrtomb";
    case 0x060d:
      return "_Wcscoll";
    case 0x060e:
      return "_Wcsxfrm";
    case 0x060f:
      return "_Xbig";
    case 0x0610:
      return "_Xp_addh";
    case 0x0611:
      return "_Xp_addx";
    case 0x0612:
      return "_Xp_getw";
    case 0x0613:
      return "_Xp_invx";
    case 0x0614:
      return "_Xp_ldexpx";
    case 0x0615:
      return "_Xp_movx";
    case 0x0616:
      return "_Xp_mulh";
    case 0x0617:
      return "_Xp_mulx";
    case 0x0618:
      return "_Xp_setn";
    case 0x0619:
      return "_Xp_setw";
    case 0x061a:
      return "_Xp_sqrtx";
    case 0x061b:
      return "_Xp_subx";
    case 0x061c:
      return "_Xtime_diff_to_millis";
    case 0x061d:
      return "_Xtime_diff_to_millis2";
    case 0x061e:
      return "_Xtime_get_ticks";
    case 0x061f:
      return "_Zero";
    case 0x0620:
      return "__Wcrtomb_lk";
    case 0x0621:
      return "xtime_get";
  }
  return nullptr;
}

}  // namespace PE
}  // namespace LIEF

#endif
