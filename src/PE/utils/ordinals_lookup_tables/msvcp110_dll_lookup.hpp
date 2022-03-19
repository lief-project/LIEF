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
#ifndef LIEF_PE_MSVCP110_DLL_LOOKUP_H_
#define LIEF_PE_MSVCP110_DLL_LOOKUP_H_

namespace LIEF {
namespace PE {

const char* msvcp110_dll_lookup(uint32_t i) {
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
      return "??Bios_base@std@@QEBAPEAXXZ";
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
      return "?NFS_Allocate@details@Concurrency@@YAPEAX_K0PEAX@Z";
    case 0x018b:
      return "?NFS_Free@details@Concurrency@@YAXPEAX@Z";
    case 0x018c:
      return "?NFS_GetLineSize@details@Concurrency@@YA_KXZ";
    case 0x018d:
      return "?_10@placeholders@std@@3V?$_Ph@$09@2@A";
    case 0x018e:
      return "?_11@placeholders@std@@3V?$_Ph@$0L@@2@A";
    case 0x018f:
      return "?_12@placeholders@std@@3V?$_Ph@$0M@@2@A";
    case 0x0190:
      return "?_13@placeholders@std@@3V?$_Ph@$0N@@2@A";
    case 0x0191:
      return "?_14@placeholders@std@@3V?$_Ph@$0O@@2@A";
    case 0x0192:
      return "?_15@placeholders@std@@3V?$_Ph@$0P@@2@A";
    case 0x0193:
      return "?_16@placeholders@std@@3V?$_Ph@$0BA@@2@A";
    case 0x0194:
      return "?_17@placeholders@std@@3V?$_Ph@$0BB@@2@A";
    case 0x0195:
      return "?_18@placeholders@std@@3V?$_Ph@$0BC@@2@A";
    case 0x0196:
      return "?_19@placeholders@std@@3V?$_Ph@$0BD@@2@A";
    case 0x0197:
      return "?_1@placeholders@std@@3V?$_Ph@$00@2@A";
    case 0x0198:
      return "?_20@placeholders@std@@3V?$_Ph@$0BE@@2@A";
    case 0x0199:
      return "?_2@placeholders@std@@3V?$_Ph@$01@2@A";
    case 0x019a:
      return "?_3@placeholders@std@@3V?$_Ph@$02@2@A";
    case 0x019b:
      return "?_4@placeholders@std@@3V?$_Ph@$03@2@A";
    case 0x019c:
      return "?_5@placeholders@std@@3V?$_Ph@$04@2@A";
    case 0x019d:
      return "?_6@placeholders@std@@3V?$_Ph@$05@2@A";
    case 0x019e:
      return "?_7@placeholders@std@@3V?$_Ph@$06@2@A";
    case 0x019f:
      return "?_8@placeholders@std@@3V?$_Ph@$07@2@A";
    case 0x01a0:
      return "?_9@placeholders@std@@3V?$_Ph@$08@2@A";
    case 0x01a1:
      return "?_Add_vtordisp1@?$basic_ios@DU?$char_traits@D@std@@@std@@UEAAXXZ";
    case 0x01a2:
      return "?_Add_vtordisp1@?$basic_ios@GU?$char_traits@G@std@@@std@@UEAAXXZ";
    case 0x01a3:
      return "?_Add_vtordisp1@?$basic_ios@_WU?$char_traits@_W@std@@@std@@"
             "UEAAXXZ";
    case 0x01a4:
      return "?_Add_vtordisp1@?$basic_istream@DU?$char_traits@D@std@@@std@@"
             "UEAAXXZ";
    case 0x01a5:
      return "?_Add_vtordisp1@?$basic_istream@GU?$char_traits@G@std@@@std@@"
             "UEAAXXZ";
    case 0x01a6:
      return "?_Add_vtordisp1@?$basic_istream@_WU?$char_traits@_W@std@@@std@@"
             "UEAAXXZ";
    case 0x01a7:
      return "?_Add_vtordisp2@?$basic_ios@DU?$char_traits@D@std@@@std@@UEAAXXZ";
    case 0x01a8:
      return "?_Add_vtordisp2@?$basic_ios@GU?$char_traits@G@std@@@std@@UEAAXXZ";
    case 0x01a9:
      return "?_Add_vtordisp2@?$basic_ios@_WU?$char_traits@_W@std@@@std@@"
             "UEAAXXZ";
    case 0x01aa:
      return "?_Add_vtordisp2@?$basic_ostream@DU?$char_traits@D@std@@@std@@"
             "UEAAXXZ";
    case 0x01ab:
      return "?_Add_vtordisp2@?$basic_ostream@GU?$char_traits@G@std@@@std@@"
             "UEAAXXZ";
    case 0x01ac:
      return "?_Add_vtordisp2@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@"
             "UEAAXXZ";
    case 0x01ad:
      return "?_Addcats@_Locinfo@std@@QEAAAEAV12@HPEBD@Z";
    case 0x01ae:
      return "?_Addfac@_Locimp@locale@std@@AEAAXPEAVfacet@23@_K@Z";
    case 0x01af:
      return "?_Addstd@ios_base@std@@SAXPEAV12@@Z";
    case 0x01b0:
      return "?_Advance@_Concurrent_queue_iterator_base_v4@details@Concurrency@"
             "@IEAAXXZ";
    case 0x01b1:
      return "?_Assign@_Concurrent_queue_iterator_base_v4@details@Concurrency@@"
             "IEAAXAEBV123@@Z";
    case 0x01b2:
      return "?_Atexit@@YAXP6AXXZ@Z";
    case 0x01b3:
      return "?_BADOFF@std@@3_JB";
    case 0x01b4:
      return "?_Byte_reverse_table@details@Concurrency@@3QBEB";
    case 0x01b5:
      return "?_C_str@?$_Yarn@D@std@@QEBAPEBDXZ";
    case 0x01b6:
      return "?_C_str@?$_Yarn@_W@std@@QEBAPEB_WXZ";
    case 0x01b7:
      return "?_Callfns@ios_base@std@@AEAAXW4event@12@@Z";
    case 0x01b8:
      return "?_Clocptr@_Locimp@locale@std@@0PEAV123@EA";
    case 0x01b9:
      return "?_Close_dir@sys@tr2@std@@YAXPEAX@Z";
    case 0x01ba:
      return "?_Copy_file@sys@tr2@std@@YAHPEBD0_N@Z";
    case 0x01bb:
      return "?_Copy_file@sys@tr2@std@@YAHPEB_W0_N@Z";
    case 0x01bc:
      return "?_Current_get@sys@tr2@std@@YAPEADPEAD@Z";
    case 0x01bd:
      return "?_Current_get@sys@tr2@std@@YAPEA_WPEA_W@Z";
    case 0x01be:
      return "?_Current_set@sys@tr2@std@@YA_NPEBD@Z";
    case 0x01bf:
      return "?_Current_set@sys@tr2@std@@YA_NPEB_W@Z";
    case 0x01c0:
      return "?_Decref@facet@locale@std@@UEAAPEAV_Facet_base@3@XZ";
    case 0x01c1:
      return "?_Donarrow@?$ctype@G@std@@IEBADGD@Z";
    case 0x01c2:
      return "?_Donarrow@?$ctype@_W@std@@IEBAD_WD@Z";
    case 0x01c3:
      return "?_Dowiden@?$ctype@G@std@@IEBAGD@Z";
    case 0x01c4:
      return "?_Dowiden@?$ctype@_W@std@@IEBA_WD@Z";
    case 0x01c5:
      return "?_Empty@?$_Yarn@D@std@@QEBA_NXZ";
    case 0x01c6:
      return "?_Empty@?$_Yarn@_W@std@@QEBA_NXZ";
    case 0x01c7:
      return "?_Equivalent@sys@tr2@std@@YAHPEBD0@Z";
    case 0x01c8:
      return "?_Equivalent@sys@tr2@std@@YAHPEB_W0@Z";
    case 0x01c9:
      return "?_Ffmt@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@AEBAPEADPEADDH@Z";
    case 0x01ca:
      return "?_Ffmt@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@AEBAPEADPEADDH@Z";
    case 0x01cb:
      return "?_Ffmt@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@AEBAPEADPEADDH@Z";
    case 0x01cc:
      return "?_File_size@sys@tr2@std@@YA_KPEBD@Z";
    case 0x01cd:
      return "?_File_size@sys@tr2@std@@YA_KPEB_W@Z";
    case 0x01ce:
      return "?_Findarr@ios_base@std@@AEAAAEAU_Iosarray@12@H@Z";
    case 0x01cf:
      return "?_Fiopen@std@@YAPEAU_iobuf@@PEBDHH@Z";
    case 0x01d0:
      return "?_Fiopen@std@@YAPEAU_iobuf@@PEBGHH@Z";
    case 0x01d1:
      return "?_Fiopen@std@@YAPEAU_iobuf@@PEB_WHH@Z";
    case 0x01d2:
      return "?_Fput@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@AEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DPEBD_K333@Z";
    case 0x01d3:
      return "?_Fput@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@AEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GPEBD_K333@Z";
    case 0x01d4:
      return "?_Fput@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@AEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_WPEBD_K444@Z";
    case 0x01d5:
      return "?_Future_error_map@std@@YAPEBDH@Z";
    case 0x01d6:
      return "?_GetCombinableSize@details@Concurrency@@YA_KXZ";
    case 0x01d7:
      return "?_GetCurrentThreadId@details@Concurrency@@YAKXZ";
    case 0x01d8:
      return "?_GetNextAsyncId@details@Concurrency@@YAIXZ";
    case 0x01d9:
      return "?_Get_future_error_what@std@@YAPEBDH@Z";
    case 0x01da:
      return "?_Getcat@?$codecvt@DDH@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01db:
      return "?_Getcat@?$codecvt@GDH@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01dc:
      return "?_Getcat@?$codecvt@_WDH@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01dd:
      return "?_Getcat@?$ctype@D@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01de:
      return "?_Getcat@?$ctype@G@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01df:
      return "?_Getcat@?$ctype@_W@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01e0:
      return "?_Getcat@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@"
             "@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01e1:
      return "?_Getcat@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@"
             "@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01e2:
      return "?_Getcat@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01e3:
      return "?_Getcat@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@"
             "@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01e4:
      return "?_Getcat@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@"
             "@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01e5:
      return "?_Getcat@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01e6:
      return "?_Getcat@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01e7:
      return "?_Getcat@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01e8:
      return "?_Getcat@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01e9:
      return "?_Getcat@?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01ea:
      return "?_Getcat@?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01eb:
      return "?_Getcat@?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z";
    case 0x01ec:
      return "?_Getcat@facet@locale@std@@SA_KPEAPEBV123@PEBV23@@Z";
    case 0x01ed:
      return "?_Getcoll@_Locinfo@std@@QEBA?AU_Collvec@@XZ";
    case 0x01ee:
      return "?_Getctype@_Locinfo@std@@QEBA?AU_Ctypevec@@XZ";
    case 0x01ef:
      return "?_Getcvt@_Locinfo@std@@QEBA?AU_Cvtvec@@XZ";
    case 0x01f0:
      return "?_Getdateorder@_Locinfo@std@@QEBAHXZ";
    case 0x01f1:
      return "?_Getdays@_Locinfo@std@@QEBAPEBDXZ";
    case 0x01f2:
      return "?_Getfalse@_Locinfo@std@@QEBAPEBDXZ";
    case 0x01f3:
      return "?_Getffld@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@2@1AEAVios_base@2@PEAH@Z";
    case 0x01f4:
      return "?_Getffld@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@2@1AEAVios_base@2@PEAH@Z";
    case 0x01f5:
      return "?_Getffld@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@2@1AEAVios_base@2@PEAH@Z";
    case 0x01f6:
      return "?_Getffldx@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@2@1AEAVios_base@2@PEAH@Z";
    case 0x01f7:
      return "?_Getffldx@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@2@1AEAVios_base@2@PEAH@Z";
    case 0x01f8:
      return "?_Getffldx@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@2@1AEAVios_base@2@PEAH@Z";
    case 0x01f9:
      return "?_Getfmt@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@IEBA?AV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@PEBD@Z";
    case 0x01fa:
      return "?_Getfmt@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@IEBA?AV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@PEBD@Z";
    case 0x01fb:
      return "?_Getfmt@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@IEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@PEBD@Z";
    case 0x01fc:
      return "?_Getgloballocale@locale@std@@CAPEAV_Locimp@12@XZ";
    case 0x01fd:
      return "?_Getifld@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@2@1HAEBVlocale@2@@Z";
    case 0x01fe:
      return "?_Getifld@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@2@1HAEBVlocale@2@@Z";
    case 0x01ff:
      return "?_Getifld@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@2@1HAEBVlocale@2@@Z";
    case 0x0200:
      return "?_Getint@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@AEBAHAEAV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@2@0HHAEAHAEBV?$ctype@D@2@@Z";
    case 0x0201:
      return "?_Getint@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@AEBAHAEAV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@2@0HHAEAHAEBV?$ctype@G@2@@Z";
    case 0x0202:
      return "?_Getint@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@AEBAHAEAV?$istreambuf_iterator@_WU?$char_traits@"
             "_W@std@@@2@0HHAEAHAEBV?$ctype@_W@2@@Z";
    case 0x0203:
      return "?_Getlconv@_Locinfo@std@@QEBAPEBUlconv@@XZ";
    case 0x0204:
      return "?_Getmonths@_Locinfo@std@@QEBAPEBDXZ";
    case 0x0205:
      return "?_Getname@_Locinfo@std@@QEBAPEBDXZ";
    case 0x0206:
      return "?_Getpfirst@_Container_base12@std@@QEBAPEAPEAU_Iterator_base12@2@"
             "XZ";
    case 0x0207:
      return "?_Getptr@_Timevec@std@@QEBAPEAXXZ";
    case 0x0208:
      return "?_Gettnames@_Locinfo@std@@QEBA?AV_Timevec@2@XZ";
    case 0x0209:
      return "?_Gettrue@_Locinfo@std@@QEBAPEBDXZ";
    case 0x020a:
      return "?_Gnavail@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBA_"
             "JXZ";
    case 0x020b:
      return "?_Gnavail@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEBA_"
             "JXZ";
    case 0x020c:
      return "?_Gnavail@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEBA_"
             "JXZ";
    case 0x020d:
      return "?_Gndec@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "IEAAPEADXZ";
    case 0x020e:
      return "?_Gndec@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "IEAAPEAGXZ";
    case 0x020f:
      return "?_Gndec@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAPEA_"
             "WXZ";
    case 0x0210:
      return "?_Gninc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "IEAAPEADXZ";
    case 0x0211:
      return "?_Gninc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "IEAAPEAGXZ";
    case 0x0212:
      return "?_Gninc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAPEA_"
             "WXZ";
    case 0x0213:
      return "?_Gnpreinc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "IEAAPEADXZ";
    case 0x0214:
      return "?_Gnpreinc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "IEAAPEAGXZ";
    case 0x0215:
      return "?_Gnpreinc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "IEAAPEA_WXZ";
    case 0x0216:
      return "?_Id_cnt@id@locale@std@@0HA";
    case 0x0217:
      return "?_Ifmt@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@AEBAPEADPEADPEBDH@Z";
    case 0x0218:
      return "?_Ifmt@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@AEBAPEADPEADPEBDH@Z";
    case 0x0219:
      return "?_Ifmt@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@AEBAPEADPEADPEBDH@Z";
    case 0x021a:
      return "?_Incref@facet@locale@std@@UEAAXXZ";
    case 0x021b:
      return "?_Index@ios_base@std@@0HA";
    case 0x021c:
      return "?_Init@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "IEAAXPEAPEAD0PEAH001@Z";
    case 0x021d:
      return "?_Init@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXXZ";
    case 0x021e:
      return "?_Init@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "IEAAXPEAPEAG0PEAH001@Z";
    case 0x021f:
      return "?_Init@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAAXXZ";
    case 0x0220:
      return "?_Init@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "IEAAXPEAPEA_W0PEAH001@Z";
    case 0x0221:
      return "?_Init@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAXXZ";
    case 0x0222:
      return "?_Init@?$codecvt@DDH@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0223:
      return "?_Init@?$codecvt@GDH@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0224:
      return "?_Init@?$codecvt@_WDH@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0225:
      return "?_Init@?$ctype@D@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0226:
      return "?_Init@?$ctype@G@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0227:
      return "?_Init@?$ctype@_W@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0228:
      return "?_Init@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0229:
      return "?_Init@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x022a:
      return "?_Init@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x022b:
      return "?_Init@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x022c:
      return "?_Init@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x022d:
      return "?_Init@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x022e:
      return "?_Init@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x022f:
      return "?_Init@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0230:
      return "?_Init@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0231:
      return "?_Init@?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0232:
      return "?_Init@?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0233:
      return "?_Init@?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@IEAAXAEBV_Locinfo@2@@Z";
    case 0x0234:
      return "?_Init@ios_base@std@@IEAAXXZ";
    case 0x0235:
      return "?_Init@locale@std@@CAPEAV_Locimp@12@_N@Z";
    case 0x0236:
      return "?_Init_cnt@Init@ios_base@std@@0HA";
    case 0x0237:
      return "?_Init_cnt@_UShinit@std@@0HA";
    case 0x0238:
      return "?_Init_cnt@_Winit@std@@0HA";
    case 0x0239:
      return "?_Init_cnt_func@Init@ios_base@std@@CAAEAHXZ";
    case 0x023a:
      return "?_Init_ctor@Init@ios_base@std@@CAXPEAV123@@Z";
    case 0x023b:
      return "?_Init_dtor@Init@ios_base@std@@CAXPEAV123@@Z";
    case 0x023c:
      return "?_Init_locks_ctor@_Init_locks@std@@CAXPEAV12@@Z";
    case 0x023d:
      return "?_Init_locks_dtor@_Init_locks@std@@CAXPEAV12@@Z";
    case 0x023e:
      return "?_Internal_assign@_Concurrent_vector_base_v4@details@Concurrency@"
             "@IEAAXAEBV123@_KP6AXPEAX1@ZP6AX2PEBX1@Z5@Z";
    case 0x023f:
      return "?_Internal_capacity@_Concurrent_vector_base_v4@details@"
             "Concurrency@@IEBA_KXZ";
    case 0x0240:
      return "?_Internal_clear@_Concurrent_vector_base_v4@details@Concurrency@@"
             "IEAA_KP6AXPEAX_K@Z@Z";
    case 0x0241:
      return "?_Internal_compact@_Concurrent_vector_base_v4@details@"
             "Concurrency@@IEAAPEAX_KPEAXP6AX10@ZP6AX1PEBX0@Z@Z";
    case 0x0242:
      return "?_Internal_copy@_Concurrent_vector_base_v4@details@Concurrency@@"
             "IEAAXAEBV123@_KP6AXPEAXPEBX1@Z@Z";
    case 0x0243:
      return "?_Internal_empty@_Concurrent_queue_base_v4@details@Concurrency@@"
             "IEBA_NXZ";
    case 0x0244:
      return "?_Internal_finish_clear@_Concurrent_queue_base_v4@details@"
             "Concurrency@@IEAAXXZ";
    case 0x0245:
      return "?_Internal_grow_by@_Concurrent_vector_base_v4@details@"
             "Concurrency@@IEAA_K_K0P6AXPEAXPEBX0@Z2@Z";
    case 0x0246:
      return "?_Internal_grow_to_at_least_with_result@_Concurrent_vector_base_"
             "v4@details@Concurrency@@IEAA_K_K0P6AXPEAXPEBX0@Z2@Z";
    case 0x0247:
      return "?_Internal_move_push@_Concurrent_queue_base_v4@details@"
             "Concurrency@@IEAAXPEAX@Z";
    case 0x0248:
      return "?_Internal_pop_if_present@_Concurrent_queue_base_v4@details@"
             "Concurrency@@IEAA_NPEAX@Z";
    case 0x0249:
      return "?_Internal_push@_Concurrent_queue_base_v4@details@Concurrency@@"
             "IEAAXPEBX@Z";
    case 0x024a:
      return "?_Internal_push_back@_Concurrent_vector_base_v4@details@"
             "Concurrency@@IEAAPEAX_KAEA_K@Z";
    case 0x024b:
      return "?_Internal_reserve@_Concurrent_vector_base_v4@details@"
             "Concurrency@@IEAAX_K00@Z";
    case 0x024c:
      return "?_Internal_resize@_Concurrent_vector_base_v4@details@Concurrency@"
             "@IEAAX_K00P6AXPEAX0@ZP6AX1PEBX0@Z3@Z";
    case 0x024d:
      return "?_Internal_size@_Concurrent_queue_base_v4@details@Concurrency@@"
             "IEBA_KXZ";
    case 0x024e:
      return "?_Internal_swap@_Concurrent_queue_base_v4@details@Concurrency@@"
             "IEAAXAEAV123@@Z";
    case 0x024f:
      return "?_Internal_swap@_Concurrent_vector_base_v4@details@Concurrency@@"
             "IEAAXAEAV123@@Z";
    case 0x0250:
      return "?_Internal_throw_exception@_Concurrent_queue_base_v4@details@"
             "Concurrency@@IEBAXXZ";
    case 0x0251:
      return "?_Internal_throw_exception@_Concurrent_vector_base_v4@details@"
             "Concurrency@@IEBAX_K@Z";
    case 0x0252:
      return "?_Ios_base_dtor@ios_base@std@@CAXPEAV12@@Z";
    case 0x0253:
      return "?_Ipfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA_N_N@Z";
    case 0x0254:
      return "?_Ipfx@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAA_N_N@Z";
    case 0x0255:
      return "?_Ipfx@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAA_N_N@Z";
    case 0x0256:
      return "?_Iput@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@AEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DPEAD_K@Z";
    case 0x0257:
      return "?_Iput@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@AEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GPEAD_K@Z";
    case 0x0258:
      return "?_Iput@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@AEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_WPEAD_K@Z";
    case 0x0259:
      return "?_Last_write_time@sys@tr2@std@@YAXPEBD_J@Z";
    case 0x025a:
      return "?_Last_write_time@sys@tr2@std@@YAXPEB_W_J@Z";
    case 0x025b:
      return "?_Last_write_time@sys@tr2@std@@YA_JPEBD@Z";
    case 0x025c:
      return "?_Last_write_time@sys@tr2@std@@YA_JPEB_W@Z";
    case 0x025d:
      return "?_Launch@_Pad@std@@QEAAXPEAU_Thrd_imp_t@@@Z";
    case 0x025e:
      return "?_Link@sys@tr2@std@@YAHPEBD0@Z";
    case 0x025f:
      return "?_Link@sys@tr2@std@@YAHPEB_W0@Z";
    case 0x0260:
      return "?_Locimp_Addfac@_Locimp@locale@std@@CAXPEAV123@PEAVfacet@23@_K@Z";
    case 0x0261:
      return "?_Locimp_ctor@_Locimp@locale@std@@CAXPEAV123@AEBV123@@Z";
    case 0x0262:
      return "?_Locimp_dtor@_Locimp@locale@std@@CAXPEAV123@@Z";
    case 0x0263:
      return "?_Locinfo_Addcats@_Locinfo@std@@SAAEAV12@PEAV12@HPEBD@Z";
    case 0x0264:
      return "?_Locinfo_ctor@_Locinfo@std@@SAXPEAV12@HPEBD@Z";
    case 0x0265:
      return "?_Locinfo_ctor@_Locinfo@std@@SAXPEAV12@PEBD@Z";
    case 0x0266:
      return "?_Locinfo_dtor@_Locinfo@std@@SAXPEAV12@@Z";
    case 0x0267:
      return "?_Lock@?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAAXXZ";
    case 0x0268:
      return "?_Lock@?$basic_streambuf@GU?$char_traits@G@std@@@std@@UEAAXXZ";
    case 0x0269:
      return "?_Lock@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@UEAAXXZ";
    case 0x026a:
      return "?_Lockit_ctor@_Lockit@std@@CAXPEAV12@@Z";
    case 0x026b:
      return "?_Lockit_ctor@_Lockit@std@@CAXPEAV12@H@Z";
    case 0x026c:
      return "?_Lockit_ctor@_Lockit@std@@SAXH@Z";
    case 0x026d:
      return "?_Lockit_dtor@_Lockit@std@@CAXPEAV12@@Z";
    case 0x026e:
      return "?_Lockit_dtor@_Lockit@std@@SAXH@Z";
    case 0x026f:
      return "?_Lstat@sys@tr2@std@@YA?AW4file_type@123@PEBDAEAH@Z";
    case 0x0270:
      return "?_Lstat@sys@tr2@std@@YA?AW4file_type@123@PEB_WAEAH@Z";
    case 0x0271:
      return "?_MP_Add@std@@YAXQEA_K_K@Z";
    case 0x0272:
      return "?_MP_Get@std@@YA_KQEA_K@Z";
    case 0x0273:
      return "?_MP_Mul@std@@YAXQEA_K_K1@Z";
    case 0x0274:
      return "?_MP_Rem@std@@YAXQEA_K_K@Z";
    case 0x0275:
      return "?_Make_dir@sys@tr2@std@@YAHPEBD@Z";
    case 0x0276:
      return "?_Make_dir@sys@tr2@std@@YAHPEB_W@Z";
    case 0x0277:
      return "?_Makeloc@_Locimp@locale@std@@CAPEAV123@AEBV_Locinfo@3@HPEAV123@"
             "PEBV23@@Z";
    case 0x0278:
      return "?_Makeushloc@_Locimp@locale@std@@CAXAEBV_Locinfo@3@HPEAV123@"
             "PEBV23@@Z";
    case 0x0279:
      return "?_Makewloc@_Locimp@locale@std@@CAXAEBV_Locinfo@3@HPEAV123@PEBV23@"
             "@Z";
    case 0x027a:
      return "?_Makexloc@_Locimp@locale@std@@CAXAEBV_Locinfo@3@HPEAV123@PEBV23@"
             "@Z";
    case 0x027b:
      return "?_Mtx_delete@threads@stdext@@YAXPEAX@Z";
    case 0x027c:
      return "?_Mtx_lock@threads@stdext@@YAXPEAX@Z";
    case 0x027d:
      return "?_Mtx_new@threads@stdext@@YAXAEAPEAX@Z";
    case 0x027e:
      return "?_Mtx_unlock@threads@stdext@@YAXPEAX@Z";
    case 0x027f:
      return "?_New_Locimp@_Locimp@locale@std@@CAPEAV123@AEBV123@@Z";
    case 0x0280:
      return "?_New_Locimp@_Locimp@locale@std@@CAPEAV123@_N@Z";
    case 0x0281:
      return "?_Open_dir@sys@tr2@std@@YAPEAXPEADPEBDAEAHAEAW4file_type@123@@Z";
    case 0x0282:
      return "?_Open_dir@sys@tr2@std@@YAPEAXPEA_WPEB_WAEAHAEAW4file_type@123@@"
             "Z";
    case 0x0283:
      return "?_Orphan_all@_Container_base0@std@@QEAAXXZ";
    case 0x0284:
      return "?_Orphan_all@_Container_base12@std@@QEAAXXZ";
    case 0x0285:
      return "?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ";
    case 0x0286:
      return "?_Osfx@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAXXZ";
    case 0x0287:
      return "?_Osfx@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAXXZ";
    case 0x0288:
      return "?_Pnavail@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBA_"
             "JXZ";
    case 0x0289:
      return "?_Pnavail@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEBA_"
             "JXZ";
    case 0x028a:
      return "?_Pnavail@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEBA_"
             "JXZ";
    case 0x028b:
      return "?_Pninc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "IEAAPEADXZ";
    case 0x028c:
      return "?_Pninc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "IEAAPEAGXZ";
    case 0x028d:
      return "?_Pninc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAPEA_"
             "WXZ";
    case 0x028e:
      return "?_Ptr_cerr@std@@3PEAV?$basic_ostream@DU?$char_traits@D@std@@@1@"
             "EA";
    case 0x028f:
      return "?_Ptr_cin@std@@3PEAV?$basic_istream@DU?$char_traits@D@std@@@1@EA";
    case 0x0290:
      return "?_Ptr_clog@std@@3PEAV?$basic_ostream@DU?$char_traits@D@std@@@1@"
             "EA";
    case 0x0291:
      return "?_Ptr_cout@std@@3PEAV?$basic_ostream@DU?$char_traits@D@std@@@1@"
             "EA";
    case 0x0292:
      return "?_Ptr_wcerr@std@@3PEAV?$basic_ostream@GU?$char_traits@G@std@@@1@"
             "EA";
    case 0x0293:
      return "?_Ptr_wcerr@std@@3PEAV?$basic_ostream@_WU?$char_traits@_W@std@@@"
             "1@EA";
    case 0x0294:
      return "?_Ptr_wcin@std@@3PEAV?$basic_istream@GU?$char_traits@G@std@@@1@"
             "EA";
    case 0x0295:
      return "?_Ptr_wcin@std@@3PEAV?$basic_istream@_WU?$char_traits@_W@std@@@1@"
             "EA";
    case 0x0296:
      return "?_Ptr_wclog@std@@3PEAV?$basic_ostream@GU?$char_traits@G@std@@@1@"
             "EA";
    case 0x0297:
      return "?_Ptr_wclog@std@@3PEAV?$basic_ostream@_WU?$char_traits@_W@std@@@"
             "1@EA";
    case 0x0298:
      return "?_Ptr_wcout@std@@3PEAV?$basic_ostream@GU?$char_traits@G@std@@@1@"
             "EA";
    case 0x0299:
      return "?_Ptr_wcout@std@@3PEAV?$basic_ostream@_WU?$char_traits@_W@std@@@"
             "1@EA";
    case 0x029a:
      return "?_Put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@AEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@PEBD_K@Z";
    case 0x029b:
      return "?_Put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@AEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@PEBG_K@Z";
    case 0x029c:
      return "?_Put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@std@@@std@@AEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@2@V32@PEB_W_K@Z";
    case 0x029d:
      return "?_Raise_handler@std@@3P6AXAEBVexception@stdext@@@ZEA";
    case 0x029e:
      return "?_Random_device@std@@YAIXZ";
    case 0x029f:
      return "?_Read_dir@sys@tr2@std@@YAPEADPEADPEAXAEAW4file_type@123@@Z";
    case 0x02a0:
      return "?_Read_dir@sys@tr2@std@@YAPEA_WPEA_WPEAXAEAW4file_type@123@@Z";
    case 0x02a1:
      return "?_Release@_Pad@std@@QEAAXXZ";
    case 0x02a2:
      return "?_Remove_dir@sys@tr2@std@@YA_NPEBD@Z";
    case 0x02a3:
      return "?_Remove_dir@sys@tr2@std@@YA_NPEB_W@Z";
    case 0x02a4:
      return "?_Rename@sys@tr2@std@@YAHPEBD0@Z";
    case 0x02a5:
      return "?_Rename@sys@tr2@std@@YAHPEB_W0@Z";
    case 0x02a6:
      return "?_Rep@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@AEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@D_K@Z";
    case 0x02a7:
      return "?_Rep@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@AEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@G_K@Z";
    case 0x02a8:
      return "?_Rep@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@std@@@std@@AEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@2@V32@_W_K@Z";
    case 0x02a9:
      return "?_Rethrow_future_exception@std@@YAXVexception_ptr@1@@Z";
    case 0x02aa:
      return "?_Rng_abort@std@@YAXPEBD@Z";
    case 0x02ab:
      return "?_Segment_index_of@_Concurrent_vector_base_v4@details@"
             "Concurrency@@KA_K_K@Z";
    case 0x02ac:
      return "?_Setgloballocale@locale@std@@CAXPEAX@Z";
    case 0x02ad:
      return "?_Src@?1??_Getffldx@?$num_get@DV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@DU?$"
             "char_traits@D@std@@@3@1AEAVios_base@3@PEAH@Z@4QBDB";
    case 0x02ae:
      return "?_Src@?1??_Getffldx@?$num_get@GV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@GU?$"
             "char_traits@G@std@@@3@1AEAVios_base@3@PEAH@Z@4QBDB";
    case 0x02af:
      return "?_Src@?1??_Getffldx@?$num_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@_"
             "WU?$char_traits@_W@std@@@3@1AEAVios_base@3@PEAH@Z@4QBDB";
    case 0x02b0:
      return "?_Src@?1??_Getifld@?$num_get@DV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@DU?$"
             "char_traits@D@std@@@3@1HAEBVlocale@3@@Z@4QBDB";
    case 0x02b1:
      return "?_Src@?1??_Getifld@?$num_get@GV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@GU?$"
             "char_traits@G@std@@@3@1HAEBVlocale@3@@Z@4QBDB";
    case 0x02b2:
      return "?_Src@?1??_Getifld@?$num_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@_"
             "WU?$char_traits@_W@std@@@3@1HAEBVlocale@3@@Z@4QBDB";
    case 0x02b3:
      return "?_Src@?3??_Getffld@?$num_get@DV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@DU?$"
             "char_traits@D@std@@@3@1AEAVios_base@3@PEAH@Z@4QBDB";
    case 0x02b4:
      return "?_Src@?3??_Getffld@?$num_get@GV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@GU?$"
             "char_traits@G@std@@@3@1AEAVios_base@3@PEAH@Z@4QBDB";
    case 0x02b5:
      return "?_Src@?3??_Getffld@?$num_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@AEBAHPEADAEAV?$istreambuf_iterator@_"
             "WU?$char_traits@_W@std@@@3@1AEAVios_base@3@PEAH@Z@4QBDB";
    case 0x02b6:
      return "?_Stat@sys@tr2@std@@YA?AW4file_type@123@PEBDAEAH@Z";
    case 0x02b7:
      return "?_Stat@sys@tr2@std@@YA?AW4file_type@123@PEB_WAEAH@Z";
    case 0x02b8:
      return "?_Statvfs@sys@tr2@std@@YA?AUspace_info@123@PEBD@Z";
    case 0x02b9:
      return "?_Statvfs@sys@tr2@std@@YA?AUspace_info@123@PEB_W@Z";
    case 0x02ba:
      return "?_Swap_all@_Container_base0@std@@QEAAXAEAU12@@Z";
    case 0x02bb:
      return "?_Swap_all@_Container_base12@std@@QEAAXAEAU12@@Z";
    case 0x02bc:
      return "?_Symlink@sys@tr2@std@@YAHPEBD0@Z";
    case 0x02bd:
      return "?_Symlink@sys@tr2@std@@YAHPEB_W0@Z";
    case 0x02be:
      return "?_Sync@ios_base@std@@0_NA";
    case 0x02bf:
      return "?_Syserror_map@std@@YAPEBDH@Z";
    case 0x02c0:
      return "?_Throw_C_error@std@@YAXH@Z";
    case 0x02c1:
      return "?_Throw_Cpp_error@std@@YAXH@Z";
    case 0x02c2:
      return "?_Throw_future_error@std@@YAXAEBVerror_code@1@@Z";
    case 0x02c3:
      return "?_Throw_lock_error@threads@stdext@@YAXXZ";
    case 0x02c4:
      return "?_Throw_resource_error@threads@stdext@@YAXXZ";
    case 0x02c5:
      return "?_Tidy@?$_Yarn@D@std@@AEAAXXZ";
    case 0x02c6:
      return "?_Tidy@?$_Yarn@_W@std@@AEAAXXZ";
    case 0x02c7:
      return "?_Tidy@?$ctype@D@std@@IEAAXXZ";
    case 0x02c8:
      return "?_Tidy@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@AEAAXXZ";
    case 0x02c9:
      return "?_Tidy@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@AEAAXXZ";
    case 0x02ca:
      return "?_Tidy@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@AEAAXXZ";
    case 0x02cb:
      return "?_Tidy@ios_base@std@@AEAAXXZ";
    case 0x02cc:
      return "?_Unlink@sys@tr2@std@@YAHPEBD@Z";
    case 0x02cd:
      return "?_Unlink@sys@tr2@std@@YAHPEB_W@Z";
    case 0x02ce:
      return "?_Unlock@?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAAXXZ";
    case 0x02cf:
      return "?_Unlock@?$basic_streambuf@GU?$char_traits@G@std@@@std@@UEAAXXZ";
    case 0x02d0:
      return "?_Unlock@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "UEAAXXZ";
    case 0x02d1:
      return "?_W_Getdays@_Locinfo@std@@QEBAPEBGXZ";
    case 0x02d2:
      return "?_W_Getmonths@_Locinfo@std@@QEBAPEBGXZ";
    case 0x02d3:
      return "?_W_Gettnames@_Locinfo@std@@QEBA?AV_Timevec@2@XZ";
    case 0x02d4:
      return "?_Winerror_map@std@@YAPEBDH@Z";
    case 0x02d5:
      return "?_XLgamma@std@@YAMM@Z";
    case 0x02d6:
      return "?_XLgamma@std@@YANN@Z";
    case 0x02d7:
      return "?_XLgamma@std@@YAOO@Z";
    case 0x02d8:
      return "?_Xbad_alloc@std@@YAXXZ";
    case 0x02d9:
      return "?_Xbad_function_call@std@@YAXXZ";
    case 0x02da:
      return "?_Xinvalid_argument@std@@YAXPEBD@Z";
    case 0x02db:
      return "?_Xlength_error@std@@YAXPEBD@Z";
    case 0x02dc:
      return "?_Xout_of_range@std@@YAXPEBD@Z";
    case 0x02dd:
      return "?_Xoverflow_error@std@@YAXPEBD@Z";
    case 0x02de:
      return "?_Xregex_error@std@@YAXW4error_type@regex_constants@1@@Z";
    case 0x02df:
      return "?_Xruntime_error@std@@YAXPEBD@Z";
    case 0x02e0:
      return "?adopt_lock@std@@3Uadopt_lock_t@1@B";
    case 0x02e1:
      return "?always_noconv@codecvt_base@std@@QEBA_NXZ";
    case 0x02e2:
      return "?bad@ios_base@std@@QEBA_NXZ";
    case 0x02e3:
      return "?c_str@?$_Yarn@D@std@@QEBAPEBDXZ";
    case 0x02e4:
      return "?cancel@agent@Concurrency@@QEAA_NXZ";
    case 0x02e5:
      return "?cancel_current_task@Concurrency@@YAXXZ";
    case 0x02e6:
      return "?cerr@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A";
    case 0x02e7:
      return "?cin@std@@3V?$basic_istream@DU?$char_traits@D@std@@@1@A";
    case 0x02e8:
      return "?classic@locale@std@@SAAEBV12@XZ";
    case 0x02e9:
      return "?classic_table@?$ctype@D@std@@SAPEBFXZ";
    case 0x02ea:
      return "?clear@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z";
    case 0x02eb:
      return "?clear@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXI@Z";
    case 0x02ec:
      return "?clear@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAXH_N@Z";
    case 0x02ed:
      return "?clear@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAXI@Z";
    case 0x02ee:
      return "?clear@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXH_N@Z";
    case 0x02ef:
      return "?clear@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXI@Z";
    case 0x02f0:
      return "?clear@ios_base@std@@QEAAXH@Z";
    case 0x02f1:
      return "?clear@ios_base@std@@QEAAXH_N@Z";
    case 0x02f2:
      return "?clear@ios_base@std@@QEAAXI@Z";
    case 0x02f3:
      return "?clog@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A";
    case 0x02f4:
      return "?copyfmt@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "AEBV12@@Z";
    case 0x02f5:
      return "?copyfmt@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "AEBV12@@Z";
    case 0x02f6:
      return "?copyfmt@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "AEBV12@@Z";
    case 0x02f7:
      return "?copyfmt@ios_base@std@@QEAAAEAV12@AEBV12@@Z";
    case 0x02f8:
      return "?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A";
    case 0x02f9:
      return "?date_order@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@QEBA?AW4dateorder@time_base@2@XZ";
    case 0x02fa:
      return "?date_order@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@QEBA?AW4dateorder@time_base@2@XZ";
    case 0x02fb:
      return "?date_order@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@"
             "_W@std@@@std@@@std@@QEBA?AW4dateorder@time_base@2@XZ";
    case 0x02fc:
      return "?defer_lock@std@@3Udefer_lock_t@1@B";
    case 0x02fd:
      return "?do_always_noconv@?$codecvt@DDH@std@@MEBA_NXZ";
    case 0x02fe:
      return "?do_always_noconv@?$codecvt@GDH@std@@MEBA_NXZ";
    case 0x02ff:
      return "?do_always_noconv@?$codecvt@_WDH@std@@MEBA_NXZ";
    case 0x0300:
      return "?do_always_noconv@codecvt_base@std@@MEBA_NXZ";
    case 0x0301:
      return "?do_date_order@?$time_get@DV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@std@@@std@@MEBA?AW4dateorder@time_base@2@XZ";
    case 0x0302:
      return "?do_date_order@?$time_get@GV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@std@@@std@@MEBA?AW4dateorder@time_base@2@XZ";
    case 0x0303:
      return "?do_date_order@?$time_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@MEBA?AW4dateorder@time_base@2@XZ";
    case 0x0304:
      return "?do_encoding@?$codecvt@GDH@std@@MEBAHXZ";
    case 0x0305:
      return "?do_encoding@?$codecvt@_WDH@std@@MEBAHXZ";
    case 0x0306:
      return "?do_encoding@codecvt_base@std@@MEBAHXZ";
    case 0x0307:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAG@Z";
    case 0x0308:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAI@Z";
    case 0x0309:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAJ@Z";
    case 0x030a:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAK@Z";
    case 0x030b:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAM@Z";
    case 0x030c:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAN@Z";
    case 0x030d:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAO@Z";
    case 0x030e:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAPEAX@Z";
    case 0x030f:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_J@Z";
    case 0x0310:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_K@Z";
    case 0x0311:
      return "?do_get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_N@Z";
    case 0x0312:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAG@Z";
    case 0x0313:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAI@Z";
    case 0x0314:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAJ@Z";
    case 0x0315:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAK@Z";
    case 0x0316:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAM@Z";
    case 0x0317:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAN@Z";
    case 0x0318:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAO@Z";
    case 0x0319:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAPEAX@Z";
    case 0x031a:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_J@Z";
    case 0x031b:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_K@Z";
    case 0x031c:
      return "?do_get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_N@Z";
    case 0x031d:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEAG@Z";
    case 0x031e:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEAI@Z";
    case 0x031f:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEAJ@Z";
    case 0x0320:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEAK@Z";
    case 0x0321:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEAM@Z";
    case 0x0322:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEAN@Z";
    case 0x0323:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEAO@Z";
    case 0x0324:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEAPEAX@Z";
    case 0x0325:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEA_J@Z";
    case 0x0326:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEA_K@Z";
    case 0x0327:
      return "?do_get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHAEA_N@Z";
    case 0x0328:
      return "?do_get@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@"
             "@@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@"
             "@2@V32@0AEAVios_base@2@AEAHPEAUtm@@DD@Z";
    case 0x0329:
      return "?do_get@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@"
             "@@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@"
             "@2@V32@0AEAVios_base@2@AEAHPEAUtm@@DD@Z";
    case 0x032a:
      return "?do_get@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@DD@Z";
    case 0x032b:
      return "?do_get_date@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x032c:
      return "?do_get_date@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x032d:
      return "?do_get_date@?$time_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$"
             "char_traits@_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x032e:
      return "?do_get_monthname@?$time_get@DV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x032f:
      return "?do_get_monthname@?$time_get@GV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0330:
      return "?do_get_monthname@?$time_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$"
             "char_traits@_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0331:
      return "?do_get_time@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0332:
      return "?do_get_time@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0333:
      return "?do_get_time@?$time_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$"
             "char_traits@_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0334:
      return "?do_get_weekday@?$time_get@DV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0335:
      return "?do_get_weekday@?$time_get@GV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0336:
      return "?do_get_weekday@?$time_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$"
             "char_traits@_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0337:
      return "?do_get_year@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0338:
      return "?do_get_year@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x0339:
      return "?do_get_year@?$time_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@MEBA?AV?$istreambuf_iterator@_WU?$"
             "char_traits@_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x033a:
      return "?do_in@?$codecvt@DDH@std@@MEBAHAEAHPEBD1AEAPEBDPEAD3AEAPEAD@Z";
    case 0x033b:
      return "?do_in@?$codecvt@GDH@std@@MEBAHAEAHPEBD1AEAPEBDPEAG3AEAPEAG@Z";
    case 0x033c:
      return "?do_in@?$codecvt@_WDH@std@@MEBAHAEAHPEBD1AEAPEBDPEA_W3AEAPEA_W@Z";
    case 0x033d:
      return "?do_is@?$ctype@G@std@@MEBAPEBGPEBG0PEAF@Z";
    case 0x033e:
      return "?do_is@?$ctype@G@std@@MEBA_NFG@Z";
    case 0x033f:
      return "?do_is@?$ctype@_W@std@@MEBAPEB_WPEB_W0PEAF@Z";
    case 0x0340:
      return "?do_is@?$ctype@_W@std@@MEBA_NF_W@Z";
    case 0x0341:
      return "?do_length@?$codecvt@DDH@std@@MEBAHAEAHPEBD1_K@Z";
    case 0x0342:
      return "?do_length@?$codecvt@GDH@std@@MEBAHAEAHPEBD1_K@Z";
    case 0x0343:
      return "?do_length@?$codecvt@_WDH@std@@MEBAHAEAHPEBD1_K@Z";
    case 0x0344:
      return "?do_max_length@?$codecvt@GDH@std@@MEBAHXZ";
    case 0x0345:
      return "?do_max_length@?$codecvt@_WDH@std@@MEBAHXZ";
    case 0x0346:
      return "?do_max_length@codecvt_base@std@@MEBAHXZ";
    case 0x0347:
      return "?do_narrow@?$ctype@D@std@@MEBADDD@Z";
    case 0x0348:
      return "?do_narrow@?$ctype@D@std@@MEBAPEBDPEBD0DPEAD@Z";
    case 0x0349:
      return "?do_narrow@?$ctype@G@std@@MEBADGD@Z";
    case 0x034a:
      return "?do_narrow@?$ctype@G@std@@MEBAPEBGPEBG0DPEAD@Z";
    case 0x034b:
      return "?do_narrow@?$ctype@_W@std@@MEBAD_WD@Z";
    case 0x034c:
      return "?do_narrow@?$ctype@_W@std@@MEBAPEB_WPEB_W0DPEAD@Z";
    case 0x034d:
      return "?do_out@?$codecvt@DDH@std@@MEBAHAEAHPEBD1AEAPEBDPEAD3AEAPEAD@Z";
    case 0x034e:
      return "?do_out@?$codecvt@GDH@std@@MEBAHAEAHPEBG1AEAPEBGPEAD3AEAPEAD@Z";
    case 0x034f:
      return "?do_out@?$codecvt@_WDH@std@@MEBAHAEAHPEB_W1AEAPEB_WPEAD3AEAPEAD@"
             "Z";
    case 0x0350:
      return "?do_put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DJ@Z";
    case 0x0351:
      return "?do_put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DK@Z";
    case 0x0352:
      return "?do_put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DN@Z";
    case 0x0353:
      return "?do_put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DO@Z";
    case 0x0354:
      return "?do_put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DPEBX@Z";
    case 0x0355:
      return "?do_put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@D_J@Z";
    case 0x0356:
      return "?do_put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@D_K@Z";
    case 0x0357:
      return "?do_put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@D_N@Z";
    case 0x0358:
      return "?do_put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GJ@Z";
    case 0x0359:
      return "?do_put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GK@Z";
    case 0x035a:
      return "?do_put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GN@Z";
    case 0x035b:
      return "?do_put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GO@Z";
    case 0x035c:
      return "?do_put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GPEBX@Z";
    case 0x035d:
      return "?do_put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@G_J@Z";
    case 0x035e:
      return "?do_put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@G_K@Z";
    case 0x035f:
      return "?do_put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@G_N@Z";
    case 0x0360:
      return "?do_put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_WJ@Z";
    case 0x0361:
      return "?do_put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_WK@Z";
    case 0x0362:
      return "?do_put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_WN@Z";
    case 0x0363:
      return "?do_put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_WO@Z";
    case 0x0364:
      return "?do_put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_WPEBX@Z";
    case 0x0365:
      return "?do_put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_W_J@Z";
    case 0x0366:
      return "?do_put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_W_K@Z";
    case 0x0367:
      return "?do_put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_W_N@Z";
    case 0x0368:
      return "?do_put@?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@"
             "@@std@@@std@@MEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@"
             "@2@V32@AEAVios_base@2@DPEBUtm@@DD@Z";
    case 0x0369:
      return "?do_put@?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@"
             "@@std@@@std@@MEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@"
             "@2@V32@AEAVios_base@2@GPEBUtm@@DD@Z";
    case 0x036a:
      return "?do_put@?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@std@@@std@@MEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@2@V32@AEAVios_base@2@_WPEBUtm@@DD@Z";
    case 0x036b:
      return "?do_scan_is@?$ctype@G@std@@MEBAPEBGFPEBG0@Z";
    case 0x036c:
      return "?do_scan_is@?$ctype@_W@std@@MEBAPEB_WFPEB_W0@Z";
    case 0x036d:
      return "?do_scan_not@?$ctype@G@std@@MEBAPEBGFPEBG0@Z";
    case 0x036e:
      return "?do_scan_not@?$ctype@_W@std@@MEBAPEB_WFPEB_W0@Z";
    case 0x036f:
      return "?do_tolower@?$ctype@D@std@@MEBADD@Z";
    case 0x0370:
      return "?do_tolower@?$ctype@D@std@@MEBAPEBDPEADPEBD@Z";
    case 0x0371:
      return "?do_tolower@?$ctype@G@std@@MEBAGG@Z";
    case 0x0372:
      return "?do_tolower@?$ctype@G@std@@MEBAPEBGPEAGPEBG@Z";
    case 0x0373:
      return "?do_tolower@?$ctype@_W@std@@MEBAPEB_WPEA_WPEB_W@Z";
    case 0x0374:
      return "?do_tolower@?$ctype@_W@std@@MEBA_W_W@Z";
    case 0x0375:
      return "?do_toupper@?$ctype@D@std@@MEBADD@Z";
    case 0x0376:
      return "?do_toupper@?$ctype@D@std@@MEBAPEBDPEADPEBD@Z";
    case 0x0377:
      return "?do_toupper@?$ctype@G@std@@MEBAGG@Z";
    case 0x0378:
      return "?do_toupper@?$ctype@G@std@@MEBAPEBGPEAGPEBG@Z";
    case 0x0379:
      return "?do_toupper@?$ctype@_W@std@@MEBAPEB_WPEA_WPEB_W@Z";
    case 0x037a:
      return "?do_toupper@?$ctype@_W@std@@MEBA_W_W@Z";
    case 0x037b:
      return "?do_unshift@?$codecvt@DDH@std@@MEBAHAEAHPEAD1AEAPEAD@Z";
    case 0x037c:
      return "?do_unshift@?$codecvt@GDH@std@@MEBAHAEAHPEAD1AEAPEAD@Z";
    case 0x037d:
      return "?do_unshift@?$codecvt@_WDH@std@@MEBAHAEAHPEAD1AEAPEAD@Z";
    case 0x037e:
      return "?do_widen@?$ctype@D@std@@MEBADD@Z";
    case 0x037f:
      return "?do_widen@?$ctype@D@std@@MEBAPEBDPEBD0PEAD@Z";
    case 0x0380:
      return "?do_widen@?$ctype@G@std@@MEBAGD@Z";
    case 0x0381:
      return "?do_widen@?$ctype@G@std@@MEBAPEBDPEBD0PEAG@Z";
    case 0x0382:
      return "?do_widen@?$ctype@_W@std@@MEBAPEBDPEBD0PEA_W@Z";
    case 0x0383:
      return "?do_widen@?$ctype@_W@std@@MEBA_WD@Z";
    case 0x0384:
      return "?done@agent@Concurrency@@IEAA_NXZ";
    case 0x0385:
      return "?eback@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ";
    case 0x0386:
      return "?eback@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEBAPEAGXZ";
    case 0x0387:
      return "?eback@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEBAPEA_"
             "WXZ";
    case 0x0388:
      return "?egptr@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ";
    case 0x0389:
      return "?egptr@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEBAPEAGXZ";
    case 0x038a:
      return "?egptr@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEBAPEA_"
             "WXZ";
    case 0x038b:
      return "?empty@?$_Yarn@D@std@@QEBA_NXZ";
    case 0x038c:
      return "?empty@locale@std@@SA?AV12@XZ";
    case 0x038d:
      return "?encoding@codecvt_base@std@@QEBAHXZ";
    case 0x038e:
      return "?endl@std@@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@1@"
             "AEAV21@@Z";
    case 0x038f:
      return "?endl@std@@YAAEAV?$basic_ostream@GU?$char_traits@G@std@@@1@"
             "AEAV21@@Z";
    case 0x0390:
      return "?endl@std@@YAAEAV?$basic_ostream@_WU?$char_traits@_W@std@@@1@"
             "AEAV21@@Z";
    case 0x0391:
      return "?ends@std@@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@1@"
             "AEAV21@@Z";
    case 0x0392:
      return "?ends@std@@YAAEAV?$basic_ostream@GU?$char_traits@G@std@@@1@"
             "AEAV21@@Z";
    case 0x0393:
      return "?ends@std@@YAAEAV?$basic_ostream@_WU?$char_traits@_W@std@@@1@"
             "AEAV21@@Z";
    case 0x0394:
      return "?eof@ios_base@std@@QEBA_NXZ";
    case 0x0395:
      return "?epptr@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ";
    case 0x0396:
      return "?epptr@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEBAPEAGXZ";
    case 0x0397:
      return "?epptr@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEBAPEA_"
             "WXZ";
    case 0x0398:
      return "?exceptions@ios_base@std@@QEAAXH@Z";
    case 0x0399:
      return "?exceptions@ios_base@std@@QEAAXI@Z";
    case 0x039a:
      return "?exceptions@ios_base@std@@QEBAHXZ";
    case 0x039b:
      return "?fail@ios_base@std@@QEBA_NXZ";
    case 0x039c:
      return "?fill@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAADD@Z";
    case 0x039d:
      return "?fill@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBADXZ";
    case 0x039e:
      return "?fill@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAGG@Z";
    case 0x039f:
      return "?fill@?$basic_ios@GU?$char_traits@G@std@@@std@@QEBAGXZ";
    case 0x03a0:
      return "?fill@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAA_W_W@Z";
    case 0x03a1:
      return "?fill@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEBA_WXZ";
    case 0x03a2:
      return "?flags@ios_base@std@@QEAAHH@Z";
    case 0x03a3:
      return "?flags@ios_base@std@@QEBAHXZ";
    case 0x03a4:
      return "?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "XZ";
    case 0x03a5:
      return "?flush@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "XZ";
    case 0x03a6:
      return "?flush@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "XZ";
    case 0x03a7:
      return "?flush@std@@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@1@"
             "AEAV21@@Z";
    case 0x03a8:
      return "?flush@std@@YAAEAV?$basic_ostream@GU?$char_traits@G@std@@@1@"
             "AEAV21@@Z";
    case 0x03a9:
      return "?flush@std@@YAAEAV?$basic_ostream@_WU?$char_traits@_W@std@@@1@"
             "AEAV21@@Z";
    case 0x03aa:
      return "?gbump@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXH@Z";
    case 0x03ab:
      return "?gbump@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAAXH@Z";
    case 0x03ac:
      return "?gbump@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAXH@Z";
    case 0x03ad:
      return "?gcount@?$basic_istream@DU?$char_traits@D@std@@@std@@QEBA_JXZ";
    case 0x03ae:
      return "?gcount@?$basic_istream@GU?$char_traits@G@std@@@std@@QEBA_JXZ";
    case 0x03af:
      return "?gcount@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEBA_JXZ";
    case 0x03b0:
      return "?get@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "AEAD@Z";
    case 0x03b1:
      return "?get@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "AEAV?$basic_streambuf@DU?$char_traits@D@std@@@2@@Z";
    case 0x03b2:
      return "?get@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "AEAV?$basic_streambuf@DU?$char_traits@D@std@@@2@D@Z";
    case 0x03b3:
      return "?get@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "PEAD_J@Z";
    case 0x03b4:
      return "?get@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "PEAD_JD@Z";
    case 0x03b5:
      return "?get@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAHXZ";
    case 0x03b6:
      return "?get@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "AEAG@Z";
    case 0x03b7:
      return "?get@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "AEAV?$basic_streambuf@GU?$char_traits@G@std@@@2@@Z";
    case 0x03b8:
      return "?get@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "AEAV?$basic_streambuf@GU?$char_traits@G@std@@@2@G@Z";
    case 0x03b9:
      return "?get@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "PEAG_J@Z";
    case 0x03ba:
      return "?get@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "PEAG_JG@Z";
    case 0x03bb:
      return "?get@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAGXZ";
    case 0x03bc:
      return "?get@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "AEAV?$basic_streambuf@_WU?$char_traits@_W@std@@@2@@Z";
    case 0x03bd:
      return "?get@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "AEAV?$basic_streambuf@_WU?$char_traits@_W@std@@@2@_W@Z";
    case 0x03be:
      return "?get@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "AEA_W@Z";
    case 0x03bf:
      return "?get@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "PEA_W_J@Z";
    case 0x03c0:
      return "?get@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "PEA_W_J_W@Z";
    case 0x03c1:
      return "?get@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAGXZ";
    case 0x03c2:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAG@Z";
    case 0x03c3:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAI@Z";
    case 0x03c4:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAJ@Z";
    case 0x03c5:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAK@Z";
    case 0x03c6:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAM@Z";
    case 0x03c7:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAN@Z";
    case 0x03c8:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAO@Z";
    case 0x03c9:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAPEAX@Z";
    case 0x03ca:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_J@Z";
    case 0x03cb:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_K@Z";
    case 0x03cc:
      return "?get@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_N@Z";
    case 0x03cd:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAG@Z";
    case 0x03ce:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAI@Z";
    case 0x03cf:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAJ@Z";
    case 0x03d0:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAK@Z";
    case 0x03d1:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAM@Z";
    case 0x03d2:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAN@Z";
    case 0x03d3:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAO@Z";
    case 0x03d4:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEAPEAX@Z";
    case 0x03d5:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_J@Z";
    case 0x03d6:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_K@Z";
    case 0x03d7:
      return "?get@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHAEA_N@Z";
    case 0x03d8:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEAG@Z";
    case 0x03d9:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEAI@Z";
    case 0x03da:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEAJ@Z";
    case 0x03db:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEAK@Z";
    case 0x03dc:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEAM@Z";
    case 0x03dd:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEAN@Z";
    case 0x03de:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEAO@Z";
    case 0x03df:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEAPEAX@Z";
    case 0x03e0:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEA_J@Z";
    case 0x03e1:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEA_K@Z";
    case 0x03e2:
      return "?get@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@0AEAVios_base@2@AEAHAEA_N@Z";
    case 0x03e3:
      return "?get@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHPEAUtm@@DD@Z";
    case 0x03e4:
      return "?get@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@0AEAVios_base@2@AEAHPEAUtm@@PEBD4@Z";
    case 0x03e5:
      return "?get@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHPEAUtm@@DD@Z";
    case 0x03e6:
      return "?get@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@0AEAVios_base@2@AEAHPEAUtm@@PEBG4@Z";
    case 0x03e7:
      return "?get@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@DD@Z";
    case 0x03e8:
      return "?get@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@PEB_W4@Z";
    case 0x03e9:
      return "?get_date@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03ea:
      return "?get_date@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03eb:
      return "?get_date@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@"
             "_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03ec:
      return "?get_monthname@?$time_get@DV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_"
             "traits@D@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03ed:
      return "?get_monthname@?$time_get@GV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_"
             "traits@G@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03ee:
      return "?get_monthname@?$time_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$"
             "char_traits@_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03ef:
      return "?get_new_handler@std@@YAP6AXXZXZ";
    case 0x03f0:
      return "?get_time@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03f1:
      return "?get_time@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03f2:
      return "?get_time@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@"
             "_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03f3:
      return "?get_weekday@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@"
             "D@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03f4:
      return "?get_weekday@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@"
             "G@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03f5:
      return "?get_weekday@?$time_get@_WV?$istreambuf_iterator@_WU?$char_"
             "traits@_W@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$"
             "char_traits@_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03f6:
      return "?get_year@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@DU?$char_traits@D@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03f7:
      return "?get_year@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@GU?$char_traits@G@"
             "std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03f8:
      return "?get_year@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_"
             "W@std@@@std@@@std@@QEBA?AV?$istreambuf_iterator@_WU?$char_traits@"
             "_W@std@@@2@V32@0AEAVios_base@2@AEAHPEAUtm@@@Z";
    case 0x03f9:
      return "?getline@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "PEAD_J@Z";
    case 0x03fa:
      return "?getline@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "PEAD_JD@Z";
    case 0x03fb:
      return "?getline@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "PEAG_J@Z";
    case 0x03fc:
      return "?getline@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "PEAG_JG@Z";
    case 0x03fd:
      return "?getline@?$basic_istream@_WU?$char_traits@_W@std@@@std@@"
             "QEAAAEAV12@PEA_W_J@Z";
    case 0x03fe:
      return "?getline@?$basic_istream@_WU?$char_traits@_W@std@@@std@@"
             "QEAAAEAV12@PEA_W_J_W@Z";
    case 0x03ff:
      return "?getloc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEBA?"
             "AVlocale@2@XZ";
    case 0x0400:
      return "?getloc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEBA?"
             "AVlocale@2@XZ";
    case 0x0401:
      return "?getloc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEBA?"
             "AVlocale@2@XZ";
    case 0x0402:
      return "?getloc@ios_base@std@@QEBA?AVlocale@2@XZ";
    case 0x0403:
      return "?global@locale@std@@SA?AV12@AEBV12@@Z";
    case 0x0404:
      return "?good@ios_base@std@@QEBA_NXZ";
    case 0x0405:
      return "?gptr@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ";
    case 0x0406:
      return "?gptr@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEBAPEAGXZ";
    case 0x0407:
      return "?gptr@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEBAPEA_"
             "WXZ";
    case 0x0408:
      return "?id@?$codecvt@DDH@std@@2V0locale@2@A";
    case 0x0409:
      return "?id@?$codecvt@GDH@std@@2V0locale@2@A";
    case 0x040a:
      return "?id@?$codecvt@_WDH@std@@2V0locale@2@A";
    case 0x040b:
      return "?id@?$collate@D@std@@2V0locale@2@A";
    case 0x040c:
      return "?id@?$collate@G@std@@2V0locale@2@A";
    case 0x040d:
      return "?id@?$collate@_W@std@@2V0locale@2@A";
    case 0x040e:
      return "?id@?$ctype@D@std@@2V0locale@2@A";
    case 0x040f:
      return "?id@?$ctype@G@std@@2V0locale@2@A";
    case 0x0410:
      return "?id@?$ctype@_W@std@@2V0locale@2@A";
    case 0x0411:
      return "?id@?$messages@D@std@@2V0locale@2@A";
    case 0x0412:
      return "?id@?$messages@G@std@@2V0locale@2@A";
    case 0x0413:
      return "?id@?$messages@_W@std@@2V0locale@2@A";
    case 0x0414:
      return "?id@?$money_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x0415:
      return "?id@?$money_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x0416:
      return "?id@?$money_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@std@@@std@@2V0locale@2@A";
    case 0x0417:
      return "?id@?$money_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x0418:
      return "?id@?$money_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x0419:
      return "?id@?$money_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@std@@@std@@2V0locale@2@A";
    case 0x041a:
      return "?id@?$moneypunct@D$00@std@@2V0locale@2@A";
    case 0x041b:
      return "?id@?$moneypunct@D$0A@@std@@2V0locale@2@A";
    case 0x041c:
      return "?id@?$moneypunct@G$00@std@@2V0locale@2@A";
    case 0x041d:
      return "?id@?$moneypunct@G$0A@@std@@2V0locale@2@A";
    case 0x041e:
      return "?id@?$moneypunct@_W$00@std@@2V0locale@2@A";
    case 0x041f:
      return "?id@?$moneypunct@_W$0A@@std@@2V0locale@2@A";
    case 0x0420:
      return "?id@?$num_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x0421:
      return "?id@?$num_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x0422:
      return "?id@?$num_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x0423:
      return "?id@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x0424:
      return "?id@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x0425:
      return "?id@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x0426:
      return "?id@?$numpunct@D@std@@2V0locale@2@A";
    case 0x0427:
      return "?id@?$numpunct@G@std@@2V0locale@2@A";
    case 0x0428:
      return "?id@?$numpunct@_W@std@@2V0locale@2@A";
    case 0x0429:
      return "?id@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x042a:
      return "?id@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x042b:
      return "?id@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@2V0locale@2@A";
    case 0x042c:
      return "?id@?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x042d:
      return "?id@?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@2V0locale@2@A";
    case 0x042e:
      return "?id@?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@2V0locale@2@A";
    case 0x042f:
      return "?ignore@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@_"
             "JH@Z";
    case 0x0430:
      return "?ignore@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@_"
             "JG@Z";
    case 0x0431:
      return "?ignore@?$basic_istream@_WU?$char_traits@_W@std@@@std@@"
             "QEAAAEAV12@_JG@Z";
    case 0x0432:
      return "?imbue@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAA?AVlocale@2@"
             "AEBV32@@Z";
    case 0x0433:
      return "?imbue@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAA?AVlocale@2@"
             "AEBV32@@Z";
    case 0x0434:
      return "?imbue@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAA?AVlocale@"
             "2@AEBV32@@Z";
    case 0x0435:
      return "?imbue@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "MEAAXAEBVlocale@2@@Z";
    case 0x0436:
      return "?imbue@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "MEAAXAEBVlocale@2@@Z";
    case 0x0437:
      return "?imbue@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "MEAAXAEBVlocale@2@@Z";
    case 0x0438:
      return "?imbue@ios_base@std@@QEAA?AVlocale@2@AEBV32@@Z";
    case 0x0439:
      return "?in@?$codecvt@DDH@std@@QEBAHAEAHPEBD1AEAPEBDPEAD3AEAPEAD@Z";
    case 0x043a:
      return "?in@?$codecvt@GDH@std@@QEBAHAEAHPEBD1AEAPEBDPEAG3AEAPEAG@Z";
    case 0x043b:
      return "?in@?$codecvt@_WDH@std@@QEBAHAEAHPEBD1AEAPEBDPEA_W3AEAPEA_W@Z";
    case 0x043c:
      return "?in_avail@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_"
             "JXZ";
    case 0x043d:
      return "?in_avail@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAA_"
             "JXZ";
    case 0x043e:
      return "?in_avail@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAA_"
             "JXZ";
    case 0x043f:
      return "?init@?$basic_ios@DU?$char_traits@D@std@@@std@@IEAAXPEAV?$basic_"
             "streambuf@DU?$char_traits@D@std@@@2@_N@Z";
    case 0x0440:
      return "?init@?$basic_ios@GU?$char_traits@G@std@@@std@@IEAAXPEAV?$basic_"
             "streambuf@GU?$char_traits@G@std@@@2@_N@Z";
    case 0x0441:
      return "?init@?$basic_ios@_WU?$char_traits@_W@std@@@std@@IEAAXPEAV?$"
             "basic_streambuf@_WU?$char_traits@_W@std@@@2@_N@Z";
    case 0x0442:
      return "?intl@?$moneypunct@D$00@std@@2_NB";
    case 0x0443:
      return "?intl@?$moneypunct@D$0A@@std@@2_NB";
    case 0x0444:
      return "?intl@?$moneypunct@G$00@std@@2_NB";
    case 0x0445:
      return "?intl@?$moneypunct@G$0A@@std@@2_NB";
    case 0x0446:
      return "?intl@?$moneypunct@_W$00@std@@2_NB";
    case 0x0447:
      return "?intl@?$moneypunct@_W$0A@@std@@2_NB";
    case 0x0448:
      return "?ipfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA_N_N@Z";
    case 0x0449:
      return "?ipfx@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAA_N_N@Z";
    case 0x044a:
      return "?ipfx@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAA_N_N@Z";
    case 0x044b:
      return "?is@?$ctype@D@std@@QEBAPEBDPEBD0PEAF@Z";
    case 0x044c:
      return "?is@?$ctype@D@std@@QEBA_NFD@Z";
    case 0x044d:
      return "?is@?$ctype@G@std@@QEBAPEBGPEBG0PEAF@Z";
    case 0x044e:
      return "?is@?$ctype@G@std@@QEBA_NFG@Z";
    case 0x044f:
      return "?is@?$ctype@_W@std@@QEBAPEB_WPEB_W0PEAF@Z";
    case 0x0450:
      return "?is@?$ctype@_W@std@@QEBA_NF_W@Z";
    case 0x0451:
      return "?is_current_task_group_canceling@Concurrency@@YA_NXZ";
    case 0x0452:
      return "?is_task_cancellation_requested@Concurrency@@YA_NXZ";
    case 0x0453:
      return "?isfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAXXZ";
    case 0x0454:
      return "?isfx@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAXXZ";
    case 0x0455:
      return "?isfx@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAXXZ";
    case 0x0456:
      return "?iword@ios_base@std@@QEAAAEAJH@Z";
    case 0x0457:
      return "?length@?$codecvt@DDH@std@@QEBAHAEAHPEBD1_K@Z";
    case 0x0458:
      return "?length@?$codecvt@GDH@std@@QEBAHAEAHPEBD1_K@Z";
    case 0x0459:
      return "?length@?$codecvt@_WDH@std@@QEBAHAEAHPEBD1_K@Z";
    case 0x045a:
      return "?max_length@codecvt_base@std@@QEBAHXZ";
    case 0x045b:
      return "?move@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAX$$QEAV12@@Z";
    case 0x045c:
      return "?move@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXAEAV12@@Z";
    case 0x045d:
      return "?move@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAX$$QEAV12@@Z";
    case 0x045e:
      return "?move@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAXAEAV12@@Z";
    case 0x045f:
      return "?move@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAX$$QEAV12@@"
             "Z";
    case 0x0460:
      return "?move@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXAEAV12@@Z";
    case 0x0461:
      return "?narrow@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBADDD@Z";
    case 0x0462:
      return "?narrow@?$basic_ios@GU?$char_traits@G@std@@@std@@QEBADGD@Z";
    case 0x0463:
      return "?narrow@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEBAD_WD@Z";
    case 0x0464:
      return "?narrow@?$ctype@D@std@@QEBADDD@Z";
    case 0x0465:
      return "?narrow@?$ctype@D@std@@QEBAPEBDPEBD0DPEAD@Z";
    case 0x0466:
      return "?narrow@?$ctype@G@std@@QEBADGD@Z";
    case 0x0467:
      return "?narrow@?$ctype@G@std@@QEBAPEBGPEBG0DPEAD@Z";
    case 0x0468:
      return "?narrow@?$ctype@_W@std@@QEBAD_WD@Z";
    case 0x0469:
      return "?narrow@?$ctype@_W@std@@QEBAPEB_WPEB_W0DPEAD@Z";
    case 0x046a:
      return "?opfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAA_NXZ";
    case 0x046b:
      return "?opfx@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAA_NXZ";
    case 0x046c:
      return "?opfx@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAA_NXZ";
    case 0x046d:
      return "?osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ";
    case 0x046e:
      return "?osfx@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAXXZ";
    case 0x046f:
      return "?osfx@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAXXZ";
    case 0x0470:
      return "?out@?$codecvt@DDH@std@@QEBAHAEAHPEBD1AEAPEBDPEAD3AEAPEAD@Z";
    case 0x0471:
      return "?out@?$codecvt@GDH@std@@QEBAHAEAHPEBG1AEAPEBGPEAD3AEAPEAD@Z";
    case 0x0472:
      return "?out@?$codecvt@_WDH@std@@QEBAHAEAHPEB_W1AEAPEB_WPEAD3AEAPEAD@Z";
    case 0x0473:
      return "?overflow@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHH@"
             "Z";
    case 0x0474:
      return "?overflow@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAAGG@"
             "Z";
    case 0x0475:
      return "?overflow@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "MEAAGG@Z";
    case 0x0476:
      return "?pbackfail@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHH@"
             "Z";
    case 0x0477:
      return "?pbackfail@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAAGG@"
             "Z";
    case 0x0478:
      return "?pbackfail@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "MEAAGG@Z";
    case 0x0479:
      return "?pbase@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ";
    case 0x047a:
      return "?pbase@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEBAPEAGXZ";
    case 0x047b:
      return "?pbase@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEBAPEA_"
             "WXZ";
    case 0x047c:
      return "?pbump@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXH@Z";
    case 0x047d:
      return "?pbump@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAAXH@Z";
    case 0x047e:
      return "?pbump@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAXH@Z";
    case 0x047f:
      return "?peek@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAHXZ";
    case 0x0480:
      return "?peek@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAGXZ";
    case 0x0481:
      return "?peek@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAGXZ";
    case 0x0482:
      return "?pptr@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ";
    case 0x0483:
      return "?pptr@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEBAPEAGXZ";
    case 0x0484:
      return "?pptr@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEBAPEA_"
             "WXZ";
    case 0x0485:
      return "?precision@ios_base@std@@QEAA_J_J@Z";
    case 0x0486:
      return "?precision@ios_base@std@@QEBA_JXZ";
    case 0x0487:
      return "?pubimbue@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA?"
             "AVlocale@2@AEBV32@@Z";
    case 0x0488:
      return "?pubimbue@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAA?"
             "AVlocale@2@AEBV32@@Z";
    case 0x0489:
      return "?pubimbue@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAA?"
             "AVlocale@2@AEBV32@@Z";
    case 0x048a:
      return "?pubseekoff@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA?"
             "AV?$fpos@H@2@_JHH@Z";
    case 0x048b:
      return "?pubseekoff@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA?"
             "AV?$fpos@H@2@_JII@Z";
    case 0x048c:
      return "?pubseekoff@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAA?"
             "AV?$fpos@H@2@_JHH@Z";
    case 0x048d:
      return "?pubseekoff@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAA?"
             "AV?$fpos@H@2@_JII@Z";
    case 0x048e:
      return "?pubseekoff@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "QEAA?AV?$fpos@H@2@_JHH@Z";
    case 0x048f:
      return "?pubseekoff@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "QEAA?AV?$fpos@H@2@_JII@Z";
    case 0x0490:
      return "?pubseekpos@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA?"
             "AV?$fpos@H@2@V32@H@Z";
    case 0x0491:
      return "?pubseekpos@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA?"
             "AV?$fpos@H@2@V32@I@Z";
    case 0x0492:
      return "?pubseekpos@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAA?"
             "AV?$fpos@H@2@V32@H@Z";
    case 0x0493:
      return "?pubseekpos@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAA?"
             "AV?$fpos@H@2@V32@I@Z";
    case 0x0494:
      return "?pubseekpos@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "QEAA?AV?$fpos@H@2@V32@H@Z";
    case 0x0495:
      return "?pubseekpos@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "QEAA?AV?$fpos@H@2@V32@I@Z";
    case 0x0496:
      return "?pubsetbuf@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "QEAAPEAV12@PEAD_J@Z";
    case 0x0497:
      return "?pubsetbuf@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "QEAAPEAV12@PEAG_J@Z";
    case 0x0498:
      return "?pubsetbuf@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "QEAAPEAV12@PEA_W_J@Z";
    case 0x0499:
      return "?pubsync@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ";
    case 0x049a:
      return "?pubsync@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAAHXZ";
    case 0x049b:
      return "?pubsync@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "QEAAHXZ";
    case 0x049c:
      return "?put@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@D@Z";
    case 0x049d:
      return "?put@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@G@Z";
    case 0x049e:
      return "?put@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@_"
             "W@Z";
    case 0x049f:
      return "?put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DJ@Z";
    case 0x04a0:
      return "?put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DK@Z";
    case 0x04a1:
      return "?put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DN@Z";
    case 0x04a2:
      return "?put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DO@Z";
    case 0x04a3:
      return "?put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DPEBX@Z";
    case 0x04a4:
      return "?put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@D_J@Z";
    case 0x04a5:
      return "?put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@D_K@Z";
    case 0x04a6:
      return "?put@?$num_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@D_N@Z";
    case 0x04a7:
      return "?put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GJ@Z";
    case 0x04a8:
      return "?put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GK@Z";
    case 0x04a9:
      return "?put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GN@Z";
    case 0x04aa:
      return "?put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GO@Z";
    case 0x04ab:
      return "?put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GPEBX@Z";
    case 0x04ac:
      return "?put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@G_J@Z";
    case 0x04ad:
      return "?put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@G_K@Z";
    case 0x04ae:
      return "?put@?$num_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@G_N@Z";
    case 0x04af:
      return "?put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@AEAVios_base@2@_WJ@Z";
    case 0x04b0:
      return "?put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@AEAVios_base@2@_WK@Z";
    case 0x04b1:
      return "?put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@AEAVios_base@2@_WN@Z";
    case 0x04b2:
      return "?put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@AEAVios_base@2@_WO@Z";
    case 0x04b3:
      return "?put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@AEAVios_base@2@_WPEBX@Z";
    case 0x04b4:
      return "?put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@AEAVios_base@2@_W_J@Z";
    case 0x04b5:
      return "?put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@AEAVios_base@2@_W_K@Z";
    case 0x04b6:
      return "?put@?$num_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@@"
             "@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@2@V32@AEAVios_base@2@_W_N@Z";
    case 0x04b7:
      return "?put@?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DPEBUtm@@DD@Z";
    case 0x04b8:
      return "?put@?$time_put@DV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@DU?$char_traits@D@std@@@"
             "2@V32@AEAVios_base@2@DPEBUtm@@PEBD3@Z";
    case 0x04b9:
      return "?put@?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GPEBUtm@@DD@Z";
    case 0x04ba:
      return "?put@?$time_put@GV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "std@@@std@@QEBA?AV?$ostreambuf_iterator@GU?$char_traits@G@std@@@"
             "2@V32@AEAVios_base@2@GPEBUtm@@PEBG3@Z";
    case 0x04bb:
      return "?put@?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@2@V32@AEAVios_base@2@_WPEBUtm@@DD@Z";
    case 0x04bc:
      return "?put@?$time_put@_WV?$ostreambuf_iterator@_WU?$char_traits@_W@std@"
             "@@std@@@std@@QEBA?AV?$ostreambuf_iterator@_WU?$char_traits@_W@"
             "std@@@2@V32@AEAVios_base@2@_WPEBUtm@@PEB_W4@Z";
    case 0x04bd:
      return "?putback@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "D@Z";
    case 0x04be:
      return "?putback@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "G@Z";
    case 0x04bf:
      return "?putback@?$basic_istream@_WU?$char_traits@_W@std@@@std@@"
             "QEAAAEAV12@_W@Z";
    case 0x04c0:
      return "?pword@ios_base@std@@QEAAAEAPEAXH@Z";
    case 0x04c1:
      return "?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAPEAV?$basic_"
             "streambuf@DU?$char_traits@D@std@@@2@PEAV32@@Z";
    case 0x04c2:
      return "?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBAPEAV?$basic_"
             "streambuf@DU?$char_traits@D@std@@@2@XZ";
    case 0x04c3:
      return "?rdbuf@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAPEAV?$basic_"
             "streambuf@GU?$char_traits@G@std@@@2@PEAV32@@Z";
    case 0x04c4:
      return "?rdbuf@?$basic_ios@GU?$char_traits@G@std@@@std@@QEBAPEAV?$basic_"
             "streambuf@GU?$char_traits@G@std@@@2@XZ";
    case 0x04c5:
      return "?rdbuf@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAPEAV?$"
             "basic_streambuf@_WU?$char_traits@_W@std@@@2@PEAV32@@Z";
    case 0x04c6:
      return "?rdbuf@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEBAPEAV?$"
             "basic_streambuf@_WU?$char_traits@_W@std@@@2@XZ";
    case 0x04c7:
      return "?rdstate@ios_base@std@@QEBAHXZ";
    case 0x04c8:
      return "?read@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "PEAD_J@Z";
    case 0x04c9:
      return "?read@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "PEAG_J@Z";
    case 0x04ca:
      return "?read@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "PEA_W_J@Z";
    case 0x04cb:
      return "?readsome@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA_"
             "JPEAD_J@Z";
    case 0x04cc:
      return "?readsome@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAA_"
             "JPEAG_J@Z";
    case 0x04cd:
      return "?readsome@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAA_"
             "JPEA_W_J@Z";
    case 0x04ce:
      return "?register_callback@ios_base@std@@QEAAXP6AXW4event@12@AEAV12@H@ZH@"
             "Z";
    case 0x04cf:
      return "?resetiosflags@std@@YA?AU?$_Smanip@H@1@H@Z";
    case 0x04d0:
      return "?sbumpc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ";
    case 0x04d1:
      return "?sbumpc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAAGXZ";
    case 0x04d2:
      return "?sbumpc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAAGXZ";
    case 0x04d3:
      return "?scan_is@?$ctype@D@std@@QEBAPEBDFPEBD0@Z";
    case 0x04d4:
      return "?scan_is@?$ctype@G@std@@QEBAPEBGFPEBG0@Z";
    case 0x04d5:
      return "?scan_is@?$ctype@_W@std@@QEBAPEB_WFPEB_W0@Z";
    case 0x04d6:
      return "?scan_not@?$ctype@D@std@@QEBAPEBDFPEBD0@Z";
    case 0x04d7:
      return "?scan_not@?$ctype@G@std@@QEBAPEBGFPEBG0@Z";
    case 0x04d8:
      return "?scan_not@?$ctype@_W@std@@QEBAPEB_WFPEB_W0@Z";
    case 0x04d9:
      return "?seekg@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?"
             "$fpos@H@2@@Z";
    case 0x04da:
      return "?seekg@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@_"
             "JH@Z";
    case 0x04db:
      return "?seekg@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@V?"
             "$fpos@H@2@@Z";
    case 0x04dc:
      return "?seekg@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@_"
             "JH@Z";
    case 0x04dd:
      return "?seekg@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "V?$fpos@H@2@@Z";
    case 0x04de:
      return "?seekg@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "_JH@Z";
    case 0x04df:
      return "?seekoff@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA?AV?$"
             "fpos@H@2@_JHH@Z";
    case 0x04e0:
      return "?seekoff@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAA?AV?$"
             "fpos@H@2@_JHH@Z";
    case 0x04e1:
      return "?seekoff@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAA?"
             "AV?$fpos@H@2@_JHH@Z";
    case 0x04e2:
      return "?seekp@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?"
             "$fpos@H@2@@Z";
    case 0x04e3:
      return "?seekp@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@_"
             "JH@Z";
    case 0x04e4:
      return "?seekp@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@V?"
             "$fpos@H@2@@Z";
    case 0x04e5:
      return "?seekp@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@_"
             "JH@Z";
    case 0x04e6:
      return "?seekp@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "V?$fpos@H@2@@Z";
    case 0x04e7:
      return "?seekp@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "_JH@Z";
    case 0x04e8:
      return "?seekpos@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA?AV?$"
             "fpos@H@2@V32@H@Z";
    case 0x04e9:
      return "?seekpos@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAA?AV?$"
             "fpos@H@2@V32@H@Z";
    case 0x04ea:
      return "?seekpos@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAA?"
             "AV?$fpos@H@2@V32@H@Z";
    case 0x04eb:
      return "?set_new_handler@std@@YAP6AXXZP6AXXZ@Z";
    case 0x04ec:
      return "?set_rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXPEAV?$"
             "basic_streambuf@DU?$char_traits@D@std@@@2@@Z";
    case 0x04ed:
      return "?set_rdbuf@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAXPEAV?$"
             "basic_streambuf@GU?$char_traits@G@std@@@2@@Z";
    case 0x04ee:
      return "?set_rdbuf@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXPEAV?$"
             "basic_streambuf@_WU?$char_traits@_W@std@@@2@@Z";
    case 0x04ef:
      return "?setbase@std@@YA?AU?$_Smanip@H@1@H@Z";
    case 0x04f0:
      return "?setbuf@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "MEAAPEAV12@PEAD_J@Z";
    case 0x04f1:
      return "?setbuf@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "MEAAPEAV12@PEAG_J@Z";
    case 0x04f2:
      return "?setbuf@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "MEAAPEAV12@PEA_W_J@Z";
    case 0x04f3:
      return "?setf@ios_base@std@@QEAAHH@Z";
    case 0x04f4:
      return "?setf@ios_base@std@@QEAAHHH@Z";
    case 0x04f5:
      return "?setg@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXPEAD00@"
             "Z";
    case 0x04f6:
      return "?setg@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAAXPEAG00@"
             "Z";
    case 0x04f7:
      return "?setg@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAXPEA_"
             "W00@Z";
    case 0x04f8:
      return "?setiosflags@std@@YA?AU?$_Smanip@H@1@H@Z";
    case 0x04f9:
      return "?setp@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXPEAD00@"
             "Z";
    case 0x04fa:
      return "?setp@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXPEAD0@"
             "Z";
    case 0x04fb:
      return "?setp@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAAXPEAG00@"
             "Z";
    case 0x04fc:
      return "?setp@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAAXPEAG0@"
             "Z";
    case 0x04fd:
      return "?setp@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAXPEA_"
             "W00@Z";
    case 0x04fe:
      return "?setp@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@IEAAXPEA_"
             "W0@Z";
    case 0x04ff:
      return "?setprecision@std@@YA?AU?$_Smanip@_J@1@_J@Z";
    case 0x0500:
      return "?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z";
    case 0x0501:
      return "?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXI@Z";
    case 0x0502:
      return "?setstate@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAXH_N@Z";
    case 0x0503:
      return "?setstate@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAXI@Z";
    case 0x0504:
      return "?setstate@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXH_N@Z";
    case 0x0505:
      return "?setstate@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXI@Z";
    case 0x0506:
      return "?setstate@ios_base@std@@QEAAXH@Z";
    case 0x0507:
      return "?setstate@ios_base@std@@QEAAXH_N@Z";
    case 0x0508:
      return "?setstate@ios_base@std@@QEAAXI@Z";
    case 0x0509:
      return "?setw@std@@YA?AU?$_Smanip@_J@1@_J@Z";
    case 0x050a:
      return "?sgetc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ";
    case 0x050b:
      return "?sgetc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAAGXZ";
    case 0x050c:
      return "?sgetc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAAGXZ";
    case 0x050d:
      return "?sgetn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_JPEAD_"
             "J@Z";
    case 0x050e:
      return "?sgetn@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAA_JPEAG_"
             "J@Z";
    case 0x050f:
      return "?sgetn@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAA_"
             "JPEA_W_J@Z";
    case 0x0510:
      return "?showmanyc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_"
             "JXZ";
    case 0x0511:
      return "?showmanyc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAA_"
             "JXZ";
    case 0x0512:
      return "?showmanyc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAA_"
             "JXZ";
    case 0x0513:
      return "?snextc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ";
    case 0x0514:
      return "?snextc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAAGXZ";
    case 0x0515:
      return "?snextc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAAGXZ";
    case 0x0516:
      return "?sputbackc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHD@"
             "Z";
    case 0x0517:
      return "?sputbackc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAAGG@"
             "Z";
    case 0x0518:
      return "?sputbackc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "QEAAG_W@Z";
    case 0x0519:
      return "?sputc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHD@Z";
    case 0x051a:
      return "?sputc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAAGG@Z";
    case 0x051b:
      return "?sputc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAAG_W@"
             "Z";
    case 0x051c:
      return "?sputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_JPEBD_"
             "J@Z";
    case 0x051d:
      return "?sputn@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAA_JPEBG_"
             "J@Z";
    case 0x051e:
      return "?sputn@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAA_"
             "JPEB_W_J@Z";
    case 0x051f:
      return "?start@agent@Concurrency@@QEAA_NXZ";
    case 0x0520:
      return "?status@agent@Concurrency@@QEAA?AW4agent_status@2@XZ";
    case 0x0521:
      return "?status_port@agent@Concurrency@@QEAAPEAV?$ISource@W4agent_status@"
             "Concurrency@@@2@XZ";
    case 0x0522:
      return "?stossc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAXXZ";
    case 0x0523:
      return "?stossc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAAXXZ";
    case 0x0524:
      return "?stossc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAAXXZ";
    case 0x0525:
      return "?sungetc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ";
    case 0x0526:
      return "?sungetc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QEAAGXZ";
    case 0x0527:
      return "?sungetc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "QEAAGXZ";
    case 0x0528:
      return "?swap@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXAEAV12@@Z";
    case 0x0529:
      return "?swap@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAXAEAV12@@Z";
    case 0x052a:
      return "?swap@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXAEAV12@@Z";
    case 0x052b:
      return "?swap@?$basic_iostream@DU?$char_traits@D@std@@@std@@IEAAXAEAV12@@"
             "Z";
    case 0x052c:
      return "?swap@?$basic_iostream@GU?$char_traits@G@std@@@std@@IEAAXAEAV12@@"
             "Z";
    case 0x052d:
      return "?swap@?$basic_iostream@_WU?$char_traits@_W@std@@@std@@"
             "IEAAXAEAV12@@Z";
    case 0x052e:
      return "?swap@?$basic_istream@DU?$char_traits@D@std@@@std@@IEAAXAEAV12@@"
             "Z";
    case 0x052f:
      return "?swap@?$basic_istream@GU?$char_traits@G@std@@@std@@IEAAXAEAV12@@"
             "Z";
    case 0x0530:
      return "?swap@?$basic_istream@_WU?$char_traits@_W@std@@@std@@IEAAXAEAV12@"
             "@Z";
    case 0x0531:
      return "?swap@?$basic_ostream@DU?$char_traits@D@std@@@std@@IEAAXAEAV12@@"
             "Z";
    case 0x0532:
      return "?swap@?$basic_ostream@GU?$char_traits@G@std@@@std@@IEAAXAEAV12@@"
             "Z";
    case 0x0533:
      return "?swap@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@IEAAXAEAV12@"
             "@Z";
    case 0x0534:
      return "?swap@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXAEAV12@"
             "@Z";
    case 0x0535:
      return "?swap@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IEAAXAEAV12@"
             "@Z";
    case 0x0536:
      return "?swap@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "IEAAXAEAV12@@Z";
    case 0x0537:
      return "?swap@ios_base@std@@QEAAXAEAV12@@Z";
    case 0x0538:
      return "?sync@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAHXZ";
    case 0x0539:
      return "?sync@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAHXZ";
    case 0x053a:
      return "?sync@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAHXZ";
    case 0x053b:
      return "?sync@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHXZ";
    case 0x053c:
      return "?sync@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAAHXZ";
    case 0x053d:
      return "?sync@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAAHXZ";
    case 0x053e:
      return "?sync_with_stdio@ios_base@std@@SA_N_N@Z";
    case 0x053f:
      return "?table@?$ctype@D@std@@QEBAPEBFXZ";
    case 0x0540:
      return "?table_size@?$ctype@D@std@@2_KB";
    case 0x0541:
      return "?tellg@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA?AV?$"
             "fpos@H@2@XZ";
    case 0x0542:
      return "?tellg@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAA?AV?$"
             "fpos@H@2@XZ";
    case 0x0543:
      return "?tellg@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAA?AV?$"
             "fpos@H@2@XZ";
    case 0x0544:
      return "?tellp@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAA?AV?$"
             "fpos@H@2@XZ";
    case 0x0545:
      return "?tellp@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAA?AV?$"
             "fpos@H@2@XZ";
    case 0x0546:
      return "?tellp@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAA?AV?$"
             "fpos@H@2@XZ";
    case 0x0547:
      return "?tie@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAPEAV?$basic_"
             "ostream@DU?$char_traits@D@std@@@2@PEAV32@@Z";
    case 0x0548:
      return "?tie@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBAPEAV?$basic_"
             "ostream@DU?$char_traits@D@std@@@2@XZ";
    case 0x0549:
      return "?tie@?$basic_ios@GU?$char_traits@G@std@@@std@@QEAAPEAV?$basic_"
             "ostream@GU?$char_traits@G@std@@@2@PEAV32@@Z";
    case 0x054a:
      return "?tie@?$basic_ios@GU?$char_traits@G@std@@@std@@QEBAPEAV?$basic_"
             "ostream@GU?$char_traits@G@std@@@2@XZ";
    case 0x054b:
      return "?tie@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAPEAV?$basic_"
             "ostream@_WU?$char_traits@_W@std@@@2@PEAV32@@Z";
    case 0x054c:
      return "?tie@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEBAPEAV?$basic_"
             "ostream@_WU?$char_traits@_W@std@@@2@XZ";
    case 0x054d:
      return "?tolower@?$ctype@D@std@@QEBADD@Z";
    case 0x054e:
      return "?tolower@?$ctype@D@std@@QEBAPEBDPEADPEBD@Z";
    case 0x054f:
      return "?tolower@?$ctype@G@std@@QEBAGG@Z";
    case 0x0550:
      return "?tolower@?$ctype@G@std@@QEBAPEBGPEAGPEBG@Z";
    case 0x0551:
      return "?tolower@?$ctype@_W@std@@QEBAPEB_WPEA_WPEB_W@Z";
    case 0x0552:
      return "?tolower@?$ctype@_W@std@@QEBA_W_W@Z";
    case 0x0553:
      return "?toupper@?$ctype@D@std@@QEBADD@Z";
    case 0x0554:
      return "?toupper@?$ctype@D@std@@QEBAPEBDPEADPEBD@Z";
    case 0x0555:
      return "?toupper@?$ctype@G@std@@QEBAGG@Z";
    case 0x0556:
      return "?toupper@?$ctype@G@std@@QEBAPEBGPEAGPEBG@Z";
    case 0x0557:
      return "?toupper@?$ctype@_W@std@@QEBAPEB_WPEA_WPEB_W@Z";
    case 0x0558:
      return "?toupper@?$ctype@_W@std@@QEBA_W_W@Z";
    case 0x0559:
      return "?try_to_lock@std@@3Utry_to_lock_t@1@B";
    case 0x055a:
      return "?uflow@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHXZ";
    case 0x055b:
      return "?uflow@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAAGXZ";
    case 0x055c:
      return "?uflow@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAAGXZ";
    case 0x055d:
      return "?uncaught_exception@std@@YA_NXZ";
    case 0x055e:
      return "?underflow@?$basic_streambuf@DU?$char_traits@D@std@@@std@@"
             "MEAAHXZ";
    case 0x055f:
      return "?underflow@?$basic_streambuf@GU?$char_traits@G@std@@@std@@"
             "MEAAGXZ";
    case 0x0560:
      return "?underflow@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@"
             "MEAAGXZ";
    case 0x0561:
      return "?unget@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "XZ";
    case 0x0562:
      return "?unget@?$basic_istream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "XZ";
    case 0x0563:
      return "?unget@?$basic_istream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "XZ";
    case 0x0564:
      return "?unsetf@ios_base@std@@QEAAXH@Z";
    case 0x0565:
      return "?unshift@?$codecvt@DDH@std@@QEBAHAEAHPEAD1AEAPEAD@Z";
    case 0x0566:
      return "?unshift@?$codecvt@GDH@std@@QEBAHAEAHPEAD1AEAPEAD@Z";
    case 0x0567:
      return "?unshift@?$codecvt@_WDH@std@@QEBAHAEAHPEAD1AEAPEAD@Z";
    case 0x0568:
      return "?wait@agent@Concurrency@@SA?AW4agent_status@2@PEAV12@I@Z";
    case 0x0569:
      return "?wait_for_all@agent@Concurrency@@SAX_KPEAPEAV12@PEAW4agent_"
             "status@2@I@Z";
    case 0x056a:
      return "?wait_for_one@agent@Concurrency@@SAX_KPEAPEAV12@AEAW4agent_"
             "status@2@AEA_KI@Z";
    case 0x056b:
      return "?wcerr@std@@3V?$basic_ostream@GU?$char_traits@G@std@@@1@A";
    case 0x056c:
      return "?wcerr@std@@3V?$basic_ostream@_WU?$char_traits@_W@std@@@1@A";
    case 0x056d:
      return "?wcin@std@@3V?$basic_istream@GU?$char_traits@G@std@@@1@A";
    case 0x056e:
      return "?wcin@std@@3V?$basic_istream@_WU?$char_traits@_W@std@@@1@A";
    case 0x056f:
      return "?wclog@std@@3V?$basic_ostream@GU?$char_traits@G@std@@@1@A";
    case 0x0570:
      return "?wclog@std@@3V?$basic_ostream@_WU?$char_traits@_W@std@@@1@A";
    case 0x0571:
      return "?wcout@std@@3V?$basic_ostream@GU?$char_traits@G@std@@@1@A";
    case 0x0572:
      return "?wcout@std@@3V?$basic_ostream@_WU?$char_traits@_W@std@@@1@A";
    case 0x0573:
      return "?widen@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBADD@Z";
    case 0x0574:
      return "?widen@?$basic_ios@GU?$char_traits@G@std@@@std@@QEBAGD@Z";
    case 0x0575:
      return "?widen@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEBA_WD@Z";
    case 0x0576:
      return "?widen@?$ctype@D@std@@QEBADD@Z";
    case 0x0577:
      return "?widen@?$ctype@D@std@@QEBAPEBDPEBD0PEAD@Z";
    case 0x0578:
      return "?widen@?$ctype@G@std@@QEBAGD@Z";
    case 0x0579:
      return "?widen@?$ctype@G@std@@QEBAPEBDPEBD0PEAG@Z";
    case 0x057a:
      return "?widen@?$ctype@_W@std@@QEBAPEBDPEBD0PEA_W@Z";
    case 0x057b:
      return "?widen@?$ctype@_W@std@@QEBA_WD@Z";
    case 0x057c:
      return "?width@ios_base@std@@QEAA_J_J@Z";
    case 0x057d:
      return "?width@ios_base@std@@QEBA_JXZ";
    case 0x057e:
      return "?write@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@"
             "PEBD_J@Z";
    case 0x057f:
      return "?write@?$basic_ostream@GU?$char_traits@G@std@@@std@@QEAAAEAV12@"
             "PEBG_J@Z";
    case 0x0580:
      return "?write@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@"
             "PEB_W_J@Z";
    case 0x0581:
      return "?ws@std@@YAAEAV?$basic_istream@DU?$char_traits@D@std@@@1@AEAV21@@"
             "Z";
    case 0x0582:
      return "?ws@std@@YAAEAV?$basic_istream@GU?$char_traits@G@std@@@1@AEAV21@@"
             "Z";
    case 0x0583:
      return "?ws@std@@YAAEAV?$basic_istream@_WU?$char_traits@_W@std@@@1@"
             "AEAV21@@Z";
    case 0x0584:
      return "?xalloc@ios_base@std@@SAHXZ";
    case 0x0585:
      return "?xsgetn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_"
             "JPEAD_J@Z";
    case 0x0586:
      return "?xsgetn@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAA_"
             "JPEAG_J@Z";
    case 0x0587:
      return "?xsgetn@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAA_"
             "JPEA_W_J@Z";
    case 0x0588:
      return "?xsputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_"
             "JPEBD_J@Z";
    case 0x0589:
      return "?xsputn@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MEAA_"
             "JPEBG_J@Z";
    case 0x058a:
      return "?xsputn@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@MEAA_"
             "JPEB_W_J@Z";
    case 0x058b:
      return "_Call_once";
    case 0x058c:
      return "_Call_onceEx";
    case 0x058d:
      return "_Cnd_broadcast";
    case 0x058e:
      return "_Cnd_destroy";
    case 0x058f:
      return "_Cnd_do_broadcast_at_thread_exit";
    case 0x0590:
      return "_Cnd_init";
    case 0x0591:
      return "_Cnd_register_at_thread_exit";
    case 0x0592:
      return "_Cnd_signal";
    case 0x0593:
      return "_Cnd_timedwait";
    case 0x0594:
      return "_Cnd_unregister_at_thread_exit";
    case 0x0595:
      return "_Cnd_wait";
    case 0x0596:
      return "_Cosh";
    case 0x0597:
      return "_Denorm";
    case 0x0598:
      return "_Dint";
    case 0x0599:
      return "_Dnorm";
    case 0x059a:
      return "_Do_call";
    case 0x059b:
      return "_Dscale";
    case 0x059c:
      return "_Dtento";
    case 0x059d:
      return "_Dtest";
    case 0x059e:
      return "_Dunscale";
    case 0x059f:
      return "_Eps";
    case 0x05a0:
      return "_Exp";
    case 0x05a1:
      return "_FCosh";
    case 0x05a2:
      return "_FDenorm";
    case 0x05a3:
      return "_FDint";
    case 0x05a4:
      return "_FDnorm";
    case 0x05a5:
      return "_FDscale";
    case 0x05a6:
      return "_FDtento";
    case 0x05a7:
      return "_FDtest";
    case 0x05a8:
      return "_FDunscale";
    case 0x05a9:
      return "_FEps";
    case 0x05aa:
      return "_FExp";
    case 0x05ab:
      return "_FInf";
    case 0x05ac:
      return "_FNan";
    case 0x05ad:
      return "_FRteps";
    case 0x05ae:
      return "_FSinh";
    case 0x05af:
      return "_FSnan";
    case 0x05b0:
      return "_FXbig";
    case 0x05b1:
      return "_FXp_addh";
    case 0x05b2:
      return "_FXp_addx";
    case 0x05b3:
      return "_FXp_getw";
    case 0x05b4:
      return "_FXp_invx";
    case 0x05b5:
      return "_FXp_ldexpx";
    case 0x05b6:
      return "_FXp_movx";
    case 0x05b7:
      return "_FXp_mulh";
    case 0x05b8:
      return "_FXp_mulx";
    case 0x05b9:
      return "_FXp_setn";
    case 0x05ba:
      return "_FXp_setw";
    case 0x05bb:
      return "_FXp_sqrtx";
    case 0x05bc:
      return "_FXp_subx";
    case 0x05bd:
      return "_FZero";
    case 0x05be:
      return "_Getcoll";
    case 0x05bf:
      return "_Getctype";
    case 0x05c0:
      return "_Getcvt";
    case 0x05c1:
      return "_Getdateorder";
    case 0x05c2:
      return "_Getwctype";
    case 0x05c3:
      return "_Getwctypes";
    case 0x05c4:
      return "_Hugeval";
    case 0x05c5:
      return "_Inf";
    case 0x05c6:
      return "_LCosh";
    case 0x05c7:
      return "_LDenorm";
    case 0x05c8:
      return "_LDint";
    case 0x05c9:
      return "_LDscale";
    case 0x05ca:
      return "_LDtento";
    case 0x05cb:
      return "_LDtest";
    case 0x05cc:
      return "_LDunscale";
    case 0x05cd:
      return "_LEps";
    case 0x05ce:
      return "_LExp";
    case 0x05cf:
      return "_LInf";
    case 0x05d0:
      return "_LNan";
    case 0x05d1:
      return "_LPoly";
    case 0x05d2:
      return "_LRteps";
    case 0x05d3:
      return "_LSinh";
    case 0x05d4:
      return "_LSnan";
    case 0x05d5:
      return "_LXbig";
    case 0x05d6:
      return "_LXp_addh";
    case 0x05d7:
      return "_LXp_addx";
    case 0x05d8:
      return "_LXp_getw";
    case 0x05d9:
      return "_LXp_invx";
    case 0x05da:
      return "_LXp_ldexpx";
    case 0x05db:
      return "_LXp_movx";
    case 0x05dc:
      return "_LXp_mulh";
    case 0x05dd:
      return "_LXp_mulx";
    case 0x05de:
      return "_LXp_setn";
    case 0x05df:
      return "_LXp_setw";
    case 0x05e0:
      return "_LXp_sqrtx";
    case 0x05e1:
      return "_LXp_subx";
    case 0x05e2:
      return "_LZero";
    case 0x05e3:
      return "_Lock_shared_ptr_spin_lock";
    case 0x05e4:
      return "_Mbrtowc";
    case 0x05e5:
      return "_Mtx_clear_owner";
    case 0x05e6:
      return "_Mtx_current_owns";
    case 0x05e7:
      return "_Mtx_destroy";
    case 0x05e8:
      return "_Mtx_getconcrtcs";
    case 0x05e9:
      return "_Mtx_init";
    case 0x05ea:
      return "_Mtx_lock";
    case 0x05eb:
      return "_Mtx_reset_owner";
    case 0x05ec:
      return "_Mtx_timedlock";
    case 0x05ed:
      return "_Mtx_trylock";
    case 0x05ee:
      return "_Mtx_unlock";
    case 0x05ef:
      return "_Mtxdst";
    case 0x05f0:
      return "_Mtxinit";
    case 0x05f1:
      return "_Mtxlock";
    case 0x05f2:
      return "_Mtxunlock";
    case 0x05f3:
      return "_Nan";
    case 0x05f4:
      return "_Once";
    case 0x05f5:
      return "_Poly";
    case 0x05f6:
      return "_Rteps";
    case 0x05f7:
      return "_Sinh";
    case 0x05f8:
      return "_Snan";
    case 0x05f9:
      return "_Stod";
    case 0x05fa:
      return "_Stodx";
    case 0x05fb:
      return "_Stof";
    case 0x05fc:
      return "_Stoflt";
    case 0x05fd:
      return "_Stofx";
    case 0x05fe:
      return "_Stold";
    case 0x05ff:
      return "_Stoldx";
    case 0x0600:
      return "_Stoll";
    case 0x0601:
      return "_Stollx";
    case 0x0602:
      return "_Stolx";
    case 0x0603:
      return "_Stopfx";
    case 0x0604:
      return "_Stoul";
    case 0x0605:
      return "_Stoull";
    case 0x0606:
      return "_Stoullx";
    case 0x0607:
      return "_Stoulx";
    case 0x0608:
      return "_Stoxflt";
    case 0x0609:
      return "_Strcoll";
    case 0x060a:
      return "_Strxfrm";
    case 0x060b:
      return "_Thrd_abort";
    case 0x060c:
      return "_Thrd_create";
    case 0x060d:
      return "_Thrd_current";
    case 0x060e:
      return "_Thrd_detach";
    case 0x060f:
      return "_Thrd_equal";
    case 0x0610:
      return "_Thrd_exit";
    case 0x0611:
      return "_Thrd_join";
    case 0x0612:
      return "_Thrd_lt";
    case 0x0613:
      return "_Thrd_sleep";
    case 0x0614:
      return "_Thrd_start";
    case 0x0615:
      return "_Thrd_yield";
    case 0x0616:
      return "_Tolower";
    case 0x0617:
      return "_Toupper";
    case 0x0618:
      return "_Towlower";
    case 0x0619:
      return "_Towupper";
    case 0x061a:
      return "_Tss_create";
    case 0x061b:
      return "_Tss_delete";
    case 0x061c:
      return "_Tss_get";
    case 0x061d:
      return "_Tss_set";
    case 0x061e:
      return "_Unlock_shared_ptr_spin_lock";
    case 0x061f:
      return "_Wcrtomb";
    case 0x0620:
      return "_Wcscoll";
    case 0x0621:
      return "_Wcsxfrm";
    case 0x0622:
      return "_Xbig";
    case 0x0623:
      return "_Xp_addh";
    case 0x0624:
      return "_Xp_addx";
    case 0x0625:
      return "_Xp_getw";
    case 0x0626:
      return "_Xp_invx";
    case 0x0627:
      return "_Xp_ldexpx";
    case 0x0628:
      return "_Xp_movx";
    case 0x0629:
      return "_Xp_mulh";
    case 0x062a:
      return "_Xp_mulx";
    case 0x062b:
      return "_Xp_setn";
    case 0x062c:
      return "_Xp_setw";
    case 0x062d:
      return "_Xp_sqrtx";
    case 0x062e:
      return "_Xp_subx";
    case 0x062f:
      return "_Xtime_diff_to_millis";
    case 0x0630:
      return "_Xtime_diff_to_millis2";
    case 0x0631:
      return "_Xtime_get_ticks";
    case 0x0632:
      return "_Zero";
    case 0x0633:
      return "__Wcrtomb_lk";
    case 0x0634:
      return "towctrans";
    case 0x0635:
      return "wctrans";
    case 0x0636:
      return "wctype";
    case 0x0637:
      return "xtime_get";
  }
  return nullptr;
}

}  // namespace PE
}  // namespace LIEF

#endif
