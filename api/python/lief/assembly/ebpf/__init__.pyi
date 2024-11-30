import enum
from typing import Iterator, Optional, Union

import lief


class Instruction(lief.assembly.Instruction):
    @property
    def opcode(self) -> OPCODE: ...

class OPCODE(enum.Enum):
    PHI = 0

    INLINEASM = 1

    INLINEASM_BR = 2

    CFI_INSTRUCTION = 3

    EH_LABEL = 4

    GC_LABEL = 5

    ANNOTATION_LABEL = 6

    KILL = 7

    EXTRACT_SUBREG = 8

    INSERT_SUBREG = 9

    IMPLICIT_DEF = 10

    SUBREG_TO_REG = 11

    COPY_TO_REGCLASS = 12

    DBG_VALUE = 13

    DBG_VALUE_LIST = 14

    DBG_INSTR_REF = 15

    DBG_PHI = 16

    DBG_LABEL = 17

    REG_SEQUENCE = 18

    COPY = 19

    BUNDLE = 20

    LIFETIME_START = 21

    LIFETIME_END = 22

    PSEUDO_PROBE = 23

    ARITH_FENCE = 24

    STACKMAP = 25

    FENTRY_CALL = 26

    PATCHPOINT = 27

    LOAD_STACK_GUARD = 28

    PREALLOCATED_SETUP = 29

    PREALLOCATED_ARG = 30

    STATEPOINT = 31

    LOCAL_ESCAPE = 32

    FAULTING_OP = 33

    PATCHABLE_OP = 34

    PATCHABLE_FUNCTION_ENTER = 35

    PATCHABLE_RET = 36

    PATCHABLE_FUNCTION_EXIT = 37

    PATCHABLE_TAIL_CALL = 38

    PATCHABLE_EVENT_CALL = 39

    PATCHABLE_TYPED_EVENT_CALL = 40

    ICALL_BRANCH_FUNNEL = 41

    MEMBARRIER = 42

    JUMP_TABLE_DEBUG_INFO = 43

    CONVERGENCECTRL_ENTRY = 44

    CONVERGENCECTRL_ANCHOR = 45

    CONVERGENCECTRL_LOOP = 46

    CONVERGENCECTRL_GLUE = 47

    G_ASSERT_SEXT = 48

    G_ASSERT_ZEXT = 49

    G_ASSERT_ALIGN = 50

    G_ADD = 51

    G_SUB = 52

    G_MUL = 53

    G_SDIV = 54

    G_UDIV = 55

    G_SREM = 56

    G_UREM = 57

    G_SDIVREM = 58

    G_UDIVREM = 59

    G_AND = 60

    G_OR = 61

    G_XOR = 62

    G_IMPLICIT_DEF = 63

    G_PHI = 64

    G_FRAME_INDEX = 65

    G_GLOBAL_VALUE = 66

    G_PTRAUTH_GLOBAL_VALUE = 67

    G_CONSTANT_POOL = 68

    G_EXTRACT = 69

    G_UNMERGE_VALUES = 70

    G_INSERT = 71

    G_MERGE_VALUES = 72

    G_BUILD_VECTOR = 73

    G_BUILD_VECTOR_TRUNC = 74

    G_CONCAT_VECTORS = 75

    G_PTRTOINT = 76

    G_INTTOPTR = 77

    G_BITCAST = 78

    G_FREEZE = 79

    G_CONSTANT_FOLD_BARRIER = 80

    G_INTRINSIC_FPTRUNC_ROUND = 81

    G_INTRINSIC_TRUNC = 82

    G_INTRINSIC_ROUND = 83

    G_INTRINSIC_LRINT = 84

    G_INTRINSIC_LLRINT = 85

    G_INTRINSIC_ROUNDEVEN = 86

    G_READCYCLECOUNTER = 87

    G_READSTEADYCOUNTER = 88

    G_LOAD = 89

    G_SEXTLOAD = 90

    G_ZEXTLOAD = 91

    G_INDEXED_LOAD = 92

    G_INDEXED_SEXTLOAD = 93

    G_INDEXED_ZEXTLOAD = 94

    G_STORE = 95

    G_INDEXED_STORE = 96

    G_ATOMIC_CMPXCHG_WITH_SUCCESS = 97

    G_ATOMIC_CMPXCHG = 98

    G_ATOMICRMW_XCHG = 99

    G_ATOMICRMW_ADD = 100

    G_ATOMICRMW_SUB = 101

    G_ATOMICRMW_AND = 102

    G_ATOMICRMW_NAND = 103

    G_ATOMICRMW_OR = 104

    G_ATOMICRMW_XOR = 105

    G_ATOMICRMW_MAX = 106

    G_ATOMICRMW_MIN = 107

    G_ATOMICRMW_UMAX = 108

    G_ATOMICRMW_UMIN = 109

    G_ATOMICRMW_FADD = 110

    G_ATOMICRMW_FSUB = 111

    G_ATOMICRMW_FMAX = 112

    G_ATOMICRMW_FMIN = 113

    G_ATOMICRMW_UINC_WRAP = 114

    G_ATOMICRMW_UDEC_WRAP = 115

    G_FENCE = 116

    G_PREFETCH = 117

    G_BRCOND = 118

    G_BRINDIRECT = 119

    G_INVOKE_REGION_START = 120

    G_INTRINSIC = 121

    G_INTRINSIC_W_SIDE_EFFECTS = 122

    G_INTRINSIC_CONVERGENT = 123

    G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS = 124

    G_ANYEXT = 125

    G_TRUNC = 126

    G_CONSTANT = 127

    G_FCONSTANT = 128

    G_VASTART = 129

    G_VAARG = 130

    G_SEXT = 131

    G_SEXT_INREG = 132

    G_ZEXT = 133

    G_SHL = 134

    G_LSHR = 135

    G_ASHR = 136

    G_FSHL = 137

    G_FSHR = 138

    G_ROTR = 139

    G_ROTL = 140

    G_ICMP = 141

    G_FCMP = 142

    G_SCMP = 143

    G_UCMP = 144

    G_SELECT = 145

    G_UADDO = 146

    G_UADDE = 147

    G_USUBO = 148

    G_USUBE = 149

    G_SADDO = 150

    G_SADDE = 151

    G_SSUBO = 152

    G_SSUBE = 153

    G_UMULO = 154

    G_SMULO = 155

    G_UMULH = 156

    G_SMULH = 157

    G_UADDSAT = 158

    G_SADDSAT = 159

    G_USUBSAT = 160

    G_SSUBSAT = 161

    G_USHLSAT = 162

    G_SSHLSAT = 163

    G_SMULFIX = 164

    G_UMULFIX = 165

    G_SMULFIXSAT = 166

    G_UMULFIXSAT = 167

    G_SDIVFIX = 168

    G_UDIVFIX = 169

    G_SDIVFIXSAT = 170

    G_UDIVFIXSAT = 171

    G_FADD = 172

    G_FSUB = 173

    G_FMUL = 174

    G_FMA = 175

    G_FMAD = 176

    G_FDIV = 177

    G_FREM = 178

    G_FPOW = 179

    G_FPOWI = 180

    G_FEXP = 181

    G_FEXP2 = 182

    G_FEXP10 = 183

    G_FLOG = 184

    G_FLOG2 = 185

    G_FLOG10 = 186

    G_FLDEXP = 187

    G_FFREXP = 188

    G_FNEG = 189

    G_FPEXT = 190

    G_FPTRUNC = 191

    G_FPTOSI = 192

    G_FPTOUI = 193

    G_SITOFP = 194

    G_UITOFP = 195

    G_FABS = 196

    G_FCOPYSIGN = 197

    G_IS_FPCLASS = 198

    G_FCANONICALIZE = 199

    G_FMINNUM = 200

    G_FMAXNUM = 201

    G_FMINNUM_IEEE = 202

    G_FMAXNUM_IEEE = 203

    G_FMINIMUM = 204

    G_FMAXIMUM = 205

    G_GET_FPENV = 206

    G_SET_FPENV = 207

    G_RESET_FPENV = 208

    G_GET_FPMODE = 209

    G_SET_FPMODE = 210

    G_RESET_FPMODE = 211

    G_PTR_ADD = 212

    G_PTRMASK = 213

    G_SMIN = 214

    G_SMAX = 215

    G_UMIN = 216

    G_UMAX = 217

    G_ABS = 218

    G_LROUND = 219

    G_LLROUND = 220

    G_BR = 221

    G_BRJT = 222

    G_VSCALE = 223

    G_INSERT_SUBVECTOR = 224

    G_EXTRACT_SUBVECTOR = 225

    G_INSERT_VECTOR_ELT = 226

    G_EXTRACT_VECTOR_ELT = 227

    G_SHUFFLE_VECTOR = 228

    G_SPLAT_VECTOR = 229

    G_VECTOR_COMPRESS = 230

    G_CTTZ = 231

    G_CTTZ_ZERO_UNDEF = 232

    G_CTLZ = 233

    G_CTLZ_ZERO_UNDEF = 234

    G_CTPOP = 235

    G_BSWAP = 236

    G_BITREVERSE = 237

    G_FCEIL = 238

    G_FCOS = 239

    G_FSIN = 240

    G_FTAN = 241

    G_FACOS = 242

    G_FASIN = 243

    G_FATAN = 244

    G_FCOSH = 245

    G_FSINH = 246

    G_FTANH = 247

    G_FSQRT = 248

    G_FFLOOR = 249

    G_FRINT = 250

    G_FNEARBYINT = 251

    G_ADDRSPACE_CAST = 252

    G_BLOCK_ADDR = 253

    G_JUMP_TABLE = 254

    G_DYN_STACKALLOC = 255

    G_STACKSAVE = 256

    G_STACKRESTORE = 257

    G_STRICT_FADD = 258

    G_STRICT_FSUB = 259

    G_STRICT_FMUL = 260

    G_STRICT_FDIV = 261

    G_STRICT_FREM = 262

    G_STRICT_FMA = 263

    G_STRICT_FSQRT = 264

    G_STRICT_FLDEXP = 265

    G_READ_REGISTER = 266

    G_WRITE_REGISTER = 267

    G_MEMCPY = 268

    G_MEMCPY_INLINE = 269

    G_MEMMOVE = 270

    G_MEMSET = 271

    G_BZERO = 272

    G_TRAP = 273

    G_DEBUGTRAP = 274

    G_UBSANTRAP = 275

    G_VECREDUCE_SEQ_FADD = 276

    G_VECREDUCE_SEQ_FMUL = 277

    G_VECREDUCE_FADD = 278

    G_VECREDUCE_FMUL = 279

    G_VECREDUCE_FMAX = 280

    G_VECREDUCE_FMIN = 281

    G_VECREDUCE_FMAXIMUM = 282

    G_VECREDUCE_FMINIMUM = 283

    G_VECREDUCE_ADD = 284

    G_VECREDUCE_MUL = 285

    G_VECREDUCE_AND = 286

    G_VECREDUCE_OR = 287

    G_VECREDUCE_XOR = 288

    G_VECREDUCE_SMAX = 289

    G_VECREDUCE_SMIN = 290

    G_VECREDUCE_UMAX = 291

    G_VECREDUCE_UMIN = 292

    G_SBFX = 293

    G_UBFX = 294

    ADJCALLSTACKDOWN = 295

    ADJCALLSTACKUP = 296

    FI_ri = 297

    MEMCPY = 298

    Select = 299

    Select_32 = 300

    Select_32_64 = 301

    Select_64_32 = 302

    Select_Ri = 303

    Select_Ri_32 = 304

    Select_Ri_32_64 = 305

    Select_Ri_64_32 = 306

    ADDR_SPACE_CAST = 307

    ADD_ri = 308

    ADD_ri_32 = 309

    ADD_rr = 310

    ADD_rr_32 = 311

    AND_ri = 312

    AND_ri_32 = 313

    AND_rr = 314

    AND_rr_32 = 315

    BE16 = 316

    BE32 = 317

    BE64 = 318

    BSWAP16 = 319

    BSWAP32 = 320

    BSWAP64 = 321

    CMPXCHGD = 322

    CMPXCHGW32 = 323

    CORE_LD32 = 324

    CORE_LD64 = 325

    CORE_SHIFT = 326

    CORE_ST = 327

    DIV_ri = 328

    DIV_ri_32 = 329

    DIV_rr = 330

    DIV_rr_32 = 331

    JAL = 332

    JALX = 333

    JCOND = 334

    JEQ_ri = 335

    JEQ_ri_32 = 336

    JEQ_rr = 337

    JEQ_rr_32 = 338

    JMP = 339

    JMPL = 340

    JNE_ri = 341

    JNE_ri_32 = 342

    JNE_rr = 343

    JNE_rr_32 = 344

    JSET_ri = 345

    JSET_ri_32 = 346

    JSET_rr = 347

    JSET_rr_32 = 348

    JSGE_ri = 349

    JSGE_ri_32 = 350

    JSGE_rr = 351

    JSGE_rr_32 = 352

    JSGT_ri = 353

    JSGT_ri_32 = 354

    JSGT_rr = 355

    JSGT_rr_32 = 356

    JSLE_ri = 357

    JSLE_ri_32 = 358

    JSLE_rr = 359

    JSLE_rr_32 = 360

    JSLT_ri = 361

    JSLT_ri_32 = 362

    JSLT_rr = 363

    JSLT_rr_32 = 364

    JUGE_ri = 365

    JUGE_ri_32 = 366

    JUGE_rr = 367

    JUGE_rr_32 = 368

    JUGT_ri = 369

    JUGT_ri_32 = 370

    JUGT_rr = 371

    JUGT_rr_32 = 372

    JULE_ri = 373

    JULE_ri_32 = 374

    JULE_rr = 375

    JULE_rr_32 = 376

    JULT_ri = 377

    JULT_ri_32 = 378

    JULT_rr = 379

    JULT_rr_32 = 380

    LDB = 381

    LDB32 = 382

    LDBSX = 383

    LDD = 384

    LDH = 385

    LDH32 = 386

    LDHSX = 387

    LDW = 388

    LDW32 = 389

    LDWSX = 390

    LD_ABS_B = 391

    LD_ABS_H = 392

    LD_ABS_W = 393

    LD_IND_B = 394

    LD_IND_H = 395

    LD_IND_W = 396

    LD_imm64 = 397

    LD_pseudo = 398

    LE16 = 399

    LE32 = 400

    LE64 = 401

    MOD_ri = 402

    MOD_ri_32 = 403

    MOD_rr = 404

    MOD_rr_32 = 405

    MOVSX_rr_16 = 406

    MOVSX_rr_32 = 407

    MOVSX_rr_32_16 = 408

    MOVSX_rr_32_8 = 409

    MOVSX_rr_8 = 410

    MOV_32_64 = 411

    MOV_ri = 412

    MOV_ri_32 = 413

    MOV_rr = 414

    MOV_rr_32 = 415

    MUL_ri = 416

    MUL_ri_32 = 417

    MUL_rr = 418

    MUL_rr_32 = 419

    NEG_32 = 420

    NEG_64 = 421

    NOP = 422

    OR_ri = 423

    OR_ri_32 = 424

    OR_rr = 425

    OR_rr_32 = 426

    RET = 427

    SDIV_ri = 428

    SDIV_ri_32 = 429

    SDIV_rr = 430

    SDIV_rr_32 = 431

    SLL_ri = 432

    SLL_ri_32 = 433

    SLL_rr = 434

    SLL_rr_32 = 435

    SMOD_ri = 436

    SMOD_ri_32 = 437

    SMOD_rr = 438

    SMOD_rr_32 = 439

    SRA_ri = 440

    SRA_ri_32 = 441

    SRA_rr = 442

    SRA_rr_32 = 443

    SRL_ri = 444

    SRL_ri_32 = 445

    SRL_rr = 446

    SRL_rr_32 = 447

    STB = 448

    STB32 = 449

    STB_imm = 450

    STD = 451

    STD_imm = 452

    STH = 453

    STH32 = 454

    STH_imm = 455

    STW = 456

    STW32 = 457

    STW_imm = 458

    SUB_ri = 459

    SUB_ri_32 = 460

    SUB_rr = 461

    SUB_rr_32 = 462

    XADDD = 463

    XADDW = 464

    XADDW32 = 465

    XANDD = 466

    XANDW32 = 467

    XCHGD = 468

    XCHGW32 = 469

    XFADDD = 470

    XFADDW32 = 471

    XFANDD = 472

    XFANDW32 = 473

    XFORD = 474

    XFORW32 = 475

    XFXORD = 476

    XFXORW32 = 477

    XORD = 478

    XORW32 = 479

    XOR_ri = 480

    XOR_ri_32 = 481

    XOR_rr = 482

    XOR_rr_32 = 483

    XXORD = 484

    XXORW32 = 485

    INSTRUCTION_LIST_END = 486
