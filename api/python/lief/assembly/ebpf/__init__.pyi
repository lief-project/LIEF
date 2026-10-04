from collections.abc import Iterator
import enum
from typing import Optional

import lief.assembly
from lief.assembly.ebpf import operands as operands


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

    INIT_UNDEF = 11

    SUBREG_TO_REG = 12

    COPY_TO_REGCLASS = 13

    DBG_VALUE = 14

    DBG_VALUE_LIST = 15

    DBG_INSTR_REF = 16

    DBG_PHI = 17

    DBG_LABEL = 18

    REG_SEQUENCE = 19

    COPY = 20

    COPY_LANEMASK = 21

    BUNDLE = 22

    LIFETIME_START = 23

    LIFETIME_END = 24

    PSEUDO_PROBE = 25

    ARITH_FENCE = 26

    STACKMAP = 27

    FENTRY_CALL = 28

    PATCHPOINT = 29

    LOAD_STACK_GUARD = 30

    PREALLOCATED_SETUP = 31

    PREALLOCATED_ARG = 32

    STATEPOINT = 33

    LOCAL_ESCAPE = 34

    FAULTING_OP = 35

    PATCHABLE_OP = 36

    PATCHABLE_FUNCTION_ENTER = 37

    PATCHABLE_RET = 38

    PATCHABLE_FUNCTION_EXIT = 39

    PATCHABLE_TAIL_CALL = 40

    PATCHABLE_EVENT_CALL = 41

    PATCHABLE_TYPED_EVENT_CALL = 42

    ICALL_BRANCH_FUNNEL = 43

    FAKE_USE = 44

    MEMBARRIER = 45

    JUMP_TABLE_DEBUG_INFO = 46

    RELOC_NONE = 47

    CONVERGENCECTRL_ENTRY = 48

    CONVERGENCECTRL_ANCHOR = 49

    CONVERGENCECTRL_LOOP = 50

    CONVERGENCECTRL_GLUE = 51

    G_ASSERT_SEXT = 52

    G_ASSERT_ZEXT = 53

    G_ASSERT_ALIGN = 54

    G_ADD = 55

    G_SUB = 56

    G_MUL = 57

    G_SDIV = 58

    G_UDIV = 59

    G_SREM = 60

    G_UREM = 61

    G_SDIVREM = 62

    G_UDIVREM = 63

    G_AND = 64

    G_OR = 65

    G_XOR = 66

    G_ABDS = 67

    G_ABDU = 68

    G_UAVGFLOOR = 69

    G_UAVGCEIL = 70

    G_SAVGFLOOR = 71

    G_SAVGCEIL = 72

    G_IMPLICIT_DEF = 73

    G_PHI = 74

    G_FRAME_INDEX = 75

    G_GLOBAL_VALUE = 76

    G_PTRAUTH_GLOBAL_VALUE = 77

    G_CONSTANT_POOL = 78

    G_EXTRACT = 79

    G_UNMERGE_VALUES = 80

    G_INSERT = 81

    G_MERGE_VALUES = 82

    G_BUILD_VECTOR = 83

    G_BUILD_VECTOR_TRUNC = 84

    G_CONCAT_VECTORS = 85

    G_PTRTOINT = 86

    G_INTTOPTR = 87

    G_BITCAST = 88

    G_FREEZE = 89

    G_CONSTANT_FOLD_BARRIER = 90

    G_INTRINSIC_FPTRUNC_ROUND = 91

    G_INTRINSIC_TRUNC = 92

    G_INTRINSIC_ROUND = 93

    G_INTRINSIC_LRINT = 94

    G_INTRINSIC_LLRINT = 95

    G_INTRINSIC_ROUNDEVEN = 96

    G_READCYCLECOUNTER = 97

    G_READSTEADYCOUNTER = 98

    G_LOAD = 99

    G_SEXTLOAD = 100

    G_ZEXTLOAD = 101

    G_FPEXTLOAD = 102

    G_INDEXED_LOAD = 103

    G_INDEXED_SEXTLOAD = 104

    G_INDEXED_ZEXTLOAD = 105

    G_STORE = 106

    G_FPTRUNCSTORE = 107

    G_INDEXED_STORE = 108

    G_ATOMIC_CMPXCHG_WITH_SUCCESS = 109

    G_ATOMIC_CMPXCHG = 110

    G_ATOMICRMW_XCHG = 111

    G_ATOMICRMW_ADD = 112

    G_ATOMICRMW_SUB = 113

    G_ATOMICRMW_AND = 114

    G_ATOMICRMW_NAND = 115

    G_ATOMICRMW_OR = 116

    G_ATOMICRMW_XOR = 117

    G_ATOMICRMW_MAX = 118

    G_ATOMICRMW_MIN = 119

    G_ATOMICRMW_UMAX = 120

    G_ATOMICRMW_UMIN = 121

    G_ATOMICRMW_FADD = 122

    G_ATOMICRMW_FSUB = 123

    G_ATOMICRMW_FMAX = 124

    G_ATOMICRMW_FMIN = 125

    G_ATOMICRMW_FMAXIMUM = 126

    G_ATOMICRMW_FMINIMUM = 127

    G_ATOMICRMW_FMAXIMUMNUM = 128

    G_ATOMICRMW_FMINIMUMNUM = 129

    G_ATOMICRMW_UINC_WRAP = 130

    G_ATOMICRMW_UDEC_WRAP = 131

    G_ATOMICRMW_USUB_COND = 132

    G_ATOMICRMW_USUB_SAT = 133

    G_FENCE = 134

    G_PREFETCH = 135

    G_BRCOND = 136

    G_BRINDIRECT = 137

    G_INVOKE_REGION_START = 138

    G_INTRINSIC = 139

    G_INTRINSIC_W_SIDE_EFFECTS = 140

    G_INTRINSIC_CONVERGENT = 141

    G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS = 142

    G_ANYEXT = 143

    G_TRUNC = 144

    G_TRUNC_SSAT_S = 145

    G_TRUNC_SSAT_U = 146

    G_TRUNC_USAT_U = 147

    G_CONSTANT = 148

    G_FCONSTANT = 149

    G_VASTART = 150

    G_VAARG = 151

    G_SEXT = 152

    G_SEXT_INREG = 153

    G_ZEXT = 154

    G_SHL = 155

    G_LSHR = 156

    G_ASHR = 157

    G_FSHL = 158

    G_FSHR = 159

    G_ROTR = 160

    G_ROTL = 161

    G_ICMP = 162

    G_FCMP = 163

    G_SCMP = 164

    G_UCMP = 165

    G_SELECT = 166

    G_UADDO = 167

    G_UADDE = 168

    G_USUBO = 169

    G_USUBE = 170

    G_SADDO = 171

    G_SADDE = 172

    G_SSUBO = 173

    G_SSUBE = 174

    G_UMULO = 175

    G_SMULO = 176

    G_UMULH = 177

    G_SMULH = 178

    G_UADDSAT = 179

    G_SADDSAT = 180

    G_USUBSAT = 181

    G_SSUBSAT = 182

    G_USHLSAT = 183

    G_SSHLSAT = 184

    G_SMULFIX = 185

    G_UMULFIX = 186

    G_SMULFIXSAT = 187

    G_UMULFIXSAT = 188

    G_SDIVFIX = 189

    G_UDIVFIX = 190

    G_SDIVFIXSAT = 191

    G_UDIVFIXSAT = 192

    G_FADD = 193

    G_FSUB = 194

    G_FMUL = 195

    G_FMA = 196

    G_FMAD = 197

    G_FDIV = 198

    G_FREM = 199

    G_FMODF = 200

    G_FPOW = 201

    G_FPOWI = 202

    G_FEXP = 203

    G_FEXP2 = 204

    G_FEXP10 = 205

    G_FLOG = 206

    G_FLOG2 = 207

    G_FLOG10 = 208

    G_FLDEXP = 209

    G_FFREXP = 210

    G_FNEG = 211

    G_FPEXT = 212

    G_FPTRUNC = 213

    G_FPTOSI = 214

    G_FPTOUI = 215

    G_SITOFP = 216

    G_UITOFP = 217

    G_FPTOSI_SAT = 218

    G_FPTOUI_SAT = 219

    G_FABS = 220

    G_FCOPYSIGN = 221

    G_IS_FPCLASS = 222

    G_FCANONICALIZE = 223

    G_FMINNUM = 224

    G_FMAXNUM = 225

    G_FMINNUM_IEEE = 226

    G_FMAXNUM_IEEE = 227

    G_FMINIMUM = 228

    G_FMAXIMUM = 229

    G_FMINIMUMNUM = 230

    G_FMAXIMUMNUM = 231

    G_GET_FPENV = 232

    G_SET_FPENV = 233

    G_RESET_FPENV = 234

    G_GET_FPMODE = 235

    G_SET_FPMODE = 236

    G_RESET_FPMODE = 237

    G_GET_ROUNDING = 238

    G_SET_ROUNDING = 239

    G_PTR_ADD = 240

    G_PTRMASK = 241

    G_SMIN = 242

    G_SMAX = 243

    G_UMIN = 244

    G_UMAX = 245

    G_ABS = 246

    G_LROUND = 247

    G_LLROUND = 248

    G_BR = 249

    G_BRJT = 250

    G_VSCALE = 251

    G_INSERT_SUBVECTOR = 252

    G_EXTRACT_SUBVECTOR = 253

    G_INSERT_VECTOR_ELT = 254

    G_EXTRACT_VECTOR_ELT = 255

    G_SHUFFLE_VECTOR = 256

    G_SPLAT_VECTOR = 257

    G_STEP_VECTOR = 258

    G_VECTOR_COMPRESS = 259

    G_CTTZ = 260

    G_CTTZ_ZERO_POISON = 261

    G_CTLZ = 262

    G_CTLZ_ZERO_POISON = 263

    G_CTLS = 264

    G_CTPOP = 265

    G_BSWAP = 266

    G_BITREVERSE = 267

    G_CLMUL = 268

    G_FCEIL = 269

    G_FCOS = 270

    G_FSIN = 271

    G_FSINCOS = 272

    G_FTAN = 273

    G_FACOS = 274

    G_FASIN = 275

    G_FATAN = 276

    G_FATAN2 = 277

    G_FCOSH = 278

    G_FSINH = 279

    G_FTANH = 280

    G_FSQRT = 281

    G_FFLOOR = 282

    G_FRINT = 283

    G_FNEARBYINT = 284

    G_ADDRSPACE_CAST = 285

    G_BLOCK_ADDR = 286

    G_JUMP_TABLE = 287

    G_DYN_STACKALLOC = 288

    G_STACKSAVE = 289

    G_STACKRESTORE = 290

    G_STRICT_FADD = 291

    G_STRICT_FSUB = 292

    G_STRICT_FMUL = 293

    G_STRICT_FDIV = 294

    G_STRICT_FREM = 295

    G_STRICT_FMA = 296

    G_STRICT_FSQRT = 297

    G_STRICT_FLDEXP = 298

    G_STRICT_FCMP = 299

    G_STRICT_FCMPS = 300

    G_READ_REGISTER = 301

    G_WRITE_REGISTER = 302

    G_MEMCPY = 303

    G_MEMCPY_INLINE = 304

    G_MEMMOVE = 305

    G_MEMSET = 306

    G_BZERO = 307

    G_MEMSET_INLINE = 308

    G_TRAP = 309

    G_DEBUGTRAP = 310

    G_UBSANTRAP = 311

    G_VECREDUCE_SEQ_FADD = 312

    G_VECREDUCE_SEQ_FMUL = 313

    G_VECREDUCE_FADD = 314

    G_VECREDUCE_FMUL = 315

    G_VECREDUCE_FMAX = 316

    G_VECREDUCE_FMIN = 317

    G_VECREDUCE_FMAXIMUM = 318

    G_VECREDUCE_FMINIMUM = 319

    G_VECREDUCE_ADD = 320

    G_VECREDUCE_MUL = 321

    G_VECREDUCE_AND = 322

    G_VECREDUCE_OR = 323

    G_VECREDUCE_XOR = 324

    G_VECREDUCE_SMAX = 325

    G_VECREDUCE_SMIN = 326

    G_VECREDUCE_UMAX = 327

    G_VECREDUCE_UMIN = 328

    G_SBFX = 329

    G_UBFX = 330

    ADJCALLSTACKDOWN = 331

    ADJCALLSTACKUP = 332

    FI_ri = 333

    LDIMM64 = 334

    LOAD_STACK_ARG_PSEUDO = 335

    MEMCPY = 336

    STORE_STACK_ARG_IMM_PSEUDO = 337

    STORE_STACK_ARG_PSEUDO = 338

    Select = 339

    Select_32 = 340

    Select_32_64 = 341

    Select_64_32 = 342

    Select_Ri = 343

    Select_Ri_32 = 344

    Select_Ri_32_64 = 345

    Select_Ri_64_32 = 346

    ADDR_SPACE_CAST = 347

    ADD_ri = 348

    ADD_ri_32 = 349

    ADD_rr = 350

    ADD_rr_32 = 351

    AND_ri = 352

    AND_ri_32 = 353

    AND_rr = 354

    AND_rr_32 = 355

    BE16 = 356

    BE32 = 357

    BE64 = 358

    BSWAP16 = 359

    BSWAP32 = 360

    BSWAP64 = 361

    CMPXCHGD = 362

    CMPXCHGW32 = 363

    CORE_LD32 = 364

    CORE_LD64 = 365

    CORE_SHIFT = 366

    CORE_ST = 367

    DIV_ri = 368

    DIV_ri_32 = 369

    DIV_rr = 370

    DIV_rr_32 = 371

    JAL = 372

    JALX = 373

    JCOND = 374

    JEQ_ri = 375

    JEQ_ri_32 = 376

    JEQ_rr = 377

    JEQ_rr_32 = 378

    JMP = 379

    JMPL = 380

    JNE_ri = 381

    JNE_ri_32 = 382

    JNE_rr = 383

    JNE_rr_32 = 384

    JSET_ri = 385

    JSET_ri_32 = 386

    JSET_rr = 387

    JSET_rr_32 = 388

    JSGE_ri = 389

    JSGE_ri_32 = 390

    JSGE_rr = 391

    JSGE_rr_32 = 392

    JSGT_ri = 393

    JSGT_ri_32 = 394

    JSGT_rr = 395

    JSGT_rr_32 = 396

    JSLE_ri = 397

    JSLE_ri_32 = 398

    JSLE_rr = 399

    JSLE_rr_32 = 400

    JSLT_ri = 401

    JSLT_ri_32 = 402

    JSLT_rr = 403

    JSLT_rr_32 = 404

    JUGE_ri = 405

    JUGE_ri_32 = 406

    JUGE_rr = 407

    JUGE_rr_32 = 408

    JUGT_ri = 409

    JUGT_ri_32 = 410

    JUGT_rr = 411

    JUGT_rr_32 = 412

    JULE_ri = 413

    JULE_ri_32 = 414

    JULE_rr = 415

    JULE_rr_32 = 416

    JULT_ri = 417

    JULT_ri_32 = 418

    JULT_rr = 419

    JULT_rr_32 = 420

    JX = 421

    LDB = 422

    LDB32 = 423

    LDBACQ32 = 424

    LDBSX = 425

    LDD = 426

    LDDACQ = 427

    LDH = 428

    LDH32 = 429

    LDHACQ32 = 430

    LDHSX = 431

    LDW = 432

    LDW32 = 433

    LDWACQ32 = 434

    LDWSX = 435

    LD_ABS_B = 436

    LD_ABS_H = 437

    LD_ABS_W = 438

    LD_IND_B = 439

    LD_IND_H = 440

    LD_IND_W = 441

    LD_imm64 = 442

    LD_pseudo = 443

    LE16 = 444

    LE32 = 445

    LE64 = 446

    MOD_ri = 447

    MOD_ri_32 = 448

    MOD_rr = 449

    MOD_rr_32 = 450

    MOVSX_rr_16 = 451

    MOVSX_rr_32 = 452

    MOVSX_rr_32_16 = 453

    MOVSX_rr_32_8 = 454

    MOVSX_rr_8 = 455

    MOV_32_64 = 456

    MOV_ri = 457

    MOV_ri_32 = 458

    MOV_rr = 459

    MOV_rr_32 = 460

    MUL_ri = 461

    MUL_ri_32 = 462

    MUL_rr = 463

    MUL_rr_32 = 464

    NEG_32 = 465

    NEG_64 = 466

    NOP = 467

    OR_ri = 468

    OR_ri_32 = 469

    OR_rr = 470

    OR_rr_32 = 471

    RET = 472

    SDIV_ri = 473

    SDIV_ri_32 = 474

    SDIV_rr = 475

    SDIV_rr_32 = 476

    SLL_ri = 477

    SLL_ri_32 = 478

    SLL_rr = 479

    SLL_rr_32 = 480

    SMOD_ri = 481

    SMOD_ri_32 = 482

    SMOD_rr = 483

    SMOD_rr_32 = 484

    SRA_ri = 485

    SRA_ri_32 = 486

    SRA_rr = 487

    SRA_rr_32 = 488

    SRL_ri = 489

    SRL_ri_32 = 490

    SRL_rr = 491

    SRL_rr_32 = 492

    STB = 493

    STB32 = 494

    STBREL32 = 495

    STB_imm = 496

    STD = 497

    STDREL = 498

    STD_imm = 499

    STH = 500

    STH32 = 501

    STHREL32 = 502

    STH_imm = 503

    STW = 504

    STW32 = 505

    STWREL32 = 506

    STW_imm = 507

    SUB_ri = 508

    SUB_ri_32 = 509

    SUB_rr = 510

    SUB_rr_32 = 511

    XADDD = 512

    XADDW = 513

    XADDW32 = 514

    XANDD = 515

    XANDW32 = 516

    XCHGD = 517

    XCHGW32 = 518

    XFADDD = 519

    XFADDW32 = 520

    XFANDD = 521

    XFANDW32 = 522

    XFORD = 523

    XFORW32 = 524

    XFXORD = 525

    XFXORW32 = 526

    XORD = 527

    XORW32 = 528

    XOR_ri = 529

    XOR_ri_32 = 530

    XOR_rr = 531

    XOR_rr_32 = 532

    XXORD = 533

    XXORW32 = 534

    INSTRUCTION_LIST_END = 535

class REG(enum.Enum):
    NoRegister = 0

    R0 = 1

    R1 = 2

    R2 = 3

    R3 = 4

    R4 = 5

    R5 = 6

    R6 = 7

    R7 = 8

    R8 = 9

    R9 = 10

    R10 = 11

    R11 = 12

    W0 = 13

    W1 = 14

    W2 = 15

    W3 = 16

    W4 = 17

    W5 = 18

    W6 = 19

    W7 = 20

    W8 = 21

    W9 = 22

    W10 = 23

    W11 = 24

    NUM_TARGET_REGS = 25

class Instruction(lief.assembly.Instruction):
    __match_args__: tuple = ...

    @property
    def opcode(self) -> OPCODE: ...

    @property
    def operands(self) -> Iterator[Optional[Operand]]: ...

class Operand:
    @property
    def to_string(self) -> str: ...

    def __str__(self) -> str: ...
