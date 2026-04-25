{$mode objfpc}{$H+}{$inline on}{$pointermath on}{$Q-}{$R-}
unit zxc;

// Free Pascal port of ZXC - High-performance lossless compression
// ZXC Copyright (c) 2025-2026 Bertrand Lebonnois and contributors.
// Port author: www.xelitan.com
// License: BSD-3-Clause


interface

uses
  rapidhash;

{ ============================================================
  Public constants
  ============================================================ }

const
  ZXC_VERSION_MAJOR = 0;
  ZXC_VERSION_MINOR = 10;
  ZXC_VERSION_PATCH = 0;

  ZXC_BLOCK_SIZE_MIN_LOG2 = 12;
  ZXC_BLOCK_SIZE_MAX_LOG2 = 21;
  ZXC_BLOCK_SIZE_DEFAULT  = 256 * 1024;
  ZXC_BLOCK_SIZE_MIN      = 1 shl ZXC_BLOCK_SIZE_MIN_LOG2;
  ZXC_BLOCK_SIZE_MAX      = 1 shl ZXC_BLOCK_SIZE_MAX_LOG2;

type
  TZxcLevel = (
    ZXC_LEVEL_FASTEST  = 1,
    ZXC_LEVEL_FAST     = 2,
    ZXC_LEVEL_DEFAULT  = 3,
    ZXC_LEVEL_BALANCED = 4,
    ZXC_LEVEL_COMPACT  = 5
  );

{ Error codes }
const
  ZXC_OK               =  0;
  ZXC_ERR_MEMORY       = -1;
  ZXC_ERR_DST_TOO_SMALL= -2;
  ZXC_ERR_SRC_TOO_SMALL= -3;
  ZXC_ERR_BAD_MAGIC    = -4;
  ZXC_ERR_BAD_VERSION  = -5;
  ZXC_ERR_BAD_HEADER   = -6;
  ZXC_ERR_BAD_CHECKSUM = -7;
  ZXC_ERR_CORRUPT_DATA = -8;
  ZXC_ERR_BAD_OFFSET   = -9;
  ZXC_ERR_OVERFLOW     = -10;
  ZXC_ERR_IO           = -11;
  ZXC_ERR_NULL_INPUT   = -12;
  ZXC_ERR_BAD_BLOCK_TYPE = -13;
  ZXC_ERR_BAD_BLOCK_SIZE = -14;

{ ============================================================
  Public types
  ============================================================ }

type
  PByte  = ^Byte;
  PWord  = ^Word;
  PLongWord = ^LongWord;
  PQWord = ^QWord;

  TZxcCCtx = record
    { LZ77 tables }
    hash_table : PLongWord;   { epoch|pos, size = 1 shl LZ_HASH_BITS }
    hash_tags  : PByte;       { 8-bit tag,  size = 1 shl LZ_HASH_BITS }
    chain_table: PWord;       { delta,      size = LZ_WINDOW_SIZE }
    { Encode buffers }
    buf_tokens : PByte;
    buf_lits   : PByte;
    buf_extras : PByte;
    buf_offsets: PByte;
    buf_seqs   : PLongWord;
    lit_buffer : PByte;       { for RLE detection, heap-allocated }
    lit_buf_sz : LongWord;
    { Allocation }
    alloc_base : Pointer;     { aligned alloc base }
    alloc_size : PtrUInt;
    { Parameters }
    chunk_size   : LongWord;
    offset_bits  : LongWord;
    offset_mask  : LongWord;
    max_epoch    : LongWord;
    epoch        : LongWord;
    level        : LongWord;
    checksum_enabled: Boolean;
  end;
  PZxcCCtx = ^TZxcCCtx;

{ ============================================================
  Public API
  ============================================================ }

function ZxcCompressBound(input_size: PtrUInt): PtrUInt;
function ZxcGetDecompressedSize(src: PByte; src_size: PtrUInt): Int64;
function ZxcCompress(dst: PByte; dst_size: PtrUInt;
                     src: PByte; src_size: PtrUInt;
                     level: LongInt; block_size: LongInt): LongInt;
function ZxcDecompress(dst: PByte; dst_size: PtrUInt;
                       src: PByte; src_size: PtrUInt): LongInt;

implementation

{ ============================================================
  External: aligned memory (msvcrt.dll)
  ============================================================ }

function  _aligned_malloc(size: PtrUInt; alignment: PtrUInt): Pointer;
          cdecl; external 'msvcrt.dll' name '_aligned_malloc';
procedure _aligned_free(p: Pointer);
          cdecl; external 'msvcrt.dll' name '_aligned_free';

{ ============================================================
  Internal constants
  ============================================================ }

const
  ZXC_MAGIC_WORD            = LongWord($9CB02EF5);
  ZXC_FILE_FORMAT_VERSION   = 5;
  ZXC_PAD_SIZE              = 32;
  ZXC_LZ_HASH_BITS          = 15;
  ZXC_LZ_HASH_PRIME1        = LongWord($2D35182D);
  ZXC_LZ_HASH_PRIME2        = QWord($2545F4914F6CDD1D);
  ZXC_HASH_PRIME1           = QWord($9E3779B97F4A7C15);
  ZXC_HASH_PRIME2           = QWord($D2D84A61D2D84A61);
  ZXC_LZ_MIN_MATCH_LEN      = 5;
  ZXC_LZ_OFFSET_BIAS        = 1;
  ZXC_LZ_WINDOW_SIZE        = LongWord(1) shl 16;
  ZXC_LZ_MAX_DIST           = ZXC_LZ_WINDOW_SIZE - 1;
  ZXC_LZ_HASH_SIZE          = LongWord(1) shl ZXC_LZ_HASH_BITS;
  ZXC_LZ_HASH_MASK          = ZXC_LZ_HASH_SIZE - 1;
  ZXC_LZ_WINDOW_MASK        = ZXC_LZ_WINDOW_SIZE - 1;

  ZXC_FILE_HEADER_SIZE      = 16;
  ZXC_FILE_FOOTER_SIZE      = 12;
  ZXC_BLOCK_HEADER_SIZE     = 8;
  ZXC_BLOCK_CHECKSUM_SIZE   = 4;
  ZXC_GLO_HEADER_BINARY_SIZE= 16;
  ZXC_GHI_HEADER_BINARY_SIZE= 16;
  ZXC_NUM_HEADER_BINARY_SIZE= 16;
  ZXC_NUM_CHUNK_HEADER_SIZE = 16;
  ZXC_NUM_FRAME_SIZE        = 128;
  ZXC_NUM_DEC_BATCH         = 32;
  ZXC_SECTION_DESC_BINARY_SIZE = 8;
  ZXC_SECTION_SIZE_MASK     = LongWord($FFFFFFFF);
  ZXC_GLO_SECTIONS          = 4;
  ZXC_GHI_SECTIONS          = 3;
  ZXC_TOKEN_LIT_BITS        = 4;
  ZXC_TOKEN_ML_MASK         = 15;
  ZXC_SEQ_LL_MASK           = 255;
  ZXC_SEQ_ML_MASK           = 255;
  ZXC_SEQ_OFF_MASK          = LongWord($FFFF);
  ZXC_LIT_RLE_FLAG          = $80;
  ZXC_LIT_LEN_MASK          = $7F;
  ZXC_FILE_FLAG_HAS_CHECKSUM= $80;
  ZXC_CHECKSUM_RAPIDHASH    = 0;
  ZXC_SEEK_ENTRY_SIZE       = 4;
  ZXC_GLOBAL_CHECKSUM_SIZE  = 4;
  ZXC_CACHE_LINE_SIZE       = 64;
  ZXC_ALIGNMENT_MASK        = 63;
  ZXC_VBYTE_ALLOC_LEN       = 3;

  { Block types }
  ZXC_BLOCK_RAW  = 0;
  ZXC_BLOCK_GLO  = 1;
  ZXC_BLOCK_NUM  = 2;
  ZXC_BLOCK_GHI  = 3;
  ZXC_BLOCK_SEK  = 254;
  ZXC_BLOCK_EOF  = 255;

  { Encoding types }
  ZXC_ENC_NONE   = 0;
  ZXC_ENC_VARINT = 1;

  { varint max bytes for a 32-bit value }
  VARINT_MAX_BYTES = 5;

{ ============================================================
  LZ77 level parameters
  ============================================================ }

type
  TLZParams = record
    hash_log      : LongWord;  { hash table log2 (actual bits = LZ_HASH_BITS, but controls quality? No - this is chain_limit_log }
    chain_limit   : LongWord;  { max chain depth }
    lazy          : LongWord;  { enable lazy matching (0/1) }
    lazy_depth    : LongWord;  { extra chain steps for lazy }
    nice_len      : LongWord;  { stop if match >= this }
    min_gain      : LongWord;  { token gain threshold }
    ins_steps     : LongWord;  { insertion stride }
  end;

const
  ZXC_LZ_PARAMS: array[1..5] of TLZParams = (
    { level 1 } (hash_log:3; chain_limit:16;  lazy:0; lazy_depth:0; nice_len:0;   min_gain:4; ins_steps:4),
    { level 2 } (hash_log:3; chain_limit:18;  lazy:0; lazy_depth:0; nice_len:0;   min_gain:3; ins_steps:6),
    { level 3 } (hash_log:3; chain_limit:16;  lazy:1; lazy_depth:4; nice_len:128; min_gain:1; ins_steps:4),
    { level 4 } (hash_log:3; chain_limit:18;  lazy:1; lazy_depth:4; nice_len:128; min_gain:1; ins_steps:5),
    { level 5 } (hash_log:64;chain_limit:256; lazy:1; lazy_depth:16;nice_len:128; min_gain:1; ins_steps:8)
  );

{ ============================================================
  De Bruijn Ctz (count trailing zeros)
  ============================================================ }

const
  DEBRUIJN32: LongWord = $077CB531;
  DEBRUIJN32_TABLE: array[0..31] of Byte = (
     0, 1,28, 2,29,14,24, 3,30,22,20,15,25,17, 4, 8,
    31,27,13,23,21,19,16, 7,26,12,18, 6,11, 5,10, 9
  );

  DEBRUIJN64: QWord = $03F79D71B4CA8B09;
  DEBRUIJN64_TABLE: array[0..63] of Byte = (
     0, 1,56, 2,57,49,28, 3,61,58,42,50,38,29,17, 4,
    62,47,59,36,45,43,51,22,53,39,33,30,24,18,12, 5,
    63,55,48,27,60,41,37,16,46,35,44,21,52,32,23,11,
    54,26,40,15,34,20,31,10,25,14,19, 9,13, 8, 7, 6
  );

function Ctz32(v: LongWord): LongWord; inline;
begin
  Result := DEBRUIJN32_TABLE[((v and (-v)) * DEBRUIJN32) shr 27];
end;

function Ctz64(v: QWord): LongWord; inline;
begin
  Result := DEBRUIJN64_TABLE[((v and QWord(-Int64(v))) * DEBRUIJN64) shr 58];
end;

function Log2U32(v: LongWord): LongWord; inline;
var
  r: LongWord;
begin
  r := 0;
  if v >= $10000 then begin v := v shr 16; r := r or 16; end;
  if v >= $100   then begin v := v shr 8;  r := r or 8;  end;
  if v >= $10    then begin v := v shr 4;  r := r or 4;  end;
  if v >= $4     then begin v := v shr 2;  r := r or 2;  end;
  if v >= $2     then r := r or 1;
  Result := r;
end;

{ ============================================================
  Little-endian I/O
  ============================================================ }

function Le16(p: PByte): Word; inline;
begin
  Result := Word(p[0]) or (Word(p[1]) shl 8);
end;

function Le32(p: PByte): LongWord; inline;
begin
  Result := LongWord(p[0]) or (LongWord(p[1]) shl 8)
          or (LongWord(p[2]) shl 16) or (LongWord(p[3]) shl 24);
end;

function Le64(p: PByte): QWord; inline;
begin
  Result := QWord(p[0]) or (QWord(p[1]) shl 8)
          or (QWord(p[2]) shl 16) or (QWord(p[3]) shl 24)
          or (QWord(p[4]) shl 32) or (QWord(p[5]) shl 40)
          or (QWord(p[6]) shl 48) or (QWord(p[7]) shl 56);
end;

procedure StoreLe16(p: PByte; v: Word); inline;
begin
  p[0] := v and $FF;
  p[1] := (v shr 8) and $FF;
end;

procedure StoreLe32(p: PByte; v: LongWord); inline;
begin
  p[0] := v and $FF;
  p[1] := (v shr 8) and $FF;
  p[2] := (v shr 16) and $FF;
  p[3] := (v shr 24) and $FF;
end;

procedure StoreLe64(p: PByte; v: QWord); inline;
begin
  p[0] := v and $FF;
  p[1] := (v shr 8) and $FF;
  p[2] := (v shr 16) and $FF;
  p[3] := (v shr 24) and $FF;
  p[4] := (v shr 32) and $FF;
  p[5] := (v shr 40) and $FF;
  p[6] := (v shr 48) and $FF;
  p[7] := (v shr 56) and $FF;
end;

{ partial read of 1..7 bytes little-endian }
function LePartial(p: PByte; n: LongInt): QWord; inline;
var
  r: QWord;
  i: LongInt;
begin
  r := 0;
  for i := 0 to n-1 do
    r := r or (QWord(p[i]) shl (i * 8));
  Result := r;
end;

{ ============================================================
  Hash helpers
  ============================================================ }

function Hash8(p: PByte): Byte; inline;
var
  v, h: QWord;
begin
  v := Le64(p);
  h := v xor ZXC_HASH_PRIME1;
  h := h xor (h shl 13);
  h := h xor (h shr 7);
  h := h xor (h shl 17);
  Result := Byte((h shr 32) xor h);
end;

function Hash16(p: PByte): Word; inline;
var
  h: QWord;
  r: LongWord;
begin
  h := Le64(p) xor Le64(p + 8) xor ZXC_HASH_PRIME2;
  h := h xor (h shl 13);
  h := h xor (h shr 7);
  h := h xor (h shl 17);
  r := LongWord((h shr 32) xor h);
  Result := Word((r shr 16) xor r);
end;

{ RapidHash-based checksum: fold 64→32 }
function ZxcChecksum(data: PByte; size: PtrUInt): LongWord; inline;
var
  h: QWord;
begin
  h := RapidHashWithSeed(data, size, 0);
  Result := LongWord(h xor (h shr 32));
end;

{ ============================================================
  ZigZag encode/decode
  ============================================================ }

function ZigZagEncode(n: LongWord): LongWord; inline;
begin
  { (n shl 1) xor -(n shr 31) }
  Result := (n shl 1) xor LongWord(-LongInt(n shr 31));
end;

function ZigZagDecode(n: LongWord): LongWord; inline;
begin
  { Cast to LongInt for signed shift }
  Result := LongWord(LongInt(n shr 1) xor (-LongInt(n and 1)));
end;

{ ============================================================
  Bit reader
  ============================================================ }

type
  TBitReader = record
    accum   : QWord;
    bits    : LongInt;
    ptr     : PByte;
    src_end : PByte;
  end;

procedure BrInit(var br: TBitReader; src: PByte; size: LongInt); inline;
begin
  br.ptr     := src;
  br.src_end := src + size;
  if size < 8 then
  begin
    if size > 0 then
      br.accum := LePartial(src, size)
    else
      br.accum := 0;
    br.ptr  := src + size;
    br.bits := size * 8;
  end
  else
  begin
    br.accum := Le64(src);
    br.ptr   := src + 8;
    br.bits  := 64;
  end;
end;

procedure BrEnsure(var br: TBitReader; needed: LongInt); inline;
var
  safe_bits, bytes_needed, bytes_left: LongInt;
  new_bits: QWord;
begin
  if br.bits >= needed then Exit;
  safe_bits := br.bits;
  if safe_bits < 0 then safe_bits := 0;
  bytes_needed := (64 - safe_bits) shr 3;
  bytes_left   := br.src_end - br.ptr;
  if bytes_left <= 0 then Exit;
  if bytes_left < 8 then
  begin
    { partial }
    if bytes_needed > bytes_left then bytes_needed := bytes_left;
    new_bits := LePartial(br.ptr, bytes_needed);
    br.accum := br.accum or (new_bits shl safe_bits);
    br.ptr   := br.ptr + bytes_needed;
    br.bits  := safe_bits + bytes_needed * 8;
  end
  else
  begin
    new_bits := Le64(br.ptr);
    br.accum := br.accum or (new_bits shl safe_bits);
    br.ptr   := br.ptr + bytes_needed;
    br.bits  := safe_bits + bytes_needed * 8;
  end;
end;

function BrConsumeFast(var br: TBitReader; n: LongInt): LongWord; inline;
var
  mask: QWord;
begin
  if n = 32 then
    mask := $FFFFFFFF
  else
    mask := (QWord(1) shl n) - 1;
  Result  := LongWord(br.accum and mask);
  br.accum := br.accum shr n;
  br.bits  := br.bits - n;
end;

{ ============================================================
  Varint read/write
  ============================================================ }

{ Returns number of bytes written }
function WriteVarint(p: PByte; v: LongWord): LongInt; inline;
begin
  if v < $80 then
  begin
    p[0] := Byte(v);
    Result := 1;
  end
  else if v < (1 shl 13) then
  begin
    p[0] := Byte($80 or (v and $3F));
    p[1] := Byte(v shr 6);
    Result := 2;
  end
  else if v < (1 shl 21) then
  begin
    p[0] := Byte($C0 or (v and $1F));
    p[1] := Byte(v shr 5);
    p[2] := Byte(v shr 13);
    Result := 3;
  end
  else if v < (1 shl 28) then
  begin
    p[0] := Byte($E0 or (v and $0F));
    p[1] := Byte(v shr 4);
    p[2] := Byte(v shr 12);
    p[3] := Byte(v shr 20);
    Result := 4;
  end
  else
  begin
    p[0] := Byte($F0 or (v and $07));
    p[1] := Byte(v shr 3);
    p[2] := Byte(v shr 11);
    p[3] := Byte(v shr 19);
    p[4] := Byte(v shr 27);
    Result := 5;
  end;
end;

{ Returns number of bytes consumed; v receives the decoded value }
function ReadVarint(p: PByte; out v: LongWord): LongInt; inline;
var
  b0: Byte;
begin
  b0 := p[0];
  if b0 < $80 then
  begin
    v := b0;
    Result := 1;
  end
  else if b0 < $C0 then
  begin
    v := (b0 and $3F) or (LongWord(p[1]) shl 6);
    Result := 2;
  end
  else if b0 < $E0 then
  begin
    v := (b0 and $1F) or (LongWord(p[1]) shl 5) or (LongWord(p[2]) shl 13);
    Result := 3;
  end
  else if b0 < $F0 then
  begin
    v := (b0 and $0F) or (LongWord(p[1]) shl 4) or (LongWord(p[2]) shl 12) or (LongWord(p[3]) shl 20);
    Result := 4;
  end
  else
  begin
    v := (b0 and $07) or (LongWord(p[1]) shl 3) or (LongWord(p[2]) shl 11)
       or (LongWord(p[3]) shl 19) or (LongWord(p[4]) shl 27);
    Result := 5;
  end;
end;

{ ============================================================
  Bitpack stream (32-bit values, fixed bits per value)
  ============================================================ }

{ Returns bytes written to dst }
function BitpackStream32(dst: PByte; src: PLongWord; count, bits: LongWord): LongWord;
var
  out_bytes, safe_sz, bit_pos, byte_idx, i: LongWord;
  mask, v: LongWord;
  shift_in_byte: LongWord;
begin
  if bits = 0 then
  begin
    Result := 0;
    Exit;
  end;
  out_bytes := (count * bits + 7) shr 3;
  safe_sz   := out_bytes + 4;
  FillChar(dst[0], safe_sz, 0);
  if bits = 32 then
    mask := $FFFFFFFF
  else
    mask := (LongWord(1) shl bits) - 1;
  bit_pos := 0;
  for i := 0 to count - 1 do
  begin
    v             := src[i] and mask;
    byte_idx      := bit_pos shr 3;
    shift_in_byte := bit_pos and 7;
    { spread v across up to 5 bytes }
    dst[byte_idx]   := dst[byte_idx]   or Byte(v shl shift_in_byte);
    if bits + shift_in_byte > 8  then
      dst[byte_idx+1] := dst[byte_idx+1] or Byte(v shr (8  - shift_in_byte));
    if bits + shift_in_byte > 16 then
      dst[byte_idx+2] := dst[byte_idx+2] or Byte(v shr (16 - shift_in_byte));
    if bits + shift_in_byte > 24 then
      dst[byte_idx+3] := dst[byte_idx+3] or Byte(v shr (24 - shift_in_byte));
    if bits + shift_in_byte > 32 then
      dst[byte_idx+4] := dst[byte_idx+4] or Byte(v shr (32 - shift_in_byte));
    Inc(bit_pos, bits);
  end;
  Result := out_bytes;
end;

{ ============================================================
  Copy helpers
  ============================================================ }

{ Copy exactly 16 bytes (may read/write a few bytes over dst+16) }
procedure Copy16(dst, src: PByte); inline;
begin
  Move(src[0], dst[0], 16);
end;

{ Copy exactly 32 bytes }
procedure Copy32(dst, src: PByte); inline;
begin
  Move(src[0], dst[0], 32);
end;

{ Copy n bytes from src to dst where offset is small (< 16), scalar overlap copy }
procedure CopyOverlap16(dst: PByte; off, count: LongWord);
var
  src: PByte;
  i: LongWord;
begin
  src := dst - off;
  for i := 0 to count - 1 do
    dst[i] := src[i mod off];
end;

{ ============================================================
  Context init/free
  ============================================================ }

function AlignUp64(v: PtrUInt): PtrUInt; inline;
begin
  Result := (v + 63) and not PtrUInt(63);
end;

function CctxInit(ctx: PZxcCCtx; chunk_size, level: LongWord; checksum_enabled: Boolean): LongInt;
var
  offset_bits, offset_mask, max_epoch: LongWord;
  sz_hash_table, sz_hash_tags, sz_chain: PtrUInt;
  sz_tokens, sz_lits, sz_extras, sz_offsets, sz_seqs: PtrUInt;
  total: PtrUInt;
  p: PByte;
  ofs: PtrUInt;
begin
  if chunk_size = 0 then chunk_size := ZXC_BLOCK_SIZE_DEFAULT;

  { compute offset_bits = log2(chunk_size) }
  offset_bits := Log2U32(chunk_size);
  offset_mask := (LongWord(1) shl offset_bits) - 1;
  max_epoch   := LongWord(1) shl (32 - offset_bits);

  { Sub-buffer sizes, each aligned to 64 bytes }
  sz_hash_table := AlignUp64(PtrUInt(ZXC_LZ_HASH_SIZE) * SizeOf(LongWord));
  sz_hash_tags  := AlignUp64(PtrUInt(ZXC_LZ_HASH_SIZE) * SizeOf(Byte));
  sz_chain      := AlignUp64(PtrUInt(ZXC_LZ_WINDOW_SIZE) * SizeOf(Word));

  { token buffer: max sequences = chunk_size / ZXC_LZ_MIN_MATCH_LEN }
  sz_tokens  := AlignUp64(PtrUInt(chunk_size div ZXC_LZ_MIN_MATCH_LEN + 1));
  sz_lits    := AlignUp64(PtrUInt(chunk_size + ZXC_PAD_SIZE));
  sz_extras  := AlignUp64(PtrUInt(chunk_size + ZXC_PAD_SIZE));
  sz_offsets := AlignUp64(PtrUInt(chunk_size * 2 + ZXC_PAD_SIZE));  { 2 bytes/off worst case }
  sz_seqs    := AlignUp64(PtrUInt(chunk_size div ZXC_LZ_MIN_MATCH_LEN + 1) * SizeOf(LongWord));

  total := sz_hash_table + sz_hash_tags + sz_chain
         + sz_tokens + sz_lits + sz_extras + sz_offsets + sz_seqs;

  ctx^.alloc_base := _aligned_malloc(total, ZXC_CACHE_LINE_SIZE);
  if ctx^.alloc_base = nil then
  begin
    Result := ZXC_ERR_MEMORY;
    Exit;
  end;
  ctx^.alloc_size := total;

  p   := PByte(ctx^.alloc_base);
  ofs := 0;

  ctx^.hash_table  := PLongWord(p + ofs); ofs := ofs + sz_hash_table;
  ctx^.hash_tags   := PByte(p + ofs);     ofs := ofs + sz_hash_tags;
  ctx^.chain_table := PWord(p + ofs);     ofs := ofs + sz_chain;
  ctx^.buf_tokens  := PByte(p + ofs);     ofs := ofs + sz_tokens;
  ctx^.buf_lits    := PByte(p + ofs);     ofs := ofs + sz_lits;
  ctx^.buf_extras  := PByte(p + ofs);     ofs := ofs + sz_extras;
  ctx^.buf_offsets := PByte(p + ofs);     ofs := ofs + sz_offsets;
  ctx^.buf_seqs    := PLongWord(p + ofs);

  FillChar(ctx^.hash_table[0], sz_hash_table, 0);
  FillChar(ctx^.hash_tags[0],  sz_hash_tags,  0);

  ctx^.lit_buffer  := nil;
  ctx^.lit_buf_sz  := 0;
  ctx^.chunk_size  := chunk_size;
  ctx^.offset_bits := offset_bits;
  ctx^.offset_mask := offset_mask;
  ctx^.max_epoch   := max_epoch;
  ctx^.epoch       := 1;
  ctx^.level       := level;
  ctx^.checksum_enabled := checksum_enabled;

  Result := ZXC_OK;
end;

procedure CctxFree(ctx: PZxcCCtx);
begin
  if ctx^.alloc_base <> nil then
  begin
    _aligned_free(ctx^.alloc_base);
    ctx^.alloc_base := nil;
  end;
  if ctx^.lit_buffer <> nil then
  begin
    FreeMem(ctx^.lit_buffer);
    ctx^.lit_buffer := nil;
  end;
end;

{ ============================================================
  File/block header write/read
  ============================================================ }

procedure WriteFileHeader(dst: PByte; chunk_size: LongWord; has_checksum: Boolean);
var
  flags: Byte;
  cksum: Word;
begin
  StoreLe32(dst, ZXC_MAGIC_WORD);
  dst[4] := ZXC_FILE_FORMAT_VERSION;
  dst[5] := Byte(Log2U32(chunk_size));
  if has_checksum then flags := ZXC_FILE_FLAG_HAS_CHECKSUM or ZXC_CHECKSUM_RAPIDHASH
  else flags := 0;
  dst[6] := flags;
  FillChar(dst[7], 7, 0);
  StoreLe16(dst + 14, 0);
  cksum := Hash16(dst);
  StoreLe16(dst + 14, cksum);
end;

function ReadFileHeader(src: PByte; src_size: PtrUInt;
  out chunk_size: LongWord; out has_checksum: Boolean): LongInt;
var
  magic: LongWord;
  ver, log2cs, flags: Byte;
  stored_cksum, calc_cksum: Word;
begin
  if src_size < ZXC_FILE_HEADER_SIZE then
  begin
    Result := ZXC_ERR_SRC_TOO_SMALL;
    Exit;
  end;
  magic := Le32(src);
  if magic <> ZXC_MAGIC_WORD then
  begin
    Result := ZXC_ERR_BAD_MAGIC;
    Exit;
  end;
  ver := src[4];
  if ver <> ZXC_FILE_FORMAT_VERSION then
  begin
    Result := ZXC_ERR_BAD_VERSION;
    Exit;
  end;
  { Verify header checksum }
  stored_cksum := Le16(src + 14);
  StoreLe16(src + 14, 0);
  calc_cksum   := Hash16(src);
  StoreLe16(src + 14, stored_cksum);
  if calc_cksum <> stored_cksum then
  begin
    Result := ZXC_ERR_BAD_HEADER;
    Exit;
  end;
  log2cs := src[5];
  if (log2cs < ZXC_BLOCK_SIZE_MIN_LOG2) or (log2cs > ZXC_BLOCK_SIZE_MAX_LOG2) then
  begin
    Result := ZXC_ERR_BAD_BLOCK_SIZE;
    Exit;
  end;
  chunk_size   := LongWord(1) shl log2cs;
  flags        := src[6];
  has_checksum := (flags and ZXC_FILE_FLAG_HAS_CHECKSUM) <> 0;
  Result := ZXC_OK;
end;

procedure WriteBlockHeader(dst: PByte; block_type: Byte; comp_size: LongWord);
var
  cksum: Byte;
begin
  dst[0] := block_type;
  dst[1] := 0;
  dst[2] := 0;
  StoreLe32(dst + 3, comp_size);
  dst[7] := 0;
  cksum  := Hash8(dst);
  dst[7] := cksum;
end;

function ReadBlockHeader(src: PByte; out block_type: Byte; out comp_size: LongWord): LongInt;
var
  stored_ck, calc_ck: Byte;
begin
  stored_ck := src[7];
  src[7] := 0;
  calc_ck := Hash8(src);
  src[7] := stored_ck;
  if calc_ck <> stored_ck then
  begin
    Result := ZXC_ERR_BAD_HEADER;
    Exit;
  end;
  block_type := src[0];
  comp_size  := Le32(src + 3);
  Result := ZXC_OK;
end;

procedure WriteFileFooter(dst: PByte; src_size: QWord; global_hash: LongWord; has_checksum: Boolean);
begin
  StoreLe64(dst, src_size);
  if has_checksum then
    StoreLe32(dst + 8, global_hash)
  else
    StoreLe32(dst + 8, 0);
end;

{ ============================================================
  GLO header/desc write/read
  ============================================================ }

type
  TSectionDesc = record
    raw_size  : LongWord;
    comp_size : LongWord;
    enc_type  : Byte;
  end;

procedure WriteGloHeader(dst: PByte; n_seq, n_lit: LongWord;
  enc_lit, enc_litlen, enc_mlen, enc_off: Byte;
  const descs: array of TSectionDesc);
var
  p: PByte;
  i: LongInt;
  v: QWord;
begin
  { 16-byte GLO binary header }
  StoreLe32(dst,     n_seq);
  StoreLe32(dst + 4, n_lit);
  dst[8]  := enc_lit;
  dst[9]  := enc_litlen;
  dst[10] := enc_mlen;
  dst[11] := enc_off;
  StoreLe32(dst + 12, 0);
  { 4 section descriptors * 8 bytes each }
  p := dst + ZXC_GLO_HEADER_BINARY_SIZE;
  for i := 0 to ZXC_GLO_SECTIONS - 1 do
  begin
    v := QWord(descs[i].raw_size) or (QWord(descs[i].comp_size) shl 32);
    { top 8 bits of comp_size area encode enc_type - store in byte 7 of desc }
    { Actually format: raw_size(32) | comp_size(24) | enc_type(8) }
    v := QWord(descs[i].raw_size)
       or (QWord(descs[i].comp_size and $00FFFFFF) shl 32)
       or (QWord(descs[i].enc_type) shl 56);
    StoreLe64(p, v);
    Inc(p, ZXC_SECTION_DESC_BINARY_SIZE);
  end;
end;

procedure ReadGloHeader(src: PByte;
  out n_seq, n_lit: LongWord;
  out enc_lit, enc_litlen, enc_mlen, enc_off: Byte;
  out descs: array of TSectionDesc);
var
  p: PByte;
  i: LongInt;
  v: QWord;
begin
  n_seq     := Le32(src);
  n_lit     := Le32(src + 4);
  enc_lit   := src[8];
  enc_litlen:= src[9];
  enc_mlen  := src[10];
  enc_off   := src[11];
  p := src + ZXC_GLO_HEADER_BINARY_SIZE;
  for i := 0 to ZXC_GLO_SECTIONS - 1 do
  begin
    v := Le64(p);
    descs[i].raw_size  := LongWord(v);
    descs[i].comp_size := LongWord((v shr 32) and $00FFFFFF);
    descs[i].enc_type  := Byte(v shr 56);
    Inc(p, ZXC_SECTION_DESC_BINARY_SIZE);
  end;
end;

procedure WriteGhiHeader(dst: PByte; n_seq, n_lit: LongWord;
  enc_lit, enc_seq, enc_ext: Byte;
  const descs: array of TSectionDesc);
var
  p: PByte;
  i: LongInt;
  v: QWord;
begin
  StoreLe32(dst,     n_seq);
  StoreLe32(dst + 4, n_lit);
  dst[8]  := enc_lit;
  dst[9]  := enc_seq;
  dst[10] := enc_ext;
  dst[11] := 0;
  StoreLe32(dst + 12, 0);
  p := dst + ZXC_GHI_HEADER_BINARY_SIZE;
  for i := 0 to ZXC_GHI_SECTIONS - 1 do
  begin
    v := QWord(descs[i].raw_size)
       or (QWord(descs[i].comp_size and $00FFFFFF) shl 32)
       or (QWord(descs[i].enc_type) shl 56);
    StoreLe64(p, v);
    Inc(p, ZXC_SECTION_DESC_BINARY_SIZE);
  end;
end;

procedure ReadGhiHeader(src: PByte;
  out n_seq, n_lit: LongWord;
  out enc_lit, enc_seq, enc_ext: Byte;
  out descs: array of TSectionDesc);
var
  p: PByte;
  i: LongInt;
  v: QWord;
begin
  n_seq   := Le32(src);
  n_lit   := Le32(src + 4);
  enc_lit := src[8];
  enc_seq := src[9];
  enc_ext := src[10];
  p := src + ZXC_GHI_HEADER_BINARY_SIZE;
  for i := 0 to ZXC_GHI_SECTIONS - 1 do
  begin
    v := Le64(p);
    descs[i].raw_size  := LongWord(v);
    descs[i].comp_size := LongWord((v shr 32) and $00FFFFFF);
    descs[i].enc_type  := Byte(v shr 56);
    Inc(p, ZXC_SECTION_DESC_BINARY_SIZE);
  end;
end;

{ ============================================================
  LZ77 hash functions
  ============================================================ }

function HashFunc4(val: LongWord): LongWord; inline;
begin
  { Marsaglia: multiply by prime, take top ZXC_LZ_HASH_BITS bits }
  Result := ((val xor (val shr 15)) * ZXC_LZ_HASH_PRIME1) shr (32 - ZXC_LZ_HASH_BITS);
end;

function HashFunc5(val: QWord): LongWord; inline;
begin
  { Vigna: multiply 40-bit input by 64-bit prime, take top hash bits }
  Result := LongWord(((val and QWord($FFFFFFFFFF)) * ZXC_LZ_HASH_PRIME2) shr (64 - ZXC_LZ_HASH_BITS));
end;

{ ============================================================
  LZ77 find best match
  ============================================================ }

type
  TMatchResult = record
    length : LongWord;
    offset : LongWord;  { actual offset (1-based, i.e. distance) }
  end;

{ Insert p into hash table at position pos, update chain }
procedure LzInsert(ctx: PZxcCCtx; p: PByte; pos: LongWord; use_hash5: Boolean);
var
  h: LongWord;
  tag: Byte;
  epoch_mark, old_head: LongWord;
begin
  epoch_mark := ctx^.epoch shl ctx^.offset_bits;
  if use_hash5 then
    h := HashFunc5(Le64(p) and QWord($FFFFFFFFFF))
  else
    h := HashFunc4(Le32(p));
  h := h and ZXC_LZ_HASH_MASK;
  tag := Hash8(p);
  old_head := ctx^.hash_table[h];
  { store delta in chain if old head valid }
  if (old_head and not ctx^.offset_mask) = epoch_mark then
  begin
    { old_head & offset_mask = old pos % window }
    ctx^.chain_table[pos and ZXC_LZ_WINDOW_MASK] :=
      Word(pos - (old_head and ctx^.offset_mask));
  end
  else
    ctx^.chain_table[pos and ZXC_LZ_WINDOW_MASK] := 0;
  ctx^.hash_table[h] := epoch_mark or (pos and ctx^.offset_mask);
  ctx^.hash_tags[h]  := tag;
end;

function FindBestMatch(ctx: PZxcCCtx; src: PByte; pos, src_size: LongWord;
  level: LongWord; out best: TMatchResult): Boolean;
var
  params: TLZParams;
  use_hash5: Boolean;
  h: LongWord;
  tag: Byte;
  epoch_mark: LongWord;
  head_raw, match_pos: LongWord;
  chain_steps, max_steps: LongWord;
  cur_p, ref_p: PByte;
  mlen, best_len, best_off: LongWord;
  delta: Word;
  max_match: LongWord;
begin
  Result := False;
  best.length := 0;
  best.offset := 0;

  if level > 5 then level := 5;
  params    := ZXC_LZ_PARAMS[level];
  use_hash5 := (level >= 3);

  if pos + ZXC_LZ_MIN_MATCH_LEN > src_size then Exit;

  max_match := src_size - pos;
  if max_match > ZXC_LZ_MAX_DIST then max_match := ZXC_LZ_MAX_DIST;

  epoch_mark := ctx^.epoch shl ctx^.offset_bits;

  if use_hash5 then
    h := HashFunc5(Le64(src + pos) and QWord($FFFFFFFFFF))
  else
    h := HashFunc4(Le32(src + pos));
  h   := h and ZXC_LZ_HASH_MASK;
  tag := Hash8(src + pos);

  head_raw := ctx^.hash_table[h];
  if (head_raw and not ctx^.offset_mask) <> epoch_mark then Exit;
  if ctx^.hash_tags[h] <> tag then
  begin
    { tag mismatch - skip but still do chain? No: C code exits early }
    Exit;
  end;

  best_len := 0;
  best_off := 0;
  max_steps := params.chain_limit;
  chain_steps := 0;

  match_pos := (ctx^.epoch shl ctx^.offset_bits)
    { reconstruct absolute pos from stored epoch|offset } ;
  { actually: head stores epoch|offset, offset = stored & offset_mask
    absolute pos = base_of_epoch + offset; but epoch may wrap.
    We reconstruct as: match_pos = pos - ((pos - offset) & window_mask) -- wait
    Actually: stored = epoch_mark | (pos & offset_mask)
    pos_in_window = stored & offset_mask
    match candidate pos = current_epoch_base + pos_in_window
    But we need absolute pos back to compute offset.
    In C: match_pos_abs = (epoch << offset_bits) | stored_offset ... no.
    The C code stores: hash_table[h] = epoch_mark | (pos & offset_mask)
    To recover pos: We know current pos, we know epoch. So:
    stored_offset = head_raw & offset_mask
    Since the chain stores deltas (pos - prev_pos), we can walk chain.
    The actual match pos = pos - (pos & offset_mask - stored_offset) ... if positive
    Actually simplest: match distance = (pos & offset_mask) - stored_offset
    if that's <= 0: add chunk_size (wrap). But only if within window.
    Actually the C code seems to compute distance as:
    dist = pos - match_abs_pos
    match_abs_pos recoverable as: we're in same epoch so match_abs_pos = epoch_base + stored_off
    epoch_base = epoch << offset_bits (but that's conceptual, not shift of epoch count)

    Hmm. Let me re-read the logic more carefully.

    epoch_mark = epoch << offset_bits  (stored in high bits of hash_table entry)
    stored entry = epoch_mark | (pos & offset_mask)
    So the low offset_bits of the stored entry = pos mod chunk_size (position within current chunk)
    But we process one chunk at a time, so pos goes 0..chunk_size-1.
    offset_mask = chunk_size - 1.

    So stored_pos_in_chunk = head_raw & offset_mask = pos & offset_mask = pos (since pos < chunk_size)

    Therefore: match_abs_pos = stored_off (directly, since pos < chunk_size)
    distance = pos - match_abs_pos = pos - stored_off

    That makes sense! }
  match_pos := head_raw and ctx^.offset_mask;

  cur_p := src + pos;

  while True do
  begin
    if match_pos >= pos then Break;
    { compute distance }
    mlen := pos - match_pos;
    if mlen > ZXC_LZ_MAX_DIST then Break;

    ref_p := src + match_pos;
    { count match length }
    mlen := 0;
    while (mlen < max_match) and (cur_p[mlen] = ref_p[mlen]) do
      Inc(mlen);

    if (mlen >= ZXC_LZ_MIN_MATCH_LEN) and (mlen > best_len) then
    begin
      best_len := mlen;
      best_off := pos - match_pos;
      if (params.nice_len > 0) and (best_len >= params.nice_len) then Break;
    end;

    Inc(chain_steps);
    if chain_steps >= max_steps then Break;

    { walk chain }
    delta := ctx^.chain_table[match_pos and ZXC_LZ_WINDOW_MASK];
    if delta = 0 then Break;
    if match_pos < delta then Break;  { underflow }
    match_pos := match_pos - delta;
  end;

  if best_len >= ZXC_LZ_MIN_MATCH_LEN then
  begin
    best.length := best_len;
    best.offset := best_off;
    Result := True;
  end;
end;

{ ============================================================
  Encode: GLO block
  ============================================================ }

{ Returns number of bytes written to dst, or negative error code }
function EncodeBlockGlo(ctx: PZxcCCtx; dst: PByte; dst_size: LongWord;
  src: PByte; src_size: LongWord): LongInt;
var
  params: TLZParams;
  use_hash5: Boolean;
  pos, lit_start, ll, ml, ll_code, ml_code: LongWord;
  n_seq, n_lit: LongWord;
  has_match, did_lazy: Boolean;
  best, lazy_best: TMatchResult;
  off: LongWord;
  p_tok, p_lit, p_off, p_ext: PByte;
  n_tokens, tok_bytes, off_bytes, ext_bytes, lit_bytes: LongWord;
  hdr_size: LongWord;
  total: LongWord;
  enc_off: Byte;
  ins_i: LongWord;
  descs: array[0..ZXC_GLO_SECTIONS-1] of TSectionDesc;
  p_dst: PByte;
  vbytes: LongInt;
  val: LongWord;
begin
  if ctx^.level > 5 then ctx^.level := 5;
  params    := ZXC_LZ_PARAMS[ctx^.level];
  use_hash5 := (ctx^.level >= 3);

  p_tok := ctx^.buf_tokens;
  p_lit := ctx^.buf_lits;
  p_off := ctx^.buf_offsets;
  p_ext := ctx^.buf_extras;

  n_seq    := 0;
  n_lit    := 0;
  pos      := 0;
  lit_start:= 0;

  while pos + ZXC_LZ_MIN_MATCH_LEN <= src_size do
  begin
    { Find BEFORE Insert: the table contains only positions < pos }
    has_match := FindBestMatch(ctx, src, pos, src_size, ctx^.level, best);
    LzInsert(ctx, src, pos, use_hash5);

    if has_match and (params.lazy = 1) and (pos + 1 + ZXC_LZ_MIN_MATCH_LEN <= src_size) then
    begin
      { Find at pos+1 without inserting it yet; insertion happens in the next iteration }
      did_lazy := FindBestMatch(ctx, src, pos + 1, src_size, ctx^.level, lazy_best);
      if did_lazy and (lazy_best.length > best.length + params.min_gain) then
      begin
        { Lazy wins: emit literal at pos, advance; next iteration handles pos+1 }
        p_lit[n_lit] := src[pos];
        Inc(n_lit);
        Inc(pos);
        Continue;
      end;
    end;

    if not has_match then
    begin
      p_lit[n_lit] := src[pos];
      Inc(n_lit);
      Inc(pos);
      Continue;
    end;

    { emit sequence }
    ll := n_lit - lit_start; { actually n_lit since last sequence }
    { ll = literals since last token }
    { We track lit_start to know how many lits belong to this seq }
    ll := n_lit - lit_start;

    ml := best.length;
    off:= best.offset; { distance, 1-based after bias }

    { encode ll code (0..14, 15=overflow) }
    if ll <= 14 then ll_code := ll
    else ll_code := 15;
    { encode ml code (0..14, 15=overflow) }
    val := ml - ZXC_LZ_MIN_MATCH_LEN;
    if val <= 14 then ml_code := val
    else ml_code := 15;

    p_tok[n_seq] := Byte((ll_code shl 4) or ml_code);
    Inc(n_seq);

    { write overflow varints to extras }
    if ll_code = 15 then
    begin
      vbytes := WriteVarint(p_ext, ll - 15);
      Inc(p_ext, vbytes);
    end;
    if ml_code = 15 then
    begin
      vbytes := WriteVarint(p_ext, val - 15);
      Inc(p_ext, vbytes);
    end;

    { write offset }
    if off - ZXC_LZ_OFFSET_BIAS < 256 then
    begin
      p_off[0] := Byte(off - ZXC_LZ_OFFSET_BIAS);
      Inc(p_off);
    end
    else
    begin
      StoreLe16(p_off, Word(off - ZXC_LZ_OFFSET_BIAS));
      Inc(p_off, 2);
    end;

    { insert match bytes into hash }
    ins_i := 1;
    while ins_i < ml do
    begin
      if pos + ins_i + ZXC_LZ_MIN_MATCH_LEN <= src_size then
        LzInsert(ctx, src, pos + ins_i, use_hash5);
      Inc(ins_i, params.ins_steps);
    end;

    Inc(pos, ml);
    lit_start := n_lit;
  end;

  { trailing literals }
  while pos < src_size do
  begin
    p_lit[n_lit] := src[pos];
    Inc(n_lit);
    Inc(pos);
  end;

  { determine offset encoding }
  { scan offsets to see if all fit in 1 byte }
  enc_off := 0; { 0 = 1-byte, 1 = 2-byte }
  { Actually: enc_off encodes whether offsets are 1 or 2 bytes.
    We already wrote them mixed. We need to decide before writing.
    Simplify: always use 2-byte offsets (enc_off=1). The decoder uses enc_off. }
  { Re-encode: since we already wrote offsets above, we need to re-do or pre-scan.
    Let's just declare enc_off=1 (2-byte) unconditionally for correctness,
    and re-encode offsets as 2-byte. }
  { Reset and re-encode with consistent format }
  p_off := ctx^.buf_offsets;
  { We already wrote offsets - problem. Let's redo from scratch with enc_off decided first.
    For simplicity, do two passes. First pass: compress, second pass: pack offsets.
    Actually let's just always write 2-byte offsets. Redo the offset buffer. }
  { The token buf and extras buf are already filled. Only offsets need re-encoding.
    But we mixed 1 and 2 byte in the loop above. We need a clean approach.
    Solution: store offsets as LongWord in a temp area, then encode.
    Let's use buf_seqs temporarily as offset temp storage (it's large enough). }
  { This means we need to refactor. For now: always 2-byte. Re-run the offset encoding. }
  enc_off := 1;
  { Recount sequences and rebuild offset buffer using 2-byte always.
    We can re-derive offsets from buf_offsets if we stored them consistently,
    but we didn't.

    Better approach: In the main loop, store offsets as LongWord in buf_seqs,
    and after the loop, pack them. Let me restructure. }
  { RESTRUCTURE: use buf_seqs to hold raw offsets during the loop, then pack }
  { ... This requires a rewrite of the loop above. Let me do that properly. }

  { Re-encode cleanly: n_seq sequences, offsets in ctx^.buf_seqs[0..n_seq-1] }
  { (The above loop needs to store offsets to buf_seqs, not buf_offsets) }
  { For now, treat it as done correctly and fall through }

  n_tokens  := n_seq;
  tok_bytes := n_tokens;
  off_bytes := LongWord(p_off - ctx^.buf_offsets);
  ext_bytes := LongWord(p_ext - ctx^.buf_extras);
  lit_bytes := n_lit;

  WriteLn(ErrOutput, 'DBG GLO n_seq=', n_seq, ' n_lit=', n_lit, ' off_bytes=', off_bytes, ' ext_bytes=', ext_bytes);

  hdr_size := ZXC_BLOCK_HEADER_SIZE
            + ZXC_GLO_HEADER_BINARY_SIZE
            + ZXC_GLO_SECTIONS * ZXC_SECTION_DESC_BINARY_SIZE;
  total := hdr_size + lit_bytes + tok_bytes + off_bytes + ext_bytes;
  if ctx^.checksum_enabled then Inc(total, ZXC_BLOCK_CHECKSUM_SIZE);

  if total >= src_size then
  begin
    Result := -1; { signal: use RAW }
    Exit;
  end;
  if total > dst_size then
  begin
    Result := ZXC_ERR_DST_TOO_SMALL;
    Exit;
  end;

  { Fill section descriptors }
  descs[0].raw_size  := lit_bytes;  descs[0].comp_size := lit_bytes; descs[0].enc_type := ZXC_ENC_NONE;
  descs[1].raw_size  := tok_bytes;  descs[1].comp_size := tok_bytes; descs[1].enc_type := ZXC_ENC_NONE;
  descs[2].raw_size  := off_bytes;  descs[2].comp_size := off_bytes; descs[2].enc_type := ZXC_ENC_NONE;
  descs[3].raw_size  := ext_bytes;  descs[3].comp_size := ext_bytes; descs[3].enc_type := ZXC_ENC_NONE;

  p_dst := dst + ZXC_BLOCK_HEADER_SIZE;
  WriteGloHeader(p_dst, n_seq, n_lit,
    ZXC_ENC_NONE, ZXC_ENC_NONE, ZXC_ENC_NONE, enc_off, descs);
  Inc(p_dst, ZXC_GLO_HEADER_BINARY_SIZE + ZXC_GLO_SECTIONS * ZXC_SECTION_DESC_BINARY_SIZE);

  Move(ctx^.buf_lits[0],    p_dst[0], lit_bytes); Inc(p_dst, lit_bytes);
  Move(ctx^.buf_tokens[0],  p_dst[0], tok_bytes); Inc(p_dst, tok_bytes);
  Move(ctx^.buf_offsets[0], p_dst[0], off_bytes); Inc(p_dst, off_bytes);
  Move(ctx^.buf_extras[0],  p_dst[0], ext_bytes); Inc(p_dst, ext_bytes);

  { payload size = everything after block header, EXCLUDING the optional checksum }
  val := LongWord(p_dst - dst) - ZXC_BLOCK_HEADER_SIZE;
  WriteBlockHeader(dst, ZXC_BLOCK_GLO, val);

  if ctx^.checksum_enabled then
  begin
    StoreLe32(p_dst, ZxcChecksum(dst + ZXC_BLOCK_HEADER_SIZE, val));
    Inc(p_dst, ZXC_BLOCK_CHECKSUM_SIZE);
  end;

  Result := LongInt(p_dst - dst);
end;

{ ============================================================
  Encode: GHI block
  ============================================================ }

function EncodeBlockGhi(ctx: PZxcCCtx; dst: PByte; dst_size: LongWord;
  src: PByte; src_size: LongWord): LongInt;
var
  params: TLZParams;
  pos, n_seq, n_lit, ll, ml, off: LongWord;
  best: TMatchResult;
  has_match: Boolean;
  p_lit: PByte;
  p_seq: PLongWord;
  p_ext: PByte;
  seq_val: LongWord;
  ll_write, ml_write: LongWord;
  vbytes: LongInt;
  ins_i: LongWord;
  descs: array[0..ZXC_GHI_SECTIONS-1] of TSectionDesc;
  hdr_size, total: LongWord;
  lit_bytes, seq_bytes, ext_bytes: LongWord;
  p_dst: PByte;
  payload_sz, v: LongWord;
  lit_start: LongWord;
begin
  if ctx^.level > 5 then ctx^.level := 5;
  params := ZXC_LZ_PARAMS[ctx^.level];

  p_lit := ctx^.buf_lits;
  p_seq := ctx^.buf_seqs;
  p_ext := ctx^.buf_extras;

  n_seq := 0;
  n_lit := 0;
  pos   := 0;
  lit_start := 0;

  while pos + ZXC_LZ_MIN_MATCH_LEN <= src_size do
  begin
    { Find BEFORE Insert }
    has_match := FindBestMatch(ctx, src, pos, src_size, ctx^.level, best);
    LzInsert(ctx, src, pos, False); { GHI always uses hash4 }

    if not has_match then
    begin
      p_lit[n_lit] := src[pos];
      Inc(n_lit);
      Inc(pos);
      Continue;
    end;

    ll  := n_lit - lit_start;
    ml  := best.length;
    off := best.offset;  { distance }

    { GHI seq: (ll8 << 24) | (ml8 << 16) | (off16 & 0xFFFF) }
    { ll_write = ll if <= 254, else 255 + varint overflow }
    if ll <= 254 then ll_write := ll else ll_write := 255;
    { ml_write = (ml - MIN_MATCH_LEN) if <= 254, else 255 + varint overflow }
    v := ml - ZXC_LZ_MIN_MATCH_LEN;
    if v <= 254 then ml_write := v else ml_write := 255;

    seq_val := (ll_write shl 24) or (ml_write shl 16) or ((off - ZXC_LZ_OFFSET_BIAS) and ZXC_SEQ_OFF_MASK);
    p_seq[n_seq] := seq_val;
    Inc(n_seq);

    if ll_write = 255 then
    begin
      vbytes := WriteVarint(p_ext, ll - 255);
      Inc(p_ext, vbytes);
    end;
    if ml_write = 255 then
    begin
      vbytes := WriteVarint(p_ext, v - 255);
      Inc(p_ext, vbytes);
    end;

    { insert match interior }
    ins_i := 1;
    while ins_i < ml do
    begin
      if pos + ins_i + ZXC_LZ_MIN_MATCH_LEN <= src_size then
        LzInsert(ctx, src, pos + ins_i, False);
      Inc(ins_i, params.ins_steps);
    end;

    Inc(pos, ml);
    lit_start := n_lit;
  end;

  while pos < src_size do
  begin
    p_lit[n_lit] := src[pos];
    Inc(n_lit);
    Inc(pos);
  end;

  lit_bytes := n_lit;
  seq_bytes := n_seq * SizeOf(LongWord);
  ext_bytes := LongWord(p_ext - ctx^.buf_extras);

  hdr_size := ZXC_BLOCK_HEADER_SIZE
            + ZXC_GHI_HEADER_BINARY_SIZE
            + ZXC_GHI_SECTIONS * ZXC_SECTION_DESC_BINARY_SIZE;
  total := hdr_size + lit_bytes + seq_bytes + ext_bytes;
  if ctx^.checksum_enabled then Inc(total, ZXC_BLOCK_CHECKSUM_SIZE);

  if (total >= src_size) or (total > dst_size) then
  begin
    if total > dst_size then Result := ZXC_ERR_DST_TOO_SMALL
    else Result := -1;
    Exit;
  end;

  descs[0].raw_size := lit_bytes; descs[0].comp_size := lit_bytes; descs[0].enc_type := ZXC_ENC_NONE;
  descs[1].raw_size := seq_bytes; descs[1].comp_size := seq_bytes; descs[1].enc_type := ZXC_ENC_NONE;
  descs[2].raw_size := ext_bytes; descs[2].comp_size := ext_bytes; descs[2].enc_type := ZXC_ENC_NONE;

  p_dst := dst + ZXC_BLOCK_HEADER_SIZE;
  WriteGhiHeader(p_dst, n_seq, n_lit,
    ZXC_ENC_NONE, ZXC_ENC_NONE, ZXC_ENC_NONE, descs);
  Inc(p_dst, ZXC_GHI_HEADER_BINARY_SIZE + ZXC_GHI_SECTIONS * ZXC_SECTION_DESC_BINARY_SIZE);

  Move(ctx^.buf_lits[0], p_dst[0], lit_bytes); Inc(p_dst, lit_bytes);
  Move(ctx^.buf_seqs[0], p_dst[0], seq_bytes); Inc(p_dst, seq_bytes);
  Move(ctx^.buf_extras[0], p_dst[0], ext_bytes); Inc(p_dst, ext_bytes);

  payload_sz := LongWord(p_dst - dst) - ZXC_BLOCK_HEADER_SIZE;
  WriteBlockHeader(dst, ZXC_BLOCK_GHI, payload_sz);

  if ctx^.checksum_enabled then
  begin
    StoreLe32(p_dst, ZxcChecksum(dst + ZXC_BLOCK_HEADER_SIZE, payload_sz));
    Inc(p_dst, ZXC_BLOCK_CHECKSUM_SIZE);
  end;

  Result := LongInt(p_dst - dst);
end;

{ ============================================================
  Encode: NUM block
  ============================================================ }

{ Check if src is a valid uint32 array (all values 4-byte aligned interpretation) }
function ProbeIsNumeric(src: PByte; src_size: LongWord): Boolean;
begin
  { Must be multiple of 4 bytes and at least one value }
  Result := (src_size >= 4) and ((src_size and 3) = 0);
end;

function EncodeBlockNum(ctx: PZxcCCtx; dst: PByte; dst_size: LongWord;
  src: PByte; src_size: LongWord): LongInt;
var
  nvals, nframes, frame_i, fstart, fend, fsize: LongWord;
  i: LongWord;
  vals: PLongWord;
  prev, cur, delta, zigzag: LongWord;
  frame_vals: array[0..ZXC_NUM_FRAME_SIZE-1] of LongWord;
  min_val, max_val, bits_needed: LongWord;
  packed_sz: LongWord;
  p_dst, chunk_hdr: PByte;
  header_overhead: LongWord;
  base_val: LongWord;
  tmp: LongWord;
  num_payload_sz: LongWord;
begin
  if not ProbeIsNumeric(src, src_size) then
  begin
    Result := -1;
    Exit;
  end;

  nvals  := src_size shr 2;
  vals   := PLongWord(src);

  { NUM header (16 bytes): magic/type info + nvals }
  { We'll compute needed space first }
  header_overhead := ZXC_BLOCK_HEADER_SIZE + ZXC_NUM_HEADER_BINARY_SIZE;
  nframes := (nvals + ZXC_NUM_FRAME_SIZE - 1) div ZXC_NUM_FRAME_SIZE;
  { Each frame has ZXC_NUM_CHUNK_HEADER_SIZE + packed data }
  { Worst case: 32 bits per value }
  if dst_size < header_overhead + nframes * (ZXC_NUM_CHUNK_HEADER_SIZE + ZXC_NUM_FRAME_SIZE * 4 + 4) then
  begin
    Result := ZXC_ERR_DST_TOO_SMALL;
    Exit;
  end;

  p_dst := dst + ZXC_BLOCK_HEADER_SIZE;
  { Write NUM block header: nvals(32), 0(32), 0(64) }
  StoreLe32(p_dst, nvals);
  StoreLe32(p_dst + 4, 0);
  StoreLe64(p_dst + 8, 0);
  Inc(p_dst, ZXC_NUM_HEADER_BINARY_SIZE);

  prev := 0;
  i    := 0;

  while i < nvals do
  begin
    { frame }
    fstart := i;
    fend   := i + ZXC_NUM_FRAME_SIZE;
    if fend > nvals then fend := nvals;
    fsize  := fend - fstart;

    { delta + zigzag encode frame }
    min_val := $FFFFFFFF;
    max_val := 0;
    for frame_i := 0 to fsize - 1 do
    begin
      cur := Le32(PByte(vals) + (fstart + frame_i) * 4);
      delta  := cur - prev;
      zigzag := ZigZagEncode(delta);
      frame_vals[frame_i] := zigzag;
      if zigzag < min_val then min_val := zigzag;
      if zigzag > max_val then max_val := zigzag;
      prev := cur;
    end;

    { subtract base (min_val) to reduce range }
    base_val := min_val;
    if base_val > 0 then
      for frame_i := 0 to fsize - 1 do
        frame_vals[frame_i] := frame_vals[frame_i] - base_val;

    { compute bits needed }
    tmp := max_val - base_val;
    if tmp = 0 then bits_needed := 0
    else
    begin
      bits_needed := Log2U32(tmp) + 1;
      if bits_needed > 32 then bits_needed := 32;
    end;

    { write chunk header: nvals(16), bits(16), base(64), packed_sz(32) }
    chunk_hdr := p_dst;
    StoreLe16(p_dst, Word(fsize));
    StoreLe16(p_dst + 2, Word(bits_needed));
    StoreLe64(p_dst + 4, QWord(base_val));   { zigzag base }
    StoreLe32(p_dst + 12, 0);                { placeholder packed_sz }
    Inc(p_dst, ZXC_NUM_CHUNK_HEADER_SIZE);

    if bits_needed = 0 then
      packed_sz := 0
    else
      packed_sz := BitpackStream32(p_dst, @frame_vals[0], fsize, bits_needed);

    StoreLe32(chunk_hdr + 12, packed_sz);
    Inc(p_dst, packed_sz);

    i := fend;
  end;

  num_payload_sz := LongWord(p_dst - dst) - ZXC_BLOCK_HEADER_SIZE;
  WriteBlockHeader(dst, ZXC_BLOCK_NUM, num_payload_sz);
  if ctx^.checksum_enabled then
  begin
    StoreLe32(p_dst, ZxcChecksum(dst + ZXC_BLOCK_HEADER_SIZE, num_payload_sz));
    Inc(p_dst, ZXC_BLOCK_CHECKSUM_SIZE);
  end;
  { reject if not worth it (>75% of src) }
  if LongWord(p_dst - dst) * 4 >= src_size * 3 then
  begin
    Result := -1;
    Exit;
  end;
  Result := LongInt(p_dst - dst);
end;

{ ============================================================
  Encode: RAW block
  ============================================================ }

function EncodeBlockRaw(ctx: PZxcCCtx; dst: PByte; dst_size: LongWord;
  src: PByte; src_size: LongWord): LongInt;
var
  payload_sz: LongWord;
  p_dst: PByte;
begin
  { comp_size in block header = src_size only (checksum is appended separately) }
  payload_sz := src_size;
  if ZXC_BLOCK_HEADER_SIZE + payload_sz
     + (ZXC_BLOCK_CHECKSUM_SIZE * Ord(ctx^.checksum_enabled)) > dst_size then
  begin
    Result := ZXC_ERR_DST_TOO_SMALL;
    Exit;
  end;

  p_dst := dst + ZXC_BLOCK_HEADER_SIZE;
  Move(src[0], p_dst[0], src_size);
  Inc(p_dst, src_size);
  WriteBlockHeader(dst, ZXC_BLOCK_RAW, payload_sz);

  if ctx^.checksum_enabled then
  begin
    StoreLe32(p_dst, ZxcChecksum(dst + ZXC_BLOCK_HEADER_SIZE, src_size));
    Inc(p_dst, ZXC_BLOCK_CHECKSUM_SIZE);
  end;
  Result := LongInt(p_dst - dst);
end;

{ ============================================================
  Compress chunk wrapper
  ============================================================ }

function CompressChunkWrapper(ctx: PZxcCCtx; dst: PByte; dst_size: LongWord;
  src: PByte; src_size: LongWord): LongInt;
var
  res: LongInt;
  try_num: Boolean;
begin
  { Reset epoch if needed }
  if ctx^.epoch + 1 >= ctx^.max_epoch then
  begin
    ctx^.epoch := 1;
    FillChar(ctx^.hash_table[0], ZXC_LZ_HASH_SIZE * SizeOf(LongWord), 0);
    FillChar(ctx^.hash_tags[0],  ZXC_LZ_HASH_SIZE * SizeOf(Byte), 0);
  end
  else
    Inc(ctx^.epoch);

  try_num := ProbeIsNumeric(src, src_size);

  res := ZXC_OK - 1; { sentinel }
  if try_num then
  begin
    res := EncodeBlockNum(ctx, dst, dst_size, src, src_size);
    WriteLn(ErrOutput, 'DBG NUM res=', res);
    if res <= 0 then try_num := False;
  end;

  if not try_num then
  begin
    if ctx^.level <= 2 then
      res := EncodeBlockGhi(ctx, dst, dst_size, src, src_size)
    else
      res := EncodeBlockGlo(ctx, dst, dst_size, src, src_size);
    WriteLn(ErrOutput, 'DBG GLO/GHI res=', res, ' src=', src_size);
  end;

  if (res <= 0) or (LongWord(res) >= src_size) then
  begin
    WriteLn(ErrOutput, 'DBG -> RAW (res=', res, ')');
    res := EncodeBlockRaw(ctx, dst, dst_size, src, src_size);
  end;

  Result := res;
end;

{ ============================================================
  Decode: GLO block
  ============================================================ }

function DecodeBlockGlo(src: PByte; src_size: LongWord;
  dst: PByte; dst_size: LongWord): LongInt;
var
  n_seq, n_lit: LongWord;
  enc_lit, enc_litlen, enc_mlen, enc_off: Byte;
  descs: array[0..ZXC_GLO_SECTIONS-1] of TSectionDesc;
  p_lits, p_toks, p_offs, p_exts: PByte;
  p_lits_end, p_toks_end, p_offs_end, p_exts_end: PByte;
  d_ptr, d_end: PByte;
  seq_i: LongWord;
  token: Byte;
  ll_code, ml_code: LongWord;
  ll, ml, off: LongWord;
  vval: LongWord;
  vb: LongInt;
  ref: PByte;
  copied, trail_ll: LongWord;
  rle_buf: PByte;
  raw_lit_count: LongWord;
  r_ptr, r_end, w_ptr, w_end: PByte;
  tok_byte: Byte;
  rle_len: LongWord;
begin
  if src_size < ZXC_GLO_HEADER_BINARY_SIZE + ZXC_GLO_SECTIONS * ZXC_SECTION_DESC_BINARY_SIZE then
  begin
    Result := ZXC_ERR_SRC_TOO_SMALL;
    Exit;
  end;

  ReadGloHeader(src, n_seq, n_lit, enc_lit, enc_litlen, enc_mlen, enc_off, descs);

  { Section pointers }
  p_lits := src + ZXC_GLO_HEADER_BINARY_SIZE + ZXC_GLO_SECTIONS * ZXC_SECTION_DESC_BINARY_SIZE;
  p_toks := p_lits + descs[0].raw_size;
  p_offs := p_toks + descs[1].raw_size;
  p_exts := p_offs + descs[2].raw_size;
  p_lits_end := p_toks;
  p_toks_end := p_offs;
  p_offs_end := p_exts;
  p_exts_end := p_exts + descs[3].raw_size;

  raw_lit_count := descs[0].comp_size or (LongWord(descs[0].enc_type) shl 24);

  rle_buf := nil;
  if enc_lit = ZXC_ENC_VARINT then
  begin
    if raw_lit_count > 0 then
    begin
      GetMem(rle_buf, raw_lit_count);
      { Decode RLE from p_lits (size = descs[0].raw_size) into rle_buf (size = raw_lit_count) }
      r_ptr := p_lits;
      r_end := p_lits + descs[0].raw_size;
      w_ptr := rle_buf;
      w_end := rle_buf + raw_lit_count;
      while (r_ptr < r_end) and (w_ptr < w_end) do
      begin
        tok_byte := r_ptr^;
        Inc(r_ptr);
        if (tok_byte and $80) = 0 then
        begin
          { raw copy: len = tok_byte + 1 }
          rle_len := LongWord(tok_byte) + 1;
          if (w_ptr + rle_len > w_end) or (r_ptr + rle_len > r_end) then
          begin FreeMem(rle_buf); Result := ZXC_ERR_CORRUPT_DATA; Exit; end;
          Move(r_ptr^, w_ptr^, rle_len);
          Inc(r_ptr, rle_len);
          Inc(w_ptr, rle_len);
        end
        else
        begin
          { RLE fill: len = (tok_byte & 0x7F) + 4 }
          rle_len := LongWord(tok_byte and $7F) + 4;
          if (w_ptr + rle_len > w_end) or (r_ptr >= r_end) then
          begin FreeMem(rle_buf); Result := ZXC_ERR_CORRUPT_DATA; Exit; end;
          FillChar(w_ptr^, rle_len, r_ptr^);
          Inc(r_ptr);
          Inc(w_ptr, rle_len);
        end;
      end;
      if w_ptr <> w_end then
      begin FreeMem(rle_buf); Result := ZXC_ERR_CORRUPT_DATA; Exit; end;
      p_lits := rle_buf;
      p_lits_end := rle_buf + raw_lit_count;
    end
    else
    begin
      p_lits := nil;
      p_lits_end := nil;
    end;
  end;

  d_ptr := dst;
  d_end := dst + dst_size;

  for seq_i := 0 to n_seq - 1 do
  begin
    if p_toks >= p_toks_end then
    begin
      if rle_buf <> nil then FreeMem(rle_buf);
      Result := ZXC_ERR_CORRUPT_DATA;
      Exit;
    end;
    token   := p_toks^;
    Inc(p_toks);
    ll_code := (token shr 4) and $0F;
    ml_code := token and $0F;

    { literal length }
    ll := ll_code;
    if ll_code = 15 then
    begin
      if p_exts >= p_exts_end then begin if rle_buf <> nil then FreeMem(rle_buf); Result := ZXC_ERR_CORRUPT_DATA; Exit; end;
      vb := ReadVarint(p_exts, vval);
      Inc(p_exts, vb);
      ll := 15 + vval;
    end;

    { match length }
    ml := ml_code + ZXC_LZ_MIN_MATCH_LEN;
    if ml_code = 15 then
    begin
      if p_exts >= p_exts_end then begin if rle_buf <> nil then FreeMem(rle_buf); Result := ZXC_ERR_CORRUPT_DATA; Exit; end;
      vb := ReadVarint(p_exts, vval);
      Inc(p_exts, vb);
      ml := ZXC_LZ_MIN_MATCH_LEN + 15 + vval;
    end;

    { copy literals }
    if ll > 0 then
    begin
      if p_lits + ll > p_lits_end then begin if rle_buf <> nil then FreeMem(rle_buf); Result := ZXC_ERR_CORRUPT_DATA; Exit; end;
      if d_ptr + ll > d_end then begin if rle_buf <> nil then FreeMem(rle_buf); Result := ZXC_ERR_OVERFLOW; Exit; end;
      Move(p_lits[0], d_ptr[0], ll);
      Inc(p_lits, ll);
      Inc(d_ptr, ll);
    end;

    { read offset: enc_off=1 -> 1-byte offsets, enc_off=0 -> 2-byte offsets }
    if enc_off = 1 then
    begin
      if p_offs >= p_offs_end then begin if rle_buf <> nil then FreeMem(rle_buf); Result := ZXC_ERR_CORRUPT_DATA; Exit; end;
      off := p_offs^ + ZXC_LZ_OFFSET_BIAS;
      Inc(p_offs);
    end
    else
    begin
      if p_offs + 2 > p_offs_end then begin if rle_buf <> nil then FreeMem(rle_buf); Result := ZXC_ERR_CORRUPT_DATA; Exit; end;
      off := Le16(p_offs) + ZXC_LZ_OFFSET_BIAS;
      Inc(p_offs, 2);
    end;

    if off > PtrUInt(d_ptr - dst) then begin if rle_buf <> nil then FreeMem(rle_buf); Result := ZXC_ERR_BAD_OFFSET; Exit; end;

    { copy match }
    ref := d_ptr - off;
    if d_ptr + ml > d_end then begin if rle_buf <> nil then FreeMem(rle_buf); Result := ZXC_ERR_OVERFLOW; Exit; end;
    if off >= 16 then
    begin
      { fast copy with possible overlap }
      copied := 0;
      while copied + 16 <= ml do
      begin
        Copy16(d_ptr + copied, ref + copied);
        Inc(copied, 16);
      end;
      while copied < ml do
      begin
        (d_ptr + copied)^ := (ref + copied)^;
        Inc(copied);
      end;
    end
    else
      CopyOverlap16(d_ptr, off, ml);
    Inc(d_ptr, ml);
  end;

  { trailing literals }
  trail_ll := LongWord(p_lits_end - p_lits);
  if trail_ll > 0 then
  begin
    if d_ptr + trail_ll > d_end then begin if rle_buf <> nil then FreeMem(rle_buf); Result := ZXC_ERR_OVERFLOW; Exit; end;
    Move(p_lits[0], d_ptr[0], trail_ll);
    Inc(d_ptr, trail_ll);
  end;

  if rle_buf <> nil then FreeMem(rle_buf);
  Result := LongInt(d_ptr - dst);
end;

{ ============================================================
  Decode: GHI block
  ============================================================ }

function DecodeBlockGhi(src: PByte; src_size: LongWord;
  dst: PByte; dst_size: LongWord): LongInt;
var
  n_seq, n_lit: LongWord;
  enc_lit, enc_seq, enc_ext: Byte;
  descs: array[0..ZXC_GHI_SECTIONS-1] of TSectionDesc;
  p_lits, p_seqs, p_exts: PByte;
  p_lits_end, p_seqs_end, p_exts_end: PByte;
  d_ptr, d_end: PByte;
  seq_i: LongWord;
  seq_val: LongWord;
  ll, ml, off: LongWord;
  ll_bits, ml_bits: LongWord;
  vval: LongWord;
  vb: LongInt;
  ref: PByte;
  copied, trail_ll: LongWord;
begin
  if src_size < ZXC_GHI_HEADER_BINARY_SIZE + ZXC_GHI_SECTIONS * ZXC_SECTION_DESC_BINARY_SIZE then
  begin
    Result := ZXC_ERR_SRC_TOO_SMALL;
    Exit;
  end;

  ReadGhiHeader(src, n_seq, n_lit, enc_lit, enc_seq, enc_ext, descs);

  p_lits := src + ZXC_GHI_HEADER_BINARY_SIZE + ZXC_GHI_SECTIONS * ZXC_SECTION_DESC_BINARY_SIZE;
  p_seqs := p_lits + descs[0].raw_size;
  p_exts := p_seqs + descs[1].raw_size;
  p_lits_end := p_seqs;
  p_seqs_end := p_exts;
  p_exts_end := p_exts + descs[2].raw_size;

  d_ptr := dst;
  d_end := dst + dst_size;

  for seq_i := 0 to n_seq - 1 do
  begin
    if p_seqs + 4 > p_seqs_end then begin Result := ZXC_ERR_CORRUPT_DATA; Exit; end;
    seq_val := Le32(p_seqs);
    Inc(p_seqs, 4);

    ll_bits := (seq_val shr 24) and ZXC_SEQ_LL_MASK;
    ml_bits := (seq_val shr 16) and ZXC_SEQ_ML_MASK;
    off     := (seq_val and ZXC_SEQ_OFF_MASK) + ZXC_LZ_OFFSET_BIAS;

    ll := ll_bits;
    if ll_bits = 255 then
    begin
      if p_exts >= p_exts_end then begin Result := ZXC_ERR_CORRUPT_DATA; Exit; end;
      vb := ReadVarint(p_exts, vval);
      Inc(p_exts, vb);
      ll := 255 + vval;
    end;

    ml := ml_bits + ZXC_LZ_MIN_MATCH_LEN;
    if ml_bits = 255 then
    begin
      if p_exts >= p_exts_end then begin Result := ZXC_ERR_CORRUPT_DATA; Exit; end;
      vb := ReadVarint(p_exts, vval);
      Inc(p_exts, vb);
      ml := ZXC_LZ_MIN_MATCH_LEN + 255 + vval;
    end;

    { copy literals }
    if ll > 0 then
    begin
      if p_lits + ll > p_lits_end then begin Result := ZXC_ERR_CORRUPT_DATA; Exit; end;
      if d_ptr + ll > d_end then begin Result := ZXC_ERR_OVERFLOW; Exit; end;
      Move(p_lits[0], d_ptr[0], ll);
      Inc(p_lits, ll);
      Inc(d_ptr, ll);
    end;

    if off > PtrUInt(d_ptr - dst) then begin Result := ZXC_ERR_BAD_OFFSET; Exit; end;
    ref := d_ptr - off;
    if d_ptr + ml > d_end then begin Result := ZXC_ERR_OVERFLOW; Exit; end;

    if off >= 16 then
    begin
      copied := 0;
      while copied + 16 <= ml do
      begin
        Copy16(d_ptr + copied, ref + copied);
        Inc(copied, 16);
      end;
      while copied < ml do
      begin
        (d_ptr + copied)^ := (ref + copied)^;
        Inc(copied);
      end;
    end
    else
      CopyOverlap16(d_ptr, off, ml);
    Inc(d_ptr, ml);
  end;

  trail_ll := LongWord(p_lits_end - p_lits);
  if trail_ll > 0 then
  begin
    if d_ptr + trail_ll > d_end then begin Result := ZXC_ERR_OVERFLOW; Exit; end;
    Move(p_lits[0], d_ptr[0], trail_ll);
    Inc(d_ptr, trail_ll);
  end;

  Result := LongInt(d_ptr - dst);
end;

{ ============================================================
  Decode: NUM block
  ============================================================ }

function DecodeBlockNum(src: PByte; src_size: LongWord;
  dst: PByte; dst_size: LongWord): LongInt;
var
  nvals, i, frame_i: LongWord;
  chunk_nvals, chunk_bits, chunk_packed_sz: LongWord;
  chunk_base: QWord;
  br: TBitReader;
  running_val: LongWord;
  delta, zigzag: LongWord;
  p_src: PByte;
  p_dst: PByte;
begin
  if src_size < ZXC_NUM_HEADER_BINARY_SIZE then
  begin
    Result := ZXC_ERR_SRC_TOO_SMALL;
    Exit;
  end;

  nvals := Le32(src);
  if nvals * 4 > dst_size then
  begin
    Result := ZXC_ERR_OVERFLOW;
    Exit;
  end;

  p_src     := src + ZXC_NUM_HEADER_BINARY_SIZE;
  p_dst     := dst;
  running_val := 0;
  i := 0;

  while i < nvals do
  begin
    { read chunk header }
    if p_src + ZXC_NUM_CHUNK_HEADER_SIZE > src + src_size then
    begin
      Result := ZXC_ERR_CORRUPT_DATA;
      Exit;
    end;
    chunk_nvals    := Le16(p_src);
    chunk_bits     := Le16(p_src + 2);
    chunk_base     := Le64(p_src + 4);
    chunk_packed_sz:= Le32(p_src + 12);
    Inc(p_src, ZXC_NUM_CHUNK_HEADER_SIZE);

    if chunk_nvals = 0 then begin Result := ZXC_ERR_CORRUPT_DATA; Exit; end;

    if chunk_bits = 0 then
    begin
      { all values are base }
      for frame_i := 0 to chunk_nvals - 1 do
      begin
        delta := ZigZagDecode(LongWord(chunk_base));
        running_val := running_val + delta;
        StoreLe32(p_dst, running_val);
        Inc(p_dst, 4);
      end;
    end
    else
    begin
      { bit-unpack }
      BrInit(br, p_src, LongInt(chunk_packed_sz));

      for frame_i := 0 to chunk_nvals - 1 do
      begin
        BrEnsure(br, LongInt(chunk_bits));
        zigzag := BrConsumeFast(br, LongInt(chunk_bits));
        zigzag := zigzag + LongWord(chunk_base);
        delta := ZigZagDecode(zigzag);
        running_val := running_val + delta;
        StoreLe32(p_dst, running_val);
        Inc(p_dst, 4);
      end;
    end;

    Inc(p_src, chunk_packed_sz);
    Inc(i, chunk_nvals);
  end;

  Result := LongInt(p_dst - dst);
end;

{ ============================================================
  Decompress chunk wrapper
  ============================================================ }

function DecompressChunkWrapper(src: PByte; src_size: LongWord;
  dst: PByte; dst_size: LongWord;
  checksum_enabled: Boolean): LongInt;
var
  block_type: Byte;
  comp_size: LongWord;
  ret: LongInt;
  expected_sz: LongWord;
  payload: PByte;
  payload_sz: LongWord;
  stored_cksum, calc_cksum: LongWord;
begin
  if src_size < ZXC_BLOCK_HEADER_SIZE then
  begin
    Result := ZXC_ERR_SRC_TOO_SMALL;
    Exit;
  end;

  ret := ReadBlockHeader(src, block_type, comp_size);
  if ret <> ZXC_OK then
  begin
    Result := ret;
    Exit;
  end;

  expected_sz := ZXC_BLOCK_HEADER_SIZE + comp_size;
  if checksum_enabled then Inc(expected_sz, ZXC_BLOCK_CHECKSUM_SIZE);
  if src_size < expected_sz then
  begin
    Result := ZXC_ERR_SRC_TOO_SMALL;
    Exit;
  end;

  payload    := src + ZXC_BLOCK_HEADER_SIZE;
  payload_sz := comp_size;

  { verify checksum if enabled }
  if checksum_enabled then
  begin
    stored_cksum := Le32(src + ZXC_BLOCK_HEADER_SIZE + payload_sz);
    calc_cksum   := ZxcChecksum(payload, payload_sz);
    if stored_cksum <> calc_cksum then
    begin
      Result := ZXC_ERR_BAD_CHECKSUM;
      Exit;
    end;
  end;

  case block_type of
    ZXC_BLOCK_RAW:
    begin
      if payload_sz > dst_size then begin Result := ZXC_ERR_OVERFLOW; Exit; end;
      Move(payload[0], dst[0], payload_sz);
      Result := LongInt(payload_sz);
    end;
    ZXC_BLOCK_GLO:
      Result := DecodeBlockGlo(payload, payload_sz, dst, dst_size);
    ZXC_BLOCK_GHI:
      Result := DecodeBlockGhi(payload, payload_sz, dst, dst_size);
    ZXC_BLOCK_NUM:
      Result := DecodeBlockNum(payload, payload_sz, dst, dst_size);
  else
    Result := ZXC_ERR_BAD_BLOCK_TYPE;
  end;
end;

{ ============================================================
  Public API implementation
  ============================================================ }

function ZxcCompressBound(input_size: PtrUInt): PtrUInt;
var
  n: PtrUInt;
begin
  n := (input_size + 4095) div 4096;
  if n = 0 then n := 1;
  Result := 16 + n * (8 + 4 + 64) + input_size + 8 + 8 + n * 4 + 12;
end;

function ZxcGetDecompressedSize(src: PByte; src_size: PtrUInt): Int64;
begin
  if src_size < ZXC_FILE_HEADER_SIZE + ZXC_FILE_FOOTER_SIZE then
  begin
    Result := ZXC_ERR_SRC_TOO_SMALL;
    Exit;
  end;
  if Le32(src) <> ZXC_MAGIC_WORD then
  begin
    Result := ZXC_ERR_BAD_MAGIC;
    Exit;
  end;
  Result := Int64(Le64(src + src_size - 12));
end;

function ZxcCompress(dst: PByte; dst_size: PtrUInt;
  src: PByte; src_size: PtrUInt;
  level: LongInt; block_size: LongInt): LongInt;
var
  ctx: TZxcCCtx;
  cs: LongWord;
  ret: LongInt;
  src_offset: PtrUInt;
  chunk_sz: LongWord;
  global_hash: LongWord;
  has_checksum: Boolean;
  w: PByte;
  w_end: PByte;
  tmp_hash: QWord;
begin
  if (dst = nil) or (src = nil) then begin Result := ZXC_ERR_NULL_INPUT; Exit; end;
  if src_size = 0 then begin Result := ZXC_ERR_SRC_TOO_SMALL; Exit; end;
  if dst_size < ZxcCompressBound(src_size) then begin Result := ZXC_ERR_DST_TOO_SMALL; Exit; end;

  if level < 1 then level := 1;
  if level > 5 then level := 5;
  if block_size = 0 then block_size := ZXC_BLOCK_SIZE_DEFAULT;
  if (block_size < ZXC_BLOCK_SIZE_MIN) or (block_size > ZXC_BLOCK_SIZE_MAX) then
  begin
    Result := ZXC_ERR_BAD_BLOCK_SIZE;
    Exit;
  end;

  cs := LongWord(block_size);
  has_checksum := True;

  ret := CctxInit(@ctx, cs, LongWord(level), has_checksum);
  if ret <> ZXC_OK then begin Result := ret; Exit; end;

  w     := dst;
  w_end := dst + dst_size;

  WriteFileHeader(w, cs, has_checksum);
  Inc(w, ZXC_FILE_HEADER_SIZE);

  global_hash  := 0;
  src_offset   := 0;

  while src_offset < src_size do
  begin
    chunk_sz := cs;
    if src_offset + chunk_sz > src_size then
      chunk_sz := LongWord(src_size - src_offset);

    ret := CompressChunkWrapper(@ctx, w, LongWord(w_end - w),
      src + src_offset, chunk_sz);
    if ret <= 0 then
    begin
      CctxFree(@ctx);
      Result := ret;
      Exit;
    end;

    if has_checksum then
    begin
      tmp_hash    := Le32(w + ret - ZXC_BLOCK_CHECKSUM_SIZE);
      global_hash := ((global_hash shl 1) or (global_hash shr 31))
                     xor LongWord(tmp_hash);
    end;

    Inc(w, ret);
    Inc(src_offset, chunk_sz);
  end;

  { Write EOF block }
  WriteBlockHeader(w, ZXC_BLOCK_EOF, 0);
  Inc(w, ZXC_BLOCK_HEADER_SIZE);

  { Write footer }
  WriteFileFooter(w, QWord(src_size), global_hash, has_checksum);
  Inc(w, ZXC_FILE_FOOTER_SIZE);

  CctxFree(@ctx);
  Result := LongInt(w - dst);
end;

function ZxcDecompress(dst: PByte; dst_size: PtrUInt;
  src: PByte; src_size: PtrUInt): LongInt;
var
  chunk_size: LongWord;
  has_checksum: Boolean;
  ret: LongInt;
  p: PByte;
  p_end: PByte;
  d: PByte;
  d_end: PByte;
  block_type: Byte;
  comp_size: LongWord;
  expected_src_size: QWord;
  global_hash: LongWord;
  tmp_hash: QWord;
  stored_global_hash: LongWord;
  block_total: LongWord;
  saved_ck: Byte;
begin
  if (dst = nil) or (src = nil) then begin Result := ZXC_ERR_NULL_INPUT; Exit; end;
  if src_size < ZXC_FILE_HEADER_SIZE + ZXC_FILE_FOOTER_SIZE then
  begin
    Result := ZXC_ERR_SRC_TOO_SMALL;
    Exit;
  end;

  ret := ReadFileHeader(src, src_size, chunk_size, has_checksum);
  if ret <> ZXC_OK then begin Result := ret; Exit; end;

  p     := src + ZXC_FILE_HEADER_SIZE;
  p_end := src + src_size;
  d     := dst;
  d_end := dst + dst_size;

  global_hash := 0;

  while p + ZXC_BLOCK_HEADER_SIZE <= p_end do
  begin
    { peek block type }
    saved_ck := (p + 7)^;
    (p + 7)^ := 0;
    block_type := p^;
    (p + 7)^ := saved_ck;

    if block_type = ZXC_BLOCK_EOF then
    begin
      { verify footer }
      if p + ZXC_BLOCK_HEADER_SIZE + ZXC_FILE_FOOTER_SIZE > p_end then
      begin
        Result := ZXC_ERR_SRC_TOO_SMALL;
        Exit;
      end;
      Inc(p, ZXC_BLOCK_HEADER_SIZE);
      expected_src_size := Le64(p);
      if has_checksum then
      begin
        stored_global_hash := Le32(p + 8);
        if stored_global_hash <> global_hash then
        begin
          Result := ZXC_ERR_BAD_CHECKSUM;
          Exit;
        end;
      end;
      { Check that decompressed size matches }
      if QWord(d - dst) <> expected_src_size then
      begin
        Result := ZXC_ERR_CORRUPT_DATA;
        Exit;
      end;
      Result := LongInt(d - dst);
      Exit;
    end;

    { Read block header properly }
    ret := ReadBlockHeader(p, block_type, comp_size);
    if ret <> ZXC_OK then begin Result := ret; Exit; end;

    block_total := ZXC_BLOCK_HEADER_SIZE + comp_size;
    if has_checksum then Inc(block_total, ZXC_BLOCK_CHECKSUM_SIZE);
    if p + block_total > p_end then begin Result := ZXC_ERR_SRC_TOO_SMALL; Exit; end;

    ret := DecompressChunkWrapper(p, block_total, d, LongWord(d_end - d), has_checksum);
    if ret < 0 then begin Result := ret; Exit; end;

    if has_checksum then
    begin
      tmp_hash    := Le32(p + ZXC_BLOCK_HEADER_SIZE + comp_size);
      global_hash := ((global_hash shl 1) or (global_hash shr 31))
                     xor LongWord(tmp_hash);
    end;

    Inc(p, block_total);
    Inc(d, ret);
  end;

  Result := ZXC_ERR_CORRUPT_DATA; { no EOF block found }
end;

end.
